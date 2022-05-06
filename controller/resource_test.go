package controller

// These tests can run against both OSS and Enterprise Consul.
// By default only the OSS tests will run and Enterprise features will not be enabled.
//
// To run the tests against an OSS Consul agent, make sure that the `consul` command is
// pointing to an OSS binary and run the tests as normal:
//
//	go test
//
// To run the tests against an Enterprise Consul agent, make sure that the `consul` command is
// pointing to an Enterprise binary and pass `-enterprise` as an arg to the tests:
//
//	go test -- -enterprise
//
// Note: the tests will not run against Consul Enterprise without the -enterprise flag.

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/consul-ecs/controller/mocks"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

const testClusterArn = "arn:aws:ecs:bogus-east-1:000000000000:cluster/my-cluster"

func makeECSTask(t *testing.T, taskId string, tags ...string) *ecs.Task {
	require.Equal(t, 0, len(tags)%2, "tags must be even length")
	var ecsTags []*ecs.Tag
	for i := 0; i < len(tags); i += 2 {
		ecsTags = append(ecsTags, &ecs.Tag{
			Key:   aws.String(tags[i]),
			Value: aws.String(tags[i+1]),
		})
	}
	return &ecs.Task{
		ClusterArn: aws.String(testClusterArn),
		TaskArn:    aws.String("arn:aws:ecs:bogus-east-1:000000000000:task/my-cluster/" + taskId),
		Tags:       ecsTags,
	}
}

func makeTaskState(taskId string, taskFound bool, tokens []*api.ACLTokenListEntry) *TaskState {
	t := &TaskState{
		TaskID:       TaskID(taskId),
		Cluster:      testClusterArn,
		ECSTaskFound: taskFound,
		ACLTokens:    tokens,
	}
	if enterpriseFlag() && taskFound {
		t.Partition = DefaultPartition
		t.NS = DefaultNamespace
	}
	return t
}

func makeTaskStateEnt(taskId string, taskFound bool, tokens []*api.ACLTokenListEntry, partition, namespace string) *TaskState {
	t := makeTaskState(taskId, taskFound, tokens)
	t.Partition = partition
	t.NS = namespace
	return t
}

func makeToken(t *testing.T, taskId string, isLogin bool) *api.ACLTokenListEntry {
	accessor, err := uuid.GenerateUUID()
	require.NoError(t, err)
	secret, err := uuid.GenerateUUID()
	require.NoError(t, err)

	description := "non login token"
	if isLogin {
		description = fmt.Sprintf(
			`token created via login: {"%s":"%s","%s":"%s"}`,
			clusterTag, testClusterArn, taskIdTag, taskId,
		)
	}
	tok := &api.ACLTokenListEntry{
		AccessorID:        accessor,
		SecretID:          secret,
		Description:       description,
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "test-service"}},
	}
	if enterpriseFlag() {
		tok.Partition = DefaultPartition
		tok.Namespace = DefaultNamespace
	}
	return tok
}

func makeTokenEnt(t *testing.T, taskId string, isLogin bool, partition, namespace string) *api.ACLTokenListEntry {
	tok := makeToken(t, taskId, isLogin)
	tok.Partition = partition
	tok.Namespace = namespace
	return tok
}

func TestTaskStateListerList(t *testing.T) {
	t.Parallel()
	meshTasks := []*ecs.Task{
		makeECSTask(t, "mesh-task-id-1", meshTag, "true"),
		makeECSTask(t, "mesh-task-id-2", meshTag, "true"),
		makeECSTask(t, "mesh-task-id-3", meshTag, "true"),
	}
	nonMeshTasks := []*ecs.Task{
		makeECSTask(t, "non-mesh-task-id-1"),
		makeECSTask(t, "non-mesh-task-id-2"),
		makeECSTask(t, "non-mesh-task-id-3"),
	}
	allTasks := append(meshTasks, nonMeshTasks...)

	loginTokens := []*api.ACLTokenListEntry{
		makeToken(t, "mesh-task-id-1", true), makeToken(t, "mesh-task-id-1", true),
		makeToken(t, "mesh-task-id-2", true), makeToken(t, "mesh-task-id-2", true),
		makeToken(t, "mesh-task-id-3", true), makeToken(t, "mesh-task-id-3", true),
	}
	nonLoginTokens := []*api.ACLTokenListEntry{
		makeToken(t, "non-mesh-task-id-1", false), makeToken(t, "mesh-task-id-1", false),
		makeToken(t, "non-mesh-task-id-2", false), makeToken(t, "mesh-task-id-2", false),
		makeToken(t, "non-mesh-task-id-3", false), makeToken(t, "mesh-task-id-3", false),
	}
	allTokens := append(loginTokens, nonLoginTokens...)

	tokenIgnoreFields := cmpopts.IgnoreFields(
		api.ACLTokenListEntry{}, "CreateIndex", "ModifyIndex", "CreateTime", "Hash",
	)
	taskStateIgnoreFields := cmpopts.IgnoreFields(TaskState{}, "ConsulClient", "Log")

	type testCase struct {
		// tasks to setup in ECS for the test
		initTasks []*ecs.Task
		// tokens to setup in Consul for the test
		initTokens []*api.ACLTokenListEntry
		// setup partitions + namespaces in Consul
		initPartitions map[string][]string
		// the controller's configured partition
		partition string

		expResources []Resource
	}
	cases := map[string]testCase{
		"no tasks and no tokens": {},
		"no mesh tasks and no login tokens": {
			initTokens: nonLoginTokens,
			initTasks:  nonMeshTasks,
			// TaskStateLister finds no resources.
		},
		"no mesh tasks with login tokens": {
			initTokens: allTokens,
			initTasks:  nonMeshTasks,
			expResources: []Resource{
				// TaskStateLister finds the tokens but does not find the task
				makeTaskState("mesh-task-id-1", false, loginTokens[0:2]),
				makeTaskState("mesh-task-id-2", false, loginTokens[2:4]),
				makeTaskState("mesh-task-id-3", false, loginTokens[4:6]),
			},
		},
		"mesh tasks without tokens": {
			initTokens: nonLoginTokens,
			initTasks:  allTasks,
			expResources: []Resource{
				// TaskStateLister finds the tasks but does not find the tokens
				makeTaskState("mesh-task-id-1", true, nil),
				makeTaskState("mesh-task-id-2", true, nil),
				makeTaskState("mesh-task-id-3", true, nil),
			},
		},
		"mesh tasks with tokens": {
			initTokens: allTokens,
			initTasks:  allTasks,
			expResources: []Resource{
				// TaskStateLister finds the tasks and tokens
				makeTaskState("mesh-task-id-1", true, loginTokens[0:2]),
				makeTaskState("mesh-task-id-2", true, loginTokens[2:4]),
				makeTaskState("mesh-task-id-3", true, loginTokens[4:6]),
			},
		},
	}

	const (
		testPtn  = "test-ptn"
		otherPtn = "other-ptn"
		testNs   = "test-ns"
	)
	allPartitions := map[string][]string{
		DefaultPartition: {testNs},
		otherPtn:         {testNs},
		testPtn:          {testNs},
	}

	if enterpriseFlag() {
		tags := []string{meshTag, "true", partitionTag, testPtn, namespaceTag, testNs}
		entMeshTasks := []*ecs.Task{
			makeECSTask(t, "partition-task-1", tags...),
			makeECSTask(t, "partition-task-2", tags...),
			makeECSTask(t, "partition-task-3", tags...),
		}
		entOtherTasks := []*ecs.Task{
			// missing mesh tag
			makeECSTask(t, "other-task-1", partitionTag, testPtn, namespaceTag, testNs),
			// different partition
			makeECSTask(t, "other-task-2", meshTag, "true", partitionTag, otherPtn, namespaceTag, testNs),
			// missing namespace
			makeECSTask(t, "other-task-3", meshTag, "true", partitionTag, testPtn),
			// missing partition
			makeECSTask(t, "other-task-4", meshTag, "true", namespaceTag, testNs),
			// missing all tags
			makeECSTask(t, "other-task-5"),
		}
		entAllTasks := append(entMeshTasks, entOtherTasks...)

		entLoginTokens := []*api.ACLTokenListEntry{
			makeTokenEnt(t, "partition-task-1", true, testPtn, testNs),
			makeTokenEnt(t, "partition-task-1", true, testPtn, "default"),
			makeTokenEnt(t, "partition-task-2", true, testPtn, testNs),
			makeTokenEnt(t, "partition-task-2", true, testPtn, "default"),
			makeTokenEnt(t, "partition-task-3", true, testPtn, testNs),
			makeTokenEnt(t, "partition-task-3", true, testPtn, "default"),
		}
		entOtherTokens := []*api.ACLTokenListEntry{
			// not login tokens
			makeTokenEnt(t, "other-task-1", false, testPtn, testNs),
			makeTokenEnt(t, "other-task-2", false, testPtn, testNs),
			// in other partition
			makeTokenEnt(t, "other-task-1", true, otherPtn, testNs),
			makeTokenEnt(t, "other-task-2", true, DefaultPartition, testNs),
		}
		entAllTokens := append(entLoginTokens, entOtherTokens...)

		cases["no tasks or tokens in partition"] = testCase{
			initPartitions: allPartitions,
			partition:      testPtn,
		}
		cases["no mesh tasks or login tokens in partition"] = testCase{
			initTasks:      entOtherTasks,
			initTokens:     entOtherTokens,
			initPartitions: allPartitions,
			partition:      testPtn,
		}
		cases["mesh tasks without tokens in partition"] = testCase{
			initTasks:      entAllTasks,
			initTokens:     entOtherTokens,
			initPartitions: allPartitions,
			partition:      testPtn,
			expResources: []Resource{
				// Finds tasks but no tokens.
				makeTaskStateEnt("partition-task-1", true, nil, testPtn, testNs),
				makeTaskStateEnt("partition-task-2", true, nil, testPtn, testNs),
				makeTaskStateEnt("partition-task-3", true, nil, testPtn, testNs),
			},
		}
		cases["no mesh tasks with tokens in partition"] = testCase{
			initTasks:      entOtherTasks,
			initTokens:     entAllTokens,
			initPartitions: allPartitions,
			partition:      testPtn,
			expResources: []Resource{
				// Partition and Namespace are not set from the ACL token.
				makeTaskStateEnt("partition-task-1", false, entLoginTokens[0:2], "", ""),
				makeTaskStateEnt("partition-task-2", false, entLoginTokens[2:4], "", ""),
				makeTaskStateEnt("partition-task-3", false, entLoginTokens[4:6], "", ""),
			},
		}
		cases["mesh tasks with tokens in partition"] = testCase{
			initTasks:      entAllTasks,
			initTokens:     entAllTokens,
			initPartitions: allPartitions,
			partition:      testPtn,
			expResources: []Resource{
				// Partition and Namespace are not set from the ACL token.
				makeTaskStateEnt("partition-task-1", true, entLoginTokens[0:2], testPtn, testNs),
				makeTaskStateEnt("partition-task-2", true, entLoginTokens[2:4], testPtn, testNs),
				makeTaskStateEnt("partition-task-3", true, entLoginTokens[4:6], testPtn, testNs),
			},
		}
	}

	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			consulClient := initConsul(t)
			lister := TaskStateLister{
				ECSClient:    &mocks.ECSClient{Tasks: c.initTasks},
				ConsulClient: consulClient,
				Cluster:      testClusterArn,
				Log:          hclog.Default().Named("lister"),
			}

			if enterpriseFlag() {
				lister.Partition = DefaultPartition
				if c.partition != "" {
					lister.Partition = c.partition
				}
				createPartitions(t, consulClient, c.initPartitions)
			}

			createTokens(t, consulClient, c.initTokens...)

			resources, err := lister.List()
			require.NoError(t, err)

			sortTaskStates(c.expResources)
			sortTaskStates(resources)

			for _, r := range resources {
				t.Logf("resource: %+v", r)
				state := r.(*TaskState)
				for _, tok := range state.ACLTokens {
					t.Logf("  token: %+v", tok)
				}
			}
			for _, r := range c.expResources {
				t.Logf("expResource: %+v", r)
				state := r.(*TaskState)
				for _, tok := range state.ACLTokens {
					t.Logf("  token: %+v", tok)
				}
			}

			require.Empty(t, cmp.Diff(c.expResources, resources, tokenIgnoreFields, taskStateIgnoreFields))
		})
	}
}

func createPartitions(t *testing.T, client *api.Client, partitions map[string][]string) {
	ctx := context.Background()
	for ptn, namespaces := range partitions {
		opts := &api.WriteOptions{Partition: ptn}
		_, _, err := client.Partitions().Create(ctx, &api.Partition{Name: ptn}, opts)
		require.NoError(t, err)

		for _, ns := range namespaces {
			_, _, err = client.Namespaces().Create(&api.Namespace{Name: ns}, opts)
			require.NoError(t, err)
		}
	}
}

func createTokens(t *testing.T, client *api.Client, tokens ...*api.ACLTokenListEntry) {
	for _, tok := range tokens {
		_, _, err := client.ACL().TokenCreate(
			&api.ACLToken{
				AccessorID:        tok.AccessorID,
				SecretID:          tok.SecretID,
				Description:       tok.Description,
				ServiceIdentities: tok.ServiceIdentities,
			},
			&api.WriteOptions{
				Partition: tok.Partition,
				Namespace: tok.Namespace,
			},
		)
		require.NoError(t, err)
	}
}

func sortTaskStates(states []Resource) {
	// Sort by TaskID
	sort.Slice(states, func(i, j int) bool {
		a := states[i].(*TaskState)
		b := states[j].(*TaskState)
		return a.TaskID < b.TaskID
	})

	// Sort ACLTokens by AccessorID
	for _, r := range states {
		state := r.(*TaskState)
		sort.Slice(state.ACLTokens, func(i, j int) bool {
			return state.ACLTokens[i].AccessorID < state.ACLTokens[j].AccessorID
		})
	}
}

func TestTaskStateReconcile(t *testing.T) {
	t.Parallel()

	type testCase struct {
		initTokens     []*api.ACLTokenListEntry
		initPartitions map[string][]string
		state          *TaskState
		expExist       []*api.ACLTokenListEntry
		expDeleted     []*api.ACLTokenListEntry
	}

	tokens := []*api.ACLTokenListEntry{
		makeToken(t, "test-task", true),
	}
	cases := map[string]testCase{
		"task not found and tokens not found": {
			initTokens: tokens,
			state:      makeTaskState("test-task", false, nil),
			expExist:   tokens,
		},
		"task found but tokens not found": {
			initTokens: tokens,
			state:      makeTaskState("test-task", true, nil),
			expExist:   tokens,
		},
		"task found and tokens found": {
			initTokens: tokens,
			state:      makeTaskState("test-task", true, tokens),
			expExist:   tokens,
		},
		"task not found but tokens found": {
			initTokens: tokens,
			state:      makeTaskState("test-task", false, tokens),
			expDeleted: tokens,
		},
	}

	if enterpriseFlag() {
		entTokens := []*api.ACLTokenListEntry{
			makeTokenEnt(t, "test-task", true, "test-ptn", "test-ns"),
		}
		partitions := map[string][]string{
			"test-ptn": {"test-ns"},
		}
		cases["task not found and tokens not found in partition"] = testCase{
			initTokens:     entTokens,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", false, nil, "test-ptn", "test-ns"),
			expExist:       entTokens,
		}
		cases["task found but tokens not found in partition"] = testCase{
			initTokens:     entTokens,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", true, nil, "test-ptn", "test-ns"),
			expExist:       entTokens,
		}
		cases["task found and tokens found in partition"] = testCase{
			initTokens:     entTokens,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", true, entTokens, "test-ptn", "test-ns"),
			expExist:       entTokens,
		}
		cases["task not found but tokens found in partition"] = testCase{
			initTokens:     entTokens,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", false, entTokens, "test-ptn", "test-ns"),
			expDeleted:     entTokens,
		}
	}
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := initConsul(t)

			if enterpriseFlag() {
				createPartitions(t, client, c.initPartitions)
			}
			createTokens(t, client, c.initTokens...)

			c.state.ConsulClient = client
			c.state.Log = hclog.NewNullLogger()
			require.NoError(t, c.state.Reconcile())

			for _, exp := range c.expDeleted {
				tok, _, err := client.ACL().TokenRead(exp.AccessorID, &api.QueryOptions{
					Namespace: exp.Namespace,
					Partition: exp.Partition,
				})
				require.Error(t, err)
				require.Contains(t, err.Error(), "403 (ACL not found)")
				require.Nil(t, tok)
			}
			for _, exp := range c.expExist {
				tok, _, err := client.ACL().TokenRead(exp.AccessorID, &api.QueryOptions{
					Namespace: exp.Namespace,
					Partition: exp.Partition,
				})
				require.NoError(t, err)
				require.NotNil(t, tok)
				require.Equal(t, exp.AccessorID, tok.AccessorID)
			}
		})
	}
}

func TestReconcileNamespaces(t *testing.T) {
	t.Parallel()
	type testCase struct {
		partition string
		resources []Resource

		expNS        map[string][]string
		expXnsPolicy bool
	}

	cases := map[string]*testCase{
		"with partitions disabled": {
			expNS: map[string][]string{},
			resources: []Resource{
				makeTaskStateEnt("some-task-id", true, nil, "default", "test-ns"),
			},
		},
	}

	if enterpriseFlag() {
		cases["with partitions disabled"].expNS = map[string][]string{"default": {"default"}}

		cases["with resources in default namespace"] = &testCase{
			partition: "default",
			expNS:     map[string][]string{"default": {"default"}},
			resources: []Resource{
				makeTaskStateEnt("some-task-id", true, nil, "default", "default"),
			},
			expXnsPolicy: true,
		}
		cases["with resources in different namespaces"] = &testCase{
			partition: "default",
			expNS: map[string][]string{
				"default": {"default", "namespace-1", "namespace-2"},
			},
			resources: []Resource{
				makeTaskStateEnt("task-1", true, nil, "default", "default"),
				makeTaskStateEnt("task-2", true, nil, "default", "namespace-1"),
				makeTaskStateEnt("task-3", true, nil, "default", "namespace-1"),
				makeTaskStateEnt("task-4", true, nil, "default", "namespace-2"),
			},
			expXnsPolicy: true,
		}
		cases["with resources in non-default partition"] = &testCase{
			partition: "part-1",
			expNS: map[string][]string{
				"default": {"default"},
				"part-1":  {"default", "namespace-1", "namespace-2"},
			},
			resources: []Resource{
				makeTaskStateEnt("task-1", true, nil, "part-1", "default"),
				makeTaskStateEnt("task-2", true, nil, "part-1", "namespace-1"),
				makeTaskStateEnt("task-3", true, nil, "part-1", "namespace-1"),
				makeTaskStateEnt("task-4", true, nil, "part-1", "namespace-2"),
			},
			expXnsPolicy: true,
		}
	}
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			consulClient := initConsul(t)
			s := TaskStateLister{
				Log:          hclog.NewNullLogger(),
				ConsulClient: consulClient,
				Partition:    c.partition,
			}

			if enterpriseFlag() && c.partition != "" {
				createPartitions(t, consulClient, map[string][]string{c.partition: nil})
			}

			require.NoError(t, s.ReconcileNamespaces(c.resources))
			require.Equal(t, c.expNS, listNamespaces(t, consulClient))

			// check cross namespace policy is created (or not)
			policy, _, err := consulClient.ACL().PolicyReadByName(
				xnsPolicyName,
				&api.QueryOptions{Partition: c.partition},
			)
			if c.expXnsPolicy {
				require.NoError(t, err)
				require.NotNil(t, policy)
				require.Equal(t, fmt.Sprintf(xnsPolicyTpl, c.partition), policy.Rules)
			} else {
				require.Error(t, err)
				require.Nil(t, policy)
			}
		})
	}
}

//func TestACLDescriptions(t *testing.T) {
//	t.Parallel()
//	cases := map[string]struct {
//		cluster     string
//		serviceName MeshTask
//	}{
//		"with partitions": {
//			cluster:     "c1",
//			serviceName: MeshTask{Name: "s1", Partition: "p1", Namespace: "n1", ACLNamespace: "default"},
//		},
//		"without partitions": {
//			cluster:     "c1",
//			serviceName: MeshTask{Name: "s1"},
//		},
//	}
//	for name, c := range cases {
//		c := c
//		t.Run(name, func(t *testing.T) {
//			t.Parallel()
//			s := &ServiceInfo{
//				Cluster:     c.cluster,
//				ServiceName: c.serviceName,
//			}
//			desc := s.aclDescription("Token")
//			l := TaskStateLister{Cluster: c.cluster, Partition: c.serviceName.Partition}
//			require.Equal(t, c.serviceName, l.serviceNameFromDescription(desc))
//		})
//	}
//}
//

// helper func that initializes a Consul test server and returns a Consul API client.
func initConsul(t *testing.T) *api.Client {
	cfg := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	return client
}

// listNamespaces is a helper func that returns a list of namespaces mapped to partition.
func listNamespaces(t *testing.T, consulClient *api.Client) map[string][]string {
	names := make(map[string][]string)

	if !enterpriseFlag() {
		return names
	}

	// list all existing namespaces and map them to partition
	partitions, _, err := consulClient.Partitions().List(context.Background(), nil)
	require.NoError(t, err)
	for _, p := range partitions {
		ns, _, err := consulClient.Namespaces().List(&api.QueryOptions{Partition: p.Name})
		require.NoError(t, err)
		for _, n := range ns {
			names[p.Name] = append(names[p.Name], n.Name)
		}
	}
	return names
}

//// helper func that lists all policies and tokens within all namespaces in a partition
//func listACLs(consulClient *api.Client, partition string) ([]*api.ACLPolicyListEntry, []*api.ACLTokenListEntry, error) {
//	var err error
//	policies := make([]*api.ACLPolicyListEntry, 0)
//	tokens := make([]*api.ACLTokenListEntry, 0)
//	opts := &api.QueryOptions{Partition: partition}
//	var namespaces []*api.Namespace
//
//	if enterpriseFlag() {
//		// only list namespaces in enterprise tests
//		namespaces, _, err = consulClient.Namespaces().List(opts)
//		if err != nil {
//			return policies, tokens, err
//		}
//	} else {
//		namespaces = append(namespaces, &api.Namespace{})
//	}
//
//	for _, ns := range namespaces {
//		opts.Namespace = ns.Name
//		aclPolicies, _, err := consulClient.ACL().PolicyList(opts)
//		if err != nil {
//			return policies, tokens, err
//		}
//		policies = append(policies, aclPolicies...)
//
//		aclTokens, _, err := consulClient.ACL().TokenList(opts)
//		if err != nil {
//			return policies, tokens, err
//		}
//		tokens = append(tokens, aclTokens...)
//	}
//	return policies, tokens, nil
//}

func enterpriseFlag() bool {
	re := regexp.MustCompile("^-+enterprise$")
	for _, a := range os.Args {
		if re.Match([]byte(strings.ToLower(a))) {
			return true
		}
	}
	return false
}
