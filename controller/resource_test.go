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

	ecsServices := []*api.CatalogRegistration{
		// These service instances have the "task-id" metadata field, and exist on the
		// shared cluster arn node , so the controller considers them for reconciliation.
		makeSvc(t, "mesh-task-id-1", testClusterArn, "task-id", "mesh-task-id-1"),
		makeSvc(t, "mesh-task-id-2", testClusterArn, "task-id", "mesh-task-id-2"),
		makeSvc(t, "mesh-task-id-3", testClusterArn, "task-id", "mesh-task-id-3"),
	}
	nonECSServices := []*api.CatalogRegistration{
		// service instance for task in different ECS cluster (node name != testClusterArn)
		makeSvc(t, "other-cluster-svc", "other-cluster-arn", "task-id", "other-cluster-svc"),
		// an "invalid" service instance registered to the cluster node but without a task-id
		// metadata field. this will be ignored by the controller, with a warning in the logs.
		makeSvc(t, "non-ecs-svc-2", testClusterArn),
		// a non ECS service instance
		makeSvc(t, "non-ecs-svc-3", "some-node"),
	}

	tokenIgnoreFields := cmpopts.IgnoreFields(
		api.ACLTokenListEntry{}, "CreateIndex", "ModifyIndex", "CreateTime", "Hash",
	)
	taskStateIgnoreFields := cmpopts.IgnoreFields(TaskState{}, "ConsulClient", "Log")

	type testCase struct {
		// tasks to setup in ECS for the test
		initTasks []*ecs.Task
		// tokens to setup in Consul for the test
		initTokens []*api.ACLTokenListEntry
		// service instances to setup in Consul for the test
		initServices []*api.CatalogRegistration
		// setup partitions + namespaces in Consul
		initPartitions map[string][]string
		// the controller's configured partition
		partition string

		expResources []Resource
	}
	cases := map[string]testCase{
		"no tasks and no tokens and no services": {},
		"no mesh tasks and no login tokens and no services": {
			initTokens: nonLoginTokens,
			initTasks:  nonMeshTasks,
			// TaskStateLister finds no resources.
		},
		"no mesh tasks with login tokens and no services": {
			initTokens: allTokens,
			initTasks:  nonMeshTasks,
			expResources: []Resource{
				// TaskStateLister finds the tokens but does not find the task
				makeTaskState("mesh-task-id-1", false, loginTokens[0:2]),
				makeTaskState("mesh-task-id-2", false, loginTokens[2:4]),
				makeTaskState("mesh-task-id-3", false, loginTokens[4:6]),
			},
		},
		"mesh tasks without tokens and no services": {
			initTokens: nonLoginTokens,
			initTasks:  allTasks,
			expResources: []Resource{
				// TaskStateLister finds the tasks but does not find the tokens
				makeTaskState("mesh-task-id-1", true, nil),
				makeTaskState("mesh-task-id-2", true, nil),
				makeTaskState("mesh-task-id-3", true, nil),
			},
		},
		"mesh tasks with tokens and no services": {
			initTokens: allTokens,
			initTasks:  allTasks,
			expResources: []Resource{
				// TaskStateLister finds the tasks and tokens
				makeTaskState("mesh-task-id-1", true, loginTokens[0:2]),
				makeTaskState("mesh-task-id-2", true, loginTokens[2:4]),
				makeTaskState("mesh-task-id-3", true, loginTokens[4:6]),
			},
		},
		"no tasks with non-ecs services and no tokens": {
			initServices: nonECSServices,
			// TaskStateLister finds no resources
		},
		"no tasks with ecs services and no tokens": {
			initServices: ecsServices,
			// TaskStateLister finds no resources
			expResources: []Resource{
				makeTaskState("mesh-task-id-1", false, nil, ecsServices[0].Service.ID),
				makeTaskState("mesh-task-id-2", false, nil, ecsServices[1].Service.ID),
				makeTaskState("mesh-task-id-3", false, nil, ecsServices[2].Service.ID),
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

		entECSServices := []*api.CatalogRegistration{
			// These service instances have the "task-id" metadata field, and exist on the
			// shared cluster arn node , so the controller considers them for reconciliation.
			// A single task will not have its service instances in different namespaces.
			makeSvcEnt(t, "partition-task-1", testClusterArn, testPtn, testNs, "task-id", "partition-task-1"),
			makeSvcEnt(t, "partition-task-1-sidecar-proxy", testClusterArn, testPtn, testNs, "task-id", "partition-task-1"),

			makeSvcEnt(t, "partition-task-2", testClusterArn, testPtn, testNs, "task-id", "partition-task-2"),
			makeSvcEnt(t, "partition-task-2-sidecar-proxy", testClusterArn, testPtn, testNs, "task-id", "partition-task-2"),

			makeSvcEnt(t, "partition-task-3", testClusterArn, testPtn, testNs, "task-id", "partition-task-3"),
			makeSvcEnt(t, "partition-task-3-sidecar-proxy", testClusterArn, testPtn, testNs, "task-id", "partition-task-3"),
		}
		entOtherServices := []*api.CatalogRegistration{
			// other partition (technically invalid, since we should have one partition per cluster arn)
			makeSvcEnt(t, "other-task-1", testClusterArn, otherPtn, testNs, "task-id", "other-task-1"),
			makeSvcEnt(t, "other-task-2", testClusterArn, otherPtn, "default", "task-id", "other-task-2"),
			// Missing task-id metadata field
			makeSvcEnt(t, "other-task-3", testClusterArn, testPtn, testNs),
			// Different node (shouldn't happen since one partition per cluster arn)
			makeSvcEnt(t, "other-task-4", "other-cluster-arn", testPtn, testNs, "task-id", "other-task-4"),
		}
		entAllServices := append(entECSServices, entOtherServices...)

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
		cases["no tasks with services in partition"] = testCase{
			initServices:   entECSServices,
			initPartitions: allPartitions,
			partition:      testPtn,
			expResources: []Resource{
				makeTaskStateEnt("partition-task-1", false, nil, testPtn, testNs, entECSServices[0].Service.ID, entECSServices[1].Service.ID),
				makeTaskStateEnt("partition-task-2", false, nil, testPtn, testNs, entECSServices[2].Service.ID, entECSServices[3].Service.ID),
				makeTaskStateEnt("partition-task-3", false, nil, testPtn, testNs, entECSServices[4].Service.ID, entECSServices[5].Service.ID),
			},
		}
		cases["mesh tasks with tokens and services in partition"] = testCase{
			initTasks:      entAllTasks,
			initTokens:     entAllTokens,
			initServices:   entAllServices,
			initPartitions: allPartitions,
			partition:      testPtn,
			expResources: []Resource{
				makeTaskStateEnt("partition-task-1", true, entLoginTokens[0:2], testPtn, testNs, entECSServices[0].Service.ID, entECSServices[1].Service.ID),
				makeTaskStateEnt("partition-task-2", true, entLoginTokens[2:4], testPtn, testNs, entECSServices[2].Service.ID, entECSServices[3].Service.ID),
				makeTaskStateEnt("partition-task-3", true, entLoginTokens[4:6], testPtn, testNs, entECSServices[4].Service.ID, entECSServices[5].Service.ID),
			},
		}

	}

	for name, c := range cases {
		c := c
		sortTaskStates(c.expResources)

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			consulClient := initConsul(t)
			lister := TaskStateLister{
				ECSClient:    &mocks.ECSClient{Tasks: c.initTasks},
				ConsulClient: consulClient,
				ClusterARN:   testClusterArn,
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
			createServiceInstances(t, consulClient, c.initServices...)

			resources, err := lister.List()
			require.NoError(t, err)

			sortTaskStates(resources)

			require.Empty(t, cmp.Diff(c.expResources, resources, tokenIgnoreFields, taskStateIgnoreFields))
		})
	}
}

func TestTaskStateReconcile(t *testing.T) {
	t.Parallel()

	type testCase struct {
		initTokens      []*api.ACLTokenListEntry
		initServices    []*api.CatalogRegistration
		initPartitions  map[string][]string
		state           *TaskState
		expTokenExist   []*api.ACLTokenListEntry
		expTokenDeleted []*api.ACLTokenListEntry
		expSvcExist     []*api.CatalogRegistration
		expSvcDeleted   []*api.CatalogRegistration
	}

	tokens := []*api.ACLTokenListEntry{
		makeToken(t, "test-task", true),
	}
	svcs := []*api.CatalogRegistration{
		makeSvc(t, "test-task", testClusterArn, "task-id", "test-task"),
	}
	cases := map[string]testCase{
		"task not found and tokens not found": {
			initTokens:    tokens,
			state:         makeTaskState("test-task", false, nil),
			expTokenExist: tokens,
		},
		"task found but tokens not found": {
			initTokens:    tokens,
			state:         makeTaskState("test-task", true, nil),
			expTokenExist: tokens,
		},
		"task found and tokens found": {
			initTokens:    tokens,
			state:         makeTaskState("test-task", true, tokens),
			expTokenExist: tokens,
		},
		"task not found but tokens found": {
			initTokens:      tokens,
			state:           makeTaskState("test-task", false, tokens),
			expTokenDeleted: tokens,
		},
		"task not found but service found": {
			initServices:  svcs,
			state:         makeTaskState("test-task", false, nil, svcs[0].Service.ID),
			expSvcDeleted: svcs,
		},
		"task found and service found": {
			initServices: svcs,
			state:        makeTaskState("test-task", true, nil, svcs[0].Service.ID),
			expSvcExist:  svcs,
		},
		"task not found but services and tokens found": {
			initTokens:      tokens,
			initServices:    svcs,
			state:           makeTaskState("test-task", false, tokens, svcs[0].Service.ID),
			expSvcDeleted:   svcs,
			expTokenDeleted: tokens,
		},
		"task found and services and tokens found": {
			initTokens:    tokens,
			initServices:  svcs,
			state:         makeTaskState("test-task", true, tokens, svcs[0].Service.ID),
			expSvcExist:   svcs,
			expTokenExist: tokens,
		},
	}

	if enterpriseFlag() {
		entTokens := []*api.ACLTokenListEntry{
			makeTokenEnt(t, "test-task", true, "test-ptn", "test-ns"),
		}
		entServices := []*api.CatalogRegistration{
			makeSvcEnt(t, "test-task", testClusterArn, "test-ptn", "test-ns", "task-id", "test-task"),
		}
		partitions := map[string][]string{
			"test-ptn": {"test-ns"},
		}
		cases["task not found and tokens not found in partition"] = testCase{
			initTokens:     entTokens,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", false, nil, "test-ptn", "test-ns"),
			expTokenExist:  entTokens,
		}
		cases["task found but tokens not found in partition"] = testCase{
			initTokens:     entTokens,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", true, nil, "test-ptn", "test-ns"),
			expTokenExist:  entTokens,
		}
		cases["task found and tokens found in partition"] = testCase{
			initTokens:     entTokens,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", true, entTokens, "test-ptn", "test-ns"),
			expTokenExist:  entTokens,
		}
		cases["task not found but tokens found in partition"] = testCase{
			initTokens:      entTokens,
			initPartitions:  partitions,
			state:           makeTaskStateEnt("test-task", false, entTokens, "test-ptn", "test-ns"),
			expTokenDeleted: entTokens,
		}
		cases["task not found but service found in partition"] = testCase{
			initServices:   entServices,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", false, nil, "test-ptn", "test-ns", entServices[0].Service.ID),
			expSvcDeleted:  entServices,
		}
		cases["task not found but service and tokens found in partition"] = testCase{
			initTokens:      entTokens,
			initServices:    entServices,
			initPartitions:  partitions,
			state:           makeTaskStateEnt("test-task", false, entTokens, "test-ptn", "test-ns", entServices[0].Service.ID),
			expSvcDeleted:   entServices,
			expTokenDeleted: entTokens,
		}

		cases["task found and service and tokens found in partition"] = testCase{
			initTokens:     entTokens,
			initServices:   entServices,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", true, entTokens, "test-ptn", "test-ns", entServices[0].Service.ID),
			expSvcExist:    entServices,
			expTokenExist:  entTokens,
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
			createServiceInstances(t, client, c.initServices...)

			c.state.ConsulClient = client
			c.state.Log = hclog.New(&hclog.LoggerOptions{
				Name:  "controller",
				Level: hclog.Debug,
			})
			require.NoError(t, c.state.Reconcile())

			for _, exp := range c.expTokenDeleted {
				tok, _, err := client.ACL().TokenRead(exp.AccessorID, &api.QueryOptions{
					Namespace: exp.Namespace,
					Partition: exp.Partition,
				})
				require.Error(t, err)
				require.Contains(t, err.Error(), "403 (ACL not found)")
				require.Nil(t, tok)
			}
			for _, exp := range c.expTokenExist {
				tok, _, err := client.ACL().TokenRead(exp.AccessorID, &api.QueryOptions{
					Namespace: exp.Namespace,
					Partition: exp.Partition,
				})
				require.NoError(t, err)
				require.NotNil(t, tok)
				require.Equal(t, exp.AccessorID, tok.AccessorID)
			}

			for _, exp := range c.expSvcDeleted {
				s, _, err := client.Catalog().NodeServiceList(exp.Node, &api.QueryOptions{
					Filter:    fmt.Sprintf(`ID == "%s"`, exp.Service.ID),
					Partition: exp.Service.Partition,
					Namespace: exp.Service.Namespace,
				})
				require.NoError(t, err)
				require.Empty(t, s.Services, "service %q not deleted", exp.Service.ID)
			}

			for _, exp := range c.expSvcExist {
				s, _, err := client.Catalog().NodeServiceList(exp.Node, &api.QueryOptions{
					Filter:    fmt.Sprintf(`ID == "%s"`, exp.Service.ID),
					Partition: exp.Service.Partition,
					Namespace: exp.Service.Namespace,
				})
				require.NoError(t, err)
				require.Len(t, s.Services, 1, "service %q does not exist", exp.Service.ID)
				require.Equal(t, exp.Service.ID, s.Services[0].ID)
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
				// simulate a task state with an empty string for the namespace
				makeTaskStateEnt("some-task-id", false, nil, "", ""),
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

			// check cross namespace xnsPolicy is created (or not)
			xnsPolicy, _, err := consulClient.ACL().PolicyReadByName(
				xnsPolicyName,
				&api.QueryOptions{Partition: c.partition},
			)
			if c.expXnsPolicy {
				require.NoError(t, err)
				require.NotNil(t, xnsPolicy)
				require.Equal(t, xnsPolicyName, xnsPolicy.Name)
				require.Equal(t, fmt.Sprintf(xnsPolicyTpl, c.partition), xnsPolicy.Rules)

				// check which namespaces have the cross-namespace policy assigned.
				xnsLink := api.ACLLink{ID: xnsPolicy.ID, Name: xnsPolicy.Name}
				for ptn, namespaces := range c.expNS {
					for _, nsName := range namespaces {
						ns, _, err := consulClient.Namespaces().Read(
							nsName, &api.QueryOptions{Partition: ptn},
						)
						require.NoError(t, err)
						require.NotNil(t, ns)
						if ptn == c.partition {
							// namespaces in the controller's assigned partition (c.partition) should have
							// the cross-namespace policy as a default policy.
							require.NotNil(t, ns.ACLs)
							require.Contains(t, ns.ACLs.PolicyDefaults, xnsLink)
						} else if ns.ACLs != nil {
							// namespaces outside the controller's assigned partition should not have the xnsPolicy
							for _, link := range ns.ACLs.PolicyDefaults {
								require.NotEqual(t, xnsLink.Name, link.Name)
							}
						}
					}
				}
			} else {
				require.Error(t, err)
				require.Nil(t, xnsPolicy)
			}
		})
	}
}

// helper func that initializes a Consul test server and returns a Consul API client.
func initConsul(t *testing.T) *api.Client {
	cfg, _ := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	return client
}

// listNamespaces is a helper func that returns a list of namespaces mapped to partition.
func listNamespaces(t *testing.T, consulClient *api.Client) map[string][]string {
	t.Helper()

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

func makeTaskState(taskId string, taskFound bool, tokens []*api.ACLTokenListEntry, serviceIds ...string) *TaskState {
	t := &TaskState{
		TaskID:       TaskID(taskId),
		ClusterARN:   testClusterArn,
		ECSTaskFound: taskFound,
		ACLTokens:    tokens,
		ServiceIDs:   serviceIds,
	}
	if enterpriseFlag() && (taskFound || len(serviceIds) > 0) {
		t.Partition = DefaultPartition
		t.NS = DefaultNamespace
	}
	return t
}

func makeTaskStateEnt(taskId string, taskFound bool, tokens []*api.ACLTokenListEntry, partition, namespace string, serviceIds ...string) *TaskState {
	t := makeTaskState(taskId, taskFound, tokens, serviceIds...)
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

func makeSvc(t *testing.T, taskId string, nodeName string, meta ...string) *api.CatalogRegistration {
	svcName := "test-service"
	svc := &api.CatalogRegistration{
		Node:    nodeName,
		Address: "127.0.0.2",
		Service: &api.AgentService{
			ID:      svcName + "-" + taskId,
			Service: svcName,
			Meta:    map[string]string{},
			Address: "127.0.0.1",
		},
	}
	require.Equal(t, 0, len(meta)%2, "meta must be even length")
	for i := 0; i < len(meta); i += 2 {
		svc.Service.Meta[meta[i]] = meta[i+1]
	}

	if enterpriseFlag() {
		svc.Service.Partition = DefaultPartition
		svc.Service.Namespace = DefaultNamespace
	}
	return svc
}

func makeSvcEnt(t *testing.T, taskId, nodeName, partition, namespace string, meta ...string) *api.CatalogRegistration {
	svc := makeSvc(t, taskId, nodeName, meta...)
	svc.Service.Partition = partition
	svc.Service.Namespace = namespace
	return svc
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

func createServiceInstances(t *testing.T, client *api.Client, svcs ...*api.CatalogRegistration) {
	for _, svc := range svcs {
		_, err := client.Catalog().Register(svc, &api.WriteOptions{
			Partition: svc.Service.Partition,
			Namespace: svc.Service.Namespace,
		})
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

	// Sort ACLTokens by AccessorID and sort ServiceIDs
	for _, r := range states {
		state := r.(*TaskState)
		sort.Slice(state.ACLTokens, func(i, j int) bool {
			return state.ACLTokens[i].AccessorID < state.ACLTokens[j].AccessorID
		})
		sort.Strings(state.ServiceIDs)
	}
}

func enterpriseFlag() bool {
	re := regexp.MustCompile("^-+enterprise$")
	for _, a := range os.Args {
		if re.Match([]byte(strings.ToLower(a))) {
			return true
		}
	}
	return false
}
