// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
	"math/rand"
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

type ClientCfg struct {
	cfg *api.Config
}

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

	services := []*api.CatalogRegistration{
		constructSvcRegInput(testClusterArn, "service-1", "mesh-task-id-1"),
		constructSvcRegInput(testClusterArn, "service-2", "mesh-task-id-2"),
		constructSvcRegInput(testClusterArn, "service-3", "mesh-task-id-3"),
		constructSvcRegInput("random-cluster-arn", "service-2", "mesh-task-id-5"),
	}

	tokenIgnoreFields := cmpopts.IgnoreFields(
		api.ACLTokenListEntry{}, "CreateIndex", "ModifyIndex", "CreateTime", "Hash",
	)
	taskStateIgnoreFields := cmpopts.IgnoreFields(TaskState{}, "Log", "SetupConsulClientFn")

	serviceIgnoreFields := cmpopts.IgnoreFields(
		api.AgentService{}, "Tags", "Weights", "CreateIndex", "ModifyIndex", "Proxy", "Connect",
	)

	type testCase struct {
		// tasks to setup in ECS for the test
		initTasks []*ecs.Task
		// tokens to setup in Consul for the test
		initTokens []*api.ACLTokenListEntry
		// setup partitions + namespaces in Consul
		initPartitions map[string][]string
		// setup services in Consul catalog
		initServices []*api.CatalogRegistration
		// the controller's configured partition
		partition string

		expResources []Resource
	}
	cases := map[string]testCase{
		"no tasks and no tokens": {},
		"no mesh tasks and no login tokens and no services": {
			initTokens: nonLoginTokens,
			initTasks:  nonMeshTasks,
			// TaskStateLister finds no resources.
		},
		"no mesh tasks with login tokens and services": {
			initTokens:   allTokens,
			initTasks:    nonMeshTasks,
			initServices: services,
			expResources: []Resource{
				// TaskStateLister finds the tokens but does not find the task
				makeTaskState("mesh-task-id-1", false, loginTokens[0:2], services[0].Service),
				makeTaskState("mesh-task-id-2", false, loginTokens[2:4], services[1].Service),
				makeTaskState("mesh-task-id-3", false, loginTokens[4:6], services[2].Service),
			},
		},
		"mesh tasks without tokens and services": {
			initTokens: nonLoginTokens,
			initTasks:  allTasks,
			expResources: []Resource{
				// TaskStateLister finds the tasks but does not find the tokens
				makeTaskState("mesh-task-id-1", true, nil, nil),
				makeTaskState("mesh-task-id-2", true, nil, nil),
				makeTaskState("mesh-task-id-3", true, nil, nil),
			},
		},
		"mesh tasks with tokens and services": {
			initTokens:   allTokens,
			initTasks:    allTasks,
			initServices: services,
			expResources: []Resource{
				// TaskStateLister finds the tasks and tokens
				makeTaskState("mesh-task-id-1", true, loginTokens[0:2], services[0].Service),
				makeTaskState("mesh-task-id-2", true, loginTokens[2:4], services[1].Service),
				makeTaskState("mesh-task-id-3", true, loginTokens[4:6], services[2].Service),
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

		entServices := []*api.CatalogRegistration{
			constructSvcRegInputEnt("partition-service-1", "partition-task-1", testNs, testPtn),
			constructSvcRegInputEnt("partition-service-2", "partition-task-2", testNs, testPtn),
			constructSvcRegInputEnt("partition-service-3", "partition-task-3", testNs, testPtn),
			constructSvcRegInputEnt("partition-service-11", "partition-task-11", "default", testPtn),
		}

		cases["no tasks or tokens/services in partition"] = testCase{
			initPartitions: allPartitions,
			partition:      testPtn,
		}
		cases["no mesh tasks or login tokens/services in partition"] = testCase{
			initTasks:      entOtherTasks,
			initTokens:     entOtherTokens,
			initServices:   entServices,
			initPartitions: allPartitions,
			partition:      testPtn,
		}
		cases["mesh tasks without tokens and services in partition"] = testCase{
			initTasks:      entAllTasks,
			initTokens:     entOtherTokens,
			initPartitions: allPartitions,
			initServices:   entServices,
			partition:      testPtn,
			expResources: []Resource{
				// Finds tasks but no tokens.
				makeTaskStateEnt("partition-task-1", true, nil, nil, testPtn, testNs),
				makeTaskStateEnt("partition-task-2", true, nil, nil, testPtn, testNs),
				makeTaskStateEnt("partition-task-3", true, nil, nil, testPtn, testNs),
			},
		}
		cases["no mesh tasks with tokens and services in partition"] = testCase{
			initTasks:      entOtherTasks,
			initTokens:     entAllTokens,
			initServices:   entServices,
			initPartitions: allPartitions,
			partition:      testPtn,
			expResources: []Resource{
				// Partition and Namespace are not set from the ACL token.
				makeTaskStateEnt("partition-task-1", false, entLoginTokens[0:2], entServices[0].Service, "", ""),
				makeTaskStateEnt("partition-task-2", false, entLoginTokens[2:4], entServices[1].Service, "", ""),
				makeTaskStateEnt("partition-task-3", false, entLoginTokens[4:6], entServices[2].Service, "", ""),
			},
		}
		cases["mesh tasks with tokens and services in partition"] = testCase{
			initTasks:      entAllTasks,
			initTokens:     entAllTokens,
			initPartitions: allPartitions,
			initServices:   entServices,
			partition:      testPtn,
			expResources: []Resource{
				// Partition and Namespace are not set from the ACL token.
				makeTaskStateEnt("partition-task-1", true, entLoginTokens[0:2], entServices[0].Service, testPtn, testNs),
				makeTaskStateEnt("partition-task-2", true, entLoginTokens[2:4], entServices[1].Service, testPtn, testNs),
				makeTaskStateEnt("partition-task-3", true, entLoginTokens[4:6], entServices[2].Service, testPtn, testNs),
			},
		}
	}

	for name, c := range cases {
		c := c
		sortTaskStates(c.expResources)

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			consulClient, cfg := initConsul(t)
			clientCfg := &ClientCfg{cfg: cfg}

			lister := TaskStateLister{
				ECSClient:           &mocks.ECSClient{Tasks: c.initTasks},
				SetupConsulClientFn: clientCfg.setupConsulClient,
				ClusterARN:          testClusterArn,
				Log:                 hclog.Default().Named("lister"),
			}

			if enterpriseFlag() {
				lister.Partition = DefaultPartition
				if c.partition != "" {
					lister.Partition = c.partition
				}
				createPartitions(t, consulClient, c.initPartitions)
			}

			createTokens(t, consulClient, c.initTokens...)
			registerServices(t, consulClient, c.initServices)

			resources, err := lister.List()
			require.NoError(t, err)

			sortTaskStates(resources)

			require.Empty(t, cmp.Diff(c.expResources, resources, tokenIgnoreFields, taskStateIgnoreFields, serviceIgnoreFields))
		})
	}
}

func TestTaskStateReconcile(t *testing.T) {
	t.Parallel()

	type testCase struct {
		initTokens         []*api.ACLTokenListEntry
		initServices       []*api.CatalogRegistration
		initPartitions     map[string][]string
		state              *TaskState
		expExistTokens     []*api.ACLTokenListEntry
		expDeletedTokens   []*api.ACLTokenListEntry
		expExistServices   []*api.AgentService
		expDeletedServices []*api.AgentService
	}

	tokens := []*api.ACLTokenListEntry{
		makeToken(t, "test-task", true),
	}

	services := []*api.CatalogRegistration{
		constructSvcRegInput(testClusterArn, "service", "test-task"),
	}
	cases := map[string]testCase{
		"task not found and tokens and services not found": {
			initTokens:     tokens,
			initServices:   services,
			state:          makeTaskState("test-task", false, nil, nil),
			expExistTokens: tokens,
			expExistServices: []*api.AgentService{
				services[0].Service,
			},
		},
		"task found but tokens and services not found": {
			initTokens:     tokens,
			initServices:   services,
			state:          makeTaskState("test-task", true, nil, nil),
			expExistTokens: tokens,
			expExistServices: []*api.AgentService{
				services[0].Service,
			},
		},
		"task found and tokens found": {
			initTokens:     tokens,
			state:          makeTaskState("test-task", true, tokens, nil),
			expExistTokens: tokens,
		},
		"task not found but tokens found": {
			initTokens:       tokens,
			state:            makeTaskState("test-task", false, tokens, nil),
			expDeletedTokens: tokens,
		},
		"task found and services found": {
			initServices: services,
			state:        makeTaskState("test-task", true, nil, services[0].Service),
			expExistServices: []*api.AgentService{
				services[0].Service,
			},
		},
		"task not found and services found": {
			initServices: services,
			state:        makeTaskState("test-task", false, nil, services[0].Service),
			expDeletedServices: []*api.AgentService{
				services[0].Service,
			},
		},
	}

	if enterpriseFlag() {
		entTokens := []*api.ACLTokenListEntry{
			makeTokenEnt(t, "test-task", true, "test-ptn", "test-ns"),
		}
		partitions := map[string][]string{
			"test-ptn": {"test-ns"},
		}
		entServices := []*api.CatalogRegistration{
			constructSvcRegInputEnt("service", "test-task", "test-ns", "test-ptn"),
		}
		cases["task not found and tokens/services not found in partition"] = testCase{
			initTokens:     entTokens,
			initPartitions: partitions,
			initServices:   entServices,
			state:          makeTaskStateEnt("test-task", false, nil, nil, "test-ptn", "test-ns"),
			expExistTokens: entTokens,
			expExistServices: []*api.AgentService{
				entServices[0].Service,
			},
		}
		cases["task found but tokens/services not found in partition"] = testCase{
			initTokens:     entTokens,
			initPartitions: partitions,
			initServices:   entServices,
			state:          makeTaskStateEnt("test-task", true, nil, nil, "test-ptn", "test-ns"),
			expExistTokens: entTokens,
			expExistServices: []*api.AgentService{
				entServices[0].Service,
			},
		}
		cases["task found and tokens found in partition"] = testCase{
			initTokens:     entTokens,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", true, entTokens, nil, "test-ptn", "test-ns"),
			expExistTokens: entTokens,
		}
		cases["task not found but tokens found in partition"] = testCase{
			initTokens:       entTokens,
			initPartitions:   partitions,
			state:            makeTaskStateEnt("test-task", false, entTokens, nil, "test-ptn", "test-ns"),
			expDeletedTokens: entTokens,
		}
		cases["task found and services found in partition"] = testCase{
			initServices:   entServices,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", true, nil, entServices[0].Service, "test-ptn", "test-ns"),
			expExistServices: []*api.AgentService{
				entServices[0].Service,
			},
		}
		cases["task not found and services found in partition"] = testCase{
			initServices:   entServices,
			initPartitions: partitions,
			state:          makeTaskStateEnt("test-task", false, nil, entServices[0].Service, "test-ptn", "test-ns"),
			expDeletedServices: []*api.AgentService{
				entServices[0].Service,
			},
		}
	}
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client, cfg := initConsul(t)
			clientCfg := &ClientCfg{cfg: cfg}

			if enterpriseFlag() {
				createPartitions(t, client, c.initPartitions)
			}
			createTokens(t, client, c.initTokens...)
			registerServices(t, client, c.initServices)

			c.state.SetupConsulClientFn = clientCfg.setupConsulClient
			c.state.Log = hclog.NewNullLogger()
			require.NoError(t, c.state.Reconcile())

			for _, exp := range c.expDeletedTokens {
				tok, _, err := client.ACL().TokenRead(exp.AccessorID, &api.QueryOptions{
					Namespace: exp.Namespace,
					Partition: exp.Partition,
				})
				require.Error(t, err)
				require.Contains(t, err.Error(), "ACL not found")
				require.Nil(t, tok)
			}
			for _, exp := range c.expExistTokens {
				tok, _, err := client.ACL().TokenRead(exp.AccessorID, &api.QueryOptions{
					Namespace: exp.Namespace,
					Partition: exp.Partition,
				})
				require.NoError(t, err)
				require.NotNil(t, tok)
				require.Equal(t, exp.AccessorID, tok.AccessorID)
			}

			for _, exp := range c.expDeletedServices {
				svcs, _, err := client.Catalog().Service(exp.Service, "", &api.QueryOptions{
					Namespace: exp.Namespace,
					Partition: exp.Partition,
				})
				require.NoError(t, err)

				var svcNames []string
				for _, svc := range svcs {
					svcNames = append(svcNames, svc.ServiceName)
				}
				require.NotContains(t, svcNames, exp.Service)
			}

			for _, exp := range c.expExistServices {
				svcs, _, err := client.Catalog().Service(exp.Service, "", &api.QueryOptions{
					Namespace: exp.Namespace,
					Partition: exp.Partition,
				})
				require.NoError(t, err)

				var svcNames []string
				for _, svc := range svcs {
					svcNames = append(svcNames, svc.ServiceName)
				}
				require.Contains(t, svcNames, exp.Service)
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
				makeTaskStateEnt("some-task-id", true, nil, nil, "default", "test-ns"),
			},
		},
	}

	if enterpriseFlag() {
		cases["with partitions disabled"].expNS = map[string][]string{"default": {"default"}}

		cases["with resources in default namespace"] = &testCase{
			partition: "default",
			expNS:     map[string][]string{"default": {"default"}},
			resources: []Resource{
				makeTaskStateEnt("some-task-id", true, nil, nil, "default", "default"),
				// simulate a task state with an empty string for the namespace
				makeTaskStateEnt("some-task-id", false, nil, nil, "", ""),
			},
			expXnsPolicy: true,
		}
		cases["with resources in different namespaces"] = &testCase{
			partition: "default",
			expNS: map[string][]string{
				"default": {"default", "namespace-1", "namespace-2"},
			},
			resources: []Resource{
				makeTaskStateEnt("task-1", true, nil, nil, "default", "default"),
				makeTaskStateEnt("task-2", true, nil, nil, "default", "namespace-1"),
				makeTaskStateEnt("task-3", true, nil, nil, "default", "namespace-1"),
				makeTaskStateEnt("task-4", true, nil, nil, "default", "namespace-2"),
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
				makeTaskStateEnt("task-1", true, nil, nil, "part-1", "default"),
				makeTaskStateEnt("task-2", true, nil, nil, "part-1", "namespace-1"),
				makeTaskStateEnt("task-3", true, nil, nil, "part-1", "namespace-1"),
				makeTaskStateEnt("task-4", true, nil, nil, "part-1", "namespace-2"),
			},
			expXnsPolicy: true,
		}
	}
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			consulClient, cfg := initConsul(t)
			clientCfg := &ClientCfg{cfg: cfg}

			s := TaskStateLister{
				Log:                 hclog.NewNullLogger(),
				SetupConsulClientFn: clientCfg.setupConsulClient,
				Partition:           c.partition,
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
				require.Nil(t, xnsPolicy)
			}
		})
	}
}

// helper func that initializes a Consul test server and returns a Consul API client.
func initConsul(t *testing.T) (*api.Client, *api.Config) {
	_, cfg := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
	clientCfg := &ClientCfg{cfg: cfg}

	client, err := clientCfg.setupConsulClient()
	require.NoError(t, err)

	return client, cfg
}

func (c *ClientCfg) setupConsulClient() (*api.Client, error) {
	return api.NewClient(c.cfg)
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

func makeTaskState(taskId string, taskFound bool, tokens []*api.ACLTokenListEntry, service *api.AgentService) *TaskState {
	t := &TaskState{
		TaskID:       TaskID(taskId),
		ClusterARN:   testClusterArn,
		ECSTaskFound: taskFound,
		ACLTokens:    tokens,
	}
	if enterpriseFlag() && taskFound {
		t.Partition = DefaultPartition
		t.NS = DefaultNamespace
	}

	if service != nil {
		t.Service = service
	}

	return t
}

func makeTaskStateEnt(taskId string, taskFound bool, tokens []*api.ACLTokenListEntry, service *api.AgentService, partition, namespace string) *TaskState {
	t := makeTaskState(taskId, taskFound, tokens, service)
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

func enterpriseFlag() bool {
	re := regexp.MustCompile("^-+enterprise$")
	for _, a := range os.Args {
		if re.Match([]byte(strings.ToLower(a))) {
			return true
		}
	}
	return false
}

func registerServices(t *testing.T, consulClient *api.Client, catalogRegInputs []*api.CatalogRegistration) {
	for _, reg := range catalogRegInputs {
		_, err := consulClient.Catalog().Register(reg, nil)
		require.NoError(t, err)
	}
}

func constructSvcRegInputEnt(name, taskID, namespace, partition string) *api.CatalogRegistration {
	input := constructSvcRegInput(testClusterArn, name, taskID)
	input.Partition = partition
	input.Service.Namespace = namespace
	input.Service.Partition = partition

	return input
}

func constructSvcRegInput(node, name, taskID string) *api.CatalogRegistration {
	input := &api.CatalogRegistration{
		Node:           node,
		SkipNodeUpdate: true,
		Service: &api.AgentService{
			ID:      fmt.Sprintf("%s-%s", name, taskID),
			Service: name,
			Address: "127.0.0.1",
			Port:    rand.Intn(10000),
			Meta: map[string]string{
				"task-id": taskID,
				"source":  "consul-ecs",
			},
		},
	}

	return input
}
