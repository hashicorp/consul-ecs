// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	meshinit "github.com/hashicorp/consul-ecs/subcommand/mesh-init"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul-server-connection-manager/discovery"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/serf/testutil/retry"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

type healthSyncContainerMetaData struct {
	// Indicates if we should mark this container missing in ECS
	// when we fetch data before syncing checks
	missing bool

	// Status of the container when we first fetch task meta info
	// from ECS
	status string
}

func TestNoCLIFlagsSupported(t *testing.T) {
	ui := cli.NewMockUi()
	cmd := Command{UI: ui}
	code := cmd.Run([]string{"some-arg"})
	require.Equal(t, 1, code)
	require.Equal(t, "unexpected argument: some-arg\n", ui.ErrorWriter.String())
}

func TestConfigValidation(t *testing.T) {
	t.Run("CONSUL_ECS_CONFIG_JSON unset", func(t *testing.T) {
		ui := cli.NewMockUi()
		cmd := Command{UI: ui}
		code := cmd.Run(nil)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(),
			fmt.Sprintf(`invalid config: "%s" isn't populated`, config.ConfigEnvironmentVariable))

	})
	t.Run("CONSUL_ECS_CONFIG_JSON is empty json", func(t *testing.T) {
		testutil.SetECSConfigEnvVar(t, map[string]interface{}{})
		ui := cli.NewMockUi()
		cmd := Command{UI: ui}
		code := cmd.Run(nil)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "invalid config: 2 errors occurred:")
	})
}

func TestConstructServiceName(t *testing.T) {
}

func TestMakeServiceID(t *testing.T) {
	expectedID := "test-service-12345"
	require.Equal(t, expectedID, makeServiceID("test-service", "12345"))
}

func TestMakeProxyServiceIDAndName(t *testing.T) {
	expectedID := "test-service-12345-sidecar-proxy"
	expectedName := "test-service-sidecar-proxy"

	actualID, actualName := makeProxySvcIDAndName("test-service-12345", "test-service")
	require.Equal(t, expectedID, actualID)
	require.Equal(t, expectedName, actualName)
}

// TestRun tests the behaviour of the health-sync container
// for a mesh service based task
func TestRun(t *testing.T) {
	family := "family-SERVICE-name"
	serviceName := "service-name"
	proxyServiceName := fmt.Sprintf("%s-sidecar-proxy", serviceName)
	servicePort := 8080
	taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
	consulLoginCfg := config.ConsulLogin{
		Enabled:       true,
		IncludeEntity: true,
		Meta: map[string]string{
			"unittest-tag": "12345",
		},
	}

	cases := map[string]struct {
		consulLogin                     config.ConsulLogin
		healthSyncContainers            map[string]healthSyncContainerMetaData
		missingDataplaneContainer       bool
		shouldMissingContainersReappear bool
	}{
		"no additional health sync containers": {},
		"one healthy health sync container": {
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					status: ecs.HealthStatusHealthy,
				},
			},
			consulLogin: consulLoginCfg,
		},
		"two healthy health sync containers": {
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					status: ecs.HealthStatusHealthy,
				},
				"container-2": {
					status: ecs.HealthStatusHealthy,
				},
			},
		},
		"one healthy and one unhealthy health sync containers": {
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					missing: false,
					status:  ecs.HealthStatusHealthy,
				},
				"container-2": {
					missing: false,
					status:  ecs.HealthStatusUnhealthy,
				},
			},
		},
		"one healthy and one missing health sync containers": {
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					status: ecs.HealthStatusHealthy,
				},
				"container-2": {
					missing: true,
					status:  ecs.HealthStatusUnhealthy,
				},
			},
			consulLogin: consulLoginCfg,
		},
		"two unhealthy health sync containers": {
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					missing: false,
					status:  ecs.HealthStatusUnhealthy,
				},
				"container-2": {
					missing: false,
					status:  ecs.HealthStatusUnhealthy,
				},
			},
		},
		"missing dataplane container": {
			missingDataplaneContainer: true,
		},
		"missing dataplane container and two healthy health sync containers": {
			missingDataplaneContainer: true,
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					status: ecs.HealthStatusHealthy,
				},
				"container-2": {
					status: ecs.HealthStatusHealthy,
				},
			},
		},
		"missing dataplane container and one healthy and one unhealthy health sync containers": {
			missingDataplaneContainer: true,
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					status: ecs.HealthStatusHealthy,
				},
				"container-2": {
					status: ecs.HealthStatusUnhealthy,
				},
			},
			consulLogin: consulLoginCfg,
		},
		"missing dataplane container and one missing health sync containers": {
			missingDataplaneContainer: true,
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					status:  ecs.HealthStatusHealthy,
					missing: true,
				},
			},
		},
		"missing healthy sync container which gets synced as healthy after it reappears": {
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					status: ecs.HealthStatusHealthy,
				},
				"container-2": {
					missing: true,
					status:  ecs.HealthStatusUnhealthy,
				},
			},
			shouldMissingContainersReappear: true,
			consulLogin:                     consulLoginCfg,
		},
	}

	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			var (
				partition = ""
				namespace = ""

				upstreams = []config.Upstream{
					{
						DestinationName: "upstream1",
						LocalBindPort:   1234,
					},
					{
						DestinationName: "upstream2",
						LocalBindPort:   1235,
					},
				}
			)

			if testutil.EnterpriseFlag() {
				partition = "foo"
				namespace = "default"
			}

			apiQueryOptions := &api.QueryOptions{
				Namespace: namespace,
				Partition: partition,
			}

			var srvConfig testutil.ServerConfigCallback
			if c.consulLogin.Enabled {
				// Enable ACLs to test with the auth method
				srvConfig = testutil.ConsulACLConfigFn
			}

			// Start the Consul server
			server, cfg := testutil.ConsulServer(t, srvConfig)
			consulClient, err := api.NewClient(cfg)
			require.NoError(t, err)

			if testutil.EnterpriseFlag() {
				createPartitionAndNamespace(t, consulClient, partition, namespace)
			}

			// Set up ECS container metadata server. This sets ECS_CONTAINER_METADATA_URI_V4.
			taskMetadataResponse := &awsutil.ECSTaskMeta{
				Cluster: "test",
				TaskARN: taskARN,
				Family:  family,
			}
			taskID := taskMetadataResponse.TaskID()
			taskMetaRespStr, err := constructTaskMetaResponseString(taskMetadataResponse)
			require.NoError(t, err)

			var currentTaskMetaResp atomic.Value
			currentTaskMetaResp.Store(taskMetaRespStr)
			testutil.TaskMetaServer(t, testutil.TaskMetaHandlerFn(t,
				func() string {
					return currentTaskMetaResp.Load().(string)
				},
			))

			if c.consulLogin.Enabled {
				fakeAws := testutil.AuthMethodInit(t, consulClient, serviceName, config.DefaultAuthMethodName, &api.WriteOptions{Partition: partition})

				// Use the fake local AWS server.
				c.consulLogin.STSEndpoint = fakeAws.URL + "/sts"

				registerNode(t, consulClient, *taskMetadataResponse, apiQueryOptions.Partition)
			}

			envoyBootstrapDir := testutil.TempDir(t)
			serverHost, serverGRPCPort := testutil.GetHostAndPortFromAddress(server.GRPCAddr)
			_, serverHTTPPort := testutil.GetHostAndPortFromAddress(server.HTTPAddr)

			containersToSync := make([]string, 0)
			for name := range c.healthSyncContainers {
				containersToSync = append(containersToSync, name)
			}
			consulEcsConfig := config.Config{
				LogLevel:             "DEBUG",
				BootstrapDir:         envoyBootstrapDir,
				HealthSyncContainers: containersToSync,
				ConsulLogin:          c.consulLogin,
				ConsulServers: config.ConsulServers{
					Hosts: "127.0.0.1",
					GRPC: config.GRPCSettings{
						Port: serverGRPCPort,
					},
					HTTP: config.HTTPSettings{
						Port: serverHTTPPort,
					},
					SkipServerWatch: true,
				},
				Proxy: &config.AgentServiceConnectProxyConfig{
					PublicListenerPort: config.DefaultPublicListenerPort,
					Upstreams:          upstreams,
				},
				Service: config.ServiceRegistration{
					Name: serviceName,
					Port: servicePort,
					Tags: []string{"tag1", "tag2"},
					Meta: map[string]string{"a": "1", "b": "2"},
				},
			}

			if testutil.EnterpriseFlag() {
				consulEcsConfig.Service.Namespace = namespace
				consulEcsConfig.Service.Partition = partition
			}

			testutil.SetECSConfigEnvVar(t, &consulEcsConfig)

			// Run the mesh-init command first because
			// it sets up the necessary prerequisites for
			// running the health sync command like registering
			// the proxy and the service and constructing
			// preliminary health checks.

			ui := cli.NewMockUi()
			ctrlPlaneCmd := meshinit.Command{UI: ui}
			code := ctrlPlaneCmd.Run(nil)

			require.Equal(t, code, 0, ui.ErrorWriter.String())
			verifyMeshInitCommandSideEffects(t, consulClient, serviceName, proxyServiceName, apiQueryOptions)

			cmd := Command{UI: ui, isTestEnv: true}
			cmd.ctx, cmd.cancel = context.WithCancel(context.Background())
			cmd.doneChan = make(chan struct{})
			cmd.proceedChan = make(chan struct{})

			watcherCh := make(chan discovery.State, 1)
			cmd.watcherCh = watcherCh
			go func() {
				testutil.SetECSConfigEnvVar(t, &consulEcsConfig)
				code := cmd.Run(nil)
				require.Equal(t, 0, code, ui.ErrorWriter.String())
			}()

			// We wait till the mesh-init process completes all the prerequisites
			// before entering into the checks reconcilation loop
			<-cmd.doneChan

			expectedSvcChecks, expectedProxyCheck := fetchSvcAndProxyHealthChecks(t, consulClient, serviceName, proxyServiceName, apiQueryOptions)

			// Verify the accumulated health checks
			require.Equal(t, len(expectedSvcChecks)+1, len(cmd.checks))
			for _, expCheck := range append(expectedSvcChecks, expectedProxyCheck) {
				require.NotNil(t, expCheck)
				check, ok := cmd.checks[expCheck.CheckID]
				require.True(t, ok)
				require.Empty(t, cmp.Diff(check, expCheck))
			}

			// Add the containers data into task meta response
			taskMetaRespStr = injectContainersIntoTaskMetaResponse(t, taskMetadataResponse, c.missingDataplaneContainer, c.healthSyncContainers)
			currentTaskMetaResp.Store(taskMetaRespStr)

			// Trigger health-sync to enter it's reconciliation loop
			close(cmd.proceedChan)

			// Align the expectations for checks according to the
			// state of health sync containers
			log.Printf("Expected Svc Checks: %+v\n", expectedSvcChecks)
			for _, check := range expectedSvcChecks {
				log.Printf("Check Name: %s, Status: %s, ServiceName: %s, CheckId: %s\n", check.Name, check.Status, check.ServiceName, check.CheckID)
			}
			markDataplaneContainerUnhealthy := false
			for _, expCheck := range expectedSvcChecks {
				found := false
				for name, hsc := range c.healthSyncContainers {
					checkID := constructCheckID(makeServiceID(serviceName, taskID), name)
					log.Printf("Checking for container: %s, hsc %s, CheckId: %s\n", name, hsc.status, checkID)
					if expCheck.CheckID == checkID {
						if hsc.missing {
							expCheck.Status = api.HealthCritical
						} else {
							expCheck.Status = ecsHealthToConsulHealth(hsc.status)
							// If there are multiple health sync containers and one of them is unhealthy
							// then the service check should be critical.
							for containerName := range c.healthSyncContainers {
								if c.healthSyncContainers[containerName].status == ecs.HealthStatusUnhealthy {
									expCheck.Status = api.HealthCritical
									log.Printf("Marking the datplane container unhealthy due to :%s \n", containerName)
									markDataplaneContainerUnhealthy = true
									break
								}
							}

						}
						found = true
						break
					}
				}

				if !found {
					if c.missingDataplaneContainer || markDataplaneContainerUnhealthy {

						expCheck.Status = api.HealthCritical

					} else {
						expCheck.Status = api.HealthPassing
					}
					if markDataplaneContainerUnhealthy {
						log.Printf("Marking expCheck for dataplane container :%s \n", expCheck.Status)
					}
				}
			}
			if markDataplaneContainerUnhealthy {
				expectedProxyCheck.Status = api.HealthCritical
			} else {
				expectedProxyCheck.Status = api.HealthPassing
			}
			log.Printf("ExpectedProxyCheck Name: %s and expCheck :%s \n", expectedProxyCheck.Name, expectedProxyCheck.Status)
			if c.missingDataplaneContainer {
				expectedProxyCheck.Status = api.HealthCritical
			}

			assertHealthChecks(t, consulClient, expectedSvcChecks, expectedProxyCheck)

			// Test server watch
			{
				addr, err := discovery.MakeAddr(serverHost, serverGRPCPort)
				require.NoError(t, err)

				newServerState := discovery.State{
					Address: addr,
				}
				if c.consulLogin.Enabled {
					newServerState.Token = getACLToken(t, envoyBootstrapDir)
				}

				watcherCh <- newServerState
			}

			// Some containers might reappear after sometime they went missing.
			// This block makes a missing reappear in the task meta response and
			// tests if the healthy-sync process is able to sync back the status of the
			// container to Consul servers.
			if c.shouldMissingContainersReappear {
				// Mark all containers as non missing
				c.missingDataplaneContainer = false
				for _, hsc := range c.healthSyncContainers {
					hsc.missing = false
				}

				// Add the containers data into task meta response
				taskMetaRespStr = injectContainersIntoTaskMetaResponse(t, taskMetadataResponse, c.missingDataplaneContainer, c.healthSyncContainers)
				currentTaskMetaResp.Store(taskMetaRespStr)

				// Align the expectations for checks according to the
				// state of health sync containers
				for _, expCheck := range expectedSvcChecks {
					found := false
					for name, hsc := range c.healthSyncContainers {
						checkID := constructCheckID(makeServiceID(serviceName, taskID), name)
						if expCheck.CheckID == checkID {
							expCheck.Status = ecsHealthToConsulHealth(hsc.status)
							if len(c.healthSyncContainers) > 1 {
								for containerName := range c.healthSyncContainers {
									if c.healthSyncContainers[containerName].status == ecs.HealthStatusUnhealthy &&
										containerName != config.ConsulDataplaneContainerName &&
										c.shouldMissingContainersReappear == false {
										expCheck.Status = api.HealthCritical
										break
									}
								}
							}
							found = true
							break
						}
					}

					if !found {
						expCheck.Status = api.HealthPassing
					}
				}
				expectedProxyCheck.Status = api.HealthPassing
				assertHealthChecks(t, consulClient, expectedSvcChecks, expectedProxyCheck)
			}

			// Send SIGTERM and verify the status of checks
			signalSIGTERM(t)

			for _, expCheck := range expectedSvcChecks {
				expCheck.Status = api.HealthCritical
			}
			expectedProxyCheck.Status = api.HealthCritical

			assertHealthChecks(t, consulClient, expectedSvcChecks, expectedProxyCheck)

			// Stop dataplane container manually because
			// health-sync waits for it before deregistering
			// the service and the proxy.
			taskMetaRespStr, err = stopDataplaneContainer(taskMetadataResponse)
			require.NoError(t, err)
			currentTaskMetaResp.Store(taskMetaRespStr)

			assertServiceAndProxyInstances(t, consulClient, serviceName, proxyServiceName, 0, apiQueryOptions)
			if c.consulLogin.Enabled {
				assertConsulLogout(t, cfg, consulEcsConfig.BootstrapDir)
			}
		})
	}
}

// TestRunGateways tests the behaviour of the health-sync container
// for a gateway based task
func TestRunGateways(t *testing.T) {
	family := "family-name-mesh-gateway"
	taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
	consulLoginCfg := config.ConsulLogin{
		Enabled:       true,
		IncludeEntity: true,
		Meta: map[string]string{
			"unittest-tag": "12345",
		},
	}

	cases := map[string]struct {
		consulLogin                     config.ConsulLogin
		healthSyncContainers            map[string]healthSyncContainerMetaData
		missingDataplaneContainer       bool
		shouldMissingContainersReappear bool
	}{
		"happy path": {},
		"missing dataplane container": {
			missingDataplaneContainer: true,
		},
		"missing healthy sync container which gets synced as healthy after it reappears": {
			missingDataplaneContainer:       true,
			shouldMissingContainersReappear: true,
			consulLogin:                     consulLoginCfg,
		},
	}

	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			var (
				partition = ""
				namespace = ""
			)

			if testutil.EnterpriseFlag() {
				partition = "foo"
				namespace = "default"
			}

			apiQueryOptions := &api.QueryOptions{
				Namespace: namespace,
				Partition: partition,
			}

			var srvConfig testutil.ServerConfigCallback
			if c.consulLogin.Enabled {
				// Enable ACLs to test with the auth method
				srvConfig = testutil.ConsulACLConfigFn
			}

			// Start the Consul server
			server, cfg := testutil.ConsulServer(t, srvConfig)
			consulClient, err := api.NewClient(cfg)
			require.NoError(t, err)

			if testutil.EnterpriseFlag() {
				createPartitionAndNamespace(t, consulClient, partition, namespace)
			}

			// Set up ECS container metadata server. This sets ECS_CONTAINER_METADATA_URI_V4.
			taskMetadataResponse := &awsutil.ECSTaskMeta{
				Cluster: "test",
				TaskARN: taskARN,
				Family:  family,
			}
			taskMetaRespStr, err := constructTaskMetaResponseString(taskMetadataResponse)
			require.NoError(t, err)

			var currentTaskMetaResp atomic.Value
			currentTaskMetaResp.Store(taskMetaRespStr)
			testutil.TaskMetaServer(t, testutil.TaskMetaHandlerFn(t,
				func() string {
					return currentTaskMetaResp.Load().(string)
				},
			))

			if c.consulLogin.Enabled {
				fakeAws := testutil.AuthMethodInit(t, consulClient, family, config.DefaultAuthMethodName, &api.WriteOptions{Partition: partition})

				// Use the fake local AWS server.
				c.consulLogin.STSEndpoint = fakeAws.URL + "/sts"

				registerNode(t, consulClient, *taskMetadataResponse, apiQueryOptions.Partition)
			}

			envoyBootstrapDir := testutil.TempDir(t)
			serverHost, serverGRPCPort := testutil.GetHostAndPortFromAddress(server.GRPCAddr)
			_, serverHTTPPort := testutil.GetHostAndPortFromAddress(server.HTTPAddr)

			consulEcsConfig := config.Config{
				LogLevel:     "DEBUG",
				BootstrapDir: envoyBootstrapDir,
				ConsulLogin:  c.consulLogin,
				ConsulServers: config.ConsulServers{
					Hosts: "127.0.0.1",
					GRPC: config.GRPCSettings{
						Port: serverGRPCPort,
					},
					HTTP: config.HTTPSettings{
						Port: serverHTTPPort,
					},
					SkipServerWatch: true,
				},
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindMeshGateway,
					LanAddress: &config.GatewayAddress{
						Port: 12345,
					},
				},
			}

			if testutil.EnterpriseFlag() {
				consulEcsConfig.Gateway.Namespace = namespace
				consulEcsConfig.Gateway.Partition = partition
			}

			testutil.SetECSConfigEnvVar(t, &consulEcsConfig)

			// Run the mesh-init command first because
			// it sets up the necessary prerequisites for
			// running the health sync command like registering
			// the proxy and the service and constructing
			// preliminary health checks.

			ui := cli.NewMockUi()
			ctrlPlaneCmd := meshinit.Command{UI: ui}
			code := ctrlPlaneCmd.Run(nil)

			require.Equal(t, code, 0, ui.ErrorWriter.String())
			verifyMeshInitCommandSideEffects(t, consulClient, "", family, apiQueryOptions)

			cmd := Command{UI: ui, isTestEnv: true}
			cmd.ctx, cmd.cancel = context.WithCancel(context.Background())
			cmd.doneChan = make(chan struct{})
			cmd.proceedChan = make(chan struct{})

			watcherCh := make(chan discovery.State, 1)
			cmd.watcherCh = watcherCh
			go func() {
				testutil.SetECSConfigEnvVar(t, &consulEcsConfig)
				code := cmd.Run(nil)
				require.Equal(t, 0, code, ui.ErrorWriter.String())
			}()

			// We wait till the mesh-init process completes all the prerequisites
			// before entering into the checks reconcilation loop
			<-cmd.doneChan

			_, expectedProxyCheck := fetchSvcAndProxyHealthChecks(t, consulClient, "", family, apiQueryOptions)

			// Verify the accumulated health checks
			require.Len(t, cmd.checks, 1)
			require.NotNil(t, expectedProxyCheck)
			check, ok := cmd.checks[expectedProxyCheck.CheckID]
			require.True(t, ok)
			require.Empty(t, cmp.Diff(check, expectedProxyCheck))

			// Add the containers data into task meta response
			taskMetaRespStr = injectContainersIntoTaskMetaResponse(t, taskMetadataResponse, c.missingDataplaneContainer, c.healthSyncContainers)
			currentTaskMetaResp.Store(taskMetaRespStr)

			// Trigger health-sync to enter it's reconciliation loop
			close(cmd.proceedChan)

			expectedProxyCheck.Status = api.HealthPassing
			if c.missingDataplaneContainer {
				expectedProxyCheck.Status = api.HealthCritical
			}

			assertHealthChecks(t, consulClient, nil, expectedProxyCheck)

			// Test server watch
			{
				addr, err := discovery.MakeAddr(serverHost, serverGRPCPort)
				require.NoError(t, err)

				newServerState := discovery.State{
					Address: addr,
				}
				if c.consulLogin.Enabled {
					newServerState.Token = getACLToken(t, envoyBootstrapDir)
				}

				watcherCh <- newServerState
			}

			// Some containers might reappear after sometime they went missing.
			// This block makes a missing reappear in the task meta response and
			// tests if the healthy-sync process is able to sync back the status of the
			// container to Consul servers.
			if c.shouldMissingContainersReappear {
				// Mark all containers as non missing
				c.missingDataplaneContainer = false

				// Add the containers data into task meta response
				taskMetaRespStr = injectContainersIntoTaskMetaResponse(t, taskMetadataResponse, c.missingDataplaneContainer, nil)
				currentTaskMetaResp.Store(taskMetaRespStr)

				expectedProxyCheck.Status = api.HealthPassing
				assertHealthChecks(t, consulClient, nil, expectedProxyCheck)
			}

			// Send SIGTERM and verify the status of checks
			signalSIGTERM(t)

			expectedProxyCheck.Status = api.HealthCritical

			assertHealthChecks(t, consulClient, nil, expectedProxyCheck)

			// Stop dataplane container manually because
			// health-sync waits for it before deregistering
			// the service and the proxy.
			taskMetaRespStr, err = stopDataplaneContainer(taskMetadataResponse)
			require.NoError(t, err)
			currentTaskMetaResp.Store(taskMetaRespStr)

			assertServiceAndProxyInstances(t, consulClient, "", family, 0, apiQueryOptions)
			if c.consulLogin.Enabled {
				assertConsulLogout(t, cfg, consulEcsConfig.BootstrapDir)
			}
		})
	}
}

func verifyMeshInitCommandSideEffects(t *testing.T, consulClient *api.Client, serviceName, proxyServiceName string, queryOpts *api.QueryOptions) {
	assertServiceAndProxyInstances(t, consulClient, serviceName, proxyServiceName, 1, queryOpts)

	areAllChecksCriticalFn := func(checks api.HealthChecks) bool {
		if checks == nil {
			return true
		}

		areChecksCritical := true
		for _, check := range checks {
			if check.Status == api.HealthCritical {
				continue
			}

			areChecksCritical = false
		}
		return areChecksCritical
	}

	svcChecks, proxyCheck := fetchSvcAndProxyHealthChecks(t, consulClient, serviceName, proxyServiceName, queryOpts)
	require.True(t, areAllChecksCriticalFn(svcChecks))
	require.True(t, areAllChecksCriticalFn([]*api.HealthCheck{proxyCheck}))
}

func createPartitionAndNamespace(t *testing.T, consulClient *api.Client, partition, namespace string) {
	_, _, err := consulClient.Partitions().Create(context.TODO(), &api.Partition{
		Name:        partition,
		Description: "Test partition",
	}, nil)
	require.NoError(t, err)

	_, _, err = consulClient.Namespaces().Create(&api.Namespace{
		Name:        namespace,
		Description: "Test partition",
		Partition:   partition,
	}, nil)
	require.NoError(t, err)
}

func assertServiceAndProxyInstances(t *testing.T, consulClient *api.Client, serviceName, proxyName string, expectedCount int, opts *api.QueryOptions) {
	timer := &retry.Timer{Timeout: 5 * time.Second, Wait: 500 * time.Millisecond}
	retry.RunWith(timer, t, func(r *retry.R) {
		if serviceName != "" {
			serviceInstances, _, err := consulClient.Catalog().Service(serviceName, "", opts)
			require.NoError(r, err)
			require.Equal(r, expectedCount, len(serviceInstances))
		}

		serviceInstances, _, err := consulClient.Catalog().Service(proxyName, "", opts)
		require.NoError(r, err)
		require.Equal(r, expectedCount, len(serviceInstances))
	})
}

func fetchSvcAndProxyHealthChecks(t *testing.T, consulClient *api.Client, svcName, proxyName string, opts *api.QueryOptions) (api.HealthChecks, *api.HealthCheck) {
	healthChecksFn := func(svc string) api.HealthChecks {
		if svc == "" {
			return nil
		}

		return fetchHealthChecks(t, consulClient, svc, opts)
	}

	proxyHealthChecks := healthChecksFn(proxyName)
	require.Len(t, proxyHealthChecks, 1)
	return healthChecksFn(svcName), proxyHealthChecks[0]
}

func fetchHealthChecks(t *testing.T, consulClient *api.Client, serviceName string, apiQueryOpts *api.QueryOptions) api.HealthChecks {
	checks, _, err := consulClient.Health().Checks(serviceName, apiQueryOpts)
	require.NoError(t, err)
	return checks
}

func constructTaskMetaResponseString(resp *awsutil.ECSTaskMeta) (string, error) {
	byteStr, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}

	return string(byteStr), nil
}

func injectContainersIntoTaskMetaResponse(t *testing.T, taskMetadataResponse *awsutil.ECSTaskMeta, missingDataplaneContainer bool, healthSyncContainers map[string]healthSyncContainerMetaData) string {
	var taskMetaContainersResponse []awsutil.ECSTaskMetaContainer
	if !missingDataplaneContainer {
		dataplaneContainerStatus := ecs.HealthStatusHealthy
		if len(healthSyncContainers) > 1 {
			log.Printf("Setting dataplane container status: %s \n", config.ConsulDataplaneContainerName)
			for containerName := range healthSyncContainers {
				log.Printf("Container Name: %s, ActualStatus:%s \n", containerName, healthSyncContainers[containerName].status)
				if healthSyncContainers[containerName].status == ecs.HealthStatusUnhealthy {
					dataplaneContainerStatus = ecs.HealthStatusUnhealthy
					break
				}
			}
		}
		taskMetaContainersResponse = append(taskMetaContainersResponse, constructContainerResponse(config.ConsulDataplaneContainerName, dataplaneContainerStatus))
	}

	for name, hsc := range healthSyncContainers {
		if hsc.missing {
			continue
		}

		taskMetaContainersResponse = append(taskMetaContainersResponse, constructContainerResponse(name, hsc.status))
	}
	taskMetadataResponse.Containers = taskMetaContainersResponse
	taskMetaRespStr, err := constructTaskMetaResponseString(taskMetadataResponse)
	require.NoError(t, err)
	log.Printf("TaskMetaResponseStr: %s, \n", taskMetaRespStr)

	return taskMetaRespStr
}

func constructContainerResponse(name, health string) awsutil.ECSTaskMetaContainer {
	return awsutil.ECSTaskMetaContainer{
		Name: name,
		Health: awsutil.ECSTaskMetaHealth{
			Status: health,
		},
	}
}

func assertHealthChecks(t *testing.T, consulClient *api.Client, expectedServiceChecks api.HealthChecks, expectedProxyCheck *api.HealthCheck) {
	timer := &retry.Timer{Timeout: 5 * time.Second, Wait: 500 * time.Millisecond}
	retry.RunWith(timer, t, func(r *retry.R) {
		// Check if checks are in the expected state for services
		for _, expCheck := range expectedServiceChecks {
			filter := fmt.Sprintf("CheckID == `%s`", expCheck.CheckID)
			checks, _, err := consulClient.Health().Checks(expCheck.ServiceName, &api.QueryOptions{Filter: filter, Namespace: expCheck.Namespace, Partition: expCheck.Partition})
			require.NoError(r, err)

			for _, check := range checks {
				log.Printf("checkName:%s , expCheck:%s , Actual Status:%s \n", expCheck.Name, expCheck.Status, check.Status)
				require.Equal(r, expCheck.Status, check.Status)
			}
		}

		// Check if the check for proxy is in the expected state
		filter := fmt.Sprintf("CheckID == `%s`", expectedProxyCheck.CheckID)
		checks, _, err := consulClient.Health().Checks(expectedProxyCheck.ServiceName, &api.QueryOptions{Filter: filter, Namespace: expectedProxyCheck.Namespace, Partition: expectedProxyCheck.Partition})
		require.NoError(r, err)
		require.Equal(r, 1, len(checks))
		log.Printf("ProxyCheckName:%s , expProxyCheck:%s , Actual procy Status:%s \n", expectedProxyCheck.Name, expectedProxyCheck.Status, checks[0].Status)
		require.Equal(r, expectedProxyCheck.Status, checks[0].Status)
	})
}

// stopDataplaneContainer marks the dataplane container's status as STOPPED in the
// task meta response
func stopDataplaneContainer(taskMetadataResp *awsutil.ECSTaskMeta) (string, error) {
	for i, c := range taskMetadataResp.Containers {
		if c.Name == config.ConsulDataplaneContainerName {
			taskMetadataResp.Containers[i].DesiredStatus = ecs.DesiredStatusStopped
			taskMetadataResp.Containers[i].KnownStatus = ecs.DesiredStatusStopped
			break
		}
	}
	return constructTaskMetaResponseString(taskMetadataResp)
}

func signalSIGTERM(t *testing.T) {
	err := syscall.Kill(os.Getpid(), syscall.SIGTERM)
	require.NoError(t, err)
	// Give it time to react
	time.Sleep(100 * time.Millisecond)
}

func assertConsulLogout(t *testing.T, cfg *api.Config, bootstrapDir string) {
	cfg.Token = getACLToken(t, bootstrapDir)
	client, err := api.NewClient(cfg)
	require.NoError(t, err)

	tok, _, err := client.ACL().TokenReadSelf(nil)
	require.Error(t, err)
	require.Nil(t, tok)
}

func getACLToken(t *testing.T, bootstrapDir string) string {
	tokenFile := filepath.Join(bootstrapDir, config.ServiceTokenFilename)
	token, err := os.ReadFile(tokenFile)
	require.NoError(t, err)
	return string(token)
}

func registerNode(t *testing.T, consulClient *api.Client, taskMeta awsutil.ECSTaskMeta, partition string) {
	clusterARN, err := taskMeta.ClusterARN()
	require.NoError(t, err)

	payload := &api.CatalogRegistration{
		Node: clusterARN,
		NodeMeta: map[string]string{
			config.SyntheticNode: "true",
		},
		Address:   taskMeta.NodeIP(),
		Partition: partition,
	}

	_, err = consulClient.Catalog().Register(payload, nil)
	require.NoError(t, err)
}
