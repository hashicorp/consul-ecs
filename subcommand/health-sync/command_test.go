// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	"github.com/hashicorp/go-hclog"
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
		expectedDataplaneHealthStatus   string
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
					status: ecs.HealthStatusHealthy,
				},
				"container-2": {
					status: ecs.HealthStatusUnhealthy,
				},
			},
			expectedDataplaneHealthStatus: api.HealthCritical,
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
			expectedDataplaneHealthStatus: api.HealthCritical,
			consulLogin:                   consulLoginCfg,
		},
		"two unhealthy health sync containers": {
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					status: ecs.HealthStatusUnhealthy,
				},
				"container-2": {
					status: ecs.HealthStatusUnhealthy,
				},
			},
			expectedDataplaneHealthStatus: api.HealthCritical,
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
					status:  ecs.HealthStatusHealthy,
				},
			},
			expectedDataplaneHealthStatus:   api.HealthCritical,
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
			markDataplaneContainerUnhealthy := false
			for _, expCheck := range expectedSvcChecks {
				found := false
				for name, hsc := range c.healthSyncContainers {
					checkID := constructCheckID(makeServiceID(serviceName, taskID), name)
					if expCheck.CheckID == checkID {
						if hsc.missing {
							expCheck.Status = api.HealthCritical
							markDataplaneContainerUnhealthy = true
						} else {
							expCheck.Status = ecsHealthToConsulHealth(hsc.status)
							// If there are multiple health sync containers and one of them is unhealthy
							// then the service check should be critical.
							for containerName := range c.healthSyncContainers {
								if c.healthSyncContainers[containerName].status == ecs.HealthStatusUnhealthy &&
									c.healthSyncContainers[containerName].missing == false {
									expCheck.Status = api.HealthCritical
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
					if c.expectedDataplaneHealthStatus != "" {
						expCheck.Status = c.expectedDataplaneHealthStatus
					} else {
						if c.missingDataplaneContainer || markDataplaneContainerUnhealthy {
							expCheck.Status = api.HealthCritical
						} else if len(c.healthSyncContainers) == 0 || !markDataplaneContainerUnhealthy {
							expCheck.Status = api.HealthPassing
						}
					}
				}
			}
			if markDataplaneContainerUnhealthy {
				expectedProxyCheck.Status = api.HealthCritical
			} else {
				expectedProxyCheck.Status = api.HealthPassing
			}

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
				for name, hsc := range c.healthSyncContainers {
					hsc.missing = false
					c.healthSyncContainers[name] = hsc
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

			if !c.missingDataplaneContainer {
				// Assert that the proxy check remains in the expected state for the full 5 seconds
				end := time.Now().Add(5 * time.Second)
				for time.Now().Before(end) {
					// This will retry for up to 5 seconds, but we want to fail immediately if the status changes
					assertHealthChecks(t, consulClient, nil, expectedProxyCheck)
					time.Sleep(100 * time.Millisecond)
				}
			}

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
		taskMetaContainersResponse = append(taskMetaContainersResponse, constructContainerResponse(config.ConsulDataplaneContainerName, ecs.HealthStatusHealthy))
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

	return taskMetaRespStr
}

func buildTaskMetaWithContainers(t *testing.T, taskMetadataResponse *awsutil.ECSTaskMeta, containers map[string]string) string {
	var taskMetaContainersResponse []awsutil.ECSTaskMetaContainer
	for name, status := range containers {
		taskMetaContainersResponse = append(taskMetaContainersResponse, constructContainerResponse(name, status))
	}
	taskMetadataResponse.Containers = taskMetaContainersResponse
	taskMetaRespStr, err := constructTaskMetaResponseString(taskMetadataResponse)
	require.NoError(t, err)

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
				require.Equal(r, expCheck.Status, check.Status)
			}
		}

		// Check if the check for proxy is in the expected state
		filter := fmt.Sprintf("CheckID == `%s`", expectedProxyCheck.CheckID)
		checks, _, err := consulClient.Health().Checks(expectedProxyCheck.ServiceName, &api.QueryOptions{Filter: filter, Namespace: expectedProxyCheck.Namespace, Partition: expectedProxyCheck.Partition})
		require.NoError(r, err)
		require.Equal(r, 1, len(checks))
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

// expectedCheck represents the expected state of a health check
type expectedCheck struct {
	serviceName string
	checkID     string
	status      string // api.HealthPassing or api.HealthCritical
}

// assertCheckStatuses verifies all expected checks exist and have the expected status, with retries
func assertCheckStatuses(t *testing.T, client *api.Client, expectedChecks []expectedCheck, opts *api.QueryOptions) {
	timer := &retry.Timer{Timeout: 5 * time.Second, Wait: 500 * time.Millisecond}
	retry.RunWith(timer, t, func(r *retry.R) {
		for _, exp := range expectedChecks {
			filter := fmt.Sprintf("CheckID == `%s`", exp.checkID)
			queryOpts := &api.QueryOptions{
				Filter:    filter,
				Namespace: opts.Namespace,
				Partition: opts.Partition,
			}
			checks, _, err := client.Health().Checks(exp.serviceName, queryOpts)
			require.NoError(r, err)
			require.Len(r, checks, 1, "expected exactly one check with ID %s", exp.checkID)
			require.Equal(r, exp.status, checks[0].Status, "check %s has unexpected status", exp.checkID)
		}
	})
}

// extractUpdatedCheckIDs parses log output and returns a set of checkIDs that were updated
func extractUpdatedCheckIDs(logContent string) map[string]bool {
	updated := make(map[string]bool)
	// Match log lines like: health check updated in Consul: checkID=xxx status=yyy
	re := regexp.MustCompile(`health check updated in Consul: checkID=([^\s]+)`)
	matches := re.FindAllStringSubmatch(logContent, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			updated[match[1]] = true
		}
	}
	return updated
}

// getExpectedUpdatedCheckIDs returns the set of checkIDs that should have been updated
// (i.e., those whose status changed between before and after)
func getExpectedUpdatedCheckIDs(before, after []expectedCheck) map[string]bool {
	beforeStatus := make(map[string]string)
	for _, c := range before {
		beforeStatus[c.checkID] = c.status
	}

	expected := make(map[string]bool)
	for _, c := range after {
		if beforeStatus[c.checkID] != c.status {
			expected[c.checkID] = true
		}
	}
	return expected
}

// assertExpectedUpdates verifies that exactly the expected checks were updated (no more, no less)
func assertExpectedUpdates(t *testing.T, logContent string, expectedBefore, expectedAfter []expectedCheck) {
	actualUpdates := extractUpdatedCheckIDs(logContent)
	expectedUpdates := getExpectedUpdatedCheckIDs(expectedBefore, expectedAfter)

	// Check for missing updates (expected but not found in logs)
	for checkID := range expectedUpdates {
		require.True(t, actualUpdates[checkID],
			"expected check %s to be updated but no log entry found", checkID)
	}

	// Check for unexpected updates (found in logs but not expected)
	for checkID := range actualUpdates {
		require.True(t, expectedUpdates[checkID],
			"check %s was updated but should not have been", checkID)
	}
}

type syncChecksTestConfig struct {
	service              *config.ServiceRegistration
	proxy                *config.AgentServiceConnectProxyConfig
	gateway              *config.GatewayRegistration
	healthSyncContainers []string
}

type syncChecksTestEnvironment struct {
	consulClient         *api.Client
	apiQueryOptions      *api.QueryOptions
	cmd                  *Command
	clusterARN           string
	containerNames       []string
	taskMetadataResponse *awsutil.ECSTaskMeta
	currentTaskMetaResp  *atomic.Value
	logBuffer            *bytes.Buffer
}

func setupSyncChecksTest(t *testing.T, cfg syncChecksTestConfig) *syncChecksTestEnvironment {
	var (
		partition = ""
		namespace = ""
	)

	if testutil.EnterpriseFlag() {
		partition = "foo"
		namespace = "default"
	}

	server, consulCfg := testutil.ConsulServer(t, nil)
	consulClient, err := api.NewClient(consulCfg)
	require.NoError(t, err)

	if testutil.EnterpriseFlag() {
		createPartitionAndNamespace(t, consulClient, partition, namespace)
	}

	_, serverGRPCPort := testutil.GetHostAndPortFromAddress(server.GRPCAddr)
	_, serverHTTPPort := testutil.GetHostAndPortFromAddress(server.HTTPAddr)

	taskMetadataResponse := &awsutil.ECSTaskMeta{
		Cluster: "arn:aws:ecs:us-east-1:123456789:cluster/test",
		TaskARN: "arn:aws:ecs:us-east-1:123456789:task/test/abcdef",
		Family:  "test-family",
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

	envoyBootstrapDir := testutil.TempDir(t)

	consulEcsConfig := config.Config{
		LogLevel:             "DEBUG",
		BootstrapDir:         envoyBootstrapDir,
		HealthSyncContainers: cfg.healthSyncContainers,
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
	}

	if cfg.gateway != nil {
		consulEcsConfig.Gateway = cfg.gateway
		if testutil.EnterpriseFlag() {
			consulEcsConfig.Gateway.Namespace = namespace
			consulEcsConfig.Gateway.Partition = partition
		}
	} else {
		consulEcsConfig.Service = *cfg.service
		consulEcsConfig.Proxy = cfg.proxy
		if testutil.EnterpriseFlag() {
			consulEcsConfig.Service.Namespace = namespace
			consulEcsConfig.Service.Partition = partition
		}
	}

	testutil.SetECSConfigEnvVar(t, &consulEcsConfig)

	// Run mesh-init to register services and create health checks
	ui := cli.NewMockUi()
	ctrlPlaneCmd := meshinit.Command{UI: ui}
	code := ctrlPlaneCmd.Run(nil)
	require.Equal(t, 0, code, ui.ErrorWriter.String())

	// Set up the Command with a logger that writes to a buffer for testing
	logBuf := &bytes.Buffer{}
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.LevelFromString(consulEcsConfig.LogLevel),
		Output: logBuf,
	})

	cmd := &Command{UI: ui}
	cmd.config = &consulEcsConfig
	cmd.log = logger

	taskMeta, err := awsutil.ECSTaskMetadata()
	require.NoError(t, err)

	cmd.checks, err = cmd.fetchHealthChecks(consulClient, taskMeta)
	require.NoError(t, err)

	clusterARN, err := taskMeta.ClusterARN()
	require.NoError(t, err)

	return &syncChecksTestEnvironment{
		consulClient: consulClient,
		apiQueryOptions: &api.QueryOptions{
			Namespace: namespace,
			Partition: partition,
		},
		cmd:                  cmd,
		clusterARN:           clusterARN,
		containerNames:       append(cfg.healthSyncContainers, config.ConsulDataplaneContainerName),
		taskMetadataResponse: taskMetadataResponse,
		currentTaskMetaResp:  &currentTaskMetaResp,
		logBuffer:            logBuf,
	}
}

// TestSyncChecks_ChangeDetection tests that syncChecks correctly updates Consul
// health checks and only updates when status actually changes.
func TestSyncChecks_ChangeDetection(t *testing.T) {
	serviceName := "test-service"
	proxyServiceName := fmt.Sprintf("%s-sidecar-proxy", serviceName)
	servicePort := 8080
	taskID := "abcdef"

	cases := map[string]struct {
		healthSyncContainers         []string
		startingContainers           map[string]string
		expectedChecksBeforeUpdate   []expectedCheck
		updatedContainers            map[string]string
		expectedChecksAfterUpdate    []expectedCheck
	}{
		"no change should not update consul": {
			healthSyncContainers: []string{"app"},
			startingContainers: map[string]string{
				"app":                                ecs.HealthStatusHealthy,
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksBeforeUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthPassing},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
			},
			updatedContainers: map[string]string{
				"app":                                ecs.HealthStatusHealthy,
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksAfterUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthPassing},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
			},
		},
		"healthy to unhealthy should update all checks": {
			healthSyncContainers: []string{"app"},
			startingContainers: map[string]string{
				"app":                                ecs.HealthStatusHealthy,
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksBeforeUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthPassing},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
			},
			updatedContainers: map[string]string{
				"app":                                ecs.HealthStatusUnhealthy,
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksAfterUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthCritical},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
			},
		},
		"one of two containers becomes unhealthy": {
			healthSyncContainers: []string{"app1", "app2"},
			startingContainers: map[string]string{
				"app1":                               ecs.HealthStatusHealthy,
				"app2":                               ecs.HealthStatusHealthy,
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksBeforeUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app1", serviceName, taskID), status: api.HealthPassing},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app2", serviceName, taskID), status: api.HealthPassing},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
			},
			updatedContainers: map[string]string{
				"app1":                               ecs.HealthStatusUnhealthy,
				"app2":                               ecs.HealthStatusHealthy,
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksAfterUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app1", serviceName, taskID), status: api.HealthCritical},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app2", serviceName, taskID), status: api.HealthPassing},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
			},
		},
		"unhealthy to healthy recovery": {
			healthSyncContainers: []string{"app"},
			startingContainers: map[string]string{
				"app":                                ecs.HealthStatusUnhealthy,
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksBeforeUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthCritical},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
			},
			updatedContainers: map[string]string{
				"app":                                ecs.HealthStatusHealthy,
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksAfterUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthPassing},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
			},
		},
		"dataplane container goes missing": {
			healthSyncContainers: []string{"app"},
			startingContainers: map[string]string{
				"app":                                ecs.HealthStatusHealthy,
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksBeforeUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthPassing},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
			},
			updatedContainers: map[string]string{
				"app": ecs.HealthStatusHealthy,
				// dataplane container is missing from task metadata
			},
			expectedChecksAfterUpdate: []expectedCheck{
				// app check remains passing since app container is still healthy
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthPassing},
				// dataplane checks become critical because dataplane container is missing
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
			},
		},
		"missing container treated as unhealthy": {
			healthSyncContainers: []string{"app"},
			startingContainers: map[string]string{
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksBeforeUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthCritical},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
			},
			updatedContainers: map[string]string{
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksAfterUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthCritical},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
			},
		},
		"container reappears healthy": {
			healthSyncContainers: []string{"app"},
			startingContainers: map[string]string{
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksBeforeUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthCritical},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
			},
			updatedContainers: map[string]string{
				"app":                                ecs.HealthStatusHealthy,
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksAfterUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-app", serviceName, taskID), status: api.HealthPassing},
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
				{serviceName: proxyServiceName, checkID: fmt.Sprintf("%s-%s-sidecar-proxy-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
			},
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			env := setupSyncChecksTest(t, syncChecksTestConfig{
				service: &config.ServiceRegistration{
					Name: serviceName,
					Port: servicePort,
				},
				proxy: &config.AgentServiceConnectProxyConfig{
					PublicListenerPort: config.DefaultPublicListenerPort,
				},
				healthSyncContainers: tc.healthSyncContainers,
			})

			// Set up initial container state
			env.currentTaskMetaResp.Store(buildTaskMetaWithContainers(t, env.taskMetadataResponse, tc.startingContainers))

			// First syncChecks call
			statuses := env.cmd.syncChecks(env.consulClient, map[string]checkStatus{}, env.clusterARN, env.containerNames)

			// Assert expected checks after first call
			assertCheckStatuses(t, env.consulClient, tc.expectedChecksBeforeUpdate, env.apiQueryOptions)

			// Update container state for second call
			env.currentTaskMetaResp.Store(buildTaskMetaWithContainers(t, env.taskMetadataResponse, tc.updatedContainers))

			// Clear log buffer before second call to isolate its log output
			env.logBuffer.Reset()

			// Second syncChecks call
			statuses = env.cmd.syncChecks(env.consulClient, statuses, env.clusterARN, env.containerNames)

			// Assert expected checks after second call
			assertCheckStatuses(t, env.consulClient, tc.expectedChecksAfterUpdate, env.apiQueryOptions)

			// Verify exactly the expected checks were updated (no more, no less)
			assertExpectedUpdates(t, env.logBuffer.String(), tc.expectedChecksBeforeUpdate, tc.expectedChecksAfterUpdate)
		})
	}
}

// TestSyncChecks_Gateway_ChangeDetection tests syncChecks change detection for gateway services
func TestSyncChecks_Gateway_ChangeDetection(t *testing.T) {
	serviceName := "test-mesh-gateway"
	taskID := "abcdef"

	cases := map[string]struct {
		startingContainers         map[string]string
		expectedChecksBeforeUpdate []expectedCheck
		updatedContainers          map[string]string
		expectedChecksAfterUpdate  []expectedCheck
	}{
		"no change should not update consul": {
			startingContainers: map[string]string{
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksBeforeUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
			},
			updatedContainers: map[string]string{
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksAfterUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
			},
		},
		"healthy to missing dataplane should update": {
			startingContainers: map[string]string{
				config.ConsulDataplaneContainerName: ecs.HealthStatusHealthy,
			},
			expectedChecksBeforeUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthPassing},
			},
			updatedContainers: map[string]string{},
			expectedChecksAfterUpdate: []expectedCheck{
				{serviceName: serviceName, checkID: fmt.Sprintf("%s-%s-consul-dataplane", serviceName, taskID), status: api.HealthCritical},
			},
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			env := setupSyncChecksTest(t, syncChecksTestConfig{
				gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindMeshGateway,
					Name: serviceName,
					LanAddress: &config.GatewayAddress{
						Port: 12345,
					},
				},
			})

			// Set up initial container state
			env.currentTaskMetaResp.Store(buildTaskMetaWithContainers(t, env.taskMetadataResponse, tc.startingContainers))

			// First syncChecks call
			statuses := env.cmd.syncChecks(env.consulClient, map[string]checkStatus{}, env.clusterARN, env.containerNames)

			// Assert expected checks after first call
			assertCheckStatuses(t, env.consulClient, tc.expectedChecksBeforeUpdate, env.apiQueryOptions)

			// Update container state for second call
			env.currentTaskMetaResp.Store(buildTaskMetaWithContainers(t, env.taskMetadataResponse, tc.updatedContainers))

			// Clear log buffer before second call to isolate its log output
			env.logBuffer.Reset()

			// Second syncChecks call
			statuses = env.cmd.syncChecks(env.consulClient, statuses, env.clusterARN, env.containerNames)

			// Assert expected checks after second call
			assertCheckStatuses(t, env.consulClient, tc.expectedChecksAfterUpdate, env.apiQueryOptions)

			// Verify exactly the expected checks were updated (no more, no less)
			assertExpectedUpdates(t, env.logBuffer.String(), tc.expectedChecksBeforeUpdate, tc.expectedChecksAfterUpdate)
		})
	}
}
