// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/freeport"
	"github.com/hashicorp/consul/sdk/testutil/retry"
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

type fileMeta struct {
	name string
	path string
	mode int
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

// Note: this test cannot currently run in parallel with other tests
// because it sets environment variables (e.g. ECS metadata URI and Consul's HTTP addr)
// that could not be shared if another test were to run in parallel.
func TestRun(t *testing.T) {
	family := "family-SERVICE-name"
	serviceName := "service-name"

	cases := map[string]struct {
		servicePort                     int
		upstreams                       []config.Upstream
		expUpstreams                    []api.Upstream
		tags                            []string
		expTags                         []string
		additionalMeta                  map[string]string
		expAdditionalMeta               map[string]string
		serviceName                     string
		expServiceName                  string
		proxyPort                       int
		healthSyncContainers            map[string]healthSyncContainerMetaData
		missingDataplaneContainer       bool
		shouldMissingContainersReappear bool
		expectedDataplaneConfigJSON     string

		consulLogin config.ConsulLogin
	}{
		"basic service": {},
		"service with port": {
			servicePort: 8080,
			proxyPort:   21000,
		},
		"service with upstreams": {
			upstreams: []config.Upstream{
				{
					DestinationName: "upstream1",
					LocalBindPort:   1234,
				},
				{
					DestinationName: "upstream2",
					LocalBindPort:   1235,
				},
			},
			expUpstreams: []api.Upstream{
				{
					DestinationType: "service",
					DestinationName: "upstream1",
					LocalBindPort:   1234,
				},
				{
					DestinationType: "service",
					DestinationName: "upstream2",
					LocalBindPort:   1235,
				},
			},
		},
		"service with one healthy healthSyncContainer": {
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					missing: false,
					status:  ecs.HealthStatusHealthy,
				},
			},
		},
		"service with two healthy healthSyncContainers": {
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					missing: false,
					status:  ecs.HealthStatusHealthy,
				},
				"container-2": {
					missing: false,
					status:  ecs.HealthStatusHealthy,
				},
			},
		},
		"service with one healthy and one unhealthy healthSyncContainers": {
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
		"service with one healthy and one missing healthSyncContainers": {
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					missing: false,
					status:  ecs.HealthStatusHealthy,
				},
				"container-2": {
					missing: true,
				},
			},
		},
		"service with missing dataplane container": {
			missingDataplaneContainer: true,
		},
		"service with a missing container synced as healthy after it appears": {
			healthSyncContainers: map[string]healthSyncContainerMetaData{
				"container-1": {
					missing: false,
					status:  ecs.HealthStatusHealthy,
				},
				"container-2": {
					missing: true,
					status:  ecs.HealthStatusUnhealthy,
				},
			},
			shouldMissingContainersReappear: true,
		},
		"service with tags": {
			tags:    []string{"tag1", "tag2"},
			expTags: []string{"tag1", "tag2"},
		},
		"service with additional metadata": {
			additionalMeta:    map[string]string{"a": "1", "b": "2"},
			expAdditionalMeta: map[string]string{"a": "1", "b": "2"},
		},
		"service with service name": {
			serviceName:    serviceName,
			expServiceName: serviceName,
		},
		"auth method enabled": {
			consulLogin: config.ConsulLogin{
				Enabled:       true,
				IncludeEntity: true,
				Meta: map[string]string{
					"unittest-tag": "12345",
				},
			},
		},
	}

	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			var (
				taskARN          = "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
				expectedTaskMeta = map[string]string{
					"task-id":  "abcdef",
					"task-arn": taskARN,
					"source":   "consul-ecs",
				}
				expectedServiceName = strings.ToLower(family)
				expectedPartition   = ""
				expectedNamespace   = ""
			)

			if testutil.EnterpriseFlag() {
				expectedPartition = "default"
				expectedNamespace = "default"
			}

			for k, v := range c.expAdditionalMeta {
				expectedTaskMeta[k] = v
			}

			expectedTags := c.expTags
			if expectedTags == nil {
				expectedTags = []string{}
			}

			if c.expServiceName != "" {
				expectedServiceName = c.expServiceName
			}

			if c.proxyPort == 0 {
				c.proxyPort = config.DefaultPublicListenerPort
			}

			for i := range c.upstreams {
				c.upstreams[i].DestinationType = "service"
				c.upstreams[i].DestinationPartition = expectedPartition
				c.upstreams[i].DestinationNamespace = expectedNamespace
			}
			for i := range c.expUpstreams {
				c.expUpstreams[i].DestinationPartition = expectedPartition
				c.expUpstreams[i].DestinationNamespace = expectedNamespace
			}

			var srvConfig testutil.ServerConfigCallback
			if c.consulLogin.Enabled {
				// Enable ACLs to test with the auth method
				srvConfig = testutil.ConsulACLConfigFn
			}

			// Start a Consul server. This sets the CONSUL_HTTP_ADDR for `consul connect envoy -bootstrap`.
			server, cfg := testutil.ConsulServer(t, srvConfig)
			consulClient, err := api.NewClient(cfg)
			require.NoError(t, err)

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
				fakeAws := testutil.AuthMethodInit(t, consulClient, expectedServiceName, config.DefaultAuthMethodName)

				// Use the fake local AWS server.
				c.consulLogin.STSEndpoint = fakeAws.URL + "/sts"

				registerNode(t, consulClient, *taskMetadataResponse, expectedPartition)
			}

			ui := cli.NewMockUi()
			cmd := Command{UI: ui, isTestEnv: true}

			port := strconv.FormatInt(int64(freeport.GetOne(t)), 10)
			cmd.healthCheckListenerAddr = net.JoinHostPort(defaultHealthCheckBindAddr, port)

			cmd.ctx, cmd.cancel = context.WithCancel(context.Background())
			t.Cleanup(func() {
				cmd.cancel()
			})

			cmd.doneChan = make(chan struct{})
			cmd.proceedChan = make(chan struct{})

			envoyBootstrapDir := testutil.TempDir(t)
			dataplaneConfigJSONFile := filepath.Join(envoyBootstrapDir, dataplaneConfigFileName)
			expectedFileMeta := []*fileMeta{
				{
					name: "consul-ecs",
					path: filepath.Join(envoyBootstrapDir, "consul-ecs"),
					mode: 0755,
				},
				{
					name: dataplaneConfigFileName,
					path: dataplaneConfigJSONFile,
					mode: 0444,
				},
			}

			_, serverGRPCPort := testutil.GetHostAndPortFromAddress(server.GRPCAddr)
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
					Hosts:     "127.0.0.1",
					GRPCPort:  serverGRPCPort,
					HTTPPort:  serverHTTPPort,
					EnableTLS: false,
				},
				Proxy: &config.AgentServiceConnectProxyConfig{
					PublicListenerPort: c.proxyPort,
					Upstreams:          c.upstreams,
				},
				Service: config.ServiceRegistration{
					Name: c.serviceName,
					Port: c.servicePort,
					Tags: c.tags,
					Meta: c.additionalMeta,
				},
			}

			if testutil.EnterpriseFlag() {
				consulEcsConfig.Service.Namespace = expectedNamespace
				consulEcsConfig.Service.Partition = expectedPartition
			}
			testutil.SetECSConfigEnvVar(t, &consulEcsConfig)

			go func() {
				code := cmd.Run(nil)
				require.Equal(t, code, 0, ui.ErrorWriter.String())
			}()

			// We wait till the control plane registers the services and proxies
			// to Consul before entering into the checks reconcilation loop
			<-cmd.doneChan

			expServiceID := fmt.Sprintf("%s-abcdef", expectedServiceName)
			expSidecarServiceID := fmt.Sprintf("%s-abcdef-sidecar-proxy", expectedServiceName)

			expectedNodeName := "arn:aws:ecs:us-east-1:123456789:cluster/test"
			expectedAddress := "127.0.0.1"

			expectedService := &api.CatalogService{
				Node:        expectedNodeName,
				NodeMeta:    getNodeMeta(),
				Address:     expectedAddress,
				ServiceID:   expServiceID,
				ServiceName: expectedServiceName,
				ServicePort: c.servicePort,
				ServiceMeta: expectedTaskMeta,
				ServiceTags: expectedTags,
				Datacenter:  "dc1",
				ServiceWeights: api.Weights{
					Passing: 1,
					Warning: 1,
				},
				ServiceProxy: &api.AgentServiceConnectProxyConfig{},
				Partition:    expectedPartition,
				Namespace:    expectedNamespace,
			}

			expectedProxy := &api.CatalogService{
				Node:        expectedNodeName,
				NodeMeta:    getNodeMeta(),
				Address:     expectedAddress,
				ServiceID:   expSidecarServiceID,
				ServiceName: fmt.Sprintf("%s-sidecar-proxy", expectedServiceName),
				ServicePort: c.proxyPort,
				ServiceProxy: &api.AgentServiceConnectProxyConfig{
					DestinationServiceName: expectedServiceName,
					DestinationServiceID:   expServiceID,
					LocalServicePort:       c.servicePort,
					Upstreams:              c.expUpstreams,
				},
				ServiceMeta: expectedTaskMeta,
				ServiceTags: expectedTags,
				Datacenter:  "dc1",
				ServiceWeights: api.Weights{
					Passing: 1,
					Warning: 1,
				},
				Partition: expectedPartition,
				Namespace: expectedNamespace,
			}

			expectedServiceChecks := api.HealthChecks{
				{
					CheckID:     constructCheckID(expServiceID, config.ConsulDataplaneContainerName),
					Type:        consulECSCheckType,
					Namespace:   expectedNamespace,
					ServiceName: expectedServiceName,
					ServiceID:   expServiceID,
					Name:        consulDataplaneReadinessCheckName,
					Status:      api.HealthCritical,
				},
			}

			for name := range c.healthSyncContainers {
				expectedServiceChecks = append(expectedServiceChecks, &api.HealthCheck{
					CheckID:     constructCheckID(expServiceID, name),
					Type:        consulECSCheckType,
					Namespace:   expectedNamespace,
					ServiceName: expectedServiceName,
					ServiceID:   expServiceID,
					Name:        consulHealthSyncCheckName,
					Status:      api.HealthCritical,
				})
			}

			expectedProxyCheck := &api.HealthCheck{
				CheckID:     constructCheckID(expectedProxy.ServiceID, config.ConsulDataplaneContainerName),
				Type:        consulECSCheckType,
				Namespace:   expectedNamespace,
				ServiceName: expectedProxy.ServiceName,
				ServiceID:   expectedProxy.ServiceID,
				Name:        consulDataplaneReadinessCheckName,
				Status:      api.HealthCritical,
			}

			assertServiceAndProxyRegistrations(t, consulClient, expectedService, expectedProxy, expectedServiceName, expectedProxy.ServiceName)
			assertCheckRegistration(t, consulClient, expectedServiceChecks, expectedProxyCheck)
			assertWrittenFiles(t, expectedFileMeta)
			assertDataplaneConfigJSON(t, serverGRPCPort, c.consulLogin.Enabled, envoyBootstrapDir, dataplaneConfigJSONFile, expectedProxy.ServiceID, expectedNamespace, expectedPartition)

			// Construct task meta response for the first few iterations
			// of syncChecks
			taskMetaRespStr = injectContainersIntoTaskMetaResponse(t, c.missingDataplaneContainer, false, taskMetadataResponse, c.healthSyncContainers)
			currentTaskMetaResp.Store(taskMetaRespStr)

			// Populate expectedServiceChecks based on the new status
			// of containers returned by the task meta server
			for _, expCheck := range expectedServiceChecks {
				found := false
				if expCheck.Name == consulDataplaneReadinessCheckName && c.missingDataplaneContainer {
					expCheck.Status = api.HealthCritical
					continue
				}

				for name, hcs := range c.healthSyncContainers {
					checkID := constructCheckID(expServiceID, name)
					if expCheck.CheckID == checkID {
						if hcs.missing {
							expCheck.Status = api.HealthCritical
						} else {
							expCheck.Status = ecsHealthToConsulHealth(hcs.status)
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
			if c.missingDataplaneContainer {
				expectedProxyCheck.Status = api.HealthCritical
			}

			// Signals control plane to enter into a state where it
			// periodically sync checks back to Consul
			close(cmd.proceedChan)

			// Verify with retries that the checks have reached the expected state
			assertHealthChecks(t, consulClient, expectedServiceChecks, expectedProxyCheck)

			// Some containers might reappear after sometime they went missing.
			// This block makes a missing reappear in the task meta response and
			// tests if the control plane is able to sync back the status of the
			// container to Consul servers.
			if c.shouldMissingContainersReappear {
				taskMetaRespStr = injectContainersIntoTaskMetaResponse(t, false, false, taskMetadataResponse, c.healthSyncContainers)
				currentTaskMetaResp.Store(taskMetaRespStr)

				for _, expCheck := range expectedServiceChecks {
					found := false
					for name, hcs := range c.healthSyncContainers {
						checkID := constructCheckID(expServiceID, name)
						if expCheck.CheckID == checkID {
							expCheck.Status = ecsHealthToConsulHealth(hcs.status)
							found = true
							break
						}
					}
					if !found {
						expCheck.Status = api.HealthPassing
					}
				}

				expectedProxyCheck.Status = api.HealthPassing
				assertHealthChecks(t, consulClient, expectedServiceChecks, expectedProxyCheck)
			}

			// Send SIGTERM and verify the status of checks
			signalSIGTERM(t)
			// SIGTERM should mark all the checks as critical
			for _, expCheck := range expectedServiceChecks {
				expCheck.Status = api.HealthCritical
			}
			expectedProxyCheck.Status = api.HealthCritical

			// Verify with retries that the checks have reached the expected state
			assertHealthChecks(t, consulClient, expectedServiceChecks, expectedProxyCheck)

			stopDataplaneContainer(taskMetadataResponse)
			taskMetaRespStr, err = constructTaskMetaResponseString(taskMetadataResponse)
			require.NoError(t, err)
			currentTaskMetaResp.Store(taskMetaRespStr)

			assertDeregistration(t, consulClient, expectedServiceName, expectedProxy.ServiceName)
			if c.consulLogin.Enabled {
				assertConsulLogout(t, cfg, envoyBootstrapDir)
			}
			cmd.cancel()
		})
	}
}

func TestGateway(t *testing.T) {
	var (
		family           = "family-name-mesh-gateway"
		serviceName      = "service-name-mesh-gateway"
		taskARN          = "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
		taskIP           = "10.1.2.3"
		publicIP         = "255.1.2.3"
		taskDNSName      = "test-dns-name"
		expectedTaskMeta = map[string]string{
			"task-id":  "abcdef",
			"task-arn": taskARN,
			"source":   "consul-ecs",
		}
	)
	// Simulate mesh gateway registration:
	// Specify "gateway" and "service" configuration, and verify the details of the registered service.

	cases := map[string]struct {
		config *config.Config

		expServiceID       string
		expServiceName     string
		expLanAddress      string
		expWanAddress      string
		expTaggedAddresses map[string]api.ServiceAddress
		expLanPort         int
	}{
		"mesh gateway default port": {
			config: &config.Config{
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindMeshGateway,
				},
			},
			expServiceID:   family + "-abcdef",
			expServiceName: family,
			expLanPort:     config.DefaultGatewayPort,
		},
		"mesh gateway with port": {
			config: &config.Config{
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindMeshGateway,
					LanAddress: &config.GatewayAddress{
						Port: 12345,
					},
				},
			},
			expServiceID:   family + "-abcdef",
			expServiceName: family,
			expLanPort:     12345,
		},
		"mesh gateway with service name": {
			config: &config.Config{
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindMeshGateway,
					LanAddress: &config.GatewayAddress{
						Port: 12345,
					},
					Name: serviceName,
				},
			},
			expServiceID:   serviceName + "-abcdef",
			expServiceName: serviceName,
			expLanPort:     12345,
		},
		"mesh gateway with lan address": {
			config: &config.Config{
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindMeshGateway,
					LanAddress: &config.GatewayAddress{
						Address: taskIP,
						Port:    12345,
					},
					Name: serviceName,
				},
			},
			expServiceID:   serviceName + "-abcdef",
			expServiceName: serviceName,
			expLanAddress:  taskIP,
			expLanPort:     12345,
			expTaggedAddresses: map[string]api.ServiceAddress{
				"lan": {
					Address: taskIP,
					Port:    12345,
				},
			},
		},
		"mesh gateway with wan address": {
			config: &config.Config{
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindMeshGateway,
					WanAddress: &config.GatewayAddress{
						Address: publicIP,
						Port:    12345,
					},
				},
				Service: config.ServiceRegistration{},
			},
			expServiceID:   family + "-abcdef",
			expServiceName: family,
			expLanPort:     config.DefaultGatewayPort,
			expLanAddress:  "",
			expTaggedAddresses: map[string]api.ServiceAddress{
				"wan": {
					Address: publicIP,
					Port:    12345,
				},
			},
		},
		"mesh gateway with auth method enabled": {
			config: &config.Config{
				ConsulLogin: config.ConsulLogin{
					Enabled:       true,
					IncludeEntity: true,
				},
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindMeshGateway,
				},
			},
			expServiceID:   family + "-abcdef",
			expServiceName: family,
			expLanPort:     config.DefaultGatewayPort,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var srvConfig testutil.ServerConfigCallback
			if c.config.ConsulLogin.Enabled {
				// Enable ACLs to test with the auth method
				srvConfig = testutil.ConsulACLConfigFn
			}

			taskMetadataResponse := &awsutil.ECSTaskMeta{
				Cluster: "test",
				TaskARN: taskARN,
				Family:  family,
				Containers: []awsutil.ECSTaskMetaContainer{
					{
						Networks: []awsutil.ECSTaskMetaNetwork{
							{
								IPv4Addresses:  []string{taskIP},
								PrivateDNSName: taskDNSName,
							},
						},
					},
				},
			}

			server, apiCfg := testutil.ConsulServer(t, srvConfig)
			taskMetadataRespStr, err := constructTaskMetaResponseString(taskMetadataResponse)
			require.NoError(t, err)

			var currentTaskMetaResp atomic.Value
			currentTaskMetaResp.Store(taskMetadataRespStr)
			testutil.TaskMetaServer(t, testutil.TaskMetaHandlerFn(t,
				func() string {
					return currentTaskMetaResp.Load().(string)
				},
			))

			consulClient, err := api.NewClient(apiCfg)
			require.NoError(t, err)

			_, serverGRPCPort := testutil.GetHostAndPortFromAddress(server.GRPCAddr)
			_, serverHTTPPort := testutil.GetHostAndPortFromAddress(server.HTTPAddr)
			c.config.ConsulServers = config.ConsulServers{
				Hosts:     "127.0.0.1",
				GRPCPort:  serverGRPCPort,
				HTTPPort:  serverHTTPPort,
				EnableTLS: false,
			}

			c.config.BootstrapDir = testutil.TempDir(t)
			dataplaneConfigJSONFile := filepath.Join(c.config.BootstrapDir, dataplaneConfigFileName)
			expectedFileMeta := []*fileMeta{
				{
					name: dataplaneConfigFileName,
					path: dataplaneConfigJSONFile,
					mode: 0444,
				},
			}

			var partition, namespace string
			if testutil.EnterpriseFlag() {
				partition = "default"
				namespace = "default"
			}

			c.config.Gateway.Namespace = namespace
			c.config.Gateway.Partition = partition

			if c.config.ConsulLogin.Enabled {
				fakeAws := testutil.AuthMethodInit(t, consulClient, c.expServiceName, config.DefaultAuthMethodName)
				// Use the fake local AWS server.
				c.config.ConsulLogin.STSEndpoint = fakeAws.URL + "/sts"

				registerNode(t, consulClient, *taskMetadataResponse, partition)
			}

			testutil.SetECSConfigEnvVar(t, c.config)

			ui := cli.NewMockUi()
			cmd := Command{UI: ui, isTestEnv: true}

			cmd.ctx, cmd.cancel = context.WithCancel(context.Background())
			t.Cleanup(func() {
				cmd.cancel()
			})

			cmd.doneChan = make(chan struct{})
			cmd.proceedChan = make(chan struct{})

			go func() {
				code := cmd.Run(nil)
				require.Equal(t, code, 0, ui.ErrorWriter.String())
			}()

			// We wait till the control plane registers the proxy
			// to Consul before entering into the checks reconcilation loop
			<-cmd.doneChan

			expectedService := &api.CatalogService{
				Node:                   "arn:aws:ecs:us-east-1:123456789:cluster/test",
				Address:                taskIP,
				NodeMeta:               getNodeMeta(),
				ServiceID:              c.expServiceID,
				ServiceName:            c.expServiceName,
				ServiceProxy:           &api.AgentServiceConnectProxyConfig{},
				ServiceAddress:         c.expLanAddress,
				ServicePort:            c.expLanPort,
				ServiceMeta:            expectedTaskMeta,
				ServiceTags:            []string{},
				Datacenter:             "dc1",
				ServiceTaggedAddresses: c.expTaggedAddresses,
				Partition:              partition,
				Namespace:              namespace,
				ServiceWeights: api.Weights{
					Passing: 1,
					Warning: 1,
				},
			}

			expectedCheck := &api.HealthCheck{
				CheckID:     constructCheckID(expectedService.ServiceID, config.ConsulDataplaneContainerName),
				Type:        consulECSCheckType,
				Namespace:   expectedService.Namespace,
				ServiceName: expectedService.ServiceName,
				ServiceID:   expectedService.ServiceID,
				Name:        consulDataplaneReadinessCheckName,
				Status:      api.HealthCritical,
			}

			assertServiceAndProxyRegistrations(t, consulClient, nil, expectedService, "", c.expServiceName)
			assertCheckRegistration(t, consulClient, nil, expectedCheck)
			assertWrittenFiles(t, expectedFileMeta)
			assertDataplaneConfigJSON(t, serverGRPCPort, c.config.ConsulLogin.Enabled, c.config.BootstrapDir, dataplaneConfigJSONFile, expectedService.ServiceID, namespace, partition)

			// Signals control plane to enter into a state where it
			// periodically sync checks back to Consul
			close(cmd.proceedChan)

			taskMetadataResponse.Containers = append(taskMetadataResponse.Containers, constructContainerResponse(config.ConsulDataplaneContainerName, ecs.HealthStatusHealthy))
			taskMetadataRespStr, err = constructTaskMetaResponseString(taskMetadataResponse)
			require.NoError(t, err)
			currentTaskMetaResp.Store(taskMetadataRespStr)

			expectedCheck.Status = api.HealthPassing

			assertHealthChecks(t, consulClient, nil, expectedCheck)

			// Send SIGTERM and verify the status of checks
			signalSIGTERM(t)

			expectedCheck.Status = api.HealthCritical
			assertHealthChecks(t, consulClient, nil, expectedCheck)

			stopDataplaneContainer(taskMetadataResponse)
			taskMetadataRespStr, err = constructTaskMetaResponseString(taskMetadataResponse)
			require.NoError(t, err)
			currentTaskMetaResp.Store(taskMetadataRespStr)

			assertDeregistration(t, consulClient, "", expectedService.ServiceName)
			if c.config.ConsulLogin.Enabled {
				assertConsulLogout(t, apiCfg, c.config.BootstrapDir)
			}
			cmd.cancel()
		})
	}
}

func TestConstructServiceName(t *testing.T) {
	cmd := Command{config: &config.Config{}}
	family := "family"

	serviceName := cmd.constructServiceName(family)
	require.Equal(t, family, serviceName)

	serviceName = cmd.constructServiceName("FAMILY")
	require.Equal(t, family, serviceName)

	expectedServiceName := "service-name"

	cmd.config.Service.Name = expectedServiceName
	serviceName = cmd.constructServiceName(family)
	require.Equal(t, expectedServiceName, serviceName)

	cmd.config.Gateway = &config.GatewayRegistration{
		Name: "",
		Kind: api.ServiceKindMeshGateway,
	}
	serviceName = cmd.constructServiceName(family)
	require.Equal(t, family, serviceName)

	expectedGatewayServiceName := "service-name"

	cmd.config.Gateway = &config.GatewayRegistration{
		Name: expectedGatewayServiceName,
	}
	serviceName = cmd.constructServiceName(family)
	require.Equal(t, expectedGatewayServiceName, serviceName)
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

func assertServiceAndProxyRegistrations(t *testing.T, consulClient *api.Client, expectedService, expectedProxy *api.CatalogService, serviceName, proxyName string) {
	// Note: TaggedAddressees may be set, but it seems like a race.
	// We don't support tproxy in ECS, so I don't think we care about this?
	agentServiceIgnoreFields := cmpopts.IgnoreFields(api.CatalogService{},
		"ModifyIndex", "CreateIndex", "TaggedAddresses", "ServiceTaggedAddresses")

	if serviceName != "" {
		serviceInstances, _, err := consulClient.Catalog().Service(serviceName, "", nil)
		require.NoError(t, err)
		require.Equal(t, 1, len(serviceInstances))
		require.Empty(t, cmp.Diff(expectedService, serviceInstances[0], agentServiceIgnoreFields))
	}

	proxyServiceInstances, _, err := consulClient.Catalog().Service(proxyName, "", nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(proxyServiceInstances))
	require.Empty(t, cmp.Diff(expectedProxy, proxyServiceInstances[0], agentServiceIgnoreFields))
}

func assertCheckRegistration(t *testing.T, consulClient *api.Client, expectedServiceChecks api.HealthChecks, expectedProxyCheck *api.HealthCheck) {
	var ignoredChecksFields = []string{"Node", "Notes", "Definition", "Output", "Partition", "CreateIndex", "ModifyIndex", "ServiceTags"}
	// Check if checks are registered for services
	for _, expCheck := range expectedServiceChecks {
		filter := fmt.Sprintf("CheckID == `%s`", expCheck.CheckID)
		checks, _, err := consulClient.Health().Checks(expCheck.ServiceName, &api.QueryOptions{Filter: filter, Namespace: expCheck.Namespace})
		require.NoError(t, err)
		require.Equal(t, len(checks), 1)
		require.Empty(t, cmp.Diff(checks[0], expCheck, cmpopts.IgnoreFields(api.HealthCheck{}, ignoredChecksFields...)))
	}

	// Check if the proxy service has a registered check
	filter := fmt.Sprintf("CheckID == `%s`", expectedProxyCheck.CheckID)
	checks, _, err := consulClient.Health().Checks(expectedProxyCheck.ServiceName, &api.QueryOptions{Filter: filter, Namespace: expectedProxyCheck.Namespace})
	require.NoError(t, err)
	require.Equal(t, len(checks), 1)
	require.Empty(t, cmp.Diff(checks[0], expectedProxyCheck, cmpopts.IgnoreFields(api.HealthCheck{}, ignoredChecksFields...)))
}

func assertWrittenFiles(t *testing.T, expectedFiles []*fileMeta) {
	for _, expectedFile := range expectedFiles {
		f, err := os.Stat(expectedFile.path)
		require.NoError(t, err)
		require.Equal(t, expectedFile.name, f.Name())
		require.Equal(t, os.FileMode(expectedFile.mode), f.Mode())
	}
}

func assertDataplaneConfigJSON(t *testing.T, grpcPort int, loginEnabled bool, bootstrapDir, dataplaneConfigJSONFile, proxySvcID, namespace, partition string) {
	var credentialsConfigJSON string
	if loginEnabled {
		token := getACLToken(t, bootstrapDir)
		credentialsConfigJSON = fmt.Sprintf(`,
		"credentials": {
			"type": "static",
			"static": {
				"token": "%s"
			}
		}`, string(token))
	}

	expectedDataplaneConfigJSON := fmt.Sprintf(getExpectedDataplaneCfgJSON(), grpcPort, credentialsConfigJSON, proxySvcID, namespace, partition)
	actualDataplaneConfig, err := os.ReadFile(dataplaneConfigJSONFile)
	require.NoError(t, err)
	require.JSONEq(t, expectedDataplaneConfigJSON, string(actualDataplaneConfig))
}

// In a ACL enabled cluster, we expect the node to be preregistered by the ecs-controller.
// This function makes sure to register the node with the bootstrap token before running the
// control plane command
func registerNode(t *testing.T, consulClient *api.Client, taskMeta awsutil.ECSTaskMeta, partition string) {
	clusterARN, err := taskMeta.ClusterARN()
	require.NoError(t, err)

	payload := &api.CatalogRegistration{
		Node:     clusterARN,
		NodeMeta: getNodeMeta(),
		Address:  taskMeta.NodeIP(),
	}

	_, err = consulClient.Catalog().Register(payload, nil)
	require.NoError(t, err)
}

func assertHealthChecks(t *testing.T, consulClient *api.Client, expectedServiceChecks api.HealthChecks, expectedProxyCheck *api.HealthCheck) {
	timer := &retry.Timer{Timeout: 5 * time.Second, Wait: 500 * time.Millisecond}
	retry.RunWith(timer, t, func(r *retry.R) {
		// Check if checks are in the expected state for services
		for _, expCheck := range expectedServiceChecks {
			filter := fmt.Sprintf("CheckID == `%s`", expCheck.CheckID)
			checks, _, err := consulClient.Health().Checks(expCheck.ServiceName, &api.QueryOptions{Filter: filter, Namespace: expCheck.Namespace})
			require.NoError(r, err)

			for _, check := range checks {
				require.Equal(r, expCheck.Status, check.Status)
			}
		}

		// Check if the check for proxy is in the expected state
		filter := fmt.Sprintf("CheckID == `%s`", expectedProxyCheck.CheckID)
		checks, _, err := consulClient.Health().Checks(expectedProxyCheck.ServiceName, &api.QueryOptions{Filter: filter, Namespace: expectedProxyCheck.Namespace})
		require.NoError(r, err)
		require.Equal(r, 1, len(checks))
		require.Equal(r, expectedProxyCheck.Status, checks[0].Status)
	})
}

func assertDeregistration(t *testing.T, consulClient *api.Client, serviceName, proxyName string) {
	timer := &retry.Timer{Timeout: 5 * time.Second, Wait: 500 * time.Millisecond}
	retry.RunWith(timer, t, func(r *retry.R) {
		if serviceName != "" {
			serviceInstances, _, err := consulClient.Catalog().Service(serviceName, "", nil)
			require.NoError(r, err)
			require.Equal(r, 0, len(serviceInstances))
		}

		serviceInstances, _, err := consulClient.Catalog().Service(proxyName, "", nil)
		require.NoError(r, err)
		require.Equal(r, 0, len(serviceInstances))
	})
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

func injectContainersIntoTaskMetaResponse(t *testing.T, skipDataplaneContainer, ignoreMissingContainers bool, taskMetadataResponse *awsutil.ECSTaskMeta, healthSyncContainers map[string]healthSyncContainerMetaData) string {
	var taskMetaContainersResponse []awsutil.ECSTaskMetaContainer
	if !ignoreMissingContainers && !skipDataplaneContainer {
		taskMetaContainersResponse = append(taskMetaContainersResponse, constructContainerResponse(config.ConsulDataplaneContainerName, ecs.HealthStatusHealthy))
	}
	for name, hsc := range healthSyncContainers {
		if !ignoreMissingContainers && hsc.missing {
			continue
		}

		taskMetaContainersResponse = append(taskMetaContainersResponse, constructContainerResponse(name, hsc.status))
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

// stopDataplaneContainer marks the dataplane container's status as STOPPED in the
// task meta response
func stopDataplaneContainer(taskMetadataResp *awsutil.ECSTaskMeta) {
	for i, c := range taskMetadataResp.Containers {
		if c.Name == config.ConsulDataplaneContainerName {
			taskMetadataResp.Containers[i].DesiredStatus = ecs.DesiredStatusStopped
			taskMetadataResp.Containers[i].KnownStatus = ecs.DesiredStatusStopped
			return
		}
	}
}

func constructTaskMetaResponseString(resp *awsutil.ECSTaskMeta) (string, error) {
	byteStr, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}

	return string(byteStr), nil
}

func getExpectedDataplaneCfgJSON() string {
	return `{
	"consul": {
	  "addresses": "127.0.0.1",
	  "grpcPort": %d,
	  "serverWatchDisabled": false%s
	},
	"service": {
	  "nodeName": "arn:aws:ecs:us-east-1:123456789:cluster/test",
	  "serviceID": "%s",
	  "namespace": "%s",
	  "partition": "%s"
	},
	"xdsServer": {
	  "bindAddress": "127.0.0.1",
	  "bindPort": 20000
	}
  }`
}

func signalSIGTERM(t *testing.T) {
	err := syscall.Kill(os.Getpid(), syscall.SIGTERM)
	require.NoError(t, err)
	// Give it time to react
	time.Sleep(100 * time.Millisecond)
}
