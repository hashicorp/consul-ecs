// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package meshinit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

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
	testRegion := "us-west-2"
	testZone := "us-west-2b"

	cases := map[string]struct {
		servicePort                 int
		upstreams                   []config.Upstream
		expUpstreams                []api.Upstream
		tags                        []string
		expTags                     []string
		additionalMeta              map[string]string
		expAdditionalMeta           map[string]string
		serviceName                 string
		expServiceName              string
		proxyPort                   int
		healthSyncContainers        []string
		expectedDataplaneConfigJSON string
		skipServerWatch             bool
		missingAWSRegion            bool

		consulLogin config.ConsulLogin
	}{
		"basic service": {
			skipServerWatch:  true,
			missingAWSRegion: true,
		},
		"service with port": {
			servicePort:     8080,
			proxyPort:       21000,
			skipServerWatch: true,
		},
		"service with upstreams": {
			skipServerWatch: true,
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
			skipServerWatch:      true,
			healthSyncContainers: []string{"container-1"},
		},
		"service with two healthy healthSyncContainers": {
			skipServerWatch:      true,
			healthSyncContainers: []string{"container-1", "container-2"},
		},
		"service with tags": {
			skipServerWatch: true,
			tags:            []string{"tag1", "tag2"},
			expTags:         []string{"tag1", "tag2"},
		},
		"service with additional metadata": {
			skipServerWatch:   true,
			additionalMeta:    map[string]string{"a": "1", "b": "2"},
			expAdditionalMeta: map[string]string{"a": "1", "b": "2"},
		},
		"service with service name": {
			skipServerWatch: true,
			serviceName:     serviceName,
			expServiceName:  serviceName,
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
				Cluster:          "test",
				TaskARN:          taskARN,
				Family:           family,
				AvailabilityZone: testZone,
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
			cmd := Command{UI: ui}

			cmd.ctx, cmd.cancel = context.WithCancel(context.Background())
			t.Cleanup(func() {
				cmd.cancel()
			})

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

			consulEcsConfig := config.Config{
				LogLevel:             "DEBUG",
				BootstrapDir:         envoyBootstrapDir,
				HealthSyncContainers: c.healthSyncContainers,
				ConsulLogin:          c.consulLogin,
				ConsulServers: config.ConsulServers{
					Hosts: "127.0.0.1",
					GRPC: config.GRPCSettings{
						Port: serverGRPCPort,
					},
					HTTP: config.HTTPSettings{
						Port: serverHTTPPort,
					},
					SkipServerWatch: c.skipServerWatch,
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

			if !c.missingAWSRegion {
				t.Setenv(awsutil.AWSRegionEnvVar, testRegion)
			}

			code := cmd.Run(nil)
			require.Equal(t, code, 0, ui.ErrorWriter.String())

			expServiceID := fmt.Sprintf("%s-abcdef", expectedServiceName)
			expSidecarServiceID := fmt.Sprintf("%s-abcdef-sidecar-proxy", expectedServiceName)

			expectedNodeName := "arn:aws:ecs:us-east-1:123456789:cluster/test"
			expectedAddress := "127.0.0.1"

			var localityParams *api.Locality
			if !c.missingAWSRegion {
				localityParams = &api.Locality{
					Region: testRegion,
					Zone:   testZone,
				}
			}

			expectedService := &api.CatalogService{
				Node:           expectedNodeName,
				NodeMeta:       getNodeMeta(),
				Address:        expectedAddress,
				ServiceID:      expServiceID,
				ServiceName:    expectedServiceName,
				ServicePort:    c.servicePort,
				ServiceMeta:    expectedTaskMeta,
				ServiceTags:    expectedTags,
				ServiceAddress: expectedAddress,
				Datacenter:     "dc1",
				ServiceWeights: api.Weights{
					Passing: 1,
					Warning: 1,
				},
				ServiceProxy:    &api.AgentServiceConnectProxyConfig{},
				Partition:       expectedPartition,
				Namespace:       expectedNamespace,
				ServiceLocality: localityParams,
			}

			expectedProxy := &api.CatalogService{
				Node:           expectedNodeName,
				NodeMeta:       getNodeMeta(),
				Address:        expectedAddress,
				ServiceID:      expSidecarServiceID,
				ServiceName:    fmt.Sprintf("%s-sidecar-proxy", expectedServiceName),
				ServicePort:    c.proxyPort,
				ServiceAddress: expectedAddress,
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
				Partition:       expectedPartition,
				Namespace:       expectedNamespace,
				ServiceLocality: localityParams,
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

			for _, name := range c.healthSyncContainers {
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
			assertDataplaneConfigJSON(t, c.skipServerWatch, serverGRPCPort, c.consulLogin.Enabled, envoyBootstrapDir, dataplaneConfigJSONFile, expectedProxy.ServiceID, expectedNamespace, expectedPartition, consulEcsConfig.LogLevel)

			for _, expCheck := range expectedServiceChecks {
				expCheck.Status = api.HealthCritical
			}
			expectedProxyCheck.Status = api.HealthCritical

			// Verify with retries that the checks have reached the expected state
			assertHealthChecks(t, consulClient, expectedServiceChecks, expectedProxyCheck)
			cmd.cancel()
		})
	}
}

func TestGateway(t *testing.T) {
	var (
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

		taskFamily         string
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
			taskFamily:     "family-name-mesh-gateway",
			expServiceID:   "family-name-mesh-gateway-abcdef",
			expServiceName: "family-name-mesh-gateway",
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
			taskFamily:     "family-name-mesh-gateway",
			expServiceID:   "family-name-mesh-gateway-abcdef",
			expServiceName: "family-name-mesh-gateway",
			expLanPort:     12345,
		},
		"mesh gateway with service name": {
			config: &config.Config{
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindMeshGateway,
					LanAddress: &config.GatewayAddress{
						Port: 12345,
					},
					Name: "service-name-mesh-gateway",
				},
			},
			taskFamily:     "family-name-mesh-gateway",
			expServiceID:   "service-name-mesh-gateway-abcdef",
			expServiceName: "service-name-mesh-gateway",
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
					Name: "service-name-mesh-gateway",
				},
			},
			taskFamily:     "family-name-mesh-gateway",
			expServiceID:   "service-name-mesh-gateway-abcdef",
			expServiceName: "service-name-mesh-gateway",
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
			taskFamily:     "family-name-mesh-gateway",
			expServiceID:   "family-name-mesh-gateway-abcdef",
			expServiceName: "family-name-mesh-gateway",
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
			taskFamily:     "family-name-mesh-gateway",
			expServiceID:   "family-name-mesh-gateway-abcdef",
			expServiceName: "family-name-mesh-gateway",
			expLanPort:     config.DefaultGatewayPort,
		},
		"terminating gateway": {
			config: &config.Config{
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindTerminatingGateway,
				},
			},
			taskFamily:     "family-name-terminating-gateway",
			expServiceID:   "family-name-terminating-gateway-abcdef",
			expServiceName: "family-name-terminating-gateway",
		},
		"terminating gateway with auth method enabled": {
			config: &config.Config{
				ConsulLogin: config.ConsulLogin{
					Enabled:       true,
					IncludeEntity: true,
				},
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindTerminatingGateway,
				},
			},
			taskFamily:     "family-name-terminating-gateway",
			expServiceID:   "family-name-terminating-gateway-abcdef",
			expServiceName: "family-name-terminating-gateway",
		},
		"api gateway": {
			config: &config.Config{
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindAPIGateway,
				},
			},
			taskFamily:     "family-name-api-gateway",
			expServiceID:   "family-name-api-gateway-abcdef",
			expServiceName: "family-name-api-gateway",
		},
		"api gateway with auth method enabled": {
			config: &config.Config{
				ConsulLogin: config.ConsulLogin{
					Enabled:       true,
					IncludeEntity: true,
				},
				Gateway: &config.GatewayRegistration{
					Kind: api.ServiceKindAPIGateway,
				},
			},
			taskFamily:     "family-name-api-gateway",
			expServiceID:   "family-name-api-gateway-abcdef",
			expServiceName: "family-name-api-gateway",
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
				Family:  c.taskFamily,
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
				Hosts: "127.0.0.1",
				GRPC: config.GRPCSettings{
					Port:      serverGRPCPort,
					EnableTLS: testutil.BoolPtr(false),
				},
				HTTP: config.HTTPSettings{
					Port:      serverHTTPPort,
					EnableTLS: testutil.BoolPtr(false),
				},
				SkipServerWatch: true,
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
			cmd := Command{UI: ui}

			cmd.ctx, cmd.cancel = context.WithCancel(context.Background())
			t.Cleanup(func() {
				cmd.cancel()
			})

			code := cmd.Run(nil)
			require.Equal(t, code, 0, ui.ErrorWriter.String())

			expPort := config.DefaultGatewayPort
			if c.expLanPort != 0 {
				expPort = c.expLanPort
			}

			expectedService := &api.CatalogService{
				Node:                   "arn:aws:ecs:us-east-1:123456789:cluster/test",
				Address:                taskIP,
				NodeMeta:               getNodeMeta(),
				ServiceID:              c.expServiceID,
				ServiceName:            c.expServiceName,
				ServiceProxy:           &api.AgentServiceConnectProxyConfig{},
				ServiceAddress:         taskIP,
				ServicePort:            expPort,
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

			if c.expLanAddress != "" {
				expectedService.Address = c.expLanAddress
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
			assertDataplaneConfigJSON(t, true, serverGRPCPort, c.config.ConsulLogin.Enabled, c.config.BootstrapDir, dataplaneConfigJSONFile, expectedService.ServiceID, namespace, partition, "INFO")

			expectedCheck.Status = api.HealthCritical
			assertHealthChecks(t, consulClient, nil, expectedCheck)

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

func TestGetLocalityParams(t *testing.T) {
	taskMeta := awsutil.ECSTaskMeta{AvailabilityZone: "us-west-2b"}
	params := getLocalityParams(taskMeta)
	require.Nil(t, params)

	t.Setenv(awsutil.AWSRegionEnvVar, "us-west-2")
	params = getLocalityParams(taskMeta)

	require.NotNil(t, params)
	require.Equal(t, "us-west-2", params.Region)
	require.Equal(t, "us-west-2b", params.Zone)
}

func TestMakeProxyServiceIDAndName(t *testing.T) {
	expectedID := "test-service-12345-sidecar-proxy"
	expectedName := "test-service-sidecar-proxy"

	actualID, actualName := makeProxySvcIDAndName("test-service-12345", "test-service")
	require.Equal(t, expectedID, actualID)
	require.Equal(t, expectedName, actualName)
}

func TestWriteCACertToVolume(t *testing.T) {
	cases := map[string]struct {
		serverConfig               config.ConsulServers
		expectedFileName           string
		caCertPemProvidedViaEnvVar bool
	}{
		"TLS disabled": {
			serverConfig: config.ConsulServers{
				Defaults: config.DefaultSettings{
					EnableTLS: false,
				},
			},
		},
		"TLS enabled and CA cert not provided via env variable": {
			serverConfig: config.ConsulServers{
				Defaults: config.DefaultSettings{
					EnableTLS:  true,
					CaCertFile: "consul-ca-cert.pem",
				},
			},
			expectedFileName: "consul-ca-cert.pem",
		},
		"TLS enabled and CA cert provided via env variable": {
			serverConfig: config.ConsulServers{
				Defaults: config.DefaultSettings{
					EnableTLS:  true,
					CaCertFile: "consul-ca-cert.pem",
				},
			},
			caCertPemProvidedViaEnvVar: true,
			expectedFileName:           caCertFileName,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {

			ui := cli.NewMockUi()
			cmd := Command{UI: ui}

			cmd.config = &config.Config{
				BootstrapDir:  testutil.TempDir(t),
				ConsulServers: c.serverConfig,
			}

			if c.caCertPemProvidedViaEnvVar {
				t.Setenv(config.ConsulGRPCCACertPemEnvVar, "SAMPLE_CA_CERT_PEM")
			}

			caCertFilePath, err := cmd.writeRPCCACertToSharedVolume()
			require.NoError(t, err)
			require.Contains(t, caCertFilePath, c.expectedFileName)

			if c.caCertPemProvidedViaEnvVar {
				contents, err := os.ReadFile(caCertFilePath)
				require.NoError(t, err)
				require.Equal(t, string(contents), "SAMPLE_CA_CERT_PEM")
			}
		})
	}
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

func assertDataplaneConfigJSON(t *testing.T, skipServerWatch bool, grpcPort int, loginEnabled bool, bootstrapDir, dataplaneConfigJSONFile, proxySvcID, namespace, partition, logLevel string) {
	var credentialsConfigJSON string
	if loginEnabled {
		token := getACLToken(t, bootstrapDir)
		credentialsConfigJSON = fmt.Sprintf(`,
		"credentials": {
			"type": "static",
			"static": {
				"token": "%s"
			}
		}`, token)
	}

	expectedDataplaneConfigJSON := fmt.Sprintf(getExpectedDataplaneCfgJSON(), grpcPort, skipServerWatch, credentialsConfigJSON, proxySvcID, namespace, partition, logLevel)
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
		Node:      clusterARN,
		NodeMeta:  getNodeMeta(),
		Address:   taskMeta.NodeIP(),
		Partition: partition,
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

func getACLToken(t *testing.T, bootstrapDir string) string {
	tokenFile := filepath.Join(bootstrapDir, config.ServiceTokenFilename)
	token, err := os.ReadFile(tokenFile)
	require.NoError(t, err)

	return string(token)
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
	  "serverWatchDisabled": %t,
	  "tls": {
		"disabled": true
	   }%s
	},
	"proxy": {
	  "nodeName": "arn:aws:ecs:us-east-1:123456789:cluster/test",
	  "id": "%s",
	  "namespace": "%s",
	  "partition": "%s"
	},
	"xdsServer": {
	  "bindAddress": "127.0.0.1"
	},
	"envoy": {
		"readyBindAddress": "127.0.0.1",
		"readyBindPort": 22000
	},
	"logging": {
		"logLevel": "%s"
	}
  }`
}
