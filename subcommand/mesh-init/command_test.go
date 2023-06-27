// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package meshinit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

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
		servicePort          int
		upstreams            []config.Upstream
		expUpstreams         []api.Upstream
		tags                 []string
		expTags              []string
		additionalMeta       map[string]string
		expAdditionalMeta    map[string]string
		serviceName          string
		expServiceName       string
		proxyPort            int
		healthSyncContainers []string

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
		"service with health sync containers input set": {
			healthSyncContainers: []string{"container1", "container2"},
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
		// "auth method enabled": {
		// 	consulLogin: config.ConsulLogin{
		// 		Enabled:       true,
		// 		IncludeEntity: true,
		// 		Meta: map[string]string{
		// 			"unittest-tag": "12345",
		// 		},
		// 	},
		// },
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
			taskMetadataResponse := fmt.Sprintf(`{"Cluster": "test", "TaskARN": "%s", "Family": "%s"}`, taskARN, family)
			testutil.TaskMetaServer(t, testutil.TaskMetaHandler(t, taskMetadataResponse))

			if c.consulLogin.Enabled {
				fakeAws := testutil.AuthMethodInit(t, consulClient, expectedServiceName, config.DefaultAuthMethodName)

				// Use the fake local AWS server.
				c.consulLogin.STSEndpoint = fakeAws.URL + "/sts"
			}

			ui := cli.NewMockUi()
			cmd := Command{UI: ui}

			envoyBootstrapDir := testutil.TempDir(t)
			copyConsulECSBinary := filepath.Join(envoyBootstrapDir, "consul-ecs")

			_, serverGRPCPort := testutil.GetHostAndPortFromAddress(server.GRPCAddr)
			_, serverHTTPPort := testutil.GetHostAndPortFromAddress(server.HTTPAddr)

			consulEcsConfig := config.Config{
				LogLevel:             "DEBUG",
				BootstrapDir:         envoyBootstrapDir,
				HealthSyncContainers: c.healthSyncContainers,
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
			testutil.SetECSConfigEnvVar(t, &consulEcsConfig)

			code := cmd.Run(nil)
			require.Equal(t, code, 0, ui.ErrorWriter.String())

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

			for _, container := range c.healthSyncContainers {
				expectedServiceChecks = append(expectedServiceChecks, &api.HealthCheck{
					CheckID:     constructCheckID(expServiceID, container),
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

			// Note: TaggedAddressees may be set, but it seems like a race.
			// We don't support tproxy in ECS, so I don't think we care about this?
			agentServiceIgnoreFields := cmpopts.IgnoreFields(api.CatalogService{},
				"ModifyIndex", "CreateIndex", "TaggedAddresses", "ServiceTaggedAddresses")

			serviceInstances, _, err := consulClient.Catalog().Service(expectedServiceName, "", nil)
			require.NoError(t, err)
			require.Equal(t, 1, len(serviceInstances))
			require.Empty(t, cmp.Diff(expectedService, serviceInstances[0], agentServiceIgnoreFields))

			proxyServiceInstances, _, err := consulClient.Catalog().Service(expectedProxy.ServiceName, "", nil)
			require.NoError(t, err)
			require.Equal(t, 1, len(proxyServiceInstances))
			require.Empty(t, cmp.Diff(expectedProxy, proxyServiceInstances[0], agentServiceIgnoreFields))

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
			checks, _, err := consulClient.Health().Checks(expectedProxy.ServiceName, &api.QueryOptions{Filter: filter, Namespace: expectedProxy.Namespace})
			require.NoError(t, err)
			require.Equal(t, len(checks), 1)
			require.Empty(t, cmp.Diff(checks[0], expectedProxyCheck, cmpopts.IgnoreFields(api.HealthCheck{}, ignoredChecksFields...)))

			copyConsulEcsStat, err := os.Stat(copyConsulECSBinary)
			require.NoError(t, err)
			require.Equal(t, "consul-ecs", copyConsulEcsStat.Name())
			require.Equal(t, os.FileMode(0755), copyConsulEcsStat.Mode())
		})
	}
}

func TestGateway(t *testing.T) {
	var (
		family               = "family-name-mesh-gateway"
		serviceName          = "service-name-mesh-gateway"
		taskARN              = "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
		taskIP               = "10.1.2.3"
		publicIP             = "255.1.2.3"
		taskDNSName          = "test-dns-name"
		taskMetadataResponse = fmt.Sprintf(`{"Cluster": "test","TaskARN": "%s","Family": "%s","Containers":[{"Networks":[{"IPv4Addresses":["%s"],"PrivateDNSName":"%s"}]}]}`, taskARN, family, taskIP, taskDNSName)
		expectedTaskMeta     = map[string]string{
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
		// TODO: revisit these tests when service registration happens via the
		// client that talks directly to the server and not the client agent
		//
		// "mesh gateway with auth method enabled": {
		// 	config: &config.Config{
		// 		ConsulLogin: config.ConsulLogin{
		// 			Enabled:       true,
		// 			IncludeEntity: true,
		// 		},
		// 		Gateway: &config.GatewayRegistration{
		// 			Kind: api.ServiceKindMeshGateway,
		// 		},
		// 	},
		// 	expServiceID:   family + "-abcdef",
		// 	expServiceName: family,
		// 	expLanPort:     config.DefaultGatewayPort,
		// },
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var srvConfig testutil.ServerConfigCallback
			if c.config.ConsulLogin.Enabled {
				// Enable ACLs to test with the auth method
				srvConfig = testutil.ConsulACLConfigFn
			}

			server, apiCfg := testutil.ConsulServer(t, srvConfig)
			testutil.TaskMetaServer(t, testutil.TaskMetaHandler(t, taskMetadataResponse))

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
			if c.config.ConsulLogin.Enabled {
				fakeAws := testutil.AuthMethodInit(t, consulClient, c.expServiceName, config.DefaultAuthMethodName)
				// Use the fake local AWS server.
				c.config.ConsulLogin.STSEndpoint = fakeAws.URL + "/sts"
			}
			testutil.SetECSConfigEnvVar(t, c.config)

			ui := cli.NewMockUi()
			cmd := Command{UI: ui}

			code := cmd.Run(nil)
			require.Equal(t, code, 0, ui.ErrorWriter.String())

			var partition, namespace string
			if testutil.EnterpriseFlag() {
				// TODO add enterprise tests
				partition = "default"
				namespace = "default"
			}

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

			agentServiceIgnoreFields := cmpopts.IgnoreFields(api.CatalogService{},
				"ModifyIndex", "CreateIndex")

			serviceInstances, _, err := consulClient.Catalog().Service(c.expServiceName, "", nil)
			require.NoError(t, err)
			require.Equal(t, 1, len(serviceInstances))
			require.Empty(t, cmp.Diff(expectedService, serviceInstances[0], agentServiceIgnoreFields))

			ignoredChecksFields := []string{"Node", "Notes", "Definition", "Output", "Partition", "CreateIndex", "ModifyIndex", "ServiceTags"}
			// Check if the service has a registered check
			filter := fmt.Sprintf("CheckID == `%s`", expectedCheck.CheckID)
			checks, _, err := consulClient.Health().Checks(expectedService.ServiceName, &api.QueryOptions{Filter: filter, Namespace: expectedService.Namespace})
			require.NoError(t, err)
			require.Equal(t, len(checks), 1)
			require.Empty(t, cmp.Diff(checks[0], expectedCheck, cmpopts.IgnoreFields(api.HealthCheck{}, ignoredChecksFields...)))
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
}
