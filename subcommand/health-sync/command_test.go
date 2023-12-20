// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	controlplane "github.com/hashicorp/consul-ecs/subcommand/control-plane"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul-server-connection-manager/discovery"
	"github.com/hashicorp/consul/api"
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

func TestRun(t *testing.T) {
	family := "family-SERVICE-name"
	serviceName := "service-name"
	proxyServiceName := fmt.Sprintf("%s-sidecar-proxy", serviceName)
	servicePort := 8080
	taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"

	cases := map[string]struct {
		consulLogin          config.ConsulLogin
		healthSyncContainers map[string]healthSyncContainerMetaData
	}{
		"simple": {},
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
				namespace = "bar"
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
				fakeAws := testutil.AuthMethodInit(t, consulClient, serviceName, config.DefaultAuthMethodName)

				// Use the fake local AWS server.
				c.consulLogin.STSEndpoint = fakeAws.URL + "/sts"

				registerNode(t, consulClient, *taskMetadataResponse, partition)
			}

			envoyBootstrapDir := testutil.TempDir(t)
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

			// Run the control-plane command first because
			// it sets up the necessary prerequisites for
			// running the health sync command like registering
			// the proxy and the service and constructing
			// preliminary health checks.

			ui := cli.NewMockUi()
			ctrlPlaneCmd := controlplane.Command{UI: ui}
			code := ctrlPlaneCmd.Run(nil)
			require.Equal(t, code, 0, ui.ErrorWriter.String())
			verifyControlPlaneCommandSideEffects(t, consulClient, serviceName, proxyServiceName, apiQueryOptions)

			cmd := Command{UI: ui, isTestEnv: true}
			cmd.ctx, cmd.cancel = context.WithCancel(context.Background())

			watcherCh := make(chan discovery.State, 1)
			cmd.watcherCh = watcherCh
			go func() {
				testutil.SetECSConfigEnvVar(t, &consulEcsConfig)
				code := cmd.Run(nil)
				require.Equal(t, 0, code, ui.ErrorWriter.String())
			}()
		})
	}
}

func verifyControlPlaneCommandSideEffects(t *testing.T, consulClient *api.Client, serviceName, proxyServiceName string, queryOpts *api.QueryOptions) {
	assertServiceAndProxyRegistrations(t, consulClient, serviceName, proxyServiceName, queryOpts)

	areAllChecksCriticalFn := func(checks api.HealthChecks) bool {
		areChecksCritical := true
		for _, check := range checks {
			if check.Status == api.HealthCritical {
				continue
			}

			areChecksCritical = false
		}
		return areChecksCritical
	}

	serviceHealthChecks := fetchHealthChecks(t, consulClient, serviceName, queryOpts)
	require.True(t, areAllChecksCriticalFn(serviceHealthChecks))

	proxyHealthChecks := fetchHealthChecks(t, consulClient, proxyServiceName, queryOpts)
	require.True(t, areAllChecksCriticalFn(proxyHealthChecks))
}

func assertServiceAndProxyRegistrations(t *testing.T, consulClient *api.Client, serviceName, proxyName string, apiQueryOpts *api.QueryOptions) {
	if serviceName != "" {
		serviceInstances, _, err := consulClient.Catalog().Service(serviceName, "", apiQueryOpts)
		require.NoError(t, err)
		require.Equal(t, 1, len(serviceInstances))
	}

	proxySvcInstances, _, err := consulClient.Catalog().Service(proxyName, "", apiQueryOpts)
	require.NoError(t, err)
	require.Equal(t, 1, len(proxySvcInstances))
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
