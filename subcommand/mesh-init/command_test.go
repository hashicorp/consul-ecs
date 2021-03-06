package meshinit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/consul-ecs/awsutil"
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
		require.Contains(t, ui.ErrorWriter.String(), "invalid config: 1 error occurred:")
	})
}

// Note: this test cannot currently run in parallel with other tests
// because it sets environment variables (e.g. ECS metadata URI and Consul's HTTP addr)
// that could not be shared if another test were to run in parallel.
func TestRun(t *testing.T) {
	family := "family-SERVICE-name"
	serviceName := "service-name"

	cases := map[string]struct {
		servicePort       int
		upstreams         []config.Upstream
		expUpstreams      []api.Upstream
		checks            []config.AgentServiceCheck
		tags              []string
		expTags           []string
		additionalMeta    map[string]string
		expAdditionalMeta map[string]string
		serviceName       string
		expServiceName    string

		consulLogin config.ConsulLogin
	}{
		"basic service": {},
		"service with port": {
			servicePort: 8080,
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
		"service with checks": {
			checks: []config.AgentServiceCheck{
				{
					// Check id should be "api-<type>" for assertions.
					CheckID:  "api-http",
					Name:     "HTTP on port 8080",
					HTTP:     "http://localhost:8080",
					Interval: "20s",
					Timeout:  "10s",
					Header:   map[string][]string{"Content-type": {"application/json"}},
					Method:   "GET",
					Notes:    "unittest http check",
				},
				{
					CheckID:  "api-tcp",
					Name:     "TCP on port 8080",
					TCP:      "localhost:8080",
					Interval: "10s",
					Timeout:  "5s",
					Notes:    "unittest tcp check",
				},
				{
					CheckID:    "api-grpc",
					Name:       "GRPC on port 8081",
					GRPC:       "localhost:8081",
					GRPCUseTLS: false,
					Interval:   "30s",
					Notes:      "unittest grpc check",
				},
			},
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

			for i := range c.upstreams {
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
			cfg := testutil.ConsulServer(t, srvConfig)
			consulClient, err := api.NewClient(cfg)
			require.NoError(t, err)

			// Set up ECS container metadata server. This sets ECS_CONTAINER_METADATA_URI_V4.
			taskMetadataResponse := fmt.Sprintf(`{"Cluster": "test", "TaskARN": "%s", "Family": "%s"}`, taskARN, family)
			testutil.TaskMetaServer(t, testutil.TaskMetaHandler(t, taskMetadataResponse))

			if c.consulLogin.Enabled {
				fakeAws := testutil.AuthMethodInit(t, consulClient, expectedServiceName)

				// Use the fake local AWS server.
				c.consulLogin.STSEndpoint = fakeAws.URL + "/sts"
			}

			ui := cli.NewMockUi()
			cmd := Command{UI: ui}

			envoyBootstrapDir := testutil.TempDir(t)
			envoyBootstrapFile := filepath.Join(envoyBootstrapDir, envoyBoostrapConfigFilename)
			copyConsulECSBinary := filepath.Join(envoyBootstrapDir, "consul-ecs")

			consulEcsConfig := config.Config{
				LogLevel:             "DEBUG",
				BootstrapDir:         envoyBootstrapDir,
				HealthSyncContainers: nil,
				ConsulLogin:          c.consulLogin,
				Proxy: &config.AgentServiceConnectProxyConfig{
					Upstreams: c.upstreams,
				},
				Service: config.ServiceRegistration{
					Name:   c.serviceName,
					Checks: c.checks,
					Port:   c.servicePort,
					Tags:   c.tags,
					Meta:   c.additionalMeta,
				},
			}
			testutil.SetECSConfigEnvVar(t, &consulEcsConfig)

			code := cmd.Run(nil)
			require.Equal(t, code, 0, ui.ErrorWriter.String())

			expServiceID := fmt.Sprintf("%s-abcdef", expectedServiceName)
			expSidecarServiceID := fmt.Sprintf("%s-abcdef-sidecar-proxy", expectedServiceName)

			expectedServiceRegistration := &api.AgentService{
				ID:         expServiceID,
				Service:    expectedServiceName,
				Port:       c.servicePort,
				Meta:       expectedTaskMeta,
				Tags:       expectedTags,
				Datacenter: "dc1",
				Weights: api.AgentWeights{
					Passing: 1,
					Warning: 1,
				},
				Partition: expectedPartition,
				Namespace: expectedNamespace,
			}

			expectedProxyServiceRegistration := &api.AgentService{
				ID:      expSidecarServiceID,
				Service: fmt.Sprintf("%s-sidecar-proxy", expectedServiceName),
				Port:    20000,
				Kind:    api.ServiceKindConnectProxy,
				Proxy: &api.AgentServiceConnectProxyConfig{
					DestinationServiceName: expectedServiceName,
					DestinationServiceID:   expServiceID,
					LocalServicePort:       c.servicePort,
					Upstreams:              c.expUpstreams,
				},
				Meta:       expectedTaskMeta,
				Tags:       expectedTags,
				Datacenter: "dc1",
				Weights: api.AgentWeights{
					Passing: 1,
					Warning: 1,
				},
				Partition: expectedPartition,
				Namespace: expectedNamespace,
			}

			// Note: TaggedAddressees may be set, but it seems like a race.
			// We don't support tproxy in ECS, so I don't think we care about this?
			agentServiceIgnoreFields := cmpopts.IgnoreFields(api.AgentService{},
				"ContentHash", "ModifyIndex", "CreateIndex", "TaggedAddresses")

			service, _, err := consulClient.Agent().Service(expServiceID, nil)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(expectedServiceRegistration, service, agentServiceIgnoreFields))

			proxyService, _, err := consulClient.Agent().Service(expSidecarServiceID, nil)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(expectedProxyServiceRegistration, proxyService, agentServiceIgnoreFields))

			envoyBootstrapContents, err := os.ReadFile(envoyBootstrapFile)
			require.NoError(t, err)
			require.NotEmpty(t, envoyBootstrapContents)

			copyConsulEcsStat, err := os.Stat(copyConsulECSBinary)
			require.NoError(t, err)
			require.Equal(t, "consul-ecs", copyConsulEcsStat.Name())
			require.Equal(t, os.FileMode(0755), copyConsulEcsStat.Mode())

			if c.checks != nil {
				actualChecks, err := consulClient.Agent().Checks()
				require.NoError(t, err)
				for _, expCheck := range c.checks {
					expectedAgentCheck := toAgentCheck(expCheck)
					// Check for "critical" status. There is no listening application here, so checks will not pass.
					expectedAgentCheck.Status = api.HealthCritical
					// Pull the check type from the CheckID: "api-<type>" -> "<type>"
					// because Consul adds the Type field in its response.
					expectedAgentCheck.Type = strings.ReplaceAll(expCheck.CheckID, "api-", "")
					expectedAgentCheck.ServiceID = expectedServiceRegistration.ID
					expectedAgentCheck.ServiceName = expectedServiceRegistration.Service

					require.Empty(t, cmp.Diff(actualChecks[expCheck.CheckID], expectedAgentCheck,
						// Due to a Consul bug, the Definition field is always empty in the response.
						cmpopts.IgnoreFields(api.AgentCheck{}, "Node", "Output", "ExposedPort", "Definition")))
				}
			}
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
				"lan_ipv4": {
					Address: taskIP,
					Port:    12345,
				},
				"wan_ipv4": {
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

			apiCfg := testutil.ConsulServer(t, srvConfig)
			testutil.TaskMetaServer(t, testutil.TaskMetaHandler(t, taskMetadataResponse))

			consulClient, err := api.NewClient(apiCfg)
			require.NoError(t, err)

			c.config.BootstrapDir = testutil.TempDir(t)
			if c.config.ConsulLogin.Enabled {
				fakeAws := testutil.AuthMethodInit(t, consulClient, c.expServiceName)
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

			expectedServiceRegistration := &api.AgentService{
				Kind:            c.config.Gateway.Kind,
				ID:              c.expServiceID,
				Service:         c.expServiceName,
				Proxy:           &api.AgentServiceConnectProxyConfig{},
				Address:         c.expLanAddress,
				Port:            c.expLanPort,
				Meta:            expectedTaskMeta,
				Tags:            []string{},
				Datacenter:      "dc1",
				TaggedAddresses: c.expTaggedAddresses,
				Partition:       partition,
				Namespace:       namespace,
				Weights: api.AgentWeights{
					Passing: 1,
					Warning: 1,
				},
			}

			agentServiceIgnoreFields := cmpopts.IgnoreFields(api.AgentService{},
				"ContentHash", "ModifyIndex", "CreateIndex")

			service, _, err := consulClient.Agent().Service(expectedServiceRegistration.ID, nil)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(expectedServiceRegistration, service, agentServiceIgnoreFields))

		})
	}
}

func TestConstructChecks(t *testing.T) {
	// Bunch of test data.
	serviceID := "serviceID"
	containerName1 := "containerName1"
	containerName2 := "containerName2"

	httpCheck := config.AgentServiceCheck{
		CheckID:  "check-1",
		Name:     "HTTP on port 8080",
		HTTP:     "http://localhost:8080",
		Interval: "20s",
		Timeout:  "10s",
		Header:   map[string][]string{"Content-type": {"application/json"}},
		Method:   "GET",
		Notes:    "unittest http check",
	}
	tcpCheck := config.AgentServiceCheck{
		CheckID:  "check-2",
		Name:     "TCP on port 8080",
		TCP:      "localhost:8080",
		Interval: "10s",
		Timeout:  "5s",
		Notes:    "unittest tcp check",
	}
	syncedCheck1 := config.AgentServiceCheck{
		CheckID: fmt.Sprintf("%s-%s-consul-ecs", serviceID, containerName1),
		Name:    "consul ecs synced",
		Notes:   "consul-ecs created and updates this check because the containerName1 container is essential and has an ECS health check.",
		TTL:     "100000h",
	}
	syncedCheck2 := config.AgentServiceCheck{
		CheckID: fmt.Sprintf("%s-%s-consul-ecs", serviceID, containerName2),
		Name:    "consul ecs synced",
		Notes:   "consul-ecs created and updates this check because the containerName2 container is essential and has an ECS health check.",
		TTL:     "100000h",
	}

	cases := map[string]struct {
		checks               []config.AgentServiceCheck
		healthSyncContainers []string
		expError             string
		expChecks            []config.AgentServiceCheck
	}{
		"0-checks-0-health-sync-containers": {},
		"1-check-0-health-sync-containers": {
			checks:    []config.AgentServiceCheck{httpCheck},
			expChecks: []config.AgentServiceCheck{httpCheck},
		},
		"2-checks-0-health-sync-containers": {
			checks:    []config.AgentServiceCheck{httpCheck, tcpCheck},
			expChecks: []config.AgentServiceCheck{httpCheck, tcpCheck},
		},
		"1-check-1-health-sync-containers-should-error": {
			checks:               []config.AgentServiceCheck{httpCheck},
			healthSyncContainers: []string{containerName1},
			expError:             "only one of service.checks or healthSyncContainers should be set",
		},
		"0-checks-1-health-sync-containers": {
			healthSyncContainers: []string{containerName1},
			expChecks:            []config.AgentServiceCheck{syncedCheck1},
		},
		"0-checks-2-health-sync-containers": {
			healthSyncContainers: []string{containerName1, containerName2},
			expChecks:            []config.AgentServiceCheck{syncedCheck1, syncedCheck2},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			checks, err := constructChecks(serviceID, c.checks, c.healthSyncContainers)
			if c.expError == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Equal(t, c.expError, err.Error())
			}
			require.Equal(t, c.expChecks, checks)
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

func TestConstructLoginParams(t *testing.T) {
	t.Parallel()

	var (
		authMethodName = "my-auth-method"
		bearerToken    = "<bogus-token>"
		cluster        = "my-cluster"
		taskID         = "abcdef"
		taskMeta       = awsutil.ECSTaskMeta{
			Cluster: cluster,
			TaskARN: "arn:aws:ecs:bogus-east-1:123456789:task/test/" + taskID,
			Family:  "my-service",
		}
	)

	cases := map[string]struct {
		conf *config.Config
		exp  *api.ACLLoginParams
	}{
		"defaults": {
			conf: &config.Config{
				ConsulLogin: config.ConsulLogin{},
			},
			exp: &api.ACLLoginParams{
				AuthMethod:  config.DefaultAuthMethodName,
				BearerToken: bearerToken,
				Meta: map[string]string{
					"consul.hashicorp.com/task-id": taskID,
					"consul.hashicorp.com/cluster": cluster,
				},
			},
		},
		"non defaults": {
			conf: &config.Config{
				ConsulLogin: config.ConsulLogin{
					Method: authMethodName,
					Meta: map[string]string{
						"unittest-tag": "1234",
					},
				},
			},
			exp: &api.ACLLoginParams{
				AuthMethod:  authMethodName,
				BearerToken: bearerToken,
				Meta: map[string]string{
					"consul.hashicorp.com/task-id": taskID,
					"consul.hashicorp.com/cluster": cluster,
					"unittest-tag":                 "1234",
				},
			},
		},
	}
	for name, c := range cases {
		c := c

		t.Run(name, func(t *testing.T) {
			cmd := &Command{config: c.conf}
			params := cmd.constructLoginParams(bearerToken, taskMeta)
			require.Equal(t, c.exp, params)
		})
	}
}

func TestWaitForTokenReplication(t *testing.T) {
	cfg := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
	client, err := api.NewClient(cfg)
	require.NoError(t, err)

	cases := []struct {
		lagTime  time.Duration
		expError bool
	}{
		{lagTime: 50 * time.Millisecond},
		{lagTime: 100 * time.Millisecond},
		{lagTime: 500 * time.Millisecond},
		// 2s is as long as we wait.
		{lagTime: 2500 * time.Millisecond, expError: true},
	}
	for _, c := range cases {
		name := c.lagTime.String()
		t.Run(name, func(t *testing.T) {
			accessorID, err := uuid.GenerateUUID()
			require.NoError(t, err)
			secretID, err := uuid.GenerateUUID()
			require.NoError(t, err)

			// Write the token to a file.
			tmpDir := testutil.TempDir(t)
			tokenFile := filepath.Join(tmpDir, "test-token")
			err = os.WriteFile(tokenFile, []byte(secretID), 0600)
			require.NoError(t, err)

			tokenCfg := api.DefaultConfig()
			tokenCfg.TokenFile = tokenFile

			tokenClient, err := api.NewClient(tokenCfg)
			require.NoError(t, err)

			// After c.lagTime, create the token.
			//
			// This simulates the token not existing for a short period of time
			// on the Consul server. This is not the exact replication lag
			// between two Consul servers, but close enough to exercise the code.
			timer := time.AfterFunc(
				c.lagTime,
				func() {
					token, _, err := client.ACL().TokenCreate(&api.ACLToken{
						AccessorID: accessorID,
						SecretID:   secretID,
					}, nil)
					require.NoError(t, err)
					// Sanity check
					require.Equal(t, accessorID, token.AccessorID)
					require.Equal(t, secretID, token.SecretID)
				},
			)
			t.Cleanup(func() { timer.Stop() })

			// Wait for the token to "replicate".
			cmd := &Command{
				log: hclog.NewNullLogger(),
				config: &config.Config{
					ConsulHTTPAddr:   cfg.Address,
					ConsulCACertFile: cfg.TLSConfig.CAFile,
				},
			}
			err = cmd.waitForTokenReplication(tokenFile)
			if c.expError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Token should exist.
				token, _, err := tokenClient.ACL().TokenReadSelf(nil)
				require.NoError(t, err)
				require.Equal(t, accessorID, token.AccessorID)
				require.Equal(t, secretID, token.SecretID)
			}

		})
	}
}

// toAgentCheck translates the request type (AgentServiceCheck) into an "expected"
// response type (AgentCheck) which we can use in assertions.
func toAgentCheck(check config.AgentServiceCheck) *api.AgentCheck {
	expInterval, _ := time.ParseDuration(check.Interval)
	expTimeout, _ := time.ParseDuration(check.Timeout)
	expPartition := ""
	expNamespace := ""
	if testutil.EnterpriseFlag() {
		expPartition = "default"
		expNamespace = "default"
	}
	return &api.AgentCheck{
		CheckID:   check.CheckID,
		Name:      check.Name,
		Notes:     check.Notes,
		Partition: expPartition,
		Namespace: expNamespace,
		Definition: api.HealthCheckDefinition{
			// HealthCheckDefinition does not have GRPC or TTL fields.
			HTTP:             check.HTTP,
			Header:           check.Header,
			Method:           check.HTTP,
			Body:             check.Body,
			TLSServerName:    check.TLSServerName,
			TLSSkipVerify:    check.TLSSkipVerify,
			TCP:              check.TCP,
			IntervalDuration: expInterval,
			TimeoutDuration:  expTimeout,
			Interval:         api.ReadableDuration(expInterval),
			Timeout:          api.ReadableDuration(expTimeout),
		},
	}
}
