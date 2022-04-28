package meshinit

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul-ecs/testutil/iamauthtest"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
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
	family := "family-service-name"
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
				ExtraLoginFlags: []string{
					"-meta", "unittest-tag=12345",
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
				expectedServiceName = family
				expectedPartition   = ""
				expectedNamespace   = ""
			)

			if enterpriseFlag() {
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
				fakeAws := authMethodInit(t, consulClient, expectedServiceName)

				// Point `consul login` at the local fake AWS server.
				c.consulLogin.ExtraLoginFlags = append(c.consulLogin.ExtraLoginFlags,
					"-aws-sts-endpoint", fakeAws.URL+"/sts",
					"-aws-region", "fake-region",
					"-aws-access-key-id", "fake-key-id",
					"-aws-secret-access-key", "fake-secret-key",
				)
			}

			ui := cli.NewMockUi()
			cmd := Command{UI: ui}

			envoyBootstrapDir := testutil.TempDir(t)
			envoyBootstrapFile := path.Join(envoyBootstrapDir, envoyBoostrapConfigFilename)
			copyConsulECSBinary := path.Join(envoyBootstrapDir, "consul-ecs")

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

// authMethodInit sets up necessary pieces for the IAM auth method:
// - Start a fake AWS server. This responds an IAM role tagged with expectedServiceName.
// - Configures an auth method + binding rule uses the tagged service name from the IAM
//   role for the service identity.
//
// When using this, you will also need to point the login command at the fake AWS server:
//
//    fakeAws := authMethodInit(...)
//    consulLogin.ExtraLoginFlags = []string{"-aws-sts-endpoint", fakeAws.URL + "/sts"}
func authMethodInit(t *testing.T, consulClient *api.Client, expectedServiceName string) *httptest.Server {
	arn := "arn:aws:iam::1234567890:role/my-role"
	uniqueId := "AAAsomeuniqueid"

	// Start a fake AWS API server for STS and IAM.
	fakeAws := iamauthtest.NewTestServer(t, &iamauthtest.Server{
		GetCallerIdentityResponse: iamauthtest.MakeGetCallerIdentityResponse(
			arn, uniqueId, "1234567890",
		),
		GetRoleResponse: iamauthtest.MakeGetRoleResponse(
			arn, uniqueId, iamauthtest.Tags{
				Members: []iamauthtest.TagMember{
					{Key: "service-name", Value: expectedServiceName},
				},
			},
		),
	})

	method, _, err := consulClient.ACL().AuthMethodCreate(&api.ACLAuthMethod{
		Name:        config.DefaultAuthMethodName,
		Type:        "aws-iam",
		Description: "aws auth method for unit test",
		Config: map[string]interface{}{
			// Trust the role to login.
			"BoundIAMPrincipalARNs": []string{arn},
			// Enable fetching the IAM role
			"EnableIAMEntityDetails": true,
			// Make this tag available to the binding rule: `entity_tags.service_name`
			"IAMEntityTags": []string{"service-name"},
			// Point the auth method at the local fake AWS server.
			"STSEndpoint": fakeAws.URL + "/sts",
			"IAMEndpoint": fakeAws.URL + "/iam",
		},
	}, nil)
	require.NoError(t, err)

	_, _, err = consulClient.ACL().BindingRuleCreate(&api.ACLBindingRule{
		AuthMethod: method.Name,
		BindType:   api.BindingRuleBindTypeService,
		// Pull the service name from the IAM role `service-name` tag.
		BindName: "${entity_tags.service-name}",
	}, nil)
	require.NoError(t, err)

	return fakeAws
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
		Notes:   "consul-ecs created and updates this check because the ${containerName} container is essential and has an ECS health check.",
		TTL:     "100000h",
	}
	syncedCheck2 := config.AgentServiceCheck{
		CheckID: fmt.Sprintf("%s-%s-consul-ecs", serviceID, containerName2),
		Name:    "consul ecs synced",
		Notes:   "consul-ecs created and updates this check because the ${containerName} container is essential and has an ECS health check.",
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

	expectedServiceName := "service-name"

	cmd.config.Service.Name = expectedServiceName
	serviceName = cmd.constructServiceName(family)
	require.Equal(t, expectedServiceName, serviceName)
}

func TestConstructLoginCmd(t *testing.T) {
	var (
		taskARN = "arn:aws:ecs:bogus-east-1:123456789:task/test/abcdef"
		meta    = awsutil.ECSTaskMeta{
			Cluster: "my-cluster",
			TaskARN: taskARN,
			Family:  "my-service",
		}
		method     = "test-method"
		tokenFile  = "test-file"
		httpAddr   = "consul.example.com"
		caCertFile = "my-ca-cert.pem"
	)

	cases := map[string]struct {
		config *config.Config
		expCmd []string
	}{
		"defaults": {
			config: &config.Config{
				ConsulHTTPAddr:   httpAddr,
				ConsulCACertFile: caCertFile,
				ConsulLogin: config.ConsulLogin{
					Method:        method,
					IncludeEntity: true, // defaults to true, when parsed from JSON
				},
			},
			expCmd: []string{
				"login", "-type", "aws", "-method", method,
				"-http-addr", httpAddr,
				"-ca-file", caCertFile,
				"-token-sink-file", tokenFile,
				"-meta", "consul.hashicorp.com/task-id=abcdef",
				"-meta", "consul.hashicorp.com/cluster=my-cluster",
				"-aws-region", "bogus-east-1",
				"-aws-auto-bearer-token", "-aws-include-entity",
			},
		},
		"fewest fields": {
			config: &config.Config{
				ConsulLogin: config.ConsulLogin{
					Method:        method,
					IncludeEntity: false,
				},
			},
			expCmd: []string{
				"login", "-type", "aws", "-method", method,
				"-http-addr", "", // unset
				"-ca-file", "",
				"-token-sink-file", tokenFile,
				"-meta", "consul.hashicorp.com/task-id=abcdef",
				"-meta", "consul.hashicorp.com/cluster=my-cluster",
				"-aws-region", "bogus-east-1",
				"-aws-auto-bearer-token",
				// no -aws-include-entity
			},
		},
		"all fields": {
			config: &config.Config{
				ConsulHTTPAddr:   httpAddr,
				ConsulCACertFile: caCertFile,
				ConsulLogin: config.ConsulLogin{
					Method:          method,
					IncludeEntity:   true,
					ExtraLoginFlags: []string{"-aws-server-id-header-value", "abcd"},
				},
			},
			expCmd: []string{
				"login", "-type", "aws", "-method", method,
				"-http-addr", httpAddr,
				"-ca-file", caCertFile,
				"-token-sink-file", tokenFile,
				"-meta", "consul.hashicorp.com/task-id=abcdef",
				"-meta", "consul.hashicorp.com/cluster=my-cluster",
				"-aws-region", "bogus-east-1",
				"-aws-auto-bearer-token", "-aws-include-entity",
				"-aws-server-id-header-value", "abcd",
			},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cmd := &Command{config: c.config}
			loginOpts, err := cmd.constructLoginCmd(tokenFile, meta)
			require.NoError(t, err)
			require.Equal(t, c.expCmd, loginOpts)
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

			tokenCfg := api.DefaultConfig()
			tokenCfg.Token = secretID

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
			err = cmd.waitForTokenReplication(tokenCfg)
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
	if enterpriseFlag() {
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

func enterpriseFlag() bool {
	re := regexp.MustCompile("^-+enterprise$")
	for _, a := range os.Args {
		if re.Match([]byte(strings.ToLower(a))) {
			return true
		}
	}
	return false
}
