package meshinit

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestConfigValidation(t *testing.T) {
	ui := cli.NewMockUi()
	cmd := Command{UI: ui}
	code := cmd.Run(nil)
	require.Equal(t, code, 1)
	require.Contains(t, ui.ErrorWriter.String(),
		fmt.Sprintf(`invalid config: "%s" isn't populated`, config.ConfigEnvironmentVariable))

	err := os.Setenv(config.ConfigEnvironmentVariable, "{}")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Unsetenv(config.ConfigEnvironmentVariable)
	})

	ui = cli.NewMockUi()
	cmd = Command{UI: ui}
	code = cmd.Run(nil)
	require.Equal(t, code, 1)
	require.Contains(t, ui.ErrorWriter.String(), "invalid config: 2 errors occurred:")

}

// Note: this test cannot currently run in parallel with other tests
// because it sets environment variables (e.g. ECS metadata URI and Consul's HTTP addr)
// that could not be shared if another test were to run in parallel.
func TestRun(t *testing.T) {
	family := "family-service-name"
	serviceName := "service-name"

	cases := map[string]struct {
		servicePort       int
		upstreams         []api.Upstream
		expUpstreams      []api.Upstream
		checks            api.AgentServiceChecks
		tags              []string
		expTags           []string
		additionalMeta    map[string]string
		expAdditionalMeta map[string]string
		serviceName       string
		expServiceName    string
	}{
		"basic service": {},
		"service with port": {
			servicePort: 8080,
		},
		"service with upstreams": {
			upstreams: []api.Upstream{
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
			checks: api.AgentServiceChecks{
				&api.AgentServiceCheck{
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
				&api.AgentServiceCheck{
					CheckID:  "api-tcp",
					Name:     "TCP on port 8080",
					TCP:      "localhost:8080",
					Interval: "10s",
					Timeout:  "5s",
					Notes:    "unittest tcp check",
				},
				&api.AgentServiceCheck{
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
			)

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

			// Set up Consul server.
			server, err := testutil.NewTestServerConfigT(t, nil)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = server.Stop()
				_ = os.Unsetenv("CONSUL_HTTP_ADDR")
			})
			server.WaitForLeader(t)
			consulClient, err := api.NewClient(&api.Config{Address: server.HTTPAddr})
			require.NoError(t, err)
			// We need to set this so that consul connect envoy -bootstrap will talk to the right agent.
			err = os.Setenv("CONSUL_HTTP_ADDR", server.HTTPAddr)
			require.NoError(t, err)

			// Set up ECS container metadata server.
			taskMetadataResponse := fmt.Sprintf(`{"Cluster": "test", "TaskARN": "%s", "Family": "%s"}`, taskARN, family)
			ecsMetadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r != nil && r.URL.Path == "/task" && r.Method == "GET" {
					_, err := w.Write([]byte(taskMetadataResponse))
					require.NoError(t, err)
				}
			}))
			err = os.Setenv(awsutil.ECSMetadataURIEnvVar, ecsMetadataServer.URL)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = os.Unsetenv(awsutil.ECSMetadataURIEnvVar)
				ecsMetadataServer.Close()
			})

			ui := cli.NewMockUi()
			cmd := Command{UI: ui}

			envoyBootstrapDir, err := ioutil.TempDir("", "")
			require.NoError(t, err)
			envoyBootstrapFile := path.Join(envoyBootstrapDir, envoyBoostrapConfigFilename)
			copyConsulECSBinary := path.Join(envoyBootstrapDir, "consul-ecs")

			t.Cleanup(func() {
				os.Remove(envoyBootstrapFile)
				os.Remove(copyConsulECSBinary)
				err := os.Remove(envoyBootstrapDir)
				if err != nil {
					t.Logf("warning, failed to cleanup temp dir %s - %s", envoyBootstrapDir, err)
				}
			})

			consulEcsConfig := config.Config{
				Secret: config.Secret{
					Provider: "secret-manager",
					Configuration: config.SecretConfiguration{
						Prefix:                     "mesh-init-unittest-TestRun",
						ConsulClientTokenSecretARN: "asdf",
					},
				},
				Mesh: config.Mesh{
					BootstrapDir:         envoyBootstrapDir,
					HealthSyncContainers: nil,
					Sidecar: config.Sidecar{
						Proxy: config.SidecarProxy{
							Upstreams: c.upstreams,
						},
					},
					Service: config.Service{
						Name:   c.serviceName,
						Checks: c.checks,
						Port:   c.servicePort,
						Tags:   c.tags,
						Meta:   c.additionalMeta,
					},
				},
			}

			configBytes, err := json.MarshalIndent(consulEcsConfig, "", "  ")
			require.NoError(t, err)

			err = os.Setenv(config.ConfigEnvironmentVariable, string(configBytes))
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = os.Unsetenv(config.ConfigEnvironmentVariable)
			})

			t.Logf("%s=%s", config.ConfigEnvironmentVariable, os.Getenv(config.ConfigEnvironmentVariable))

			code := cmd.Run(nil)
			require.Equal(t, code, 0, ui.ErrorWriter.String())

			expServiceID := fmt.Sprintf("%s-abcdef", expectedServiceName)
			expSidecarServiceID := fmt.Sprintf("%s-abcdef-sidecar-proxy", expectedServiceName)

			expectedServiceRegistration := &api.AgentService{
				ID:      expServiceID,
				Service: expectedServiceName,
				Port:    c.servicePort,
				Meta:    expectedTaskMeta,
				Tags:    expectedTags,
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
				Meta: expectedTaskMeta,
				Tags: expectedTags,
			}

			agentServiceIgnoreFields := cmpopts.IgnoreFields(api.AgentService{},
				"Datacenter", "Weights", "ContentHash", "ModifyIndex", "CreateIndex")

			service, _, err := consulClient.Agent().Service(expServiceID, nil)
			require.NoError(t, err)
			require.True(t, cmp.Equal(expectedServiceRegistration, service, agentServiceIgnoreFields))

			proxyService, _, err := consulClient.Agent().Service(expSidecarServiceID, nil)
			require.NoError(t, err)
			require.True(t, cmp.Equal(expectedProxyServiceRegistration, proxyService, agentServiceIgnoreFields))

			envoyBootstrapContents, err := ioutil.ReadFile(envoyBootstrapFile)
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
						cmpopts.IgnoreFields(api.AgentCheck{}, "Node", "Output", "ExposedPort", "Definition", "Namespace")))
				}
			}
		})
	}
}

func TestConstructChecks(t *testing.T) {
	// Bunch of test data.
	serviceID := "serviceID"
	containerName1 := "containerName1"
	containerName2 := "containerName2"

	httpCheck := &api.AgentServiceCheck{
		CheckID:  "check-1",
		Name:     "HTTP on port 8080",
		HTTP:     "http://localhost:8080",
		Interval: "20s",
		Timeout:  "10s",
		Header:   map[string][]string{"Content-type": {"application/json"}},
		Method:   "GET",
		Notes:    "unittest http check",
	}
	tcpCheck := &api.AgentServiceCheck{
		CheckID:  "check-2",
		Name:     "TCP on port 8080",
		TCP:      "localhost:8080",
		Interval: "10s",
		Timeout:  "5s",
		Notes:    "unittest tcp check",
	}
	syncedCheck1 := &api.AgentServiceCheck{
		CheckID: fmt.Sprintf("%s-%s-consul-ecs", serviceID, containerName1),
		Name:    "consul ecs synced",
		Notes:   "consul-ecs created and updates this check because the ${containerName} container is essential and has an ECS health check.",
		TTL:     "100000h",
	}
	syncedCheck2 := &api.AgentServiceCheck{
		CheckID: fmt.Sprintf("%s-%s-consul-ecs", serviceID, containerName2),
		Name:    "consul ecs synced",
		Notes:   "consul-ecs created and updates this check because the ${containerName} container is essential and has an ECS health check.",
		TTL:     "100000h",
	}

	cases := map[string]struct {
		checks               api.AgentServiceChecks
		healthSyncContainers []string
		expError             string
		expChecks            api.AgentServiceChecks
	}{
		"0-checks-0-health-sync-containers": {},
		"1-check-0-health-sync-containers": {
			checks:    api.AgentServiceChecks{httpCheck},
			expChecks: api.AgentServiceChecks{httpCheck},
		},
		"2-checks-0-health-sync-containers": {
			checks:    api.AgentServiceChecks{httpCheck, tcpCheck},
			expChecks: api.AgentServiceChecks{httpCheck, tcpCheck},
		},
		"1-check-1-health-sync-containers-should-error": {
			checks:               api.AgentServiceChecks{httpCheck},
			healthSyncContainers: []string{containerName1},
			expError:             fmt.Sprint("only one of mesh.checks or mesh.healthSyncContainers should be set"),
		},
		"0-checks-1-health-sync-containers": {
			healthSyncContainers: []string{containerName1},
			expChecks:            api.AgentServiceChecks{syncedCheck1},
		},
		"0-checks-2-health-sync-containers": {
			healthSyncContainers: []string{containerName1, containerName2},
			expChecks:            api.AgentServiceChecks{syncedCheck1, syncedCheck2},
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

	cmd.config.Mesh.Service.Name = expectedServiceName
	serviceName = cmd.constructServiceName(family)
	require.Equal(t, expectedServiceName, serviceName)
}

// toAgentCheck translates the request type (AgentServiceCheck) into an "expected"
// response type (AgentCheck) which we can use in assertions.
func toAgentCheck(check *api.AgentServiceCheck) *api.AgentCheck {
	expInterval, _ := time.ParseDuration(check.Interval)
	expTimeout, _ := time.ParseDuration(check.Timeout)
	expDeregisterCriticalAfter, _ := time.ParseDuration(check.DeregisterCriticalServiceAfter)
	return &api.AgentCheck{
		CheckID: check.CheckID,
		Name:    check.Name,
		Notes:   check.Notes,
		Definition: api.HealthCheckDefinition{
			// HealthCheckDefinition does not have GRPC or TTL fields.
			HTTP:                                   check.HTTP,
			Header:                                 check.Header,
			Method:                                 check.HTTP,
			Body:                                   check.Body,
			TLSServerName:                          check.TLSServerName,
			TLSSkipVerify:                          check.TLSSkipVerify,
			TCP:                                    check.TCP,
			IntervalDuration:                       expInterval,
			TimeoutDuration:                        expTimeout,
			DeregisterCriticalServiceAfterDuration: expDeregisterCriticalAfter,
			Interval:                               api.ReadableDuration(expInterval),
			Timeout:                                api.ReadableDuration(expTimeout),
			DeregisterCriticalServiceAfter:         api.ReadableDuration(expDeregisterCriticalAfter),
		},
	}
}
