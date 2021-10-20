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
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestFlagValidation(t *testing.T) {
	ui := cli.NewMockUi()
	cmd := Command{
		UI: ui,
	}
	code := cmd.Run(nil)
	require.Equal(t, code, 1)
	require.Contains(t, ui.ErrorWriter.String(), "-envoy-bootstrap-file must be set")
}

// Note: this test cannot currently run in parallel with other tests
// because it sets environment variables (e.g. ECS metadata URI and Consul's HTTP addr)
// that could not be shared if another test were to run in parallel.
func TestRun(t *testing.T) {
	cases := map[string]struct {
		servicePort  int
		upstreams    string
		expUpstreams []api.Upstream
		checks       api.AgentServiceChecks
	}{
		"basic service": {},
		"service with port": {
			servicePort: 8080,
		},
		"service with upstreams": {
			upstreams: "upstream1:1234,upstream2:1235",
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
			)

			// Set up Consul server.
			server, err := testutil.NewTestServerConfigT(t, nil)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = server.Stop()
				os.Unsetenv("CONSUL_HTTP_ADDR")
			})
			server.WaitForLeader(t)
			consulClient, err := api.NewClient(&api.Config{Address: server.HTTPAddr})
			require.NoError(t, err)
			// We need to set this so that consul connect envoy -bootstrap will talk to the right agent.
			os.Setenv("CONSUL_HTTP_ADDR", server.HTTPAddr)

			// Set up ECS container metadata server.
			taskMetadataResponse := fmt.Sprintf(`{"Cluster": "test", "TaskARN": "%s", "Family": "test-service"}`, taskARN)
			ecsMetadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r != nil && r.URL.Path == "/task" && r.Method == "GET" {
					_, err := w.Write([]byte(taskMetadataResponse))
					require.NoError(t, err)
				}
			}))
			os.Setenv(awsutil.ECSMetadataURIEnvVar, ecsMetadataServer.URL)
			t.Cleanup(func() {
				os.Unsetenv(awsutil.ECSMetadataURIEnvVar)
				ecsMetadataServer.Close()
			})

			ui := cli.NewMockUi()
			cmd := Command{
				UI: ui,
			}

			envoyBootstrapDir, err := ioutil.TempDir("", "")
			require.NoError(t, err)
			envoyBootstrapFile := path.Join(envoyBootstrapDir, "envoy.yaml")
			copyConsulEcsFile := path.Join(envoyBootstrapDir, "consul-ecs")

			t.Cleanup(func() {
				os.Remove(envoyBootstrapFile)
				os.Remove(copyConsulEcsFile)
				err := os.Remove(envoyBootstrapDir)
				if err != nil {
					t.Logf("warning, failed to cleanup temp dir %s - %s", envoyBootstrapDir, err)
				}
			})

			cmdArgs := []string{"-envoy-bootstrap-file", envoyBootstrapFile}
			if c.servicePort != 0 {
				cmdArgs = append(cmdArgs, "-port", fmt.Sprintf("%d", c.servicePort))
			}
			if c.upstreams != "" {
				cmdArgs = append(cmdArgs, "-upstreams", c.upstreams)
			}
			if c.checks != nil {
				healthCheckBytes, err := json.Marshal(c.checks)
				require.NoError(t, err)
				cmdArgs = append(cmdArgs, "-checks", string(healthCheckBytes))
			}
			code := cmd.Run(cmdArgs)
			require.Equal(t, code, 0)

			expectedServiceRegistration := &api.AgentService{
				ID:      "test-service-abcdef",
				Service: "test-service",
				Port:    c.servicePort,
				Meta:    expectedTaskMeta,
			}

			expectedProxyServiceRegistration := &api.AgentService{
				ID:      "test-service-abcdef-sidecar-proxy",
				Service: "test-service-sidecar-proxy",
				Port:    20000,
				Kind:    api.ServiceKindConnectProxy,
				Proxy: &api.AgentServiceConnectProxyConfig{
					DestinationServiceName: "test-service",
					DestinationServiceID:   "test-service-abcdef",
					LocalServicePort:       c.servicePort,
					Upstreams:              c.expUpstreams,
				},
				Meta: expectedTaskMeta,
			}

			agentServiceIgnoreFields := cmpopts.IgnoreFields(api.AgentService{},
				"Datacenter", "Tags", "Weights", "ContentHash", "ModifyIndex", "CreateIndex")

			service, _, err := consulClient.Agent().Service("test-service-abcdef", nil)
			require.NoError(t, err)
			require.True(t, cmp.Equal(expectedServiceRegistration, service, agentServiceIgnoreFields))

			proxyService, _, err := consulClient.Agent().Service("test-service-abcdef-sidecar-proxy", nil)
			require.NoError(t, err)
			require.True(t, cmp.Equal(expectedProxyServiceRegistration, proxyService, agentServiceIgnoreFields))

			envoyBootstrapContents, err := ioutil.ReadFile(envoyBootstrapFile)
			require.NoError(t, err)
			require.NotEmpty(t, envoyBootstrapContents)

			copyConsulEcsStat, err := os.Stat(copyConsulEcsFile)
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
	serviceID := "serviceID"

	_, err := constructChecks(serviceID, "asdf", "asdf")
	require.Error(t, err)

	argChecks := api.AgentServiceChecks{
		&api.AgentServiceCheck{
			CheckID:  "check-1",
			Name:     "HTTP on port 8080",
			HTTP:     "http://localhost:8080",
			Interval: "20s",
			Timeout:  "10s",
			Header:   map[string][]string{"Content-type": {"application/json"}},
			Method:   "GET",
			Notes:    "unittest http check",
		},
		&api.AgentServiceCheck{
			CheckID:  "check-2",
			Name:     "TCP on port 8080",
			TCP:      "localhost:8080",
			Interval: "10s",
			Timeout:  "5s",
			Notes:    "unittest tcp check",
		},
		&api.AgentServiceCheck{
			CheckID:    "check-3",
			Name:       "GRPC on port 8081",
			GRPC:       "localhost:8081",
			GRPCUseTLS: false,
			Interval:   "30s",
			Notes:      "unittest grpc check",
		},
	}
	encodedChecks, err := json.Marshal(argChecks)
	require.NoError(t, err)

	checks, err := constructChecks(serviceID, string(encodedChecks), "")
	require.NoError(t, err)
	require.Equal(t, argChecks, checks)

	containerName1 := "containerName1"
	containerName2 := "containerName2"
	expectedChecks := api.AgentServiceChecks{
		&api.AgentServiceCheck{
			CheckID: fmt.Sprintf("%s-%s-consul-ecs", serviceID, containerName1),
			Name:    "consul ecs synced",
			Notes:   "consul-ecs created and updates this check because the ${containerName} container is essential and has an ECS health check.",
			TTL:     "100000h",
		},
		&api.AgentServiceCheck{
			CheckID: fmt.Sprintf("%s-%s-consul-ecs", serviceID, containerName2),
			Name:    "consul ecs synced",
			Notes:   "consul-ecs created and updates this check because the ${containerName} container is essential and has an ECS health check.",
			TTL:     "100000h",
		},
	}

	checks, err = constructChecks(serviceID, "", fmt.Sprintf("%s,%s", containerName1, containerName2))
	require.NoError(t, err)
	require.Equal(t, expectedChecks, checks)

	expectedChecks = api.AgentServiceChecks{
		&api.AgentServiceCheck{
			CheckID: fmt.Sprintf("%s-%s-consul-ecs", serviceID, containerName1),
			Name:    "consul ecs synced",
			Notes:   "consul-ecs created and updates this check because the ${containerName} container is essential and has an ECS health check.",
			TTL:     "100000h",
		},
	}
	checks, err = constructChecks(serviceID, "[]", containerName1)
	require.NoError(t, err)
	require.Equal(t, expectedChecks, checks)
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
