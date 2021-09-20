package meshinit

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

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
					CheckID:  "api-http",
					Name:     "HTTP on port 8080",
					HTTP:     "http://localhost:8080",
					Interval: "10s",
					Timeout:  "5s",
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
					Interval:   "10s",
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

			envoyBootstrapFile, err := ioutil.TempFile("", "")
			require.NoError(t, err)
			t.Cleanup(func() {
				os.Remove(envoyBootstrapFile.Name())
			})

			cmdArgs := []string{"-envoy-bootstrap-file", envoyBootstrapFile.Name()}
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
			t.Logf("cmdArgs: %v", cmdArgs)
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

			if c.checks != nil {
				// Validate the check is present
				checks, err := consulClient.Agent().Checks()
				require.NoError(t, err)
				for _, expCheck := range c.checks {
					require.Contains(t, checks, expCheck.CheckID)
				}

				// Ensure health status is "critical".
				// These tests do not start a listening application, so the checks will not pass.
				healthStatus, checksInfo, err := consulClient.Agent().AgentHealthServiceByID(service.ID)
				require.NoError(t, err)
				require.NotNil(t, checksInfo)
				require.Equal(t, healthStatus, api.HealthCritical)
			}

			envoyBootstrapContents, err := ioutil.ReadFile(envoyBootstrapFile.Name())
			require.NoError(t, err)
			require.NotEmpty(t, envoyBootstrapContents)
		})
	}
}
