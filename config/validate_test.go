package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	cases := map[string]struct {
		filename       string
		expectedConfig *Config
	}{
		"basic_config": {
			filename:       "resources/test_config.json",
			expectedConfig: expectedConfig,
		},
		"extensive_config": {
			filename:       "resources/test_extensive_config.json",
			expectedConfig: expectedExtensiveConfig,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rawConfig := OpenFile(t, c.filename)
			parsedConfig, err := parse(rawConfig)
			require.NoError(t, err)
			require.Equal(t, c.expectedConfig, parsedConfig)
		})
	}
}

func TestParseErrors(t *testing.T) {
	rawConfig := OpenFile(t, "resources/test_config_missing_fields.json")
	_, err := parse(rawConfig)
	require.Error(t, err)

	expectedErrors := []string{
		"mesh.bootstrapDir: String length must be greater than or equal to 1",
		"aclTokenSecret: provider is required",
	}
	require.Contains(t, err.Error(), fmt.Sprintf("%d errors occurred:", len(expectedErrors)))
	for _, expError := range expectedErrors {
		require.Contains(t, err.Error(), expError)
	}
}

func TestFromEnv(t *testing.T) {
	rawConfig := OpenFile(t, "resources/test_config.json")
	err := os.Setenv(ConfigEnvironmentVariable, rawConfig)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := os.Unsetenv(ConfigEnvironmentVariable)
		require.NoError(t, err)
	})

	parsedConfig, err := FromEnv()
	require.NoError(t, err)
	require.Equal(t, expectedConfig, parsedConfig)
}

func OpenFile(t *testing.T, path string) string {
	byteFile, err := ioutil.ReadFile(path)
	require.NoError(t, err)
	return string(byteFile)
}

var (
	expectedConfig = &Config{
		Secret: AclTokenSecret{
			Provider: "secrets-manager",
			Configuration: SecretConfiguration{
				Prefix:                     "asdf",
				ConsulClientTokenSecretARN: "ARN",
			},
		},
		Mesh: Mesh{
			Service: ServiceRegistration{
				Name: "blah",
				Port: 1234,
				Tags: []string{"tag1"},
				Meta: map[string]string{"a": "1"},
			},
			Proxy: &AgentServiceConnectProxyConfig{
				Upstreams: []Upstream{
					{
						DestinationName: "asdf",
						LocalBindPort:   543,
					},
				},
			},
			HealthSyncContainers: []string{"container1"},
			BootstrapDir:         "/consul/",
		},
	}

	expectedExtensiveConfig = &Config{
		Secret: AclTokenSecret{
			Provider: "secrets-manager",
			Configuration: SecretConfiguration{
				Prefix:                     "abc123",
				ConsulClientTokenSecretARN: "some-long-arn",
			},
		},
		Mesh: Mesh{
			BootstrapDir:         "/consul/",
			HealthSyncContainers: []string{"frontend"},
			Service: ServiceRegistration{
				Name:              "frontend",
				Tags:              []string{"frontend"},
				Port:              8080,
				EnableTagOverride: true,
				Meta: map[string]string{
					"env":     "test",
					"version": "x.y.z",
				},
				Weights: &AgentWeights{
					Passing: 6,
					Warning: 5,
				},
				Checks: []AgentServiceCheck{
					{
						CheckID: "frontend-http",
						Name:    "frontend-http",
						HTTP:    "http://localhost:8080/health",
						Method:  "POST",
						Body:    "{\"method\": \"health\"}",
						Notes:   "Health check for the frontend service",
						Header: map[string][]string{
							"Content-Type": {"application/json"},
						},
						Interval:               "30s",
						Timeout:                "10s",
						SuccessBeforePassing:   3,
						FailuresBeforeCritical: 4,
					},
					{
						CheckID:  "frontend-tcp",
						Name:     "frontend-tcp",
						TCP:      "localhost:8080",
						Interval: "15s",
						Timeout:  "5s",
					},
					{
						CheckID:    "frontend-grpc",
						Name:       "frontend-grpc",
						GRPC:       "localhost:8080",
						GRPCUseTLS: true,
						Interval:   "20s",
						Timeout:    "5s",
					},
					{
						CheckID: "frontend-ttl",
						Name:    "frontend-ttl",
						TTL:     "10m",
						Status:  "passing",
					},
					// TODO: api.AgentServiceCheck has no H2Ping field (in v1.10.1)
					// 		 Looks like it's been added to the api package on Consul main,
					// 		 so should come in a future release.
					//{
					//	CheckID:       "frontend-http2",
					//	Name:          "frontend-http2",
					//	TLSSkipVerify: true,
					//	Interval:      "25s",
					//	Timeout:       "5s",
					//},
					{
						CheckID:      "frontend-backend-alias",
						Name:         "frontend-backend-alias",
						AliasNode:    "backend-node",
						AliasService: "backend",
					},
				},
				Namespace: "test-ns",
			},
			Proxy: &AgentServiceConnectProxyConfig{
				Config: map[string]interface{}{
					"data": "some-config-data",
				},
				Upstreams: []Upstream{
					{
						DestinationType:      api.UpstreamDestTypeService,
						DestinationNamespace: "test-ns",
						DestinationName:      "backend",
						Datacenter:           "dc2",
						LocalBindAddress:     "localhost",
						LocalBindPort:        1234,
						Config: map[string]interface{}{
							"data": "some-upstream-config-data",
						},
						MeshGateway: MeshGatewayConfig{
							Mode: api.MeshGatewayModeLocal,
						},
					},
				},
				MeshGateway: MeshGatewayConfig{
					Mode: api.MeshGatewayModeLocal,
				},
				Expose: ExposeConfig{
					Checks: true,
					Paths: []ExposePath{
						{
							ListenerPort:  20001,
							Path:          "/things",
							LocalPathPort: 8080,
							Protocol:      "http2",
						},
					},
				},
			},
		},
	}
)
