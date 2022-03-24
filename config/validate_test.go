package config

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
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
		"null_top_level_fields": {
			filename:       "resources/test_config_null_top_level_fields.json",
			expectedConfig: expectedConfigNullTopLevelFields,
		},
		"null_proxy_and_service_fields": {
			filename:       "resources/test_config_null_proxy_and_service_fields.json",
			expectedConfig: expectedConfigNullProxyAndServiceFields,
		},
		"empty_fields": {
			filename:       "resources/test_config_empty_fields.json",
			expectedConfig: expectedConfigEmptyFields,
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

func TestMetaSchemaValidation(t *testing.T) {
	// Validate that our schema adheres to the JSON Schema spec.
	// gojsonschema embeds the meta-schema document, so no HTTP requests needed.
	loader := gojsonschema.NewSchemaLoader()
	loader.Validate = true
	err := loader.AddSchemas(gojsonschema.NewStringLoader(Schema))
	require.NoError(t, err)
}

func TestParseErrors(t *testing.T) {
	rawConfig := OpenFile(t, "resources/test_config_missing_fields.json")
	_, err := parse(rawConfig)
	require.Error(t, err)

	expectedErrors := []string{
		"bootstrapDir: String length must be greater than or equal to 1",
		"(root): service is required",
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
	byteFile, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(byteFile)
}

var (
	expectedConfig = &Config{
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
	}

	expectedExtensiveConfig = &Config{
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
				{
					CheckID:      "frontend-h2ping",
					Name:         "frontend-h2ping",
					H2PPING:      "localhost:2222",
					H2PingUseTLS: true,
					Interval:     "30s",
					Timeout:      "9s",
				},
				{
					CheckID:      "frontend-backend-alias",
					Name:         "frontend-backend-alias",
					AliasNode:    "backend-node",
					AliasService: "backend",
				},
			},
			Namespace: "test-ns",
			Partition: "test-partition",
		},
		Proxy: &AgentServiceConnectProxyConfig{
			Config: map[string]interface{}{
				"data": "some-config-data",
			},
			Upstreams: []Upstream{
				{
					DestinationType:      api.UpstreamDestTypeService,
					DestinationNamespace: "test-ns",
					DestinationPartition: "test-partition",
					DestinationName:      "backend",
					Datacenter:           "dc2",
					LocalBindAddress:     "localhost",
					LocalBindPort:        1234,
					Config: map[string]interface{}{
						"data": "some-upstream-config-data",
					},
					MeshGateway: &MeshGatewayConfig{
						Mode: api.MeshGatewayModeLocal,
					},
				},
			},
			MeshGateway: &MeshGatewayConfig{
				Mode: api.MeshGatewayModeLocal,
			},
			Expose: &ExposeConfig{
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
	}

	expectedConfigNullTopLevelFields = &Config{
		BootstrapDir:         "/consul/",
		HealthSyncContainers: nil,
		Service: ServiceRegistration{
			Name:              "",
			Tags:              nil,
			Port:              9000,
			EnableTagOverride: false,
			Meta:              nil,
			Weights:           nil,
			Checks:            nil,
			Namespace:         "",
			Partition:         "",
		},
		Proxy: nil,
	}

	expectedConfigNullProxyAndServiceFields = &Config{
		BootstrapDir:         "/consul/",
		HealthSyncContainers: nil,
		Service: ServiceRegistration{
			Name:              "",
			Tags:              nil,
			Port:              9000,
			EnableTagOverride: false,
			Meta:              nil,
			Weights:           nil,
			Checks: []AgentServiceCheck{
				{
					CheckID:                "",
					Name:                   "check-null",
					Args:                   nil,
					Interval:               "",
					Timeout:                "",
					TTL:                    "",
					HTTP:                   "",
					Header:                 nil,
					Method:                 "",
					Body:                   "",
					TCP:                    "",
					Status:                 "",
					Notes:                  "",
					TLSServerName:          "",
					TLSSkipVerify:          false,
					GRPC:                   "",
					GRPCUseTLS:             false,
					H2PPING:                "",
					H2PingUseTLS:           false,
					AliasNode:              "",
					AliasService:           "",
					SuccessBeforePassing:   0,
					FailuresBeforeCritical: 0,
				},
			},
			Namespace: "",
			Partition: "",
		},
		Proxy: &AgentServiceConnectProxyConfig{
			Config: nil,
			Upstreams: []Upstream{
				{
					DestinationType:      "",
					DestinationNamespace: "",
					DestinationPartition: "",
					DestinationName:      "backend",
					Datacenter:           "",
					LocalBindAddress:     "",
					LocalBindPort:        2345,
					Config:               nil,
					MeshGateway:          nil,
				},
			},
			MeshGateway: nil,
			Expose:      nil,
		},
	}

	expectedConfigEmptyFields = &Config{
		BootstrapDir:         "/consul/",
		HealthSyncContainers: []string{},
		Service: ServiceRegistration{
			Name:              "",
			Tags:              []string{},
			Port:              9000,
			EnableTagOverride: false,
			Meta:              map[string]string{},
			Weights:           nil,
			Checks:            []AgentServiceCheck{},
			Namespace:         "",
			Partition:         "",
		},
		Proxy: &AgentServiceConnectProxyConfig{
			Config:      nil,
			Upstreams:   nil,
			MeshGateway: nil,
			Expose:      nil,
		},
	}
)
