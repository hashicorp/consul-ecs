// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
		"null_nested_fields": {
			filename:       "resources/test_config_null_nested_fields.json",
			expectedConfig: expectedConfigNullNestedFields,
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
	cases := map[string]struct {
		filename       string
		expectedErrors []string
	}{
		"missing_fields": {
			filename: "resources/test_config_missing_fields.json",
			expectedErrors: []string{
				"bootstrapDir: String length must be greater than or equal to 1",
			},
		},
		"uppercase_service_names": {
			filename: "resources/test_config_uppercase_service_names.json",
			expectedErrors: []string{
				"gateway.name: Does not match pattern",
				"service.name: Does not match pattern",
			},
		},
	}
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			rawConfig := OpenFile(t, c.filename)
			_, err := parse(rawConfig)
			require.Error(t, err)

			msg := "%d errors occurred:"
			if len(c.expectedErrors) == 1 {
				msg = "%d error occurred:"
			}

			require.Contains(t, err.Error(), fmt.Sprintf(msg, len(c.expectedErrors)))
			for _, expError := range c.expectedErrors {
				require.Contains(t, err.Error(), expError)
			}
		})
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
		LogLevel: "",
		ConsulLogin: ConsulLogin{
			Enabled: false,
			Method:  "",
			// Because ConsulLogin is not a pointer, when `consulLogin` is absent from
			// the JSON, UnmarshalJSON is not called, so IncludeEntity is not defaulted
			// to `true`. This is okay since if Enabled=false, IncludeEntity is not used.
			IncludeEntity:       false,
			Meta:                nil,
			Region:              "",
			STSEndpoint:         "",
			ServerIDHeaderValue: "",
		},
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
		LogLevel:             "DEBUG",
		ConsulHTTPAddr:       "consul.example.com",
		ConsulCACertFile:     "/consul/consul-ca-cert.pem",
		ConsulLogin: ConsulLogin{
			Enabled:       true,
			Method:        "my-auth-method",
			IncludeEntity: false,
			Meta: map[string]string{
				"tag-1": "val-1",
				"tag-2": "val-2",
			},
			Region:              "bogus-east-2",
			STSEndpoint:         "https://sts.bogus-east-2.example.com",
			ServerIDHeaderValue: "my.consul.example.com",
		},
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
		Gateway: &GatewayRegistration{
			Kind: "mesh-gateway",
			LanAddress: &GatewayAddress{
				Address: "10.0.0.1",
				Port:    8443,
			},
			WanAddress: &GatewayAddress{
				Address: "172.16.0.0",
				Port:    443,
			},
			Name: "ecs-mesh-gateway",
			Tags: []string{"a", "b"},
			Meta: map[string]string{
				"env":     "test",
				"version": "x.y.z",
			},
			Namespace: "ns1",
			Partition: "ptn1",
			Proxy: &GatewayProxyConfig{
				Config: map[string]interface{}{
					"data": "some-config-data",
				},
			},
		},
		Proxy: &AgentServiceConnectProxyConfig{
			Config: map[string]interface{}{
				"data": "some-config-data",
			},
			PublicListenerPort: 21000,
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
		LogLevel:             "",
		ConsulHTTPAddr:       "",
		ConsulCACertFile:     "",
		ConsulLogin: ConsulLogin{
			Enabled:             false,
			Method:              "",
			IncludeEntity:       true,
			Meta:                nil,
			Region:              "",
			STSEndpoint:         "",
			ServerIDHeaderValue: "",
		},
		Gateway: &GatewayRegistration{
			Kind:       "mesh-gateway",
			LanAddress: nil,
			WanAddress: nil,
			Name:       "",
			Tags:       nil,
			Meta:       nil,
			Namespace:  "",
			Partition:  "",
			Proxy:      nil,
		},
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

	expectedConfigNullNestedFields = &Config{
		BootstrapDir:         "/consul/",
		HealthSyncContainers: nil,
		ConsulHTTPAddr:       "",
		ConsulCACertFile:     "",
		ConsulLogin: ConsulLogin{
			Enabled:             false,
			Method:              "",
			IncludeEntity:       true,
			Meta:                nil,
			Region:              "",
			STSEndpoint:         "",
			ServerIDHeaderValue: "",
		},
		Gateway: &GatewayRegistration{
			Kind: "mesh-gateway",
			LanAddress: &GatewayAddress{
				Address: "",
				Port:    0,
			},
			WanAddress: &GatewayAddress{
				Address: "",
				Port:    0,
			},
			Name:      "",
			Tags:      nil,
			Meta:      nil,
			Namespace: "",
			Partition: "",
			Proxy: &GatewayProxyConfig{
				Config: nil,
			},
		},
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
			Config:             nil,
			PublicListenerPort: 0,
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
		ConsulLogin: ConsulLogin{
			Enabled:             false,
			Method:              "",
			IncludeEntity:       true,
			Meta:                nil,
			Region:              "",
			STSEndpoint:         "",
			ServerIDHeaderValue: "",
		},
		Gateway: &GatewayRegistration{
			Kind:       "mesh-gateway",
			LanAddress: &GatewayAddress{},
			WanAddress: &GatewayAddress{},
			Name:       "",
			Tags:       []string{},
			Meta:       map[string]string{},
			Namespace:  "",
			Partition:  "",
			Proxy:      &GatewayProxyConfig{},
		},
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
			Config:             nil,
			PublicListenerPort: 0,
			Upstreams:          nil,
			MeshGateway:        nil,
			Expose:             nil,
		},
	}
)
