package config

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/require"
)

func TestServiceRegistrationToConsulType(t *testing.T) {
	consulType := testServiceRegistration.ToConsulType()
	require.Equal(t, consulType, expectedConsulServiceRegistration)
}

func TestProxyRegistrationToConsulType(t *testing.T) {
	consulType := testProxyRegistration.ToConsulType()
	require.Equal(t, consulType, expectedConsulProxyRegistration)
}

// Test that IncludEntity defaults to true.
func TestConsulLoginIncludeEntity(t *testing.T) {
	cases := map[string]struct {
		extraFields      map[string]interface{}
		expIncludeEntity bool
	}{
		"includeEntity absent": {
			expIncludeEntity: true,
		},
		"includeEntity = null": {
			extraFields: map[string]interface{}{
				"includeEntity": nil,
			},
			expIncludeEntity: true,
		},
		"includeEntity = false": {
			extraFields: map[string]interface{}{
				"includeEntity": false,
			},
			expIncludeEntity: false,
		},
		"includeEntity = true": {
			extraFields: map[string]interface{}{
				"includeEntity": true,
			},
			expIncludeEntity: true,
		},
	}
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			fields := map[string]interface{}{
				"enabled": true,
				"method":  "my-method",
				"meta": map[string]string{
					"tag-1": "val-1",
					"tag-2": "val-2",
				},
				"region":              "bogus-east-1",
				"stsEndpoint":         "https://sts.bogus-east-2.example.com",
				"serverIdHeaderValue": "my.consul.example.com",
			}
			for k, v := range c.extraFields {
				fields[k] = v
			}

			jsonBytes, err := json.Marshal(fields)
			require.NoError(t, err)
			t.Logf("json = %s", string(jsonBytes))

			var login ConsulLogin
			require.NoError(t, json.Unmarshal(jsonBytes, &login))

			t.Logf("parsed = %+v", login)
			require.Equal(t, fields["enabled"], login.Enabled)
			require.Equal(t, fields["method"], login.Method)
			require.Equal(t, fields["meta"], login.Meta)
			require.Equal(t, fields["region"], login.Region)
			require.Equal(t, fields["stsEndpoint"], login.STSEndpoint)
			require.Equal(t, fields["serverIdHeaderValue"], login.ServerIDHeaderValue)
			require.Equal(t, c.expIncludeEntity, login.IncludeEntity)
		})
	}

}

var (
	testCheck = AgentServiceCheck{
		CheckID:  "check-1",
		Name:     "test-check",
		Args:     []string{"x", "y"},
		Interval: "30s",
		Timeout:  "5s",
		TTL:      "30s",
		HTTP:     "http://localhost:5000/health",
		Header: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Method:                 "POST",
		Body:                   `{"data": "abc123"}"`,
		TCP:                    "localhost:5000",
		Status:                 "204",
		Notes:                  "A test check",
		TLSServerName:          "test.example.com",
		TLSSkipVerify:          true,
		GRPC:                   "127.0.0.1:5000",
		GRPCUseTLS:             true,
		H2PPING:                "localhost:2222",
		H2PingUseTLS:           true,
		AliasNode:              "node-1",
		AliasService:           "service-1",
		SuccessBeforePassing:   5,
		FailuresBeforeCritical: 3,
	}

	expectedConsulCheck = &api.AgentServiceCheck{
		CheckID:           "check-1",
		Name:              "test-check",
		Args:              []string{"x", "y"},
		DockerContainerID: "",
		Shell:             "",
		Interval:          "30s",
		Timeout:           "5s",
		TTL:               "30s",
		HTTP:              "http://localhost:5000/health",
		Header: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Method:                 "POST",
		Body:                   `{"data": "abc123"}"`,
		TCP:                    "localhost:5000",
		Status:                 "204",
		Notes:                  "A test check",
		TLSServerName:          "test.example.com",
		TLSSkipVerify:          true,
		GRPC:                   "127.0.0.1:5000",
		GRPCUseTLS:             true,
		H2PING:                 "localhost:2222",
		H2PingUseTLS:           true,
		AliasNode:              "node-1",
		AliasService:           "service-1",
		SuccessBeforePassing:   5,
		FailuresBeforeCritical: 3,
	}

	testServiceRegistration = ServiceRegistration{
		Name:              "service-1",
		Tags:              []string{"tag1", "tag2"},
		Port:              1234,
		EnableTagOverride: true,
		Meta:              map[string]string{"env": "test", "version": "x.y.z"},
		Weights: &AgentWeights{
			Passing: 3,
			Warning: 2,
		},
		Checks:    []AgentServiceCheck{testCheck},
		Namespace: "test-ns",
		Partition: "test-partition",
	}

	expectedConsulServiceRegistration = &api.AgentServiceRegistration{
		Kind:              "",
		ID:                "",
		Name:              "service-1",
		Tags:              []string{"tag1", "tag2"},
		Port:              1234,
		Address:           "",
		SocketPath:        "",
		TaggedAddresses:   nil,
		EnableTagOverride: true,
		Meta:              map[string]string{"env": "test", "version": "x.y.z"},
		Weights: &api.AgentWeights{
			Passing: 3,
			Warning: 2,
		},
		Check:     nil,
		Checks:    api.AgentServiceChecks{expectedConsulCheck},
		Proxy:     nil,
		Connect:   nil,
		Namespace: "test-ns",
		Partition: "test-partition",
	}

	testProxyRegistration = &AgentServiceConnectProxyConfig{
		Config: map[string]interface{}{
			"data": "some-test-data",
		},
		Upstreams: []Upstream{
			{
				DestinationType:      api.UpstreamDestTypeService,
				DestinationNamespace: "test-ns-2",
				DestinationPartition: "test-partition-2",
				DestinationName:      "upstream-svc",
				Datacenter:           "dc2",
				LocalBindAddress:     "localhost",
				LocalBindPort:        1235,
				Config: map[string]interface{}{
					"data": "some-upstream-test-data",
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
					ListenerPort:  2345,
					Path:          "/test",
					LocalPathPort: 2346,
					Protocol:      "http",
				},
			},
		},
	}

	expectedConsulProxyRegistration = &api.AgentServiceConnectProxyConfig{
		DestinationServiceName: "",
		DestinationServiceID:   "",
		LocalServiceAddress:    "",
		LocalServicePort:       0,
		LocalServiceSocketPath: "",
		Config: map[string]interface{}{
			"data": "some-test-data",
		},
		Upstreams: []api.Upstream{
			{
				DestinationType:      api.UpstreamDestTypeService,
				DestinationNamespace: "test-ns-2",
				DestinationPartition: "test-partition-2",
				DestinationName:      "upstream-svc",
				Datacenter:           "dc2",
				LocalBindAddress:     "localhost",
				LocalBindPort:        1235,
				LocalBindSocketPath:  "",
				LocalBindSocketMode:  "",
				Config: map[string]interface{}{
					"data": "some-upstream-test-data",
				},
				MeshGateway: api.MeshGatewayConfig{
					Mode: api.MeshGatewayModeLocal,
				},
			},
		},
		MeshGateway: api.MeshGatewayConfig{
			Mode: api.MeshGatewayModeLocal,
		},
		Expose: api.ExposeConfig{
			Checks: true,
			Paths: []api.ExposePath{
				{
					ListenerPort:  2345,
					Path:          "/test",
					LocalPathPort: 2346,
					Protocol:      "http",
				},
			},
		},
	}
)
