package config

import (
	"testing"

	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/require"
)

func TestServiceRegistrationToConsulType(t *testing.T) {
	consulType := testServiceRegistration.ToConsulType()
	require.Equal(t, consulType, expectedConsulServiceRegistration)
}

func TestSidecarProxyRegistrationToConsulType(t *testing.T) {
	consulType := testProxyRegistration.ToConsulType()
	require.Equal(t, consulType, expectedConsulProxyRegistration)
}

var (
	testCheck = AgentServiceCheck{
		CheckID:           "check-1",
		Name:              "test-check",
		Args:              []string{"x", "y"},
		DockerContainerID: "0123456789",
		Shell:             "/bin/bash",
		Interval:          "30s",
		Timeout:           "5s",
		TTL:               "30s",
		HTTP:              "http://localhost:5000/health",
		Header: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Method:                         "POST",
		Body:                           `{"data": "abc123"}"`,
		TCP:                            "localhost:5000",
		Status:                         "204",
		Notes:                          "A test check",
		TLSServerName:                  "test.example.com",
		TLSSkipVerify:                  true,
		GRPC:                           "127.0.0.1:5000",
		GRPCUseTLS:                     true,
		AliasNode:                      "node-1",
		AliasService:                   "service-1",
		SuccessBeforePassing:           5,
		FailuresBeforeCritical:         3,
		DeregisterCriticalServiceAfter: "1m",
	}

	expectedConsulCheck = &api.AgentServiceCheck{
		CheckID:           "check-1",
		Name:              "test-check",
		Args:              []string{"x", "y"},
		DockerContainerID: "0123456789",
		Shell:             "/bin/bash",
		Interval:          "30s",
		Timeout:           "5s",
		TTL:               "30s",
		HTTP:              "http://localhost:5000/health",
		Header: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Method:                         "POST",
		Body:                           `{"data": "abc123"}"`,
		TCP:                            "localhost:5000",
		Status:                         "204",
		Notes:                          "A test check",
		TLSServerName:                  "test.example.com",
		TLSSkipVerify:                  true,
		GRPC:                           "127.0.0.1:5000",
		GRPCUseTLS:                     true,
		AliasNode:                      "node-1",
		AliasService:                   "service-1",
		SuccessBeforePassing:           5,
		FailuresBeforeCritical:         3,
		DeregisterCriticalServiceAfter: "1m",
	}

	testServiceRegistration = ServiceRegistration{
		Name:       "service-1",
		Tags:       []string{"tag1", "tag2"},
		Port:       1234,
		Address:    "127.0.0.1",
		SocketPath: "/path/to/socket",
		TaggedAddresses: map[string]ServiceAddress{
			"lan": {
				Address: "10.0.0.1",
				Port:    1234,
			},
		},
		EnableTagOverride: true,
		Meta:              map[string]string{"env": "test", "version": "x.y.z"},
		Weights: &AgentWeights{
			Passing: 3,
			Warning: 2,
		},
		Checks:    []AgentServiceCheck{testCheck},
		Namespace: "test-ns",
	}

	expectedConsulServiceRegistration = &api.AgentServiceRegistration{
		Kind:       "",
		ID:         "",
		Name:       "service-1",
		Tags:       []string{"tag1", "tag2"},
		Port:       1234,
		Address:    "127.0.0.1",
		SocketPath: "/path/to/socket",
		TaggedAddresses: map[string]api.ServiceAddress{
			"lan": {
				Address: "10.0.0.1",
				Port:    1234,
			},
		},
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
	}

	testProxyRegistration = SidecarProxyRegistration{
		TaggedAddresses: map[string]ServiceAddress{
			"lan": {
				Address: "192.168.1.1",
				Port:    1235,
			},
		},
		EnableTagOverride: true,
		Weights: &AgentWeights{
			Passing: 3,
			Warning: 2,
		},
		Checks: []AgentServiceCheck{testCheck},
		Proxy: &AgentServiceConnectProxyConfig{
			DestinationServiceName: "service-1",
			DestinationServiceID:   "service-1-id",
			LocalServiceAddress:    "localhost",
			LocalServicePort:       1234,
			LocalServiceSocketPath: "/path/to/socket",
			Config: map[string]interface{}{
				"data": "some-test-data",
			},
			Upstreams: []Upstream{
				{
					DestinationType:      api.UpstreamDestTypeService,
					DestinationNamespace: "test-ns-2",
					DestinationName:      "upstream-svc",
					Datacenter:           "dc2",
					LocalBindAddress:     "localhost",
					LocalBindPort:        1235,
					LocalBindSocketPath:  "/path/to/socket",
					LocalBindSocketMode:  "0700",
					Config: map[string]interface{}{
						"data": "some-upstream-test-data",
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
						ListenerPort:  2345,
						Path:          "/test",
						LocalPathPort: 2346,
						Protocol:      "http",
					},
				},
			},
		},
	}

	expectedConsulProxyRegistration = &api.AgentServiceRegistration{
		Kind:       "",
		ID:         "",
		Name:       "",
		Tags:       nil,
		Port:       0,
		Address:    "",
		SocketPath: "",
		TaggedAddresses: map[string]api.ServiceAddress{
			"lan": {
				Address: "192.168.1.1",
				Port:    1235,
			},
		},
		EnableTagOverride: true,
		Meta:              nil,
		Weights: &api.AgentWeights{
			Passing: 3,
			Warning: 2,
		},
		Check:  nil,
		Checks: api.AgentServiceChecks{expectedConsulCheck},
		Proxy: &api.AgentServiceConnectProxyConfig{
			DestinationServiceName: "service-1",
			DestinationServiceID:   "service-1-id",
			LocalServiceAddress:    "localhost",
			LocalServicePort:       1234,
			LocalServiceSocketPath: "/path/to/socket",
			Config: map[string]interface{}{
				"data": "some-test-data",
			},
			Upstreams: []api.Upstream{
				{
					DestinationType:      api.UpstreamDestTypeService,
					DestinationNamespace: "test-ns-2",
					DestinationName:      "upstream-svc",
					Datacenter:           "dc2",
					LocalBindAddress:     "localhost",
					LocalBindPort:        1235,
					LocalBindSocketPath:  "/path/to/socket",
					LocalBindSocketMode:  "0700",
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
		},
		Connect:   nil,
		Namespace: "",
	}
)
