package dataplane

import (
	"fmt"
	"testing"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/require"
)

func TestGetDataplaneConfigJSON(t *testing.T) {
	testCases := map[string]struct {
		input        *GetDataplaneConfigJSONInput
		expectedJSON string
	}{
		"Test JSON generation with TLS and Consul login disabled": {
			input: &GetDataplaneConfigJSONInput{
				ProxyRegistration: &api.CatalogRegistration{
					Node: "test-node-name",
					Service: &api.AgentService{
						ID:      "test-side-car-123",
						Service: "test-side-car",
						Port:    1234,
					},
				},
				ConsulServerConfig: config.ConsulServers{
					Hosts:           "consul.dc1",
					GRPCPort:        8503,
					SkipServerWatch: true,
				},
			},
			expectedJSON: `{
				"consul": {
				  "addresses": "consul.dc1",
				  "grpcPort": 8503,
				  "serverWatchDisabled": true
				},
				"service": {
				  "nodeName": "test-node-name",
				  "serviceID": "test-side-car-123",
				  "namespace": "%s",
				  "partition": "%s"
				},
				"logging": {
				  "logLevel": "INFO",
				  "logJSON": false
				},
				"xdsServer": {
				  "bindAddress": "127.0.0.1",
				  "bindPort": 20000
				},
				"envoy": {
				  "adminBindAddress": "127.0.0.1",
				  "adminBindPort": 19000
				},
				"telemetry": {
				  "useCentralConfig": false
				}
			}`,
		},
		"Test JSON generation with TLS enabled": {
			input: &GetDataplaneConfigJSONInput{
				ProxyRegistration: &api.CatalogRegistration{
					Node: "test-node-name",
					Service: &api.AgentService{
						ID:      "test-side-car-123",
						Service: "test-side-car",
						Port:    1234,
					},
				},
				ConsulServerConfig: config.ConsulServers{
					Hosts:           "consul.dc1",
					GRPCPort:        8503,
					SkipServerWatch: true,
					EnableTLS:       true,
					TLSServerName:   "consul.dc1",
					CACertFile:      "/consul/ca-cert.pem",
				},
			},
			expectedJSON: `{
				"consul": {
				  "addresses": "consul.dc1",
				  "grpcPort": 8503,
				  "serverWatchDisabled": true,
				  "tls": {
					"disabled": false,
					"caCertsPath": "/consul/ca-cert.pem",
					"tlsServerName": "consul.dc1"
				  }
				},
				"service": {
				  "nodeName": "test-node-name",
				  "serviceID": "test-side-car-123",
				  "namespace": "%s",
				  "partition": "%s"
				},
				"logging": {
				  "logLevel": "INFO",
				  "logJSON": false
				},
				"xdsServer": {
				  "bindAddress": "127.0.0.1",
				  "bindPort": 20000
				},
				"envoy": {
				  "adminBindAddress": "127.0.0.1",
				  "adminBindPort": 19000
				},
				"telemetry": {
				  "useCentralConfig": false
				}
			}`,
		},
		"Test JSON generation with Consul Login enabled": {
			input: &GetDataplaneConfigJSONInput{
				ProxyRegistration: &api.CatalogRegistration{
					Node: "test-node-name",
					Service: &api.AgentService{
						ID:      "test-side-car-123",
						Service: "test-side-car",
						Port:    1234,
					},
				},
				ConsulServerConfig: config.ConsulServers{
					Hosts:           "consul.dc1",
					GRPCPort:        8502,
					SkipServerWatch: false,
					EnableTLS:       false,
				},
				ConsulToken: "test-token-123",
			},
			expectedJSON: `{
				"consul": {
				  "addresses": "consul.dc1",
				  "grpcPort": 8502,
				  "serverWatchDisabled": false,
				  "credentials": {
					"type": "static",
					"static": {
						"token": "test-token-123"
					}
				  }
				},
				"service": {
				  "nodeName": "test-node-name",
				  "serviceID": "test-side-car-123",
				  "namespace": "%s",
				  "partition": "%s"
				},
				"logging": {
				  "logLevel": "INFO",
				  "logJSON": false
				},
				"xdsServer": {
				  "bindAddress": "127.0.0.1",
				  "bindPort": 20000
				},
				"envoy": {
				  "adminBindAddress": "127.0.0.1",
				  "adminBindPort": 19000
				},
				"telemetry": {
				  "useCentralConfig": false
				}
			}`,
		},
		"Test JSON generation with TLS and Consul Login enabled": {
			input: &GetDataplaneConfigJSONInput{
				ProxyRegistration: &api.CatalogRegistration{
					Node: "test-node-name",
					Service: &api.AgentService{
						ID:      "test-side-car-123",
						Service: "test-side-car",
						Port:    1234,
					},
				},
				ConsulServerConfig: config.ConsulServers{
					Hosts:           "consul.dc1",
					GRPCPort:        8503,
					SkipServerWatch: true,
					EnableTLS:       true,
					TLSServerName:   "consul.dc1",
					CACertFile:      "/consul/ca-cert.pem",
				},
				ConsulToken: "test-token-123",
			},
			expectedJSON: `{
				"consul": {
				  "addresses": "consul.dc1",
				  "grpcPort": 8503,
				  "serverWatchDisabled": true,
				  "tls": {
					"disabled": false,
					"caCertsPath": "/consul/ca-cert.pem",
					"tlsServerName": "consul.dc1"
				  },
				  "credentials": {
					"type": "static",
					"static": {
						"token": "test-token-123"
					}
				  }
				},
				"service": {
				  "nodeName": "test-node-name",
				  "serviceID": "test-side-car-123",
				  "namespace": "%s",
				  "partition": "%s"
				},
				"logging": {
				  "logLevel": "INFO",
				  "logJSON": false
				},
				"xdsServer": {
				  "bindAddress": "127.0.0.1",
				  "bindPort": 20000
				},
				"envoy": {
				  "adminBindAddress": "127.0.0.1",
				  "adminBindPort": 19000
				},
				"telemetry": {
				  "useCentralConfig": false
				}
			}`,
		},
	}

	for name, c := range testCases {
		t.Run(name, func(t *testing.T) {
			namespace := ""
			partition := ""
			if testutil.EnterpriseFlag() {
				namespace = "test-ns"
				partition = "test-par"
			}

			c.input.ProxyRegistration.Service.Namespace = namespace
			c.input.ProxyRegistration.Service.Partition = partition
			c.input.ProxyRegistration.Partition = partition

			expectedJSON := fmt.Sprintf(c.expectedJSON, namespace, partition)

			actualJSON, err := c.input.GetDataplaneConfigJSON()
			require.NoError(t, err)

			require.JSONEq(t, expectedJSON, string(actualJSON))
		})
	}
}
