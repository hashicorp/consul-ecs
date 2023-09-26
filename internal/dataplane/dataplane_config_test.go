// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
					Hosts: "consul.dc1",
					GRPC: config.GRPCSettings{
						Port: 8503,
					},
					SkipServerWatch: true,
				},
				ProxyHealthCheckPort: 22000,
				LogLevel:             "INFO",
			},
			expectedJSON: `{
				"consul": {
				  "addresses": "consul.dc1",
				  "grpcPort": 8503,
				  "serverWatchDisabled": true,
				  "tls": {
					"disabled": true
				  }
				},
				"proxy": {
				  "nodeName": "test-node-name",
				  "id": "test-side-car-123",
				  "namespace": "%s",
				  "partition": "%s"
				},
				"xdsServer": {
				  "bindAddress": "127.0.0.1"
				},
				"envoy": {
					"readyBindAddress": "127.0.0.1",
					"readyBindPort": 22000
				},
				"logging": {
					"logLevel": "INFO"
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
					SkipServerWatch: true,
					GRPC: config.GRPCSettings{
						Port:          8503,
						CaCertFile:    "/consul/ca-cert.pem",
						TLSServerName: "consul.dc1",
						EnableTLS:     testutil.BoolPtr(true),
					},
				},
				CACertFile:           "/consul/ca-cert.pem",
				ProxyHealthCheckPort: 22000,
				LogLevel:             "DEBUG",
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
				"proxy": {
				  "nodeName": "test-node-name",
				  "id": "test-side-car-123",
				  "namespace": "%s",
				  "partition": "%s"
				},
				"xdsServer": {
				  "bindAddress": "127.0.0.1"
				},
				"envoy": {
					"readyBindAddress": "127.0.0.1",
					"readyBindPort": 22000
				},
				"logging": {
					"logLevel": "DEBUG"
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
					SkipServerWatch: false,
					GRPC: config.GRPCSettings{
						Port:      8502,
						EnableTLS: testutil.BoolPtr(false),
					},
				},
				ConsulToken:          "test-token-123",
				ProxyHealthCheckPort: 22000,
				LogLevel:             "WARN",
			},
			expectedJSON: `{
				"consul": {
				  "addresses": "consul.dc1",
				  "grpcPort": 8502,
				  "serverWatchDisabled": false,
				  "tls": {
					"disabled": true
				  },
				  "credentials": {
					"type": "static",
					"static": {
						"token": "test-token-123"
					}
				  }
				},
				"proxy": {
				  "nodeName": "test-node-name",
				  "id": "test-side-car-123",
				  "namespace": "%s",
				  "partition": "%s"
				},
				"xdsServer": {
				  "bindAddress": "127.0.0.1"
				},
				"envoy": {
					"readyBindAddress": "127.0.0.1",
					"readyBindPort": 22000
				},
				"logging": {
					"logLevel": "WARN"
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
					SkipServerWatch: true,
					GRPC: config.GRPCSettings{
						Port:          8503,
						CaCertFile:    "/consul/ca-cert.pem",
						TLSServerName: "consul.dc1",
						EnableTLS:     testutil.BoolPtr(true),
					},
				},
				ConsulToken:          "test-token-123",
				CACertFile:           "/consul/ca-cert.pem",
				ProxyHealthCheckPort: 23000,
				LogLevel:             "TRACE",
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
				"proxy": {
				  "nodeName": "test-node-name",
				  "id": "test-side-car-123",
				  "namespace": "%s",
				  "partition": "%s"
				},
				"xdsServer": {
				  "bindAddress": "127.0.0.1"
				},
				"envoy": {
					"readyBindAddress": "127.0.0.1",
					"readyBindPort": 23000
				},
				"logging": {
					"logLevel": "TRACE"
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
