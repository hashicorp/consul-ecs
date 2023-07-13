// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

func TestConsulServersHoldsDefaultValues(t *testing.T) {
	type TestStruct struct {
		Key1          string        `json:"key1"`
		ConsulServers ConsulServers `json:"consulServers"`
	}

	cases := map[string]struct {
		data                    string
		expectedConsulServerCfg ConsulServers
	}{
		"all non required fields are empty": {
			data: `{
				"key1": "value1",
				"consulServers": {
					"hosts": "consul.dc1"
				}
			}`,
			expectedConsulServerCfg: ConsulServers{
				Hosts:       "consul.dc1",
				EnableTLS:   true,
				EnableHTTPS: true,
				HTTPPort:    8501,
				GRPCPort:    8503,
			},
		},
		"Empty HTTPS input": {
			data: `{
				"key1": "value1",
				"consulServers": {
					"hosts": "consul.dc1",
					"httpPort": 8501,
					"grpcPort": 8502,
					"tls": false
				}
			}`,
			expectedConsulServerCfg: ConsulServers{
				Hosts:       "consul.dc1",
				EnableTLS:   false,
				HTTPPort:    8501,
				GRPCPort:    8502,
				EnableHTTPS: true,
			},
		},
		"Empty TLS input": {
			data: `{
				"key1": "value1",
				"consulServers": {
					"hosts": "consul.dc1",
					"httpPort": 8500,
					"grpcPort": 8502,
					"https": false
				}
			}`,
			expectedConsulServerCfg: ConsulServers{
				Hosts:       "consul.dc1",
				EnableTLS:   true,
				EnableHTTPS: false,
				HTTPPort:    8500,
				GRPCPort:    8502,
			},
		},
		"Empty HTTP port input": {
			data: `{
				"key1": "value1",
				"consulServers": {
					"hosts": "consul.dc1",
					"tls": false,
					"grpcPort": 8502
				}
			}`,
			expectedConsulServerCfg: ConsulServers{
				Hosts:       "consul.dc1",
				EnableTLS:   false,
				EnableHTTPS: true,
				HTTPPort:    8501,
				GRPCPort:    8502,
			},
		},
		"Empty GRPC port input": {
			data: `{
				"key1": "value1",
				"consulServers": {
					"hosts": "consul.dc1",
					"tls": true,
					"httpPort": 8501
				}
			}`,
			expectedConsulServerCfg: ConsulServers{
				Hosts:       "consul.dc1",
				EnableTLS:   true,
				EnableHTTPS: true,
				HTTPPort:    8501,
				GRPCPort:    8503,
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var unmarshalledCfg TestStruct
			err := json.Unmarshal([]byte(c.data), &unmarshalledCfg)
			require.NoError(t, err)
			require.Equal(t, c.expectedConsulServerCfg, unmarshalledCfg.ConsulServers)
		})
	}
}

func TestControllerHoldsDefaultValues(t *testing.T) {
	type TestStruct struct {
		Key1       string     `json:"key1"`
		Controller Controller `json:"controller"`
	}

	cases := map[string]struct {
		data                  string
		expectedControllerCfg Controller
	}{
		"all non required fields are empty": {
			data: `{
				"key1": "value1",
				"controller": {
				}
			}`,
			expectedControllerCfg: Controller{
				Partition:         "",
				PartitionsEnabled: false,
				IAMRolePath:       defaultIAMRolePath,
			},
		},
		"empty iamRolePath input": {
			data: `{
				"key1": "value1",
				"controller": {
					"iamRolePath": ""
				}
			}`,
			expectedControllerCfg: Controller{
				Partition:         "",
				PartitionsEnabled: false,
				IAMRolePath:       defaultIAMRolePath,
			},
		},
		"all controller fields have proper inputs": {
			data: `{
				"key1": "value1",
				"controller": {
					"iamRolePath": "/consul-iam/",
					"partitionsEnabled": true,
					"partition": "test-partition"
				}
			}`,
			expectedControllerCfg: Controller{
				Partition:         "test-partition",
				PartitionsEnabled: true,
				IAMRolePath:       "/consul-iam/",
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var unmarshalledCfg TestStruct
			err := json.Unmarshal([]byte(c.data), &unmarshalledCfg)
			require.NoError(t, err)
			require.Equal(t, c.expectedControllerCfg, unmarshalledCfg.Controller)
		})
	}
}

var (
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
		Namespace: "test-ns",
		Partition: "test-partition",
	}

	expectedConsulServiceRegistration = &api.AgentService{
		Kind:              "",
		ID:                "",
		Service:           "service-1",
		Tags:              []string{"tag1", "tag2"},
		Port:              1234,
		Address:           "",
		SocketPath:        "",
		TaggedAddresses:   nil,
		EnableTagOverride: true,
		Meta:              map[string]string{"env": "test", "version": "x.y.z"},
		Weights: api.AgentWeights{
			Passing: 3,
			Warning: 2,
		},
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
