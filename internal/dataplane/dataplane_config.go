// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dataplane

import (
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
)

const (
	localhostAddr = "127.0.0.1"
)

// GetDataplaneConfigJSONInputs are the inputs needed to
// generate a dataplane configuration JSON
type GetDataplaneConfigJSONInput struct {
	// Registration details about the proxy service
	ProxyRegistration *api.CatalogRegistration

	// User provided information about the Consul servers
	ConsulServerConfig config.ConsulServers

	// ACL token returned by the server after a successful login.
	// If empty, credential details are not populated in the resulting
	// dataplane config JSON.
	ConsulToken string

	// Path of the CA cert file for Consul server's RPC interface
	CACertFile string

	// The HTTP health check port that indicates envoy's readiness
	ProxyHealthCheckPort int

	// The logLevel that will be used to configure dataplane's logger.
	LogLevel string
}

// GetDataplaneConfigJSON returns back a configuration JSON which
// (after writing it to a shared volume) can be used to start consul-dataplane
func (i *GetDataplaneConfigJSONInput) GetDataplaneConfigJSON() ([]byte, error) {
	cfg := &dataplaneConfig{
		Consul: ConsulConfig{
			Addresses:       i.ConsulServerConfig.Hosts,
			GRPCPort:        i.ConsulServerConfig.GRPC.Port,
			SkipServerWatch: i.ConsulServerConfig.SkipServerWatch,
		},
		Service: ServiceConfig{
			NodeName:       i.ProxyRegistration.Node,
			ProxyServiceID: i.ProxyRegistration.Service.ID,
			Namespace:      i.ProxyRegistration.Service.Namespace,
			Partition:      i.ProxyRegistration.Service.Partition,
		},
		XDSServer: XDSServerConfig{
			Address: localhostAddr,
		},
		Envoy: EnvoyConfig{
			ReadyBindAddr: localhostAddr,
			ReadyBindPort: i.ProxyHealthCheckPort,
		},
		Logging: LoggingConfig{
			LogLevel: i.LogLevel,
		},
	}

	cfg.Consul.TLS = &TLSConfig{
		Disabled: true,
	}

	cfg.Consul.TLS = &TLSConfig{
		Disabled: true,
	}

	grpcTLSSettings := i.ConsulServerConfig.GetGRPCTLSSettings()
	if grpcTLSSettings.Enabled {
		cfg.Consul.TLS = &TLSConfig{
			Disabled:       false,
			GRPCCACertPath: i.CACertFile,
			TLSServerName:  grpcTLSSettings.TLSServerName,
		}
	}

	if i.ConsulToken != "" {
		cfg.Consul.Credentials = &CredentialsConfig{
			CredentialType: "static",
			Static: StaticCredentialConfig{
				Token: i.ConsulToken,
			},
		}
	}

	return cfg.generateJSON()
}
