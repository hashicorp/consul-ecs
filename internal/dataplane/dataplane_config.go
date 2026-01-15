// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package dataplane

import (
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-server-connection-manager/discovery"
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

	// Login credentials that will be passed on to the dataplane's
	// configuration.
	ConsulLoginCredentials *discovery.Credentials

	// Path of the CA cert file for Consul server's RPC interface
	CACertFile string

	// The HTTP health check port that indicates envoy's readiness
	ProxyHealthCheckPort int

	// The logLevel that will be used to configure dataplane's logger.
	LogLevel string

	// Whether Consul DNS is enabled in the mesh-task. If yes, dataplane
	// starts a local DNS server and transparently proxies it to Consul
	// server's DNS interface
	ConsulDNSEnabled bool
}

// GetDataplaneConfigJSON returns back a configuration JSON which
// (after writing it to a shared volume) can be used to start consul-dataplane
func (i *GetDataplaneConfigJSONInput) GetDataplaneConfigJSON() ([]byte, error) {
	cfg := &DataplaneConfig{
		Consul: ConsulConfig{
			Addresses:       i.ConsulServerConfig.Hosts,
			GRPCPort:        i.ConsulServerConfig.GRPC.Port,
			SkipServerWatch: i.ConsulServerConfig.SkipServerWatch,
		},
		Proxy: ProxyConfig{
			NodeName:  i.ProxyRegistration.Node,
			ID:        i.ProxyRegistration.Service.ID,
			Namespace: i.ProxyRegistration.Service.Namespace,
			Partition: i.ProxyRegistration.Service.Partition,
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

	if i.ConsulLoginCredentials != nil {
		cfg.Consul.Credentials = &CredentialsConfig{
			CredentialType: "login",
			Login: LoginCredentialsConfig{
				AuthMethod:  i.ConsulLoginCredentials.Login.AuthMethod,
				Namespace:   i.ConsulLoginCredentials.Login.Namespace,
				Partition:   i.ConsulLoginCredentials.Login.Partition,
				Datacenter:  i.ConsulLoginCredentials.Login.Datacenter,
				BearerToken: i.ConsulLoginCredentials.Login.BearerToken,
				Meta:        i.ConsulLoginCredentials.Login.Meta,
			},
		}
	}

	if i.ConsulDNSEnabled {
		cfg.DNSServer = &DNSServerConfig{
			BindAddress: config.ConsulDataplaneDNSBindHost,
			BindPort:    config.ConsulDataplaneDNSBindPort,
		}
	}

	return cfg.generateJSON()
}
