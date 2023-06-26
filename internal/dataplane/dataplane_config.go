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
}

// GetDataplaneConfigJSON returns back a configuration JSON which
// (after writing it to a shared volume) can be used to start consul-dataplane
func (i *GetDataplaneConfigJSONInput) GetDataplaneConfigJSON() ([]byte, error) {
	cfg := &dataplaneConfig{
		consul: consulConfig{
			addresses:       i.ConsulServerConfig.Hosts,
			grpcPort:        i.ConsulServerConfig.GRPCPort,
			skipServerWatch: i.ConsulServerConfig.SkipServerWatch,
		},
		service: serviceConfig{
			nodeName:       i.ProxyRegistration.Node,
			proxyServiceID: i.ProxyRegistration.Service.ID,
			namespace:      i.ProxyRegistration.Service.Namespace,
			partition:      i.ProxyRegistration.Service.Partition,
		},
		xdsServer: xdsServerConfig{
			address: localhostAddr,
			port:    20000,
		},
	}

	if i.ConsulServerConfig.EnableTLS {
		cfg.consul.tls = &tlsConfig{
			grpcCACertPath: i.ConsulServerConfig.CACertFile,
			tlsServerName:  i.ConsulServerConfig.TLSServerName,
		}
	}

	if i.ConsulToken != "" {
		cfg.consul.credentials = &credentialsConfig{
			credentialType: "static",
			static: staticCredentialConfig{
				token: i.ConsulToken,
			},
		}
	}

	return cfg.generateJSON()
}
