package config

import "github.com/hashicorp/consul/api"

// Config is the top-level config object.
type Config struct {
	Secret AclTokenSecret `json:"aclTokenSecret"`
	Mesh   Mesh           `json:"mesh"`
}

// Mesh is the configuration for joining the service mesh.
type Mesh struct {
	BootstrapDir         string                   `json:"bootstrapDir"`
	HealthSyncContainers []string                 `json:"healthSyncContainers,omitempty"`
	Sidecar              SidecarProxyRegistration `json:"sidecar"`
	Service              ServiceRegistration      `json:"service"`
}

// AclTokenSecret is the configuration for ACL tokens.
type AclTokenSecret struct {
	Provider      SecretProvider      `json:"provider"`
	Configuration SecretConfiguration `json:"configuration"`
}

// SecretConfiguration is the configuration for secret management for ACL tokens.
type SecretConfiguration struct {
	Prefix                     string `json:"prefix"`
	ConsulClientTokenSecretARN string `json:"consulClientTokenSecretArn"`
}

// SecretProvider is the secret provider to use for secrets management.
type SecretProvider string

const (
	SecretsManagerProvider SecretProvider = "secrets-manager"
)

// ServiceRegistration configures the Consul service registration.
//
// NOTE:
// - The Kind and Id fields are set by mesh-init during service/proxy registration.
// - The Connect field is not supported:
//   - No Connect-native support for now. We assume Envoy is used.
//   - Proxy registration occurs in a separate request, so no need to inline the proxy config.
//     See the SidecarProxyRegistration type.
type ServiceRegistration struct {
	Name              string                    `json:"name"`
	Tags              []string                  `json:"tags,omitempty"`
	Port              int                       `json:"port"`
	Address           string                    `json:"address,omitempty"`
	SocketPath        string                    `json:"socketPath,omitempty"`
	TaggedAddresses   map[string]ServiceAddress `json:"taggedAddresses,omitempty"`
	EnableTagOverride bool                      `json:"enableTagOverride,omitempty"`
	Meta              map[string]string         `json:"meta,omitempty"`
	Weights           *AgentWeights             `json:"weights,omitempty"`
	Checks            []AgentServiceCheck       `json:"checks,omitempty"`
	Namespace         string                    `json:"ns,omitempty"`
}

func (r *ServiceRegistration) ToConsulType() *api.AgentServiceRegistration {
	result := &api.AgentServiceRegistration{
		Name:              r.Name,
		Tags:              r.Tags,
		Port:              r.Port,
		Address:           r.Address,
		SocketPath:        r.SocketPath,
		TaggedAddresses:   nil,
		EnableTagOverride: r.EnableTagOverride,
		Meta:              r.Meta,
		Weights:           nil,
		Checks:            nil,
		Namespace:         r.Namespace,
	}
	if r.TaggedAddresses != nil {
		result.TaggedAddresses = map[string]api.ServiceAddress{}
		for k, v := range r.TaggedAddresses {
			result.TaggedAddresses[k] = v.ToConsulType()
		}
	}
	if r.Weights != nil {
		result.Weights = r.Weights.ToConsulType()
	}
	for _, check := range r.Checks {
		result.Checks = append(result.Checks, check.ToConsulType())
	}
	return result

}

// SidecarProxyRegistration configures the sidecar proxy registration.
//
// NOTE:
// - The Kind and Port are set by mesh-init, so these fields are not configurable.
// - The ID, Name, Tags, and Meta are inferred or copied from the service registration by mesh-init.
// - The bind address will always be localhost in ECS, so the Address and SocketPath are excluded.
// - The Connect field is excluded. Since the sidecar proxy is being used, it's not a Connect-native
//   service, and we don't need the recursive proxy config included in the Connect field.
type SidecarProxyRegistration struct {
	TaggedAddresses   map[string]ServiceAddress       `json:"taggedAddresses,omitempty"`
	EnableTagOverride bool                            `json:"enableTagOverride,omitempty"`
	Meta              map[string]string               `json:"meta,omitempty"`
	Weights           *AgentWeights                   `json:"weights,omitempty"`
	Checks            []AgentServiceCheck             `json:"checks,omitempty"`
	Namespace         string                          `json:"ns,omitempty"`
	Proxy             *AgentServiceConnectProxyConfig `json:"proxy,omitempty"`
}

func (p *SidecarProxyRegistration) ToConsulType() *api.AgentServiceRegistration {
	proxyConfig := p.Proxy.ToConsulType()
	result := &api.AgentServiceRegistration{
		TaggedAddresses:   nil,
		EnableTagOverride: p.EnableTagOverride,
		Meta:              p.Meta,
		Weights:           nil,
		Checks:            nil,
		Proxy:             &proxyConfig,
		Namespace:         p.Namespace,
	}
	if p.TaggedAddresses != nil {
		result.TaggedAddresses = map[string]api.ServiceAddress{}
		for k, v := range p.TaggedAddresses {
			result.TaggedAddresses[k] = v.ToConsulType()
		}
	}
	if p.Weights != nil {
		result.Weights = p.Weights.ToConsulType()
	}
	for _, check := range p.Checks {
		result.Checks = append(result.Checks, check.ToConsulType())
	}
	return result
}

// AgentServiceCheck configures a Consul Check.
type AgentServiceCheck struct {
	CheckID                        string              `json:"checkId,omitempty"`
	Name                           string              `json:"name,omitempty"`
	Args                           []string            `json:"args,omitempty"`
	DockerContainerID              string              `json:"dockerContainerId,omitempty"`
	Shell                          string              `json:"shell,omitempty"` // Only supported for Docker.
	Interval                       string              `json:"interval,omitempty"`
	Timeout                        string              `json:"timeout,omitempty"`
	TTL                            string              `json:"ttl,omitempty"`
	HTTP                           string              `json:"http,omitempty"`
	Header                         map[string][]string `json:"header,omitempty"`
	Method                         string              `json:"method,omitempty"`
	Body                           string              `json:"body,omitempty"`
	TCP                            string              `json:"tcp,omitempty"`
	Status                         string              `json:"status,omitempty"`
	Notes                          string              `json:"notes,omitempty"`
	TLSServerName                  string              `json:"tlsServerName,omitempty"`
	TLSSkipVerify                  bool                `json:"tlsSkipVerify,omitempty"`
	GRPC                           string              `json:"grpc,omitempty"`
	GRPCUseTLS                     bool                `json:"grpcUseTls,omitempty"`
	AliasNode                      string              `json:"aliasNode,omitempty"`
	AliasService                   string              `json:"aliasService,omitempty"`
	SuccessBeforePassing           int                 `json:"successBeforePassing,omitempty"`
	FailuresBeforeCritical         int                 `json:"failuresBeforeCritical,omitempty"`
	DeregisterCriticalServiceAfter string              `json:"deregisterCriticalServiceAfter,omitempty"`
}

func (c *AgentServiceCheck) ToConsulType() *api.AgentServiceCheck {
	return &api.AgentServiceCheck{
		CheckID:                        c.CheckID,
		Name:                           c.Name,
		Args:                           c.Args,
		DockerContainerID:              c.DockerContainerID,
		Shell:                          c.Shell,
		Interval:                       c.Interval,
		Timeout:                        c.Timeout,
		TTL:                            c.TTL,
		HTTP:                           c.HTTP,
		Header:                         c.Header,
		Method:                         c.Method,
		Body:                           c.Body,
		TCP:                            c.TCP,
		Status:                         c.Status,
		Notes:                          c.Notes,
		TLSServerName:                  c.TLSServerName,
		TLSSkipVerify:                  c.TLSSkipVerify,
		GRPC:                           c.GRPC,
		GRPCUseTLS:                     c.GRPCUseTLS,
		AliasNode:                      c.AliasNode,
		AliasService:                   c.AliasService,
		SuccessBeforePassing:           c.SuccessBeforePassing,
		FailuresBeforeCritical:         c.FailuresBeforeCritical,
		DeregisterCriticalServiceAfter: c.DeregisterCriticalServiceAfter,
	}
}

type ServiceAddress struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

func (a *ServiceAddress) ToConsulType() api.ServiceAddress {
	return api.ServiceAddress{
		Address: a.Address,
		Port:    a.Port,
	}
}

type AgentWeights struct {
	Passing int `json:"passing"`
	Warning int `json:"warning"`
}

func (w *AgentWeights) ToConsulType() *api.AgentWeights {
	return &api.AgentWeights{
		Passing: w.Passing,
		Warning: w.Warning,
	}
}

// AgentServiceConnectProxyConfig defines the sidecar proxy configuration.
//
// NOTE:
// - TProxy is not supported on ECS, so the Mode and TransparentProxy fields are excluded.
type AgentServiceConnectProxyConfig struct {
	DestinationServiceName string `json:"destinationServiceName,omitempty"`
	DestinationServiceID   string `json:"destinationServiceId,omitempty"`
	LocalServiceAddress    string `json:"localServiceAddress,omitempty"`
	LocalServicePort       int    `json:"localServicePort,omitempty"`
	LocalServiceSocketPath string `json:"localServiceSocketPath,omitempty"`
	//Mode                   api.ProxyMode `json:"mode,omitempty"`
	//TransparentProxy       *api.TransparentProxyConfig `json:"transparentProxy,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Upstreams   []Upstream             `json:"upstreams,omitempty"`
	MeshGateway MeshGatewayConfig      `json:"meshGateway,omitempty"`
	Expose      ExposeConfig           `json:"expose,omitempty"`
}

func (a *AgentServiceConnectProxyConfig) ToConsulType() api.AgentServiceConnectProxyConfig {
	result := api.AgentServiceConnectProxyConfig{
		DestinationServiceName: a.DestinationServiceName,
		DestinationServiceID:   a.DestinationServiceID,
		LocalServiceAddress:    a.LocalServiceAddress,
		LocalServicePort:       a.LocalServicePort,
		LocalServiceSocketPath: a.LocalServiceSocketPath,
		//Mode: a.Mode,
		//TransparentProxy: a.TransparentProxy,
		Config: a.Config,
		//Upstreams: a.Upstreams,
		MeshGateway: a.MeshGateway.ToConsulType(),
		Expose:      a.Expose.ToConsulType(),
	}
	for _, u := range a.Upstreams {
		result.Upstreams = append(result.Upstreams, u.ToConsulType())
	}
	return result
}

// Upstream describes an upstream Consul Service.
type Upstream struct {
	DestinationType      api.UpstreamDestType   `json:"destinationType,omitempty"`
	DestinationNamespace string                 `json:"destinationNamespace,omitempty"`
	DestinationName      string                 `json:"destinationName,omitempty"`
	Datacenter           string                 `json:"datacenter,omitempty"`
	LocalBindAddress     string                 `json:"localBindAddress,omitempty"`
	LocalBindPort        int                    `json:"localBindPort,omitempty"`
	LocalBindSocketPath  string                 `json:"localBindSocketPath,omitempty"`
	LocalBindSocketMode  string                 `json:"localBindSocketMode,omitempty"`
	Config               map[string]interface{} `json:"config,omitempty"`
	MeshGateway          MeshGatewayConfig      `json:"meshGateway,omitempty"`
}

func (u *Upstream) ToConsulType() api.Upstream {
	return api.Upstream{
		DestinationType:      u.DestinationType,
		DestinationNamespace: u.DestinationNamespace,
		DestinationName:      u.DestinationName,
		Datacenter:           u.Datacenter,
		LocalBindAddress:     u.LocalBindAddress,
		LocalBindPort:        u.LocalBindPort,
		LocalBindSocketPath:  u.LocalBindSocketPath,
		LocalBindSocketMode:  u.LocalBindSocketMode,
		Config:               u.Config,
		MeshGateway:          u.MeshGateway.ToConsulType(),
	}
}

// MeshGatewayConfig describes how to use mesh gateways to reach other services.
type MeshGatewayConfig struct {
	Mode api.MeshGatewayMode `json:"mode,omitempty"`
}

func (m *MeshGatewayConfig) ToConsulType() api.MeshGatewayConfig {
	return api.MeshGatewayConfig{
		Mode: m.Mode,
	}
}

// ExposeConfig describes HTTP paths to expose through Envoy outside of Connect.
type ExposeConfig struct {
	Checks bool         `json:"checks,omitempty"`
	Paths  []ExposePath `json:"paths,omitempty"`
}

func (e *ExposeConfig) ToConsulType() api.ExposeConfig {
	result := api.ExposeConfig{
		Checks: e.Checks,
	}
	for _, path := range e.Paths {
		result.Paths = append(result.Paths, path.ToConsulType())
	}
	return result
}

// ExposePath are the paths to expose outside of connect. See ExposeConfig.
type ExposePath struct {
	ListenerPort  int    `json:"listenerPort,omitempty"`
	Path          string `json:"path,omitempty"`
	LocalPathPort int    `json:"localPathPort,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
}

func (e *ExposePath) ToConsulType() api.ExposePath {
	return api.ExposePath{
		ListenerPort:  e.ListenerPort,
		Path:          e.Path,
		LocalPathPort: e.LocalPathPort,
		Protocol:      e.Protocol,
	}
}
