// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:generate go run gen.go
package config

import (
	"encoding/json"

	"github.com/hashicorp/consul/api"
)

const (
	// ServiceTokenFilename is the file in the BootstrapDir where the service token is written by `consul login`.
	ServiceTokenFilename = "service-token"

	// ClientTokenFilename is the file in the BootstrapDir where the Consul client token is expected.
	// The consul-ecs binary does not write this file, but health-sync will attempt to do a `consul logout` for this token.
	ClientTokenFilename = "client-token"

	// DefaultAuthMethodName is the default name of the Consul IAM auth method used for `consul login`.
	DefaultAuthMethodName = "iam-ecs-service-token"

	// DefaultGatewayPort (8443) is the default gateway registration port used by 'consul connect envoy -register'.
	DefaultGatewayPort = 8443

	// DefaultPublicListenerPort is the default public listener port for sidecar proxies.
	DefaultPublicListenerPort = 20000

	// TaggedAddressLAN is the map key for LAN tagged addresses.
	TaggedAddressLAN = "lan"

	// TaggedAddressWAN is the map key for WAN tagged addresses.
	TaggedAddressWAN = "wan"

	// Match Consul: https://github.com/hashicorp/consul/blob/68e79b8180ca89e8cfca291b40a30d943039bd49/agent/consul/authmethod/awsauth/aws.go#L16-L20
	AuthMethodType         string = "aws-iam"
	IAMServerIDHeaderName  string = "X-Consul-IAM-ServerID"
	GetEntityMethodHeader  string = "X-Consul-IAM-GetEntity-Method"
	GetEntityURLHeader     string = "X-Consul-IAM-GetEntity-URL"
	GetEntityHeadersHeader string = "X-Consul-IAM-GetEntity-Headers"
	GetEntityBodyHeader    string = "X-Consul-IAM-GetEntity-Body"
)

// Config is the top-level config object.
type Config struct {
	BootstrapDir         string                          `json:"bootstrapDir"`
	ConsulHTTPAddr       string                          `json:"consulHTTPAddr"`
	ConsulCACertFile     string                          `json:"consulCACertFile"`
	ConsulLogin          ConsulLogin                     `json:"consulLogin"`
	HealthSyncContainers []string                        `json:"healthSyncContainers,omitempty"`
	LogLevel             string                          `json:"logLevel,omitempty"`
	Proxy                *AgentServiceConnectProxyConfig `json:"proxy"`
	Gateway              *GatewayRegistration            `json:"gateway,omitempty"`
	Service              ServiceRegistration             `json:"service"`
	ConsulServers        ConsulServers                   `json:"consulServers"`
}

// ConsulLogin configures login options for the Consul IAM auth method.
type ConsulLogin struct {
	Enabled       bool              `json:"enabled"`
	Method        string            `json:"method"`
	IncludeEntity bool              `json:"includeEntity"`
	Meta          map[string]string `json:"meta"`
	Region        string            `json:"region"`
	Datacenter    string            `json:"datacenter"`

	// These are passed through to the consul-awsauth library.
	STSEndpoint         string `json:"stsEndpoint"`
	ServerIDHeaderValue string `json:"serverIdHeaderValue"`

	// These are for unit tests. They are disallowed by the JSON schema.
	AccessKeyID     string `json:"-"`
	SecretAccessKey string `json:"-"`
}

// UnmarshalJSON is a custom unmarshaller that defaults `includeEntity` to true
func (c *ConsulLogin) UnmarshalJSON(data []byte) error {
	type Alias ConsulLogin // Avoid recursive calls to this function
	alias := struct {
		*Alias
		// *bool to detect if field is not present
		RawIncludeEntity *bool `json:"includeEntity"`
	}{
		Alias: (*Alias)(c), // Unmarshal other fields into *c
	}

	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	// Default IncludeEntity to true
	if alias.RawIncludeEntity == nil {
		c.IncludeEntity = true
	} else {
		c.IncludeEntity = *alias.RawIncludeEntity
	}
	return nil
}

// ConsulServers configures options that helps the ECS control plane discover
// the consul servers.
type ConsulServers struct {
	Hosts           string `json:"hosts"`
	EnableHTTPS     bool   `json:"https"`
	HTTPPort        int    `json:"httpPort"`
	GRPCPort        int    `json:"grpcPort"`
	EnableTLS       bool   `json:"tls"`
	HTTPSCACertFile string `json:"httpsCACertFile"`
	CACertFile      string `json:"caCertFile"`
	TLSServerName   string `json:"tlsServerName"`
	SkipServerWatch bool   `json:"skipServerWatch"`
}

// UnmarshalJSON is a custom unmarshaller that assigns defaults to certain fields
func (c *ConsulServers) UnmarshalJSON(data []byte) error {
	type Alias ConsulServers
	alias := struct {
		*Alias

		RawEnableHTTPS *bool `json:"https"`
		RawHTTPPort    *int  `json:"httpPort"`
		RawGRPCPort    *int  `json:"grpcPort"`
		RawEnableTLS   *bool `json:"tls"`
	}{
		Alias: (*Alias)(c), // Unmarshal other fields into *c
	}

	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	// Default RawEnableHTTPS to true
	if alias.RawEnableHTTPS == nil {
		c.EnableHTTPS = true
	} else {
		c.EnableHTTPS = *alias.RawEnableHTTPS
	}

	// Default EnableTLS to true
	if alias.RawEnableTLS == nil {
		c.EnableTLS = true
	} else {
		c.EnableTLS = *alias.RawEnableTLS
	}

	// Default HTTPPort to 8501
	if alias.RawHTTPPort == nil {
		c.HTTPPort = defaultHTTPPort
	} else {
		c.HTTPPort = *alias.RawHTTPPort
	}

	// Default GRPCPort to 8503
	if alias.RawGRPCPort == nil {
		c.GRPCPort = defaultGRPCPort
	} else {
		c.GRPCPort = *alias.RawGRPCPort
	}
	return nil
}

// ServiceRegistration configures the Consul service registration.
//
// NOTE:
// - The Kind and Id fields are set by mesh-init during service/proxy registration.
// - The Address field excluded. The agent's address (task ip) should always be used in ECS.
// - The Connect field is not supported:
//   - No Connect-native support for now. We assume Envoy is used.
//   - Proxy registration occurs in a separate request, so no need to inline the proxy config.
//     See the SidecarProxyRegistration type.
type ServiceRegistration struct {
	Name              string              `json:"name"`
	Tags              []string            `json:"tags,omitempty"`
	Port              int                 `json:"port"`
	EnableTagOverride bool                `json:"enableTagOverride,omitempty"`
	Meta              map[string]string   `json:"meta,omitempty"`
	Weights           *AgentWeights       `json:"weights,omitempty"`
	Checks            []AgentServiceCheck `json:"checks,omitempty"`
	Namespace         string              `json:"namespace,omitempty"`
	Partition         string              `json:"partition,omitempty"`
}

func (r *ServiceRegistration) ToConsulType() *api.AgentServiceRegistration {
	result := &api.AgentServiceRegistration{
		Name:              r.Name,
		Tags:              r.Tags,
		Port:              r.Port,
		EnableTagOverride: r.EnableTagOverride,
		Meta:              r.Meta,
		Weights:           nil,
		Checks:            nil,
		Namespace:         r.Namespace,
		Partition:         r.Partition,
	}
	if r.Weights != nil {
		result.Weights = r.Weights.ToConsulType()
	}
	for _, check := range r.Checks {
		result.Checks = append(result.Checks, check.ToConsulType())
	}
	return result

}

// AgentServiceCheck configures a Consul Check.
//
// NOTE:
//   - The DockerContainerID and Shell fields are excluded. Shell is only used for Docker checks, and
//     Docker checks won't work on ECS. They cannot work on Fargate, and require specific config to access
//     the host's Docker daemon on the EC2 launch type.
//   - DeregisterCriticalServiceAfter is also excluded. We have health check support to handle service deregistration.
type AgentServiceCheck struct {
	CheckID                string              `json:"checkId,omitempty"`
	Name                   string              `json:"name,omitempty"`
	Args                   []string            `json:"args,omitempty"`
	Interval               string              `json:"interval,omitempty"`
	Timeout                string              `json:"timeout,omitempty"`
	TTL                    string              `json:"ttl,omitempty"`
	HTTP                   string              `json:"http,omitempty"`
	Header                 map[string][]string `json:"header,omitempty"`
	Method                 string              `json:"method,omitempty"`
	Body                   string              `json:"body,omitempty"`
	TCP                    string              `json:"tcp,omitempty"`
	Status                 string              `json:"status,omitempty"`
	Notes                  string              `json:"notes,omitempty"`
	TLSServerName          string              `json:"tlsServerName,omitempty"`
	TLSSkipVerify          bool                `json:"tlsSkipVerify,omitempty"`
	GRPC                   string              `json:"grpc,omitempty"`
	GRPCUseTLS             bool                `json:"grpcUseTls,omitempty"`
	H2PPING                string              `json:"h2ping,omitempty"`
	H2PingUseTLS           bool                `json:"h2pingUseTLS,omitempty"`
	AliasNode              string              `json:"aliasNode,omitempty"`
	AliasService           string              `json:"aliasService,omitempty"`
	SuccessBeforePassing   int                 `json:"successBeforePassing,omitempty"`
	FailuresBeforeCritical int                 `json:"failuresBeforeCritical,omitempty"`
}

func (c *AgentServiceCheck) ToConsulType() *api.AgentServiceCheck {
	return &api.AgentServiceCheck{
		CheckID:                c.CheckID,
		Name:                   c.Name,
		Args:                   c.Args,
		Interval:               c.Interval,
		Timeout:                c.Timeout,
		TTL:                    c.TTL,
		HTTP:                   c.HTTP,
		Header:                 c.Header,
		Method:                 c.Method,
		Body:                   c.Body,
		TCP:                    c.TCP,
		Status:                 c.Status,
		Notes:                  c.Notes,
		TLSServerName:          c.TLSServerName,
		TLSSkipVerify:          c.TLSSkipVerify,
		GRPC:                   c.GRPC,
		GRPCUseTLS:             c.GRPCUseTLS,
		H2PING:                 c.H2PPING,
		H2PingUseTLS:           c.H2PingUseTLS,
		AliasNode:              c.AliasNode,
		AliasService:           c.AliasService,
		SuccessBeforePassing:   c.SuccessBeforePassing,
		FailuresBeforeCritical: c.FailuresBeforeCritical,
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
// NOTE: For the proxy registration request (api.AgentServiceRegistration in Consul),
//   - The Kind and Port are set by mesh-init, so these fields are not configurable.
//   - The ID, Name, Tags, Meta, EnableTagOverride, and Weights fields are inferred or copied
//     from the service registration by mesh-init.
//   - The bind address is always localhost in ECS, so the Address and SocketPath are excluded.
//   - The Connect field is excluded. Since the sidecar proxy is being used, it's not a Connect-native
//     service, and we don't need the nested proxy config included in the Connect field.
//   - The Partition field is excluded. mesh-init will use the partition from the service registration.
//   - The Namespace field is excluded. mesh-init will use the namespace from the service registration.
//   - There's not a use-case for specifying TaggedAddresses with Consul ECS, and Enable
//
// For the proxy configuration (api.AgentServiceConnectProxyConfig in Consul),
//   - The DestinationServiceName, DestinationServiceId, LocalServiceAddress, and LocalServicePort
//     are all set by mesh-init, based on the service configuration.
//   - The LocalServiceSocketPath is excluded, since it would conflict with the address/port set by mesh-init.
//   - Checks are excluded. mesh-init automatically configures useful checks for the proxy.
//   - TProxy is not supported on ECS, so the Mode and TransparentProxy fields are excluded.
type AgentServiceConnectProxyConfig struct {
	Config             map[string]interface{} `json:"config,omitempty"`
	PublicListenerPort int                    `json:"publicListenerPort,omitempty"`
	Upstreams          []Upstream             `json:"upstreams,omitempty"`
	MeshGateway        *MeshGatewayConfig     `json:"meshGateway,omitempty"`
	Expose             *ExposeConfig          `json:"expose,omitempty"`
}

func (a *AgentServiceConnectProxyConfig) ToConsulType() *api.AgentServiceConnectProxyConfig {
	result := &api.AgentServiceConnectProxyConfig{
		Config:    a.Config,
		Upstreams: nil,
	}
	if a.MeshGateway != nil {
		result.MeshGateway = a.MeshGateway.ToConsulType()
	}
	if a.Expose != nil {
		result.Expose = a.Expose.ToConsulType()
	}
	for _, u := range a.Upstreams {
		result.Upstreams = append(result.Upstreams, u.ToConsulType())
	}
	return result
}

func (a *AgentServiceConnectProxyConfig) GetPublicListenerPort() int {
	if a.PublicListenerPort != 0 {
		return a.PublicListenerPort
	}
	return DefaultPublicListenerPort

}

// Upstream describes an upstream Consul Service.
//
// NOTE: The LocalBindSocketPath and LocalBindSocketMode are excluded. This level of control/restriction
// is not as relevant in ECS since each proxy runs in an isolated Docker container.
type Upstream struct {
	DestinationType      api.UpstreamDestType   `json:"destinationType,omitempty"`
	DestinationNamespace string                 `json:"destinationNamespace,omitempty"`
	DestinationPartition string                 `json:"destinationPartition,omitempty"`
	DestinationName      string                 `json:"destinationName,omitempty"`
	Datacenter           string                 `json:"datacenter,omitempty"`
	LocalBindAddress     string                 `json:"localBindAddress,omitempty"`
	LocalBindPort        int                    `json:"localBindPort,omitempty"`
	Config               map[string]interface{} `json:"config,omitempty"`
	MeshGateway          *MeshGatewayConfig     `json:"meshGateway,omitempty"`
}

func (u *Upstream) ToConsulType() api.Upstream {
	result := api.Upstream{
		DestinationType:      u.DestinationType,
		DestinationNamespace: u.DestinationNamespace,
		DestinationPartition: u.DestinationPartition,
		DestinationName:      u.DestinationName,
		Datacenter:           u.Datacenter,
		LocalBindAddress:     u.LocalBindAddress,
		LocalBindPort:        u.LocalBindPort,
		Config:               u.Config,
	}
	if u.MeshGateway != nil {
		result.MeshGateway = u.MeshGateway.ToConsulType()
	}
	return result
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

type GatewayRegistration struct {
	Kind       api.ServiceKind     `json:"kind"`
	LanAddress *GatewayAddress     `json:"lanAddress,omitempty"`
	WanAddress *GatewayAddress     `json:"wanAddress,omitempty"`
	Name       string              `json:"name,omitempty"`
	Tags       []string            `json:"tags,omitempty"`
	Meta       map[string]string   `json:"meta,omitempty"`
	Namespace  string              `json:"namespace,omitempty"`
	Partition  string              `json:"partition,omitempty"`
	Proxy      *GatewayProxyConfig `json:"proxy,omitempty"`
}

func (g *GatewayRegistration) ToConsulType() *api.AgentServiceRegistration {
	result := &api.AgentServiceRegistration{
		Kind:      g.Kind,
		Port:      DefaultGatewayPort,
		Name:      g.Name,
		Tags:      g.Tags,
		Meta:      g.Meta,
		Namespace: g.Namespace,
		Partition: g.Partition,
	}

	if g.Proxy != nil {
		result.Proxy = g.Proxy.ToConsulType()
	}

	return result
}

type GatewayProxyConfig struct {
	Config map[string]interface{} `json:"config,omitempty"`
}

func (p *GatewayProxyConfig) ToConsulType() *api.AgentServiceConnectProxyConfig {
	return &api.AgentServiceConnectProxyConfig{Config: p.Config}
}

type GatewayAddress struct {
	Address string `json:"address,omitempty"`
	Port    int    `json:"port,omitempty"`
}

func (a *GatewayAddress) ToConsulType() api.ServiceAddress {
	result := api.ServiceAddress{
		Address: a.Address,
		Port:    a.Port,
	}
	if result.Port == 0 {
		result.Port = DefaultGatewayPort
	}
	return result
}
