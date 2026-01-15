// Copyright IBM Corp. 2021, 2025
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

	// DefaultAuthMethodName is the default name of the Consul IAM auth method used for `consul login`.
	DefaultAuthMethodName = "iam-ecs-service-token"

	// DefaultGatewayPort (8443) is the default gateway registration port used by 'consul connect envoy -register'.
	DefaultGatewayPort = 8443

	// DefaultPublicListenerPort is the default public listener port for sidecar proxies.
	DefaultPublicListenerPort = 20000

	// DefaultProxyHealthCheckPort is the default HTTP health check port for the proxy.
	DefaultProxyHealthCheckPort = 22000

	// TaggedAddressLAN is the map key for LAN tagged addresses.
	TaggedAddressLAN = "lan"

	// TaggedAddressWAN is the map key for WAN tagged addresses.
	TaggedAddressWAN = "wan"

	// Name of the dataplane's container
	ConsulDataplaneContainerName = "consul-dataplane"

	// Match Consul: https://github.com/hashicorp/consul/blob/68e79b8180ca89e8cfca291b40a30d943039bd49/agent/consul/authmethod/awsauth/aws.go#L16-L20
	AuthMethodType         string = "aws-iam"
	IAMServerIDHeaderName  string = "X-Consul-IAM-ServerID"
	GetEntityMethodHeader  string = "X-Consul-IAM-GetEntity-Method"
	GetEntityURLHeader     string = "X-Consul-IAM-GetEntity-URL"
	GetEntityHeadersHeader string = "X-Consul-IAM-GetEntity-Headers"
	GetEntityBodyHeader    string = "X-Consul-IAM-GetEntity-Body"

	SyntheticNode string = "synthetic-node"
)

// Config is the top-level config object.
type Config struct {
	BootstrapDir         string                          `json:"bootstrapDir"`
	ConsulLogin          ConsulLogin                     `json:"consulLogin"`
	HealthSyncContainers []string                        `json:"healthSyncContainers,omitempty"`
	LogLevel             string                          `json:"logLevel,omitempty"`
	Proxy                *AgentServiceConnectProxyConfig `json:"proxy"`
	Gateway              *GatewayRegistration            `json:"gateway,omitempty"`
	Service              ServiceRegistration             `json:"service"`
	ConsulServers        ConsulServers                   `json:"consulServers"`
	Controller           Controller                      `json:"controller"`
	TransparentProxy     TransparentProxyConfig          `json:"transparentProxy"`
}

// UnmarshalJSON is a custom unmarshaller that assigns defaults to certain fields
func (c *Config) UnmarshalJSON(data []byte) error {
	type Alias Config
	alias := struct {
		*Alias

		RawTransparentProxyConfig *TransparentProxyConfig `json:"transparentProxy"`
	}{
		Alias: (*Alias)(c), // Unmarshal other fields into *c
	}

	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	if alias.RawTransparentProxyConfig == nil {
		c.TransparentProxy = TransparentProxyConfig{
			Enabled: true,
		}
	} else {
		c.TransparentProxy = *alias.RawTransparentProxyConfig
	}

	return nil
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

// ConsulServers configures options that helps the Consul specific ECS containers discover
// the consul servers.
type ConsulServers struct {
	Hosts           string          `json:"hosts"`
	SkipServerWatch bool            `json:"skipServerWatch"`
	Defaults        DefaultSettings `json:"defaults"`
	GRPC            GRPCSettings    `json:"grpc"`
	HTTP            HTTPSettings    `json:"http"`
}

// UnmarshalJSON is a custom unmarshaller that assigns defaults to certain fields
func (c *ConsulServers) UnmarshalJSON(data []byte) error {
	type Alias ConsulServers
	alias := struct {
		*Alias

		RawDefaultSettings *DefaultSettings `json:"defaults"`
		RawGRPCSettings    *GRPCSettings    `json:"grpc"`
		RawHTTPSettings    *HTTPSettings    `json:"http"`
	}{
		Alias: (*Alias)(c), // Unmarshal other fields into *c
	}

	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	// Assign defaults, if the user hasn't provided
	// values for `consulServers.defaults`
	if alias.RawDefaultSettings == nil {
		c.Defaults = DefaultSettings{
			EnableTLS: true,
		}
	} else {
		c.Defaults = *alias.RawDefaultSettings
	}

	// Assign defaults, if the user hasn't provided
	// values for `consulServers.grpc`
	if alias.RawGRPCSettings == nil {
		c.GRPC = GRPCSettings{
			Port: defaultGRPCPort,
		}
	} else {
		c.GRPC = *alias.RawGRPCSettings
	}

	// Assign defaults, if the user hasn't provided
	// values for `consulServers.http`
	if alias.RawHTTPSettings == nil {
		c.HTTP = HTTPSettings{
			Port:        defaultHTTPPort,
			EnableHTTPS: true,
		}
	} else {
		c.HTTP = *alias.RawHTTPSettings
	}

	return nil
}

// DefaultSettings hold the default TLS settings for Consul server's RPC and HTTP interfaces
type DefaultSettings struct {
	CaCertFile    string `json:"caCertFile"`
	EnableTLS     bool   `json:"tls"`
	TLSServerName string `json:"tlsServerName"`
}

// UnmarshalJSON is a custom unmarshaller that assigns defaults to certain fields
func (d *DefaultSettings) UnmarshalJSON(data []byte) error {
	type Alias DefaultSettings
	alias := struct {
		*Alias

		RawEnableTLS *bool `json:"tls"`
	}{
		Alias: (*Alias)(d),
	}

	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	// Default EnableTLS to true
	if alias.RawEnableTLS == nil {
		d.EnableTLS = true
	} else {
		d.EnableTLS = *alias.RawEnableTLS
	}

	return nil
}

// GRPCSettings hold the settings for Consul server's RPC interfaces.
// Overrides the configuration present in DefaultSettings for TLS.
type GRPCSettings struct {
	Port          int    `json:"port"`
	CaCertFile    string `json:"caCertFile"`
	EnableTLS     *bool  `json:"tls"`
	TLSServerName string `json:"tlsServerName"`
}

// UnmarshalJSON is a custom unmarshaller that assigns defaults to certain fields
func (g *GRPCSettings) UnmarshalJSON(data []byte) error {
	type Alias GRPCSettings
	alias := struct {
		*Alias

		RawPort *int `json:"port"`
	}{
		Alias: (*Alias)(g),
	}

	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	// Default Port to 8503
	if alias.RawPort == nil {
		g.Port = defaultGRPCPort
	} else {
		g.Port = *alias.RawPort
	}
	return nil
}

// HTTPSettings hold the settings for Consul server's HTTP interfaces.
// Overrides the configuration present in DefaultSettings for TLS.
type HTTPSettings struct {
	Port          int    `json:"port"`
	EnableHTTPS   bool   `json:"https"`
	CaCertFile    string `json:"caCertFile"`
	EnableTLS     *bool  `json:"tls"`
	TLSServerName string `json:"tlsServerName"`
}

// UnmarshalJSON is a custom unmarshaller that assigns defaults to certain fields
func (h *HTTPSettings) UnmarshalJSON(data []byte) error {
	type Alias HTTPSettings
	alias := struct {
		*Alias

		RawPort        *int  `json:"port"`
		RawEnableHTTPS *bool `json:"https"`
	}{
		Alias: (*Alias)(h),
	}

	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	// Default EnableHTTPS to true
	if alias.RawEnableHTTPS == nil {
		h.EnableHTTPS = true
	} else {
		h.EnableHTTPS = *alias.RawEnableHTTPS
	}

	// Default Port to 8501
	if alias.RawPort == nil {
		h.Port = defaultHTTPPort
	} else {
		h.Port = *alias.RawPort
	}
	return nil
}

// Controller configures the options to start the consul-ecs-controller command.
type Controller struct {
	IAMRolePath       string `json:"iamRolePath"`
	PartitionsEnabled bool   `json:"partitionsEnabled"`
	Partition         string `json:"partition"`
}

// UnmarshalJSON is a custom unmarshaller that assigns defaults to certain fields
func (c *Controller) UnmarshalJSON(data []byte) error {
	type Alias Controller
	alias := struct {
		*Alias

		RawIAMRolePath *string `json:"iamRolePath"`
	}{
		Alias: (*Alias)(c), // Unmarshal other fields into *c
	}

	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	// Default iamRolePath to /consul-ecs/
	if alias.RawIAMRolePath == nil {
		c.IAMRolePath = defaultIAMRolePath
	} else {
		c.IAMRolePath = *alias.RawIAMRolePath
	}

	if c.IAMRolePath == "" {
		c.IAMRolePath = defaultIAMRolePath
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
	Name              string            `json:"name"`
	Tags              []string          `json:"tags,omitempty"`
	Port              int               `json:"port"`
	EnableTagOverride bool              `json:"enableTagOverride,omitempty"`
	Meta              map[string]string `json:"meta,omitempty"`
	Weights           *AgentWeights     `json:"weights,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	Partition         string            `json:"partition,omitempty"`
}

func (r *ServiceRegistration) ToConsulType() *api.AgentService {
	result := &api.AgentService{
		Service:           r.Name,
		Tags:              r.Tags,
		Meta:              r.Meta,
		Port:              r.Port,
		Weights:           api.AgentWeights{},
		EnableTagOverride: r.EnableTagOverride,
		Namespace:         r.Namespace,
		Partition:         r.Partition,
	}

	if r.Weights != nil {
		result.Weights = r.Weights.ToConsulType()
	}

	return result
}

type AgentWeights struct {
	Passing int `json:"passing"`
	Warning int `json:"warning"`
}

func (w *AgentWeights) ToConsulType() api.AgentWeights {
	return api.AgentWeights{
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
//   - The bind address defaults to localhost in ECS but can be overridden with LocalServiceAddress and
//     SocketPath is excluded.
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
	Config              map[string]interface{} `json:"config,omitempty"`
	LocalServiceAddress string                 `json:"localServiceAddress,omitempty"`
	PublicListenerPort  int                    `json:"publicListenerPort,omitempty"`
	HealthCheckPort     int                    `json:"healthCheckPort,omitempty"`
	Upstreams           []Upstream             `json:"upstreams,omitempty"`
	MeshGateway         *MeshGatewayConfig     `json:"meshGateway,omitempty"`
	Expose              *ExposeConfig          `json:"expose,omitempty"`
}

func (a *AgentServiceConnectProxyConfig) ToConsulType() *api.AgentServiceConnectProxyConfig {
	result := &api.AgentServiceConnectProxyConfig{
		Config:    a.Config,
		Upstreams: nil,
	}
	if a.LocalServiceAddress != "" {
		result.LocalServiceAddress = a.LocalServiceAddress
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
	DestinationPeer      string                 `json:"destinationPeer,omitempty"`
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
		DestinationPeer:      u.DestinationPeer,
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
	Kind            api.ServiceKind     `json:"kind"`
	LanAddress      *GatewayAddress     `json:"lanAddress,omitempty"`
	WanAddress      *GatewayAddress     `json:"wanAddress,omitempty"`
	Name            string              `json:"name,omitempty"`
	Tags            []string            `json:"tags,omitempty"`
	Meta            map[string]string   `json:"meta,omitempty"`
	Namespace       string              `json:"namespace,omitempty"`
	Partition       string              `json:"partition,omitempty"`
	Proxy           *GatewayProxyConfig `json:"proxy,omitempty"`
	HealthCheckPort int                 `json:"healthCheckPort,omitempty"`
}

func (g *GatewayRegistration) ToConsulType() *api.AgentService {
	result := &api.AgentService{
		Kind:      g.Kind,
		Port:      DefaultGatewayPort,
		Service:   g.Name,
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

func GetHealthCheckPort(p int) int {
	if p != 0 {
		return p
	}

	return DefaultProxyHealthCheckPort
}

type TransparentProxyConfig struct {
	Enabled              bool      `json:"enabled"`
	ExcludeInboundPorts  []int     `json:"excludeInboundPorts"`
	ExcludeOutboundPorts []int     `json:"excludeOutboundPorts"`
	ExcludeOutboundCIDRs []string  `json:"excludeOutboundCIDRs"`
	ExcludeUIDs          []string  `json:"excludeUIDs"`
	ConsulDNS            ConsulDNS `json:"consulDNS"`
}

func (c *TransparentProxyConfig) UnmarshalJSON(data []byte) error {
	type Alias TransparentProxyConfig
	alias := struct {
		*Alias

		RawEnabled *bool `json:"enabled"`
	}{
		Alias: (*Alias)(c), // Unmarshal other fields into *c
	}

	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	if alias.RawEnabled == nil {
		c.Enabled = true
	} else {
		c.Enabled = *alias.RawEnabled
	}

	return nil
}

func (cfg *Config) TransparentProxyEnabled() bool {
	return cfg.TransparentProxy.Enabled && !cfg.IsGateway()
}

type ConsulDNS struct {
	Enabled bool `json:"enabled"`
}

func (cfg *Config) ConsulDNSEnabled() bool {
	return cfg.TransparentProxy.Enabled && cfg.TransparentProxy.ConsulDNS.Enabled && !cfg.IsGateway()
}
