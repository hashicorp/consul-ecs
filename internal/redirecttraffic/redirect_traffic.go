// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package redirecttraffic

import (
	"fmt"
	"net"
	"strconv"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/iptables"
	"github.com/mitchellh/mapstructure"
)

const (
	defaultProxyUserID = 5995

	// UID of the health-sync container
	defaultHealthSyncProcessUID = "5996"
)

type trafficRedirectProxyConfig struct {
	BindPort           int    `mapstructure:"bind_port"`
	PrometheusBindAddr string `mapstructure:"envoy_prometheus_bind_addr"`
	StatsBindAddr      string `mapstructure:"envoy_stats_bind_addr"`
}

type TrafficRedirectionCfg struct {
	ProxySvc *api.AgentService

	EnableConsulDNS      bool
	ExcludeInboundPorts  []int
	ExcludeOutboundPorts []int
	ExcludeOutboundCIDRs []string
	ExcludeUIDs          []string

	iptablesCfg iptables.Config

	// Fields used only for unit tests
	iptablesProvider iptables.Provider
}

type TrafficRedirectionProvider interface {
	// Apply applies the traffic redirection with iptables
	Apply() error

	// Config returns the resultant iptables config that gets
	// applied by the provider
	Config() iptables.Config
}

type TrafficRedirectionOpts func(*TrafficRedirectionCfg)

func WithIPTablesProvider(provider iptables.Provider) TrafficRedirectionOpts {
	return func(c *TrafficRedirectionCfg) {
		c.iptablesProvider = provider
	}
}

func New(cfg *config.Config, proxySvc *api.AgentService, additionalInboundPortsToExclude []int, opts ...TrafficRedirectionOpts) TrafficRedirectionProvider {
	trafficRedirectionCfg := &TrafficRedirectionCfg{
		ProxySvc:             proxySvc,
		EnableConsulDNS:      cfg.ConsulDNSEnabled(),
		ExcludeInboundPorts:  cfg.TransparentProxy.ExcludeInboundPorts,
		ExcludeOutboundPorts: cfg.TransparentProxy.ExcludeOutboundPorts,
		ExcludeOutboundCIDRs: cfg.TransparentProxy.ExcludeOutboundCIDRs,
		ExcludeUIDs:          cfg.TransparentProxy.ExcludeUIDs,
	}

	trafficRedirectionCfg.ExcludeInboundPorts = append(trafficRedirectionCfg.ExcludeInboundPorts, additionalInboundPortsToExclude...)

	for _, opt := range opts {
		opt(trafficRedirectionCfg)
	}

	return trafficRedirectionCfg
}

// applyTrafficRedirectionRules creates and applies traffic redirection rules with
// the help of iptables
//
// iptables.Config:
//
//	ConsulDNSIP: Consul Dataplane's DNS server (i.e. localhost)
//	ConsulDNSPort: Consul Dataplane's DNS server's bind port
//	ProxyUserID: a constant set by default in the mesh-task module for the Consul dataplane's container
//	ProxyInboundPort: the proxy service's port or bind port
//	ProxyOutboundPort: default transparent proxy outbound port
//	ExcludeInboundPorts: prometheus, envoy stats, expose paths and `transparentProxy.excludeInboundPorts`
//	ExcludeOutboundPorts: `transparentProxy.excludeOutboundPorts` in CONSUL_ECS_CONFIG_JSON
//	ExcludeOutboundCIDRs: `transparentProxy.excludeOutboundCIDRs` in CONSUL_ECS_CONFIG_JSON
//	ExcludeUIDs: `transparentProxy.excludeUIDs` in CONSUL_ECS_CONFIG_JSON
func (c *TrafficRedirectionCfg) Apply() error {
	if c.ProxySvc == nil {
		return fmt.Errorf("proxy service details are required to enable traffic redirection")
	}

	// Decode proxy's opaque config
	var trCfg trafficRedirectProxyConfig
	if err := mapstructure.WeakDecode(c.ProxySvc.Proxy.Config, &trCfg); err != nil {
		return fmt.Errorf("failed parsing proxy service's Proxy.Config: %w", err)
	}

	c.iptablesCfg = iptables.Config{
		ProxyUserID:       strconv.Itoa(defaultProxyUserID),
		ProxyInboundPort:  c.ProxySvc.Port,
		ProxyOutboundPort: iptables.DefaultTProxyOutboundPort,
	}

	// Override proxyInboundPort with bind_port
	if trCfg.BindPort != 0 {
		c.iptablesCfg.ProxyInboundPort = trCfg.BindPort
	}

	// Override the outbound port if the outbound port present in the proxy registration
	if c.ProxySvc.Proxy.TransparentProxy != nil && c.ProxySvc.Proxy.TransparentProxy.OutboundListenerPort != 0 {
		c.iptablesCfg.ProxyOutboundPort = c.ProxySvc.Proxy.TransparentProxy.OutboundListenerPort
	}

	// Inbound ports
	{
		for _, port := range c.ExcludeInboundPorts {
			c.iptablesCfg.ExcludeInboundPorts = append(c.iptablesCfg.ExcludeInboundPorts, strconv.Itoa(port))
		}

		// Exclude envoy_prometheus_bind_addr port from inbound redirection rules.
		if trCfg.PrometheusBindAddr != "" {
			_, port, err := net.SplitHostPort(trCfg.PrometheusBindAddr)
			if err != nil {
				return fmt.Errorf("failed parsing host and port from envoy_prometheus_bind_addr: %w", err)
			}

			c.iptablesCfg.ExcludeInboundPorts = append(c.iptablesCfg.ExcludeInboundPorts, port)
		}

		// Exclude envoy_stats_bind_addr port from inbound redirection rules.
		if trCfg.StatsBindAddr != "" {
			_, port, err := net.SplitHostPort(trCfg.StatsBindAddr)
			if err != nil {
				return fmt.Errorf("failed parsing host and port from envoy_stats_bind_addr: %w", err)
			}

			c.iptablesCfg.ExcludeInboundPorts = append(c.iptablesCfg.ExcludeInboundPorts, port)
		}

		// Exclude expose path ports from inbound traffic redirection
		for _, exposePath := range c.ProxySvc.Proxy.Expose.Paths {
			if exposePath.ListenerPort != 0 {
				c.iptablesCfg.ExcludeInboundPorts = append(c.iptablesCfg.ExcludeInboundPorts, strconv.Itoa(exposePath.ListenerPort))
			}
		}
	}

	// Outbound ports
	for _, port := range c.ExcludeOutboundPorts {
		c.iptablesCfg.ExcludeOutboundPorts = append(c.iptablesCfg.ExcludeOutboundPorts, strconv.Itoa(port))
	}

	// Outbound CIDRs
	c.iptablesCfg.ExcludeOutboundCIDRs = append(c.iptablesCfg.ExcludeOutboundCIDRs, c.ExcludeOutboundCIDRs...)

	// UIDs
	c.iptablesCfg.ExcludeUIDs = append(c.iptablesCfg.ExcludeUIDs, c.ExcludeUIDs...)
	c.iptablesCfg.ExcludeUIDs = append(c.iptablesCfg.ExcludeUIDs, defaultHealthSyncProcessUID)

	// Consul DNS
	if c.EnableConsulDNS {
		c.iptablesCfg.ConsulDNSIP = config.ConsulDataplaneDNSBindHost
		c.iptablesCfg.ConsulDNSPort = config.ConsulDataplaneDNSBindPort
	}

	if c.iptablesProvider != nil {
		c.iptablesCfg.IptablesProvider = c.iptablesProvider
	}

	c.iptablesCfg.AddAdditionalRulesFn = func(iptablesProvider iptables.Provider) {
		iptablesProvider.AddRule("iptables", "-t", "nat", "--policy", "POSTROUTING", "ACCEPT")
	}

	err := iptables.Setup(c.iptablesCfg)
	if err != nil {
		return fmt.Errorf("failed to setup traffic redirection rules %w", err)
	}

	return nil
}

func (c *TrafficRedirectionCfg) Config() iptables.Config {
	return c.iptablesCfg
}
