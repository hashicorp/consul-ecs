// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package redirecttraffic

import (
	"fmt"
	"net"
	"strconv"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/nftables"
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

	iptablesCfg nftables.Config

	// Fields used only for unit tests
	iptablesProvider nftables.Provider
}

type TrafficRedirectionProvider interface {
	// Apply applies the traffic redirection with nftables
	Apply() error

	// Config returns the resultant nftables config that gets
	// applied by the provider
	Config() nftables.Config
}

type TrafficRedirectionOpts func(*TrafficRedirectionCfg)

func WithIPTablesProvider(provider nftables.Provider) TrafficRedirectionOpts {
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
// the help of nftables
//
// nftables.Config:
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

	c.iptablesCfg = nftables.Config{
		ProxyUserID:       strconv.Itoa(defaultProxyUserID),
		ProxyInboundPort:  c.ProxySvc.Port,
		ProxyOutboundPort: nftables.DefaultTProxyOutboundPort,
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
		c.iptablesCfg.NftablesProvider = c.iptablesProvider
	}

	// This rule works around a Docker/ECS-optimized-AMI-specific problem where the
	// host's real, shared "nat" table's POSTROUTING chain policy ends up as something
	// other than ACCEPT, which silently breaks Docker's own container SNAT/MASQUERADE
	// rule (also in that same POSTROUTING chain) once transparent proxy redirection is
	// enabled -- causing redirected traffic to time out. See the original fix and its
	// rationale: https://github.com/hashicorp/consul/pull/20232.
	//
	// Despite the SDK migrating its own managed chains from the shared iptables "nat"
	// table to a private nftables table ("inet consul_tproxy", see the SDK's tproxyTable
	// constant), this particular rule is NOT about the SDK's own chains -- neither the
	// old nor new SDK ever creates a POSTROUTING chain of its own (only inbound/outbound
	// hooks). It exists solely to fix Docker's real, global "nat" table, which Docker
	// still manages the same way (still via the "ip" family, since Docker itself issues
	// iptables/iptables-nft commands, unaffected by our SDK's internal table rename).
	// So this rule must keep targeting that same real "ip nat" table, not "consul_tproxy"
	// -- pointing it at our own private table would be a no-op that leaves the original
	// ECS EC2 timeout bug unfixed.
	//
	// Docker guarantees this chain already exists by the time mesh-init runs (it's a
	// prerequisite for any container network to work at all), so we use nft's `chain`
	// subcommand to update only the existing chain's policy -- mirroring `iptables
	// --policy`, which likewise only ever updates an existing built-in chain's policy
	// and never creates one.
	addAdditionalRulesFn := func(nftablesProvider nftables.Provider) {
		nftablesProvider.AddRule("nft", "add", "chain", "ip", "nat", "POSTROUTING", "{ policy accept ; }")
	}

	err := nftables.SetupWithAdditionalRules(c.iptablesCfg, addAdditionalRulesFn, false)
	if err != nil {
		return fmt.Errorf("failed to setup traffic redirection rules %w", err)
	}

	return nil
}

func (c *TrafficRedirectionCfg) Config() nftables.Config {
	return c.iptablesCfg
}
