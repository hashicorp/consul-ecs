// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package redirecttraffic

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/nftables"
	"github.com/stretchr/testify/require"
)

func TestApply(t *testing.T) {
	cases := map[string]struct {
		wantErr              bool
		proxySvc             *api.AgentService
		cfg                  *config.Config
		assertNftablesConfig func(t *testing.T, actual nftables.Config)
	}{
		"proxy service is nil": {
			cfg:     &config.Config{},
			wantErr: true,
		},
		"default redirection behaviour": {
			cfg: &config.Config{
				TransparentProxy: config.TransparentProxyConfig{
					Enabled: true,
				},
			},
			proxySvc: &api.AgentService{
				Port:  20000,
				Proxy: &api.AgentServiceConnectProxyConfig{},
			},
			assertNftablesConfig: func(t *testing.T, cfg nftables.Config) {
				require.Equal(t, 20000, cfg.ProxyInboundPort)
				require.Equal(t, nftables.DefaultTProxyOutboundPort, cfg.ProxyOutboundPort)
				require.Equal(t, strconv.Itoa(defaultProxyUserID), cfg.ProxyUserID)
			},
		},
		"envoy bind port is present in proxy config": {
			cfg: &config.Config{
				TransparentProxy: config.TransparentProxyConfig{
					Enabled: true,
				},
			},
			proxySvc: &api.AgentService{
				Port: 20000,
				Proxy: &api.AgentServiceConnectProxyConfig{
					Config: map[string]interface{}{
						"bind_port": 12000,
					},
				},
			},
			assertNftablesConfig: func(t *testing.T, cfg nftables.Config) {
				require.Equal(t, 12000, cfg.ProxyInboundPort)
			},
		},
		"outbound listener port present in proxy config": {
			cfg: &config.Config{
				TransparentProxy: config.TransparentProxyConfig{
					Enabled: true,
				},
			},
			proxySvc: &api.AgentService{
				Port: 20000,
				Proxy: &api.AgentServiceConnectProxyConfig{
					TransparentProxy: &api.TransparentProxyConfig{
						OutboundListenerPort: 12000,
					},
				},
			},
			assertNftablesConfig: func(t *testing.T, cfg nftables.Config) {
				require.Equal(t, 12000, cfg.ProxyOutboundPort)
			},
		},
		"envoy_stats_bind_addr port, envoy_prometheus_bind_addr port, expose path ports and user specified inbound ports should be excluded": {
			cfg: &config.Config{
				TransparentProxy: config.TransparentProxyConfig{
					Enabled:             true,
					ExcludeInboundPorts: []int{1234, 5678, 8901},
				},
			},
			proxySvc: &api.AgentService{
				Port: 20000,
				Proxy: &api.AgentServiceConnectProxyConfig{
					Config: map[string]interface{}{
						"envoy_prometheus_bind_addr": "0.0.0.0:9090",
						"envoy_stats_bind_addr":      "0.0.0.0:8080",
					},
					Expose: api.ExposeConfig{
						Paths: []api.ExposePath{
							{
								ListenerPort: 14000,
							},
							{
								ListenerPort: 15000,
							},
						},
					},
				},
			},
			assertNftablesConfig: func(t *testing.T, cfg nftables.Config) {
				expectedPorts := []string{
					"1234",
					"5678",
					"8901",
					"14000",
					"15000",
					"9090",  // Prometheus server port
					"8080",  // Envoy stats bind port
					"22000", //Proxy health check port
				}
				for _, port := range cfg.ExcludeInboundPorts {
					require.Contains(t, expectedPorts, port)
				}
			},
		},
		"user specified outbound ports should be excluded": {
			cfg: &config.Config{
				TransparentProxy: config.TransparentProxyConfig{
					Enabled:              true,
					ExcludeOutboundPorts: []int{1234, 5678, 8901},
				},
			},
			proxySvc: &api.AgentService{
				Port:  20000,
				Proxy: &api.AgentServiceConnectProxyConfig{},
			},
			assertNftablesConfig: func(t *testing.T, cfg nftables.Config) {
				expectedPorts := []string{
					"1234",
					"5678",
					"8901",
				}
				for _, port := range cfg.ExcludeOutboundPorts {
					require.Contains(t, expectedPorts, port)
				}
			},
		},
		"user specified UIDs should be excluded": {
			cfg: &config.Config{
				TransparentProxy: config.TransparentProxyConfig{
					Enabled:     true,
					ExcludeUIDs: []string{"1234", "5678"},
				},
			},
			proxySvc: &api.AgentService{
				Port:  20000,
				Proxy: &api.AgentServiceConnectProxyConfig{},
			},
			assertNftablesConfig: func(t *testing.T, cfg nftables.Config) {
				expectedUIDs := []string{
					"1234",
					"5678",
					"5996", // Health sync container UID
				}
				for _, uid := range cfg.ExcludeUIDs {
					require.Contains(t, expectedUIDs, uid)
				}
			},
		},
		"user specified CIDRs should be excluded": {
			cfg: &config.Config{
				TransparentProxy: config.TransparentProxyConfig{
					Enabled:              true,
					ExcludeOutboundCIDRs: []string{"1.1.1.1/24", "2.2.2.2/24"},
				},
			},
			proxySvc: &api.AgentService{
				Port:  20000,
				Proxy: &api.AgentServiceConnectProxyConfig{},
			},
			assertNftablesConfig: func(t *testing.T, cfg nftables.Config) {
				expectedCIDRs := []string{
					"1.1.1.1/24",
					"2.2.2.2/24",
				}
				for _, cidr := range cfg.ExcludeOutboundCIDRs {
					require.Contains(t, expectedCIDRs, cidr)
				}
			},
		},
		"Consul DNS enabled": {
			cfg: &config.Config{
				TransparentProxy: config.TransparentProxyConfig{
					Enabled: true,
					ConsulDNS: config.ConsulDNS{
						Enabled: true,
					},
				},
			},
			proxySvc: &api.AgentService{
				Port:  20000,
				Proxy: &api.AgentServiceConnectProxyConfig{},
			},
			assertNftablesConfig: func(t *testing.T, cfg nftables.Config) {
				require.Equal(t, config.ConsulDataplaneDNSBindHost, cfg.ConsulDNSIP)
				require.Equal(t, config.ConsulDataplaneDNSBindPort, cfg.ConsulDNSPort)
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			nftablesProvider := &mockNftablesProvider{}
			provider := New(c.cfg,
				c.proxySvc,
				[]int{22000},
				WithNftablesProvider(nftablesProvider),
			)

			err := provider.Apply()
			if c.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Truef(t, nftablesProvider.applyCalled, "redirect traffic rules were not applied")

				// Regression guard: nftables (unlike legacy iptables) doesn't
				// pre-create any tables/chains, so the "ip nat" table must be
				// created before its POSTROUTING chain is added. Omitting the
				// "add table" step fails at runtime with "No such file or
				// directory" (confirmed against a real ECS EC2 instance).
				require.Contains(t, nftablesProvider.Rules(), "add table ip nat")
				require.Contains(t, nftablesProvider.Rules(),
					"add chain ip nat POSTROUTING { type nat hook postrouting priority 100 ; policy accept ; }")

				if c.assertNftablesConfig != nil {
					c.assertNftablesConfig(t, provider.Config())
				}
			}
		})
	}
}

type mockNftablesProvider struct {
	applyCalled bool
	rules       []string
}

func (f *mockNftablesProvider) AddRule(_ string, args ...string) {
	f.rules = append(f.rules, strings.Join(args, " "))
}

func (f *mockNftablesProvider) ApplyRules(_ string) error {
	f.applyCalled = true
	return nil
}

func (f *mockNftablesProvider) Rules() []string {
	return f.rules
}

func (f *mockNftablesProvider) ClearAllRules() {
	f.rules = nil
}
