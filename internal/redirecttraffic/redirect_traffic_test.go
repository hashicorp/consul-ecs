// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package redirecttraffic

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/iptables"
	"github.com/stretchr/testify/require"
)

func TestApply(t *testing.T) {
	cases := map[string]struct {
		wantErr              bool
		proxySvc             *api.AgentService
		cfg                  *config.Config
		assertIptablesConfig func(t *testing.T, actual iptables.Config)
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
				Proxy: &api.AgentServiceConnectProxyConfig{},
			},
			assertIptablesConfig: func(t *testing.T, cfg iptables.Config) {
				require.Equal(t, defaultProxyInboundPort, cfg.ProxyInboundPort)
				require.Equal(t, iptables.DefaultTProxyOutboundPort, cfg.ProxyOutboundPort)
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
				Proxy: &api.AgentServiceConnectProxyConfig{
					Config: map[string]interface{}{
						"bind_port": 12000,
					},
				},
			},
			assertIptablesConfig: func(t *testing.T, cfg iptables.Config) {
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
				Proxy: &api.AgentServiceConnectProxyConfig{
					TransparentProxy: &api.TransparentProxyConfig{
						OutboundListenerPort: 12000,
					},
				},
			},
			assertIptablesConfig: func(t *testing.T, cfg iptables.Config) {
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
			assertIptablesConfig: func(t *testing.T, cfg iptables.Config) {
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
				Proxy: &api.AgentServiceConnectProxyConfig{},
			},
			assertIptablesConfig: func(t *testing.T, cfg iptables.Config) {
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
				Proxy: &api.AgentServiceConnectProxyConfig{},
			},
			assertIptablesConfig: func(t *testing.T, cfg iptables.Config) {
				expectedUIDs := []string{
					"1234",
					"5678",
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
				Proxy: &api.AgentServiceConnectProxyConfig{},
			},
			assertIptablesConfig: func(t *testing.T, cfg iptables.Config) {
				expectedCIDRs := []string{
					"1.1.1.1/24",
					"2.2.2.2/24",
					"172.67.89.20/32",
					"169.254.170.2/32",
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
				Proxy: &api.AgentServiceConnectProxyConfig{},
			},
			assertIptablesConfig: func(t *testing.T, cfg iptables.Config) {
				require.Equal(t, config.ConsulDataplaneDNSBindHost, cfg.ConsulDNSIP)
				require.Equal(t, config.ConsulDataplaneDNSBindPort, cfg.ConsulDNSPort)
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(awsutil.ECSMetadataURIEnvVar, "http://169.254.170.2/v4/task_id")
			iptablesProvider := &mockIptablesProvider{}
			provider := New(c.cfg,
				c.proxySvc,
				"172.67.89.20",
				"arn:aws:ecs:us-east-1:123456789:cluster/test",
				22000,
				WithIPTablesProvider(iptablesProvider),
			)

			err := provider.Apply()
			if c.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Truef(t, iptablesProvider.applyCalled, "redirect traffic rules were not applied")

				if c.assertIptablesConfig != nil {
					c.assertIptablesConfig(t, provider.config())
				}
			}
		})
	}
}

type mockIptablesProvider struct {
	applyCalled bool
	rules       []string
}

func (f *mockIptablesProvider) AddRule(_ string, args ...string) {
	f.rules = append(f.rules, strings.Join(args, " "))
}

func (f *mockIptablesProvider) ApplyRules() error {
	f.applyCalled = true
	return nil
}

func (f *mockIptablesProvider) Rules() []string {
	return f.rules
}
