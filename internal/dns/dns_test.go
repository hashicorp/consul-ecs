// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package dns

import (
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestConfigureConsulDNS(t *testing.T) {
	cases := map[string]struct {
		etcResolvConf   string
		assertDNSConfig func(*testing.T, *dns.ClientConfig)
	}{
		"empty /etc/resolv.conf file": {
			assertDNSConfig: func(t *testing.T, cfg *dns.ClientConfig) {
				require.Equal(t, 1, len(cfg.Servers))
				require.Contains(t, cfg.Servers, "127.0.0.1")
			},
		},
		"single nameserver": {
			etcResolvConf: `nameserver 1.1.1.1`,
			assertDNSConfig: func(t *testing.T, cfg *dns.ClientConfig) {
				require.Equal(t, 2, len(cfg.Servers))
				require.Contains(t, cfg.Servers, "127.0.0.1")
			},
		},
		"several nameservers, searches and options": {
			etcResolvConf: `
nameserver 1.1.1.1
nameserver 2.2.2.2
nameserver 3.3.3.3
nameserver 4.4.4.4
search foo.bar bar.baz bar.foo
options ndots:5 timeout:6 attempts:3`,
			assertDNSConfig: func(t *testing.T, cfg *dns.ClientConfig) {
				require.Equal(t, 5, len(cfg.Servers))
				require.Contains(t, cfg.Servers, "127.0.0.1")
				require.Equal(t, 5, cfg.Ndots)
				require.Equal(t, 6, cfg.Timeout)
				require.Equal(t, 3, cfg.Attempts)
				require.Equal(t, 3, len(cfg.Search))
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			etcResolvFile, err := os.CreateTemp("", "")
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = os.Remove(etcResolvFile.Name())
			})
			_, err = etcResolvFile.WriteString(c.etcResolvConf)
			require.NoError(t, err)

			inp := &ConfigureConsulDNSInput{
				ETCResolvConfFile: etcResolvFile.Name(),
			}

			require.NoError(t, inp.ConfigureConsulDNS())

			// Assert the DNS config
			cfg, err := dns.ClientConfigFromFile(inp.ETCResolvConfFile)
			require.NoError(t, err)
			c.assertDNSConfig(t, cfg)
		})
	}
}
