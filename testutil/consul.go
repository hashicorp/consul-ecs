// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/logger"
)

type ServerConfigCallback = testutil.ServerConfigCallback

const AdminToken = "123e4567-e89b-12d3-a456-426614174000"

// ConsulServer initializes a Consul test server and returns Consul client config
// and the configured test server
func ConsulServer(t *testing.T, cb ServerConfigCallback) (*testutil.TestServer, *api.Config) {
	server, err := testutil.NewTestServerConfigT(t,
		func(c *testutil.TestServerConfig) {
			if cb != nil {
				cb(c)
			}
			// A "peering" config block is passed to the Consul, which causes a config parse error in Consul 1.12.
			// This ensures no "peering" config block is passed, so that Consul uses its defaults.
			c.Peering = nil
		},
	)

	require.NoError(t, err)
	t.Cleanup(func() {
		_ = server.Stop()
	})
	server.WaitForLeader(t)

	cfg := api.DefaultConfig()
	cfg.Address = server.HTTPAddr
	if server.Config.ACL.Enabled {
		cfg.Token = AdminToken
		client, err := api.NewClient(cfg)
		require.NoError(t, err)

		for {
			ready, err := isACLBootstrapped(client)
			require.NoError(t, err)
			if ready {
				break
			}

			logger.Warn("ACL system is not ready yet")
			time.Sleep(250 * time.Millisecond)
		}

		for {
			_, _, err = client.ACL().TokenReadSelf(nil)
			if err != nil {
				if isACLNotBootstrapped(err) {
					logger.Warn("system is rebooting", "error", err)
					time.Sleep(250 * time.Millisecond)
					continue
				}

				t.Fail()
			}
			break
		}
	}

	// Set CONSUL_HTTP_ADDR for mesh-init. Required to invoke the consul binary (i.e. in mesh-init).
	require.NoError(t, os.Setenv("CONSUL_HTTP_ADDR", server.HTTPAddr))
	t.Cleanup(func() {
		_ = os.Unsetenv("CONSUL_HTTP_ADDR")
	})

	return server, cfg
}

// ConsulACLConfigFn configures a Consul test server with ACLs.
func ConsulACLConfigFn(c *testutil.TestServerConfig) {
	c.ACL.Enabled = true
	c.ACL.Tokens.InitialManagement = AdminToken
	c.ACL.DefaultPolicy = "deny"
}

func GetHostAndPortFromAddress(address string) (string, int) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0
	}

	port, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		return "", 0
	}

	return host, int(port)
}

func isACLBootstrapped(client *api.Client) (bool, error) {
	policy, _, err := client.ACL().PolicyReadByName("global-management", nil)
	if err != nil {
		if strings.Contains(err.Error(), "Unexpected response code: 403 (ACL not found)") {
			return false, nil
		} else if isACLNotBootstrapped(err) {
			return false, nil
		}
		return false, err
	}
	return policy != nil, nil
}

func isACLNotBootstrapped(err error) bool {
	switch {
	case strings.Contains(err.Error(), "ACL system must be bootstrapped before making any requests that require authorization"):
		return true
	case strings.Contains(err.Error(), "The ACL system is currently in legacy mode"):
		return true
	}
	return false
}
