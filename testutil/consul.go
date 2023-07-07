// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/stretchr/testify/require"
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
		cfg.Token = server.Config.ACL.Tokens.InitialManagement
	}

	// Set CONSUL_HTTP_ADDR for control-plane. Required to invoke the consul binary (i.e. in control-plane).
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
