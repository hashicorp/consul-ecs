package testutil

import (
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/stretchr/testify/require"
)

type ServerConfigCallback = testutil.ServerConfigCallback

const AdminToken = "123e4567-e89b-12d3-a456-426614174000"

// ConsulServer initializes a Consul test server and returns Consul client config.
func ConsulServer(t *testing.T, cb ServerConfigCallback) (*api.Config, config.ConsulServers) {
	server, err := testutil.NewTestServerConfigT(t, cb)
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

	// Set CONSUL_HTTP_ADDR for control-plane. Required to invoke the consul binary as a subprocess.
	// TODO: consul binary is no longer needed for agentless, once we have consul-dataplane.
	require.NoError(t, os.Setenv("CONSUL_HTTP_ADDR", server.HTTPAddr))
	t.Cleanup(func() {
		_ = os.Unsetenv("CONSUL_HTTP_ADDR")
	})

	parts := strings.Split(cfg.Address, ":")
	require.Len(t, parts, 2)
	host := parts[0]

	t.Logf("consul server details: %#v", server)
	ecsConf := config.ConsulServers{
		Hosts:    host,
		HTTPS:    false,
		HTTPPort: server.Config.Ports.HTTP,
		GRPCPort: server.Config.Ports.GRPC,
	}
	return cfg, ecsConf
}

// ConsulACLConfigFn configures a Consul test server with ACLs.
func ConsulACLConfigFn(c *testutil.TestServerConfig) {
	c.ACL.Enabled = true
	c.ACL.Tokens.InitialManagement = AdminToken
	c.ACL.DefaultPolicy = "deny"
}
