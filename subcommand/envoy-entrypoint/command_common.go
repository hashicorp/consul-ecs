// Package envoyentrypoint
//
// This is intended to be used a Docker entrypoint for Envoy:
// * Run Envoy in a subprocess
// * Forward all signals to the subprocess, except for SIGTERM
// * Monitor task metadata to terminate Envoy after application container(s) stop
package envoyentrypoint

import (
	"github.com/hashicorp/go-hclog"
)

func (c *Command) init() {
	c.log = hclog.New(&hclog.LoggerOptions{Name: "consul-ecs"})
}

func (c *Command) Help() string {
	return ""
}

func (c *Command) Synopsis() string {
	return "Entrypoint for running Envoy in ECS"
}
