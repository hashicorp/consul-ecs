// Package entrypoint
//
// This is intended for used as a Docker entrypoint for Envoy:
// * Run a given command in a subprocess
// * Forward all signals to the subprocess, except for SIGTERM
// * Monitor task metadata to terminate Envoy after application containers exit.

package envoyentrypoint

import (
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

type Command struct {
	UI cli.Ui

	log hclog.Logger

	// unit testing hack
	pid int
}

func (c *Command) Help() string {
	return ""
}

func (c *Command) Synopsis() string {
	return "Custom entrypoint for starting Envoy in ECS"
}
