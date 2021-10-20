// Package entrypoint
//
// This is intended for used as a Docker entrypoint for Envoy:
// * Run a given command in a subprocess
// * Forward all signals to the subprocess, except for SIGTERM

package entrypoint

import (
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

type Command struct {
	UI cli.Ui

	log hclog.Logger
}

func (c *Command) Help() string {
	return ""
}

func (c *Command) Synopsis() string {
	return "Custom entrypoint for starting Envoy in ECS"
}
