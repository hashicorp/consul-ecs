// Package entrypoint
//
// This is intended for used as a Docker entrypoint for Envoy:
// * Run a given command in a subprocess
// * Forward all signals to the subprocess, except for SIGTERM
// * Monitor task metadata to terminate Envoy after application container(s) stop

package envoyentrypoint

import (
	"context"
	"os"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

type Command struct {
	UI   cli.Ui
	log  hclog.Logger
	once sync.Once

	sigs       chan os.Signal
	wg         *sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	envoyCmd   *EnvoyCmd
	appMonitor *AppContainerMonitor
}

func (c *Command) init() {
	c.log = hclog.New(&hclog.LoggerOptions{Name: "consul-ecs"})
}

func (c *Command) Help() string {
	return ""
}

func (c *Command) Synopsis() string {
	return "Custom entrypoint for starting Envoy in ECS"
}
