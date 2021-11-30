//go:build windows
// +build windows

// Not implemented for Windows.
// Our Unix implementation doesn't compile on Windows, and we only need to support
// Linux since this is an entrypoint to a Docker container.

package appentrypoint

import (
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

type Command struct {
	UI  cli.Ui
	log hclog.Logger
}

func (c *Command) Run(args []string) int {
	c.UI.Error("not implemented on Windows")
	return 1
}
