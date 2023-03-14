// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package netdial

import (
	"net"

	"github.com/mitchellh/cli"
)

type Command struct {
	UI cli.Ui
}

func (c *Command) Run(args []string) int {
	if len(args) != 1 {
		c.UI.Error("invalid invocation, expected one positional argument: <host>:<port>")
		return 1
	}

	conn, err := net.Dial("tcp", args[0])
	if err != nil {
		return 2
	}
	conn.Close()

	return 0
}

func (c *Command) Synopsis() string {
	return "Checks for a TCP listener on a host"
}

func (c *Command) Help() string {
	return `usage: consul-ecs net-dial <host>:<port>

Attempts to open a TCP connection to <host>:<port>.
An exit code of 0 is returned if the connection succeeds.
A non zero exit code is returned if the connection fails for any reason.
`
}
