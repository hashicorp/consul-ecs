// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package netdial

import (
	"fmt"
	"net"

	"github.com/mitchellh/cli"
)

type Command struct {
	UI cli.Ui
}

func (c *Command) Run(args []string) int {
	if len(args) != 2 {
		c.UI.Error("invalid invocation, expected two positional args: <host> <port>")
		return 1
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", args[0], args[1]))
	if err != nil {
		return 1
	}
	conn.Close()

	return 0
}

func (c *Command) Synopsis() string {
	return "Performs a simple health check by opening a TCP connection to a host and port"
}

func (c *Command) Help() string {
	return `usage: consul-ecs net-dial <host> <port>

Attempts to open a TCP connection to <host>:<port>.
It returns with an exit code of 0 if the connection succeeds.
If the connection fails for any reason, an exit code of 1 is returned.
`
}
