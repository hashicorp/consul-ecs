// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package appentrypoint

func (c *Command) Help() string {
	return ""
}

func (c *Command) Synopsis() string {
	return "Entrypoint for running a command in ECS"
}
