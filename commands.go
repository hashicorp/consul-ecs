// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"

	"github.com/mitchellh/cli"

	cmdController "github.com/hashicorp/consul-ecs/subcommand/acl-controller"
	cmdAppEntrypoint "github.com/hashicorp/consul-ecs/subcommand/app-entrypoint"
	cmdEnvoyEntrypoint "github.com/hashicorp/consul-ecs/subcommand/envoy-entrypoint"
	cmdHealthSync "github.com/hashicorp/consul-ecs/subcommand/health-sync"
	cmdMeshInit "github.com/hashicorp/consul-ecs/subcommand/mesh-init"
	cmdNetDial "github.com/hashicorp/consul-ecs/subcommand/net-dial"
	cmdVersion "github.com/hashicorp/consul-ecs/subcommand/version"
	"github.com/hashicorp/consul-ecs/version"
)

// Commands is the mapping of all available consul-ecs commands.
var Commands map[string]cli.CommandFactory

func init() {
	ui := &cli.BasicUi{Writer: os.Stdout, ErrorWriter: os.Stderr}

	Commands = map[string]cli.CommandFactory{
		"version": func() (cli.Command, error) {
			if version.IsFIPS() {
				return &cmdVersion.Command{UI: ui, Version: version.GetHumanVersion(), FIPS: version.GetFIPSInfo()}, nil
			}
			return &cmdVersion.Command{UI: ui, Version: version.GetHumanVersion()}, nil
		},
		"mesh-init": func() (cli.Command, error) {
			return &cmdMeshInit.Command{UI: ui}, nil
		},
		"acl-controller": func() (cli.Command, error) {
			return &cmdController.Command{UI: ui}, nil
		},
		"health-sync": func() (cli.Command, error) {
			return &cmdHealthSync.Command{UI: ui}, nil
		},
		"envoy-entrypoint": func() (cli.Command, error) {
			return &cmdEnvoyEntrypoint.Command{UI: ui}, nil
		},
		"app-entrypoint": func() (cli.Command, error) {
			return &cmdAppEntrypoint.Command{UI: ui}, nil
		},
		"net-dial": func() (cli.Command, error) {
			return &cmdNetDial.Command{UI: ui}, nil
		},
	}
}

func helpFunc() cli.HelpFunc {
	// This should be updated for any commands we want to hide for any reason.
	// Hidden commands can still be executed if you know the command, but
	// aren't shown in any help output. We use this for prerelease functionality
	// or advanced features.
	hidden := map[string]struct{}{}

	var include []string
	for k := range Commands {
		if _, ok := hidden[k]; !ok {
			include = append(include, k)
		}
	}

	return cli.FilteredHelpFunc(include, cli.BasicHelpFunc("consul-ecs"))
}
