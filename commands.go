package main

import (
	"os"

	cmdDiscoverServers "github.com/hashicorp/consul-ecs/subcommand/discover-servers"
	cmdHealthSync "github.com/hashicorp/consul-ecs/subcommand/health-sync"
	cmdMeshInit "github.com/hashicorp/consul-ecs/subcommand/mesh-init"
	cmdVersion "github.com/hashicorp/consul-ecs/subcommand/version"
	cmdPglassApp "github.com/hashicorp/consul-ecs/subcommand/pglass-app"
	"github.com/hashicorp/consul-ecs/version"
	"github.com/mitchellh/cli"
)

// Commands is the mapping of all available consul-ecs commands.
var Commands map[string]cli.CommandFactory

func init() {
	ui := &cli.BasicUi{Writer: os.Stdout, ErrorWriter: os.Stderr}

	Commands = map[string]cli.CommandFactory{
		"version": func() (cli.Command, error) {
			return &cmdVersion.Command{UI: ui, Version: version.GetHumanVersion()}, nil
		},
		"mesh-init": func() (cli.Command, error) {
			return &cmdMeshInit.Command{UI: ui}, nil
		},
		"discover-servers": func() (cli.Command, error) {
			return &cmdDiscoverServers.Command{UI: ui}, nil
		},
		"health-sync": func() (cli.Command, error) {
			return &cmdHealthSync.Command{UI: ui}, nil
		},
		"pglass-app": func() (cli.Command, error) {
			return &cmdPglassApp.Command{UI: ui}, nil
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
