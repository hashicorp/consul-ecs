package pglassapp

import (
	"flag"
	"fmt"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

const (
	flagClient = "client"
	flagServer = "server"
	flagHost = "host"
	flagPort = "port"
)

type Command struct {
	UI      cli.Ui

	flagClient bool
	flagServer bool

	flagHost string
	flagPort int

	flagSet *flag.FlagSet
	log hclog.Logger

	once sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.BoolVar(&c.flagServer, flagServer, false, "Run the server")
	c.flagSet.BoolVar(&c.flagClient, flagClient, false, "Run the client")
	c.flagSet.StringVar(&c.flagHost, flagHost, "127.0.0.1", "Bind host (server), or server host (client)")
	c.flagSet.IntVar(&c.flagPort, flagPort, 7123, "Bind port (server), or server port (client)")

	c.log = hclog.New(nil)
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)
	if err := c.flagSet.Parse(args); err != nil {
		 return 1
	}

	if !c.flagClient && !c.flagServer {
		c.UI.Error(fmt.Sprintf("-%s or -%s is required", flagClient, flagServer))
		return 1
	}


	if c.flagHost == "" {
		c.UI.Error(fmt.Sprintf("-%s is required", flagHost))
	}

	if c.flagPort == 0 {
		c.UI.Error(fmt.Sprintf("-%s must have non-zero port", flagPort))
		return 1
	}

	err := c.realMain()
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	return 0
}

func (c *Command) realMain() error {
	if c.flagServer {
		return c.serverMain()
	} else {
		return c.clientMain()
	}
}

func (c *Command) Synopsis() string {
	return "Test server/client for pglass"
}

func (c *Command) Help() string {
	return ""
}