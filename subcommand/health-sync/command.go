// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/logging"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/cli"
)

type Command struct {
	UI     cli.Ui
	config *config.Config
	log    hclog.Logger
}

func (c *Command) Run(args []string) int {
	if len(args) > 0 {
		c.UI.Error(fmt.Sprintf("unexpected argument: %s", args[0]))
		return 1
	}

	conf, err := config.FromEnv()
	if err != nil {
		c.UI.Error(fmt.Sprintf("invalid config: %s", err))
		return 1
	}
	c.config = conf

	c.log = logging.FromConfig(c.config).Logger()

	cfg := api.DefaultConfig()
	if c.config.ConsulLogin.Enabled {
		// This file will already have been written by mesh-init.
		cfg.TokenFile = filepath.Join(c.config.BootstrapDir, config.ServiceTokenFilename)
	}

	consulClient, err := api.NewClient(cfg)
	if err != nil {
		c.UI.Error(fmt.Sprintf("constructing consul client: %s", err))
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())

	c.ignoreSIGTERM(cancel)

	if err := c.realRun(ctx, consulClient); err != nil {
		c.log.Error("error running main", "err", err)
		return 1
	}

	return 0
}

func (c *Command) realRun(ctx context.Context, consulClient *api.Client) error {
	<-ctx.Done()
	var result error
	if c.config.ConsulLogin.Enabled {
		if err := c.logout(config.ServiceTokenFilename); err != nil {
			result = multierror.Append(result, err)
		}
		if err := c.logout(config.ClientTokenFilename); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return result
}

// ignoreSIGTERM logs when the SIGTERM occurs and then calls the cancel context
// function
func (c *Command) ignoreSIGTERM(cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	// Don't need to do anything for now. Just catch the SIGTERM so we don't exit.
	// And, print when we receive the SIGTERM
	go func() {
		for sig := range sigs {
			c.log.Info("signal received, ignoring", "signal", sig)
			cancel()
		}
	}()
}

// logout calls POST /acl/logout to destroy the token in the given file.
// The given file should be relative path of a file in the bootstrap directory.
func (c *Command) logout(tokenFile string) error {
	tokenFile = filepath.Join(c.config.BootstrapDir, tokenFile)
	c.log.Info("log out token", "file", tokenFile)
	cfg := api.DefaultConfig()
	if c.config.ConsulHTTPAddr != "" {
		cfg.Address = c.config.ConsulHTTPAddr
	}
	if c.config.ConsulCACertFile != "" {
		cfg.TLSConfig.CAFile = c.config.ConsulCACertFile
	}
	cfg.TokenFile = tokenFile

	client, err := api.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("creating client for logout: %w", err)
	}
	_, err = client.ACL().Logout(nil)
	if err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}
	return nil
}

func (c *Command) Synopsis() string {
	return "Syncs ECS container health to Consul"
}

func (c *Command) Help() string {
	return ""
}
