//go:build !windows
// +build !windows

package envoyentrypoint

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/hashicorp/consul-ecs/entrypoint"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

type Command struct {
	UI   cli.Ui
	log  hclog.Logger
	once sync.Once

	sigs       chan os.Signal
	ctx        context.Context
	cancel     context.CancelFunc
	envoyCmd   *entrypoint.Cmd
	appMonitor *AppContainerMonitor
}

func (c *Command) init() {
	c.log = hclog.New(&hclog.LoggerOptions{Name: "consul-ecs"})
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)

	if len(args) == 0 {
		c.UI.Error("command is required")
		return 1
	}

	c.sigs = make(chan os.Signal, 1)
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.envoyCmd = entrypoint.NewCmd(c.log, args)
	c.appMonitor = NewAppContainerMonitor(c.log, c.ctx)

	return c.realRun()
}

func (c *Command) realRun() int {
	signal.Notify(c.sigs)
	defer c.cleanup()

	// Run Envoy in the background.
	go c.envoyCmd.Run()
	// The appMonitor wakes up on SIGTERM to poll task metadata. It is done
	// when the application container(s) stop, or when it is cancelled.
	go c.appMonitor.Run()

	// Wait for Envoy to start.
	if _, ok := <-c.envoyCmd.Started(); !ok {
		c.log.Error("Envoy failed to start")
		return 1
	}

	for {
		select {
		case <-c.envoyCmd.Done():
			// When the Envoy process exits, we're done.
			return c.envoyCmd.ProcessState.ExitCode()
		case sig := <-c.sigs:
			c.handleSignal(sig)
		case _, ok := <-c.appMonitor.Done():
			// When the application containers stop (after SIGTERM), tell Envoy to exit.
			if ok {
				c.log.Info("terminating Envoy with sigterm")
				// A negative pid signals the process group to exit, to try to clean up subprocesses as well
				if err := syscall.Kill(-c.envoyCmd.Process.Pid, syscall.SIGTERM); err != nil {
					c.log.Warn("sending sigterm to Envoy", "error", err.Error())
				}
			}
		}
	}
}

func (c *Command) handleSignal(sig os.Signal) {
	switch sig {
	case syscall.SIGTERM, syscall.SIGCHLD, syscall.SIGURG:
		return
	default:
		if err := c.envoyCmd.Process.Signal(sig); err != nil {
			c.log.Warn("forwarding signal", "err", err.Error())
		}
	}
}

func (c *Command) cleanup() {
	signal.Stop(c.sigs)
	// Cancel background goroutines
	c.cancel()
	<-c.appMonitor.Done()
	<-c.envoyCmd.Done()
}
