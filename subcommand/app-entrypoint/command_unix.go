//go:build !windows
// +build !windows

package appentrypoint

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/consul-ecs/entrypoint"
	"github.com/hashicorp/consul-ecs/logging"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

const (
	flagShutdownDelay = "shutdown-delay"
)

type Command struct {
	UI      cli.Ui
	log     hclog.Logger
	once    sync.Once
	flagSet *flag.FlagSet

	sigs          chan os.Signal
	appCmd        *entrypoint.Cmd
	shutdownDelay time.Duration

	logging.LogOpts
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.DurationVar(&c.shutdownDelay, flagShutdownDelay, 0,
		`Continue running for this long after receiving SIGTERM. Must be a duration (e.g. "10s").`)
	logging.Merge(c.flagSet, c.LogOpts.Flags())
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)

	// Flag parsing stops just before the first non-flag argument ("-" is a non-flag argument)
	// or after the terminator "--"
	if err := c.flagSet.Parse(args); err != nil {
		c.UI.Error(fmt.Sprint(err))
		return 1
	}

	c.log = c.LogOpts.Logger().Named("consul-ecs")

	// Remaining args for the application command, after parsing our flags
	args = c.flagSet.Args()

	if len(args) == 0 {
		c.UI.Error("command is required")
		return 1
	}

	c.sigs = make(chan os.Signal, 1)
	c.appCmd = entrypoint.NewCmd(c.log, args)

	return c.realRun()
}

func (c *Command) realRun() int {
	signal.Notify(c.sigs)
	defer c.cleanup()

	go c.appCmd.Run()
	if _, ok := <-c.appCmd.Started(); !ok {
		return 1
	}

	if exitCode, exited := c.waitForSigterm(); exited {
		return exitCode
	}
	if c.shutdownDelay > 0 {
		c.log.Info(fmt.Sprintf("received sigterm. waiting %s before terminating application.", c.shutdownDelay))
		if exitCode, exited := c.waitForShutdownDelay(); exited {
			return exitCode
		}
	}
	// We've signaled for the process to exit, so wait until it does.
	c.waitForAppExit()
	return c.appCmd.ProcessState.ExitCode()
}

// waitForSigterm waits until c.appCmd has exited, or until a sigterm is received.
// It returns (exitCode, exited), where if exited=true, then c.appCmd has exited.
func (c *Command) waitForSigterm() (int, bool) {
	for {
		select {
		case <-c.appCmd.Done():
			return c.appCmd.ProcessState.ExitCode(), true
		case sig := <-c.sigs:
			if sig == syscall.SIGTERM {
				return -1, false
			}
			c.forwardSignal(sig)
		}
	}
}

// waitForShutdownDelay waits for c.appCmd to exit for `delay` seconds.
// After the delay has passed, it sends a sigterm to c.appCmd.
// It returns (exitCode, exited), where if exited=true, then c.appCmd has exited.
func (c *Command) waitForShutdownDelay() (int, bool) {
	timer := time.After(c.shutdownDelay)
	for {
		select {
		case <-c.appCmd.Done():
			return c.appCmd.ProcessState.ExitCode(), true
		case sig := <-c.sigs:
			c.forwardSignal(sig)
		case <-timer:
			if err := syscall.Kill(-c.appCmd.Process.Pid, syscall.SIGTERM); err != nil {
				c.log.Warn("error sending sigterm to application", "error", err.Error())
			}
		}
	}

}

func (c *Command) waitForAppExit() {
	for {
		select {
		case <-c.appCmd.Done():
			return
		case sig := <-c.sigs:
			c.forwardSignal(sig)
		}
	}
}

func (c *Command) forwardSignal(sig os.Signal) {
	switch sig {
	case syscall.SIGCHLD, syscall.SIGURG:
		return
	default:
		if err := c.appCmd.Process.Signal(sig); err != nil {
			c.log.Warn("forwarding signal", "err", err.Error())
		}
	}
}

func (c *Command) cleanup() {
	signal.Stop(c.sigs)
	<-c.appCmd.Done()
}
