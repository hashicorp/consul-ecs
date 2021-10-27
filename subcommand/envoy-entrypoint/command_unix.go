//go:build !windows
// +build !windows

package envoyentrypoint

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)

	if len(args) == 0 {
		c.UI.Error("command is required")
		return 1
	}

	c.sigs = make(chan os.Signal, 1)
	c.wg = &sync.WaitGroup{}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.envoyCmd = NewEnvoyCmd(c.ctx, args)
	c.appMonitor = NewAppContainerMonitor(c.log, c.ctx)

	return c.realRun()
}

func (c *Command) realRun() int {
	signal.Notify(c.sigs)
	defer c.cleanup()

	// Run Envoy in the background, cancellable via the context.
	go c.envoyCmd.Run(c.wg)

	// Wait for Envoy to start.
	if _, ok := <-c.envoyCmd.PidCh; !ok {
		c.log.Error("Envoy failed to start")
		return 1
	}

	for {
		select {
		case exitCode, ok := <-c.envoyCmd.ExitCodeCh:
			// When the Envoy process exits, we're done.
			if ok {
				return exitCode
			}
			return -1
		case sig := <-c.sigs:
			c.handleSignal(sig)
		case <-c.appMonitor.Done():
			// When the application containers stop (after SIGTERM), we're done.
			return 0
		}
	}
}

func (c *Command) handleSignal(sig os.Signal) {
	if sig == syscall.SIGTERM {
		c.log.Info("received", "signal", sig)
		go c.appMonitor.Run(c.wg)
	} else if sig == syscall.SIGCHLD || sig == syscall.SIGURG {
		// do not forward
	} else if err := c.envoyCmd.Process.Signal(sig); err != nil {
		c.log.Warn("forwarding signal", "err", err.Error())
	}
}

func (c *Command) cleanup() {
	signal.Stop(c.sigs)
	// Cancel the command and background goroutines.
	c.cancel()
	c.wg.Wait()
}
