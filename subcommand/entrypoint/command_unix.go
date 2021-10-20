//go:build !windows
// +build !windows

package entrypoint

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/hashicorp/go-hclog"
)

func (c *Command) Run(args []string) int {
	c.log = hclog.New(nil)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Use a process group that we can signal for cleanup.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	c.log.Info("Spawning sub-process", "cmd", args)
	err := cmd.Start()
	if err != nil {
		c.log.Error(err.Error())
		return 1
	}

	// Forward all signals to the child process, except certain ones (SIGTERM, SIGCHLD).
	ctx, cancel := context.WithCancel(context.Background())
	c.forwardSignals(ctx, cmd.Process)

	defer func() {
		// Cancel signal forwarding.
		c.log.Debug("Cleaning up")
		cancel()
		// Negative PID signals the process group.
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		if err != nil {
			c.log.Debug("Error killing process group", "err", err.Error())
		}
	}()

	err = cmd.Wait()
	if err != nil {
		// Skip logging an error if it's just a non-zero exit code.
		if _, ok := err.(*exec.ExitError); !ok {
			c.log.Error(err.Error())
		}
	}
	return cmd.ProcessState.ExitCode()
}

func (c *Command) forwardSignals(ctx context.Context, procs ...*os.Process) {
	sigs := make(chan os.Signal, 1)
	// Intercept all signals
	signal.Notify(sigs)

	go func() {
		defer signal.Stop(sigs)
		for {
			select {
			case <-ctx.Done():
				return
			case sig := <-sigs:
				if sig == syscall.SIGTERM || sig == syscall.SIGCHLD {
					// Ignore SIGTERM so that Envoy continues running into Task shutdown
					c.log.Info("ignoring", "signal", sig)
				} else {
					// Forward all other signals to the child.
					c.log.Debug("forwarding", "signal", sig)
					for _, proc := range procs {
						err := proc.Signal(sig)
						if err != nil {
							c.log.Error("forwarding", "signal", sig, "err", err.Error())
						}
					}
				}
			}
		}
	}()
}
