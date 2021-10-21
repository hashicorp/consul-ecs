//go:build !windows
// +build !windows

package entrypoint

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/go-hclog"
)

func (c *Command) Run(args []string) int {
	c.log = hclog.New(nil)

	if len(args) == 0 {
		c.UI.Error("command is required")
		return 1
	}

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
	// unit testing hack
	c.pid = cmd.Process.Pid

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	var killOnce sync.Once
	killSubprocess := func() {
		killOnce.Do(func() {
			c.log.Info("Killing subprocess")
			// Negative PID signals the process group.
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		})
	}

	defer func() {
		// Ensure goroutines are cancelled before waiting on them.
		cancel()
		killSubprocess()
		wg.Wait()
	}()

	// Forward all signals to the child process, except certain ones (SIGTERM, SIGCHLD).
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.forwardSignals(ctx, cmd.Process)
	}()
	// After sigterm, wait for application containers to exit, and call the given cleanup function.
	go func() {
		defer wg.Done()
		c.shutdownAfterSigterm(ctx, killSubprocess)
	}()

	err = cmd.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Skip logging an error if it's only a non-zero exit code.
			return exitErr.ExitCode()
		}
		c.log.Error(err.Error())
	}
	// "returns the exit code of the exited process, or -1
	// if the process hasn't exited or was terminated by a signal."
	return cmd.ProcessState.ExitCode()
}

func (c *Command) forwardSignals(ctx context.Context, proc *os.Process) {
	sigs := make(chan os.Signal, 1)
	// Intercept all signals
	signal.Notify(sigs)
	defer signal.Stop(sigs)

	for {
		select {
		case <-ctx.Done():
			// Allow cancelling this loop.
			return
		case sig := <-sigs:
			if sig == syscall.SIGTERM || sig == syscall.SIGCHLD {
				// Ignore SIGTERM so that Envoy continues running into Task shutdown
				c.log.Debug("ignoring", "signal", sig)
			} else {
				// Forward all other signals to the child.
				c.log.Debug("forwarding", "signal", sig)
				err := proc.Signal(sig)
				if err != nil {
					c.log.Error("forwarding", "signal", sig, "err", err.Error())
				}
			}
		}
	}
}

func (c *Command) shutdownAfterSigterm(ctx context.Context, cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	defer signal.Stop(sigs)

	// Wait for SIGTERM.
	var sig os.Signal
	for sig != syscall.SIGTERM {
		select {
		case <-ctx.Done():
			return
		case sig = <-sigs:
		}
	}

	// Poll task metadata to wait for application containers to exit.
	nonAppContainers := []string{"consul-client", "sidecar-proxy", "health-sync", "mesh-init"}
	isAppContainer := func(container awsutil.ECSTaskMetaContainer) bool {
		for _, ignoreName := range nonAppContainers {
			if container.Name == ignoreName {
				return false
			}
		}
		return true
	}

	c.log.Info("waiting for application to shutdown")
	for {
		select {
		case <-ctx.Done():
			// Allow cancelling this loop.
			return
		case <-time.After(1 * time.Second):
			taskMeta, err := awsutil.ECSTaskMetadata()
			if err != nil {
				c.log.Error("fetching task metadata", "err", err.Error())
			} else {
				var appContainers []awsutil.ECSTaskMetaContainer
				for _, container := range taskMeta.Containers {
					if isAppContainer(container) {
						appContainers = append(appContainers, container)
					}
				}

				doneWaiting := true
				for _, container := range appContainers {
					// We're in Task shutdown, so we'd expect DesiredStatus to be stopped for all containers.
					if container.DesiredStatus == "STOPPED" && container.KnownStatus == "STOPPED" {
						c.log.Info("app container has stopped", "name", container.Name, "status", container.KnownStatus)
					} else {
						c.log.Info("app container not yet stopped", "name", container.Name, "status", container.KnownStatus)
						doneWaiting = false
					}
				}

				if doneWaiting {
					c.log.Info("application container(s) have exited. terminating envoy")
					cancel()
					return
				}
			}
		}
	}
}
