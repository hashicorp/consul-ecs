//go:build !windows
// +build !windows

package envoyentrypoint

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
	// TODO: Make log level a flag
	c.log = hclog.New(&hclog.LoggerOptions{
		Name:  "consul-ecs",
		Level: hclog.Info,
	})

	if len(args) == 0 {
		c.UI.Error("command is required")
		return 1
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		c.log.Debug("cancelling")
		cancel()
		c.log.Debug("waiting for goroutines")
		wg.Wait()
		c.log.Debug("done waiting for goroutines")
	}()

	cmd := c.makeCommand(ctx, args)
	exitCodeChan := make(chan int, 1)
	pidChan := make(chan int, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runCommand(cmd, exitCodeChan, pidChan)
	}()

	// Wait for the subprocess to start.
	if pid, ok := <-pidChan; !ok {
		c.log.Error("could not run command")
		return -1
	} else {
		c.log.Debug("subprocess started", "pid", pid)
		c.pid = pid // unit testing hack
	}

	// Forward all signals to the subprocess. Except SIGTERM.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs)
	defer signal.Stop(sigs)

	// On SIGTERM, spawn a goroutine that monitors for app containers to exit.
	// This channel lets us know the application containers have exited.
	appExitedChan := make(chan bool, 1)
	var once sync.Once

	for {
		select {
		case exitCode, ok := <-exitCodeChan:
			if ok {
				c.log.Debug("command exited", "exitCode", exitCode)
				return exitCode
			}
			return -1
		case sig := <-sigs:
			if sig == syscall.SIGTERM {
				// start monitoring task metadata
				c.log.Debug("received", "signal", sig)
				once.Do(func() {
					// ehh
					wg.Add(1)
					go func() {
						defer wg.Done()
						c.monitorTaskMeta(ctx, appExitedChan)
					}()
				})
			} else if sig == syscall.SIGCHLD || sig == syscall.SIGURG {
				// do not forward
			} else {
				c.log.Debug("forward signal", "sig", sig)
				if err := cmd.Process.Signal(sig); err != nil {
					c.log.Debug("forwarding signal", "err", err.Error())
				}
			}
		case <-appExitedChan:
			c.log.Debug("app containers done")
			return cmd.ProcessState.ExitCode()
		}
	}
}

func (c *Command) makeCommand(ctx context.Context, args []string) *exec.Cmd {
	// CommandContext allows cancelling the command.
	// When cancelled, the process is sent a SIGKILL and is not waited on.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Use a process group that we can signal for cleanup.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return cmd
}

// runCommand Runs the given command, and sends the exit code and process id on the given channels.
func (c *Command) runCommand(cmd *exec.Cmd, exitCodeCh chan int, pidCh chan int) {
	defer close(exitCodeCh)
	defer close(pidCh)

	c.log.Debug("starting subprocess", "path", cmd.Path, "args", cmd.Args)
	if err := cmd.Start(); err != nil {
		c.log.Debug("cmd.Start() returned error", "err", err.Error())
		// Channels are closed in defers to indicate that the command did not start.
		return
	} else {
		pidCh <- cmd.Process.Pid
	}

	if err := cmd.Wait(); err != nil {
		c.log.Debug("cmd.Wait() returned error", "err", err.Error())
		exitCodeCh <- cmd.ProcessState.ExitCode()
	} else {
		exitCodeCh <- 0
	}
	// Kill the process group to try to clean up leftover sub-processes.
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	if err != nil {
		c.log.Debug("killing process group", "err", err.Error())
	}
}

func (c *Command) monitorTaskMeta(ctx context.Context, done chan bool) {
	defer close(done)

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
				break // escape this case of the select
			}

			doneWaiting := true
			for _, container := range taskMeta.Containers {
				if !isAppContainer(container) {
					continue
				}

				// We're in Task shutdown, so we'd expect DesiredStatus to be stopped for all containers.
				if container.DesiredStatus == "STOPPED" && container.KnownStatus == "STOPPED" {
					c.log.Debug("app container has stopped", "name", container.Name, "status", container.KnownStatus)
				} else {
					c.log.Debug("app container not yet stopped", "name", container.Name, "status", container.KnownStatus)
					doneWaiting = false
				}
			}

			if doneWaiting {
				c.log.Debug("application container(s) have exited. terminating envoy")
				done <- true
				return
			}
		}
	}
}
