//go:build !windows
// +build !windows

package envoyentrypoint

import (
	"os"
	"os/exec"
	"syscall"
)

type EnvoyCmd struct {
	*exec.Cmd

	doneCh    chan struct{}
	startedCh chan struct{}
}

func NewEnvoyCmd(args []string) *EnvoyCmd {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Use a process group that we can signal for cleanup.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	return &EnvoyCmd{
		Cmd:       cmd,
		doneCh:    make(chan struct{}, 1),
		startedCh: make(chan struct{}, 1),
	}
}

// Run the command. The Started() and Done() functions can be used
// to wait for the process to start and exit, respectively.
func (e *EnvoyCmd) Run() {
	defer close(e.doneCh)
	defer close(e.startedCh)

	if err := e.Cmd.Start(); err != nil {
		// Closed channels (in defers) indicate the command failed to start.
		return
	}
	e.startedCh <- struct{}{}

	_ = e.Cmd.Wait()
	e.doneCh <- struct{}{}

	// Signal the process group to exit, to try to clean up subprocesses.
	_ = syscall.Kill(-e.Cmd.Process.Pid, syscall.SIGTERM)
}

func (e *EnvoyCmd) Started() chan struct{} {
	return e.startedCh
}

func (e *EnvoyCmd) Done() chan struct{} {
	return e.doneCh
}
