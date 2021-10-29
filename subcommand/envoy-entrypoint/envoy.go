//go:build !windows
// +build !windows

package envoyentrypoint

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/hashicorp/go-hclog"
)

type EnvoyCmd struct {
	*exec.Cmd

	log       hclog.Logger
	doneCh    chan struct{}
	startedCh chan struct{}
}

func NewEnvoyCmd(log hclog.Logger, args []string) *EnvoyCmd {
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
		log:       log,
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
		e.log.Error("starting Envoy process", "error", err.Error())
		// Closed channels (in defers) indicate the command failed to start.
		return
	}
	e.startedCh <- struct{}{}

	if err := e.Cmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			// Do not log if it is only a non-zero exit code.
			e.log.Error("waiting for Envoy process to finish", "error", err.Error())
		}
	}
	e.doneCh <- struct{}{}
}

func (e *EnvoyCmd) Started() chan struct{} {
	return e.startedCh
}

func (e *EnvoyCmd) Done() chan struct{} {
	return e.doneCh
}
