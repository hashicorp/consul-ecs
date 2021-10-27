package envoyentrypoint

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

type EnvoyCmd struct {
	*exec.Cmd

	ExitCodeCh chan int
	PidCh      chan int
}

func NewEnvoyCmd(ctx context.Context, args []string) *EnvoyCmd {
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

	return &EnvoyCmd{
		Cmd:        cmd,
		ExitCodeCh: make(chan int, 1),
		PidCh:      make(chan int, 1),
	}
}

// Run the command. The process id and exit code of the process, once known,
// will be sent on the PidCh and ExitCodeCh channels, respectively.
func (e *EnvoyCmd) Run(wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	defer close(e.ExitCodeCh)
	defer close(e.PidCh)

	if err := e.Cmd.Start(); err != nil {
		// Closed channels indicate the command failed to start.
		return
	}
	e.PidCh <- e.Cmd.Process.Pid

	if err := e.Cmd.Wait(); err != nil {
		e.ExitCodeCh <- e.Cmd.ProcessState.ExitCode()
	} else {
		e.ExitCodeCh <- 0
	}

	// Signal the process group to exit, to try to clean up subprocesses.
	_ = syscall.Kill(-e.Cmd.Process.Pid, syscall.SIGTERM)
}
