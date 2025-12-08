// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build !windows
// +build !windows

package entrypoint

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/hashicorp/go-hclog"
)

// Cmd runs a command in a subprocess (asynchronously).
// Call `go cmd.Run()` to run the command asynchronously.
// Use the Started() channel to wait for the command to start.
// Use the Done() channel to wait for the command to complete.
type Cmd struct {
	*exec.Cmd

	log       hclog.Logger
	doneCh    chan struct{}
	startedCh chan struct{}
}

func NewCmd(log hclog.Logger, args []string) *Cmd {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Use a process group that we can signal for cleanup.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	return &Cmd{
		Cmd:       cmd,
		log:       log,
		doneCh:    make(chan struct{}, 1),
		startedCh: make(chan struct{}, 1),
	}
}

// Run the command. The Started() and Done() functions can be used
// to wait for the process to start and exit, respectively.
func (e *Cmd) Run() {
	defer close(e.doneCh)
	defer close(e.startedCh)

	if err := e.Cmd.Start(); err != nil {
		e.log.Error("starting process", "error", err.Error())
		// Closed channels (in defers) indicate the command failed to start.
		return
	}
	e.startedCh <- struct{}{}

	if err := e.Cmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			// Do not log if it is only a non-zero exit code.
			e.log.Error("waiting for process to finish", "error", err.Error())
		}
	}
	e.doneCh <- struct{}{}
}

func (e *Cmd) Started() chan struct{} {
	return e.startedCh
}

func (e *Cmd) Done() chan struct{} {
	return e.doneCh
}
