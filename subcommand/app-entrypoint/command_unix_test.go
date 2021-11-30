//go:build !windows
// +build !windows

package appentrypoint

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func fakeAppScript(sleepSeconds int) string {
	return fmt.Sprintf(`sleep %d &
export SLEEP_PID=$!
trap "{ echo 'target command was interrupted'; kill $SLEEP_PID; exit 42; }" INT
trap "{ echo 'target command was terminated'; kill $SLEEP_PID; exit 55; }" TERM
wait $SLEEP_PID
`, sleepSeconds)
}

func TestFlagValidation(t *testing.T) {
	cases := map[string]struct {
		args          []string
		code          int
		error         string
		shutdownDelay time.Duration
	}{
		"no-args": {
			args:  nil,
			code:  1,
			error: "command is required",
		},
		"invalid-delay": {
			args:  []string{"--shutdown-delay", "asdf"},
			code:  1,
			error: `invalid value "asdf" for flag -shutdown-delay`,
		},
		"delay-without-app-command": {
			args:          []string{"--shutdown-delay", "10s"},
			code:          1,
			error:         "command is required",
			shutdownDelay: 10 * time.Second,
		},
		"app-command-with-flag-collision": {
			// What if the app command uses a flag that collides with one of our flags?
			args: []string{"/bin/sh", "-c", "echo", "--shutdown-delay", "asdf"},
			code: 0,
		},
		"delay-with-app-command": {
			args:          []string{"--shutdown-delay", "5s", "/bin/sh", "-c", "exit 0"},
			code:          0,
			shutdownDelay: 5 * time.Second,
		},
		"delay-with-app-command-and-double-dash": {
			// "--" terminates flag parsing, to separate consul-ecs from application args
			args:          []string{"--shutdown-delay", "5s", "--", "/bin/sh", "-c", "exit 0"},
			code:          0,
			shutdownDelay: 5 * time.Second,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ui := cli.NewMockUi()
			cmd := Command{UI: ui}
			code := cmd.Run(c.args)
			require.Equal(t, c.code, code)
			require.Contains(t, ui.ErrorWriter.String(), c.error)
			require.Equal(t, cmd.shutdownDelay, c.shutdownDelay)
		})
	}
}

func TestRun(t *testing.T) {
	cases := map[string]struct {
		targetCommand string
		sendSigterm   bool
		sendSigint    bool
		shutdownDelay time.Duration
		exitCode      int
	}{
		"app-exit-before-sigterm": {
			targetCommand: "exit 0",
		},
		"app-exit-after-sigterm": {
			// T0 : app start
			// T1 : entrypoint receives sigterm (ignored)
			// T2 : app exits on its own
			targetCommand: fakeAppScript(2),
			sendSigterm:   true,
		},
		"app-exit-before-shutdown-delay": {
			// T0 : app start
			// T1 : entrypoint receives sigterm (ignored)
			// T2 : entrypoint waits for the shutdown delay
			// T3 : app exits on its own
			targetCommand: fakeAppScript(2),
			sendSigterm:   true,
			shutdownDelay: 10 * time.Second,
		},
		"app-exit-after-shutdown-delay": {
			// T0 : app start
			// T1 : entrypoint receives sigterm (ignored)
			// T2 : entrypoint waits for the shutdown delay
			// T3 : entrypoint sends sigterm to app after shutdown delay
			// T4 : app exits due to sigterm
			targetCommand: fakeAppScript(10),
			sendSigterm:   true,
			shutdownDelay: 1 * time.Second,
			// Our test script exits with 55 when receiving sigterm.
			exitCode: 55,
		},
		"sigint-is-forwarded": {
			targetCommand: fakeAppScript(10),
			sendSigint:    true,
			exitCode:      42,
		},
		"sigint-is-forwarded-after-sigterm": {
			targetCommand: fakeAppScript(10),
			sendSigterm:   true,
			sendSigint:    true,
			exitCode:      42,
		},
		"sigint-is-forwarded-during-shutdown-delay": {
			targetCommand: fakeAppScript(10),
			sendSigterm:   true,
			sendSigint:    true,
			shutdownDelay: 10 * time.Second,
			exitCode:      42,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ui := cli.NewMockUi()
			cmd := Command{UI: ui}

			// Start the target command asynchronously.
			exitCodeChan := make(chan int, 1)
			go func() {
				defer close(exitCodeChan)
				var args []string
				if c.shutdownDelay > 0 {
					args = append(args, "-shutdown-delay", c.shutdownDelay.String())
				}
				args = append(args, "/bin/sh", "-c", c.targetCommand)
				exitCodeChan <- cmd.Run(args)
			}()

			t.Logf("Wait for fake app process to start")
			retry.RunWith(&retry.Timer{Timeout: 1 * time.Second, Wait: 100 * time.Millisecond}, t, func(r *retry.R) {
				require.NotNil(r, cmd.appCmd)
				require.NotNil(r, cmd.appCmd.Process)
				require.Greater(r, cmd.appCmd.Process.Pid, 0)
			})
			appPid := cmd.appCmd.Process.Pid
			t.Logf("Fake app process started pid=%v", appPid)

			// Testing signal handling requires signaling the entrypoint process.
			// This is awkward since that is the CURRENT process running this test.
			// To avoid accidentally terminating the test run, intercept signals here as well.
			// This is okay. Go supports multiple registered channels for signal notification.
			sigs := make(chan os.Signal, 2)
			signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
			t.Cleanup(func() {
				signal.Stop(sigs)
			})

			if c.sendSigterm {
				t.Logf("Sending sigterm to the entrypoint")
				err := syscall.Kill(os.Getpid(), syscall.SIGTERM)
				require.NoError(t, err)
				time.Sleep(500 * time.Millisecond) // Give it time to react

				t.Logf("Check the fake app process is still running")
				proc, err := os.FindProcess(appPid)
				require.NoError(t, err, "Failed to find fake app process")
				// A zero-signal lets us check the process is still valid/running.
				require.NoError(t, proc.Signal(syscall.Signal(0)),
					"Sigterm was not ignored by the entrypoint")
			}

			if c.sendSigint {
				t.Logf("Send sigint to entrypoint")
				err := syscall.Kill(os.Getpid(), syscall.SIGINT)
				require.NoError(t, err)

				t.Logf("Check the fake app process has exited")
				retry.RunWith(&retry.Timer{Timeout: 2 * time.Second, Wait: 100 * time.Millisecond}, t, func(r *retry.R) {
					proc, err := os.FindProcess(appPid)
					require.NoError(r, err, "Failed to find fake app process")
					err = proc.Signal(syscall.Signal(0))
					require.Error(r, err, "Sigint was not forwarded to fake app process")
					require.Equal(r, os.ErrProcessDone, err)
				})
			}

			// If !ok, then the channel was closed without actually sending the exit code.
			exitCode, ok := <-exitCodeChan
			require.True(t, ok)
			require.Equal(t, c.exitCode, exitCode)
		})
	}
}
