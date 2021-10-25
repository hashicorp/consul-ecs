//go:build !windows
// +build !windows

package entrypoint

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

// sleepScript is a script used to validate our `entrypoint` command.
//
// Why not just a simple 'sleep 120'?
// * Bash actually ignores SIGINT by default (note: CTRL-C sends SIGINT to the process group, not just the parent)
// * Tests can be run in different places, so /bin/sh could be any shell with different behavior.
// Why a background process + wait? Why not just a trap + sleep?
// * The sleep blocks the trap. Traps are not executed until the current command completes, except for `wait`.
const sleepScript = `sleep 120 &
export SLEEP_PID=$!
trap "{ echo 'target command was interrupted'; kill $SLEEP_PID; exit 42; }" INT
wait $SLEEP_PID
`

func TestFlagValidation(t *testing.T) {
	ui := cli.NewMockUi()
	cmd := Command{
		UI: ui,
	}
	code := cmd.Run(nil)
	require.Equal(t, code, 1)
	require.Contains(t, ui.ErrorWriter.String(), "command is required")
}

func TestRunNoSigterm(t *testing.T) {
	cmd := Command{
		UI: cli.NewMockUi(),
	}
	code := cmd.Run([]string{"/bin/sh", "-c", "sleep 0"})
	require.Equal(t, 0, code)
}

func TestRun(t *testing.T) {
	cases := map[string]struct {
		targetCommand    string
		sendSigterm      bool
		sendSigint       bool
		mockTaskMetadata bool
		exitCode         int
	}{
		"short lived process": {
			targetCommand: "sleep 0",
			exitCode:      0,
		},
		"sigterm is ignored": {
			targetCommand: "sleep 3",
			sendSigterm:   true,
			exitCode:      0,
		},
		"sigint is forwarded": {
			targetCommand: sleepScript,
			sendSigint:    true,
			exitCode:      42,
		},
		"sigterm is ignored and then sigint is forwarded": {
			targetCommand: sleepScript,
			sendSigterm:   true,
			sendSigint:    true,
			exitCode:      42,
		},
		"sigterm is ignored and then exits after the app container": {
			targetCommand:    sleepScript,
			sendSigterm:      true,
			mockTaskMetadata: true,
			exitCode:         -1,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cliCmd := Command{
				UI: cli.NewMockUi(),
			}

			// Start the target command asynchronously.
			exitCodeChan := make(chan int, 1)
			go func() {
				defer close(exitCodeChan)
				exitCodeChan <- cliCmd.Run([]string{"/bin/sh", "-c", c.targetCommand})
			}()

			// Wait for the sub-process to start.
			// Hack: requires cliCmd to set the `pid` field
			t.Logf("Wait for sub-process to start")
			retry.RunWith(&retry.Timer{Timeout: 1 * time.Second, Wait: 100 * time.Millisecond}, t, func(r *retry.R) {
				require.Greater(r, cliCmd.pid, 0)
			})
			t.Logf("Sub-process started (pid=%v)", cliCmd.pid)

			// Testing signal handling requires signaling the entrypoint process.
			// This is awkward since that is the CURRENT process running this test.
			// To avoid accidentally terminating the test run, intercept signals here as well.
			// This is okay. Go supports multiple registered channels for signal notification.
			sigs := make(chan os.Signal, 2)
			signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
			t.Cleanup(func() {
				signal.Stop(sigs)
			})

			ecsMetaRequestCount := 0
			if c.mockTaskMetadata {
				// Simulate two requests with the app container running, and the rest with it stopped.
				meta := awsutil.ECSTaskMeta{
					Cluster: "test",
					TaskARN: "abc123",
					Family:  "test-service",
					Containers: []awsutil.ECSTaskMetaContainer{
						{
							Name:          "some-app-container",
							DesiredStatus: "STOPPED",
							KnownStatus:   "RUNNING",
						},
						// Mark all the rest of these containers running to check that the entrypoint ignores them.
						{
							Name:          "consul-client",
							DesiredStatus: "STOPPED",
							KnownStatus:   "RUNNING",
						},
						{
							Name:          "health-sync",
							DesiredStatus: "STOPPED",
							KnownStatus:   "RUNNING",
						},
						{
							Name:          "mesh-init",
							DesiredStatus: "STOPPED",
							KnownStatus:   "RUNNING",
						},
						{
							Name:          "sidecar-proxy",
							DesiredStatus: "STOPPED",
							KnownStatus:   "RUNNING",
						},
					},
				}
				ecsMetadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r != nil && r.URL.Path == "/task" && r.Method == "GET" {
						if ecsMetaRequestCount < 2 {
							meta.Containers[0].KnownStatus = "RUNNING"
						} else {
							meta.Containers[0].KnownStatus = "STOPPED"
						}
						ecsMetaRequestCount++
						respData, err := json.Marshal(meta)
						require.NoError(t, err)
						_, err = w.Write(respData)
						require.NoError(t, err)
					}
				}))
				_ = os.Setenv(awsutil.ECSMetadataURIEnvVar, ecsMetadataServer.URL)
				t.Cleanup(func() {
					_ = os.Unsetenv(awsutil.ECSMetadataURIEnvVar)
					ecsMetadataServer.Close()
				})
			}

			if c.sendSigterm {
				t.Logf("Send sigterm to parent process")
				err := syscall.Kill(os.Getpid(), syscall.SIGTERM)
				require.NoError(t, err)
				time.Sleep(500 * time.Millisecond) // Give it time to react

				// NOTE: On failure to fetch Task metadata, Envoy should continue running.
				t.Logf("Check the sub-process is still running")
				proc, err := os.FindProcess(cliCmd.pid)
				require.NoError(t, err, "Failed to find entrypoint sub-process")
				// A zero-signal lets us check the process is still valid/running.
				require.NoError(t, proc.Signal(syscall.Signal(0)), "Sigterm was not ignored")
			}

			// After SIGTERM, the entrypoint begins polling the task metadata server.
			// It exits when the application container(s) have exited.
			if c.mockTaskMetadata {
				retry.RunWith(&retry.Timer{Timeout: 4 * time.Second, Wait: 500 * time.Millisecond}, t, func(r *retry.R) {
					// Sanity check. We mock two requests with app container running, and the rest with the app container stopped.
					require.GreaterOrEqual(r, ecsMetaRequestCount, 3)

					t.Logf("Check the sub-process exits")
					proc, err := os.FindProcess(cliCmd.pid)
					require.NoError(r, err, "Failed to find sub-process")
					// A zero-signal checks the validity of the process id.
					err = proc.Signal(syscall.Signal(0))
					require.Error(r, err, "Application container exited, but entrypoint did not terminate Envoy")
					require.Equal(r, os.ErrProcessDone, err)
				})
			}

			// Send a SIGINT to the entrypoint. This should be forwarded along to the sub-process,
			// which causes the sleepScript to exit.
			if c.sendSigint {
				t.Logf("Send sigint to parent process")
				err := syscall.Kill(os.Getpid(), syscall.SIGINT)
				require.NoError(t, err)
				time.Sleep(500 * time.Millisecond) // Give it time to react

				t.Logf("Check the sub-process has exited")
				retry.RunWith(&retry.Timer{Timeout: 2 * time.Second, Wait: 250 * time.Millisecond}, t, func(r *retry.R) {
					proc, err := os.FindProcess(cliCmd.pid)
					require.NoError(r, err, "Failed to find entrypoint sub-process")
					err = proc.Signal(syscall.Signal(0))
					require.Error(r, err, "Sigint was not forwarded to entrypoint sub-process")
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
