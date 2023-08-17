// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !windows
// +build !windows

package envoyentrypoint

import (
	"encoding/json"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestFlagValidation(t *testing.T) {
	ui := cli.NewMockUi()
	cmd := Command{
		UI: ui,
	}
	code := cmd.Run(nil)
	require.Equal(t, code, 1)
	require.Contains(t, ui.ErrorWriter.String(), "command is required")
}

func TestRun(t *testing.T) {
	cases := map[string]struct {
		fakeEnvoy        testutil.FakeCommand
		sendSigterm      bool
		sendSigint       bool
		mockTaskMetadata bool
		exitCode         int
	}{
		"short lived process": {
			fakeEnvoy: testutil.SimpleFakeCommand(t, 0),
			exitCode:  0,
		},
		"sigterm is ignored": {
			fakeEnvoy:   testutil.SimpleFakeCommand(t, 3),
			sendSigterm: true,
			exitCode:    0,
		},
		"sigint is forwarded": {
			fakeEnvoy:  testutil.FakeCommandWithTraps(t, 120),
			sendSigint: true,
			exitCode:   42,
		},
		"sigterm is ignored and then sigint is forwarded": {
			fakeEnvoy:   testutil.FakeCommandWithTraps(t, 120),
			sendSigterm: true,
			sendSigint:  true,
			exitCode:    42,
		},
		"sigterm is ignored and envoy terminates after the app container": {
			fakeEnvoy:        testutil.FakeCommandWithTraps(t, 120),
			sendSigterm:      true,
			mockTaskMetadata: true,
			exitCode:         55,
		},
	}

	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			cliCmd := Command{
				UI: cli.NewMockUi(),
			}
			// Necessary to avoid a race with initializing the `started` channel
			cliCmd.once.Do(cliCmd.init)

			// Start the target command asynchronously.
			exitCodeChan := make(chan int, 1)
			go func() {
				defer close(exitCodeChan)
				code := cliCmd.Run([]string{"-log-level", "debug", "/bin/sh", "-c", c.fakeEnvoy.Command})
				exitCodeChan <- code
			}()

			t.Logf("Wait for fake Envoy process to start")
			retry.RunWith(&retry.Timer{Timeout: 1 * time.Second, Wait: 100 * time.Millisecond}, t, func(r *retry.R) {
				require.FileExists(r, c.fakeEnvoy.ReadyFile)
			})

			// Necessary to avoid concurrent accesses that trigger the race detector.
			t.Logf("Wait for envoy-entrypoint to see Envoy has started")
			_, ok := <-cliCmd.started
			require.True(t, ok)

			envoyPid := cliCmd.envoyCmd.Process.Pid
			t.Logf("Fake Envoy process started (pid=%v)", envoyPid)

			// Testing signal handling requires signaling the entrypoint process.
			// This is awkward since that is the CURRENT process running this test.
			// To avoid accidentally terminating the test run, intercept signals here as well.
			// This is okay. Go supports multiple registered channels for signal notification.
			sigs := make(chan os.Signal, 2)
			signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
			t.Cleanup(func() {
				signal.Stop(sigs)
			})

			var ecsMetaRequestCount int64 // atomic, to pass race detector
			if c.mockTaskMetadata {
				// Simulate two requests with the app container running, and the rest with it stopped.
				testutil.TaskMetaServer(t, testutil.TaskMetaHandlerFn(t, func() string {
					meta := makeTaskMeta(
						"some-app-container",
						"consul-ecs-control-plane",
					)

					if atomic.LoadInt64(&ecsMetaRequestCount) < 2 {
						meta.Containers[0].KnownStatus = "RUNNING"
					} else {
						meta.Containers[0].KnownStatus = "STOPPED"
					}
					atomic.AddInt64(&ecsMetaRequestCount, 1)
					respData, err := json.Marshal(meta)
					require.NoError(t, err)
					return string(respData)
				}))
			}

			if c.sendSigterm {
				t.Logf("Send sigterm to the entrypoint")
				err := syscall.Kill(os.Getpid(), syscall.SIGTERM)
				require.NoError(t, err)
				time.Sleep(100 * time.Millisecond) // Give it time to react

				// NOTE: On failure to fetch Task metadata, Envoy should continue running.
				t.Logf("Check the fake Envoy process is still running")
				proc, err := os.FindProcess(envoyPid)
				require.NoError(t, err, "Failed to find fake Envoy process")
				// A zero-signal lets us check the process is still valid/running.
				require.NoError(t, proc.Signal(syscall.Signal(0)),
					"Sigterm was not ignored by the entrypoint")
			}

			// After SIGTERM, the entrypoint begins polling the task metadata server.
			// It exits when the application container(s) have exited.
			if c.mockTaskMetadata {
				retry.RunWith(&retry.Timer{Timeout: 4 * time.Second, Wait: 500 * time.Millisecond}, t, func(r *retry.R) {
					// Sanity check. We mock two requests with app container running, and the rest with the app container stopped.
					require.GreaterOrEqual(r, atomic.LoadInt64(&ecsMetaRequestCount), int64(3))

					t.Logf("Check the fake Envoy process exits")
					proc, err := os.FindProcess(envoyPid)
					require.NoError(r, err, "Failed to find fake Envoy process")
					// A zero-signal checks the validity of the process id.
					err = proc.Signal(syscall.Signal(0))
					msg := "Application exited, but entrypoint did not terminate fake Envoy"
					require.Error(r, err, msg)
					require.Equal(r, os.ErrProcessDone, err, msg)
				})
			}

			// Send a SIGINT to the entrypoint. This should be forwarded along to the sub-process,
			// which causes the fakeEnvoyScript to exit.
			if c.sendSigint {
				t.Logf("Send sigint to entrypoint")
				err := syscall.Kill(os.Getpid(), syscall.SIGINT)
				require.NoError(t, err)
				time.Sleep(100 * time.Millisecond) // Give it time to react

				t.Logf("Check the fake Envoy process has exited")
				retry.RunWith(&retry.Timer{Timeout: 2 * time.Second, Wait: 250 * time.Millisecond}, t, func(r *retry.R) {
					proc, err := os.FindProcess(envoyPid)
					require.NoError(r, err, "Failed to find fake Envoy process")
					err = proc.Signal(syscall.Signal(0))
					require.Error(r, err, "Sigint was not forwarded to fake Envoy process")
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

// makeTaskMeta returns task metadata with the given container names.
// All containers are put in DesiredStatus=STOPPED and KnownStatus=RUNNING,
// to allow us to simulate task shutdown.
func makeTaskMeta(containerNames ...string) awsutil.ECSTaskMeta {
	var containers []awsutil.ECSTaskMetaContainer
	for _, name := range containerNames {
		containers = append(containers, awsutil.ECSTaskMetaContainer{
			Name:          name,
			DesiredStatus: ecs.DesiredStatusStopped,
			KnownStatus:   ecs.DesiredStatusRunning,
		})
	}

	return awsutil.ECSTaskMeta{
		Cluster:    "test",
		TaskARN:    "abc123",
		Family:     "test-service",
		Containers: containers,
	}
}
