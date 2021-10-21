//go:build !windows
// +build !windows

package entrypoint

import (
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

func TestRunSigtermThenSigint(t *testing.T) {
	cmd := Command{
		UI: cli.NewMockUi(),
	}

	// Start the command asynchronously.
	// Later, we can wait on this channel to receive the exit code.
	exitCodeChan := make(chan int, 1)
	go func() {
		defer close(exitCodeChan)
		exitCodeChan <- cmd.Run([]string{"/bin/sh", "-c", "sleep 5"})
	}()

	// Wait for the sub-process to start.
	// Hack! Requires the implementation to set `cmd.pid` to the sub-process id...
	t.Logf("Wait for sub-process to start")
	retry.RunWith(&retry.Timer{Timeout: 1 * time.Second, Wait: 100 * time.Millisecond}, t, func(r *retry.R) {
		require.Greater(r, cmd.pid, 0)
	})
	t.Logf("Sub-process started (pid=%v)", cmd.pid)

	// Test that SIGTERM is ignored:
	// * Send a TERM signal to the parent
	// * Validate the sub-process is still running
	//
	// This is awkward since the parent process is the CURRENT process running this test!
	// To avoid this terminating the test run, intercept signals here as well.
	// This is fine, since golang can send signals to multiple registered channels.
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	t.Logf("Send sigterm to parent process")
	err := syscall.Kill(os.Getpid(), syscall.SIGTERM)
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond) // Give it time to react

	// NOTE: On errors from the Task metadata (as in this case), it should continue running.
	t.Logf("Check the sub-process is still running")
	proc, err := os.FindProcess(cmd.pid)
	require.NoError(t, err, "Failed to find sub-process")
	// A zero-signal checks the validity of the process id.
	require.NoError(t, proc.Signal(syscall.Signal(0)), "Sigterm was not ignored")

	// Now send an interrupt. This is forwarded to the sub-process, causing it to exit.
	t.Logf("Send sigint to parent process")
	err = syscall.Kill(os.Getpid(), syscall.SIGINT)
	require.NoError(t, err)

	t.Logf("Check the sub-process has exited")
	retry.RunWith(&retry.Timer{Timeout: 2 * time.Second, Wait: 250 * time.Millisecond}, t, func(r *retry.R) {
		proc, err = os.FindProcess(cmd.pid)
		require.NoError(r, err, "Failed to find sub-process")
		// A zero-signal checks the validity of the process id.
		err := proc.Signal(syscall.Signal(0))
		require.Error(r, err)
		// Not sure if this message is consistent across Unixes.
		require.Contains(r, err.Error(), "process already finished")
	})

	// Wait for exitCode
	exitCode := <-exitCodeChan
	// -1 is maybe a weird exit code?
	require.Equal(t, -1, exitCode)
}

func TestRunSigtermThenAppContainerExit(t *testing.T) {
	cmd := Command{
		UI: cli.NewMockUi(),
	}

	// Start the command asynchronously.
	// Later, we can wait on this channel to receive the exit code.
	exitCodeChan := make(chan int, 1)
	go func() {
		defer close(exitCodeChan)
		exitCodeChan <- cmd.Run([]string{"/bin/sh", "-c", "sleep 5"})
	}()

	// Wait for the sub-process to start.
	// Hack! Requires the implementation to set `cmd.pid` to the sub-process id...
	t.Logf("Wait for sub-process to start")
	retry.RunWith(&retry.Timer{Timeout: 1 * time.Second, Wait: 100 * time.Millisecond}, t, func(r *retry.R) {
		require.Greater(r, cmd.pid, 0)
	})
	t.Logf("Sub-process started (pid=%v)", cmd.pid)

	// Test that SIGTERM is ignored:
	// * Send a TERM signal to the parent
	// * Validate the sub-process is still running
	//
	// This is awkward since the parent process is the CURRENT process running this test!
	// To avoid this terminating the test run, intercept signals here as well.
	// This is fine, since golang can send signals to multiple registered channels.
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	// Set up ECS container metadata server.
	// This just has an empty list of containers.
	taskMetadataResponse := `{"Cluster": "test", "TaskARN": "abc123", "Family": "test-service"}`
	ecsMetaRequestCount := 0
	ecsMetadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil && r.URL.Path == "/task" && r.Method == "GET" {
			_, err := w.Write([]byte(taskMetadataResponse))
			require.NoError(t, err)
			ecsMetaRequestCount += 1
		}
	}))
	os.Setenv(awsutil.ECSMetadataURIEnvVar, ecsMetadataServer.URL)
	t.Cleanup(func() {
		os.Unsetenv(awsutil.ECSMetadataURIEnvVar)
		ecsMetadataServer.Close()
	})

	// Send a SIGTERM, as if the Task is stopping.
	// The entrypoint should start to poll the task metadata to wait for an application conatiner to exit.
	// Since there are no containers returned, it will assume they've stopped and exit.
	t.Logf("Send sigterm to parent process")
	err := syscall.Kill(os.Getpid(), syscall.SIGTERM)
	require.NoError(t, err)

	t.Logf("Check the sub-process exits")
	retry.RunWith(&retry.Timer{Timeout: 2 * time.Second, Wait: 250 * time.Millisecond}, t, func(r *retry.R) {
		proc, err := os.FindProcess(cmd.pid)
		require.NoError(r, err, "Failed to find sub-process")
		// A zero-signal checks the validity of the process id.
		err = proc.Signal(syscall.Signal(0))
		require.Error(r, err)
		// Not sure if this message is consistent across Unixes.
		require.Contains(r, err.Error(), "process already finished")
	})

	// Validate the entrypoint hit the task metadata.
	require.Equal(t, ecsMetaRequestCount, 1)

	exitCode := <-exitCodeChan
	require.Equal(t, -1, exitCode)
}
