package discoverservers

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/subcommand/discover-servers/mocks"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestFlagValidation(t *testing.T) {
	cases := []struct {
		args  []string
		error string
	}{
		{
			nil,
			"-service-name must be set",
		},
		{
			[]string{"-service-name", "test"},
			"-out must be set",
		},
	}

	ui := cli.NewMockUi()
	cmd := Command{
		UI: ui,
	}
	for _, c := range cases {
		code := cmd.Run(c.args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), c.error)
	}
}

func TestDiscoverServers(t *testing.T) {
	cases := map[string]func(*ecs.Task) []*ecs.Task{
		"no-tasks": func(_ *ecs.Task) []*ecs.Task {
			return nil
		},
		"no-containers": func(task *ecs.Task) []*ecs.Task {
			task.Containers = nil
			return []*ecs.Task{task}
		},
		"no-consul-server-container": func(task *ecs.Task) []*ecs.Task {
			task.Containers[0].Name = aws.String("not-the-server-container")
			return []*ecs.Task{task}
		},
		"no-network-interfaces": func(task *ecs.Task) []*ecs.Task {
			task.Containers[0].NetworkInterfaces = nil
			return []*ecs.Task{task}
		},
		"no-ipv4-addresses": func(task *ecs.Task) []*ecs.Task {
			task.Containers[0].NetworkInterfaces[0].PrivateIpv4Address = nil
			return []*ecs.Task{task}
		},
		"valid-tasks": func(task *ecs.Task) []*ecs.Task {
			return []*ecs.Task{task}
		},
	}

	for name, modifyTasksFn := range cases {
		t.Run(name, func(t *testing.T) {
			taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
			expectedIpAddress := "10.1.2.3"

			// Set up ECS container metadata server.
			taskMetadataResponse := fmt.Sprintf(`{"Cluster": "test", "TaskARN": "%s", "Family": "test-service"}`, taskARN)
			ecsMetadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r != nil && r.URL.Path == "/task" && r.Method == "GET" {
					_, err := w.Write([]byte(taskMetadataResponse))
					require.NoError(t, err)
				}
			}))
			t.Cleanup(ecsMetadataServer.Close)
			os.Setenv(awsutil.ECSMetadataURIEnvVar, ecsMetadataServer.URL)

			ui := cli.NewMockUi()
			cmd := Command{
				UI: ui,
				// MockECS returns IncompleteTasks once and then CompleteTasks forever after (per method).
				// This simulates eventually ready tasks and exercises discover-servers retry logic.
				ecsClient: &mocks.MockECS{
					// One copy of the mocked consul-server task is modified to simulate some failure.
					// MockConsulServerTask must be deterministic for this to work.
					CompleteTasks:   []*ecs.Task{mocks.MockConsulServerTask(expectedIpAddress, taskARN)},
					IncompleteTasks: modifyTasksFn(mocks.MockConsulServerTask(expectedIpAddress, taskARN)),
				},
			}

			serverIpFile, err := ioutil.TempFile("", "")
			require.NoError(t, err)
			defer os.Remove(serverIpFile.Name())

			cmdArgs := []string{"-service-name", "test-consul-server", "-out", serverIpFile.Name()}
			code := cmd.Run(cmdArgs)
			require.Equal(t, code, 0)

			ipAddress, err := ioutil.ReadFile(serverIpFile.Name())
			require.NoError(t, err)
			require.Equal(t, expectedIpAddress, string(ipAddress))
		})
	}
}
