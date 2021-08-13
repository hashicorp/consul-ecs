package healthsync

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRunWithoutContainerNames(t *testing.T) {
	ui := cli.NewMockUi()
	cmd := Command{
		UI: ui,
	}
	code := cmd.Run(nil)
	require.Equal(t, 0, code)
}

func TestEcsHealthToConsulHealth(t *testing.T) {
	require.Equal(t, api.HealthPassing, ecsHealthToConsulHealth("HEALTHY"))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth("UNHEALTHY"))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth("UNKNOWN"))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(""))
}

type minimalContainerMetadata struct {
	name      string
	status    string
	essential bool
}

var (
	serviceName = "Family"
	taskID      = "TaskId"
	taskARN     = fmt.Sprintf("asdf/%s", taskID)
	serviceID   = fmt.Sprintf("%s-%s", serviceName, taskID)
)

func metadataResponse(containerMetadatas []minimalContainerMetadata) string {
	var taskMetaContainers []awsutil.ECSTaskMetaContainer
	for _, containerMetadata := range containerMetadatas {
		metaContainer := awsutil.ECSTaskMetaContainer{
			Name: containerMetadata.name,
		}
		metaContainer.Health.Status = containerMetadata.status
		taskMetaContainers = append(taskMetaContainers, metaContainer)
	}

	taskMeta := awsutil.ECSTaskMeta{
		Family:     serviceName,
		TaskARN:    taskARN,
		Containers: taskMetaContainers,
	}
	json, _ := json.Marshal(taskMeta)
	return string(json)
}

func setupServiceAndChecks(t *testing.T, consulClient *api.Client, containers []minimalContainerMetadata) {
	checks := api.AgentServiceChecks{}
	for _, container := range containers {
		if !container.essential {
			continue
		}

		checks = append(checks, &api.AgentServiceCheck{
			CheckID: makeCheckID(serviceName, container.name),
			TTL:     "10000h",
		})
	}

	err := consulClient.Agent().ServiceRegister(&api.AgentServiceRegistration{
		ID:   serviceID,
		Name: serviceName,
		Port: 1000,
		Meta: map[string]string{
			"task-id":  taskID,
			"task-arn": taskARN,
			"source":   "consul-ecs",
		},
		Checks: checks,
	})
	require.NoError(t, err)
}

func assertHealthChecks(t *testing.T, consulClient *api.Client, containers []minimalContainerMetadata) {
	filter := fmt.Sprintf(`ServiceID == "%s"`, serviceID)
	checks, err := consulClient.Agent().ChecksWithFilter(filter)
	require.NoError(t, err)
	for _, container := range containers {
		checkID := makeCheckID(serviceName, container.name)
		check, ok := checks[checkID]

		if !container.essential {
			require.False(t, ok)
			continue
		}

		require.True(t, ok)
		require.Equal(t, ecsHealthToConsulHealth(container.status), check.Status)
	}
}

var cases map[string][]minimalContainerMetadata = map[string][]minimalContainerMetadata{
	"one essential healthy container": {
		{
			name:      "container1",
			status:    "HEALTHY",
			essential: true,
		},
	},
	"two essential containers that are healthy": {
		{
			name:      "container1",
			status:    "HEALTHY",
			essential: true,
		},
		{
			name:      "container2",
			status:    "HEALTHY",
			essential: true,
		},
	},
	"two essential containers where one is unhealthy": {
		{
			name:      "container1",
			status:    "HEALTHY",
			essential: true,
		},
		{
			name:      "container2",
			status:    "UNHEALTHY",
			essential: true,
		},
	},
	"one essential container and one non-essential": {
		{
			name:      "container1",
			status:    "HEALTHY",
			essential: true,
		},
		{
			name:      "container2",
			status:    "UNHEALTHY",
			essential: false,
		},
	},
}

func TestRunWithContainerNames(t *testing.T) {
	for name, containers := range cases {
		t.Run(name, func(t *testing.T) {

			server, err := testutil.NewTestServerConfigT(t, nil)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = server.Stop()
			})

			consulClient, err := api.NewClient(&api.Config{Address: server.HTTPAddr})
			require.NoError(t, err)

			setupServiceAndChecks(t, consulClient, containers)

			essentialContainers := []string{}
			for _, container := range containers {
				if container.essential {
					essentialContainers = append(essentialContainers, container.name)
				}
			}

			ecsMetadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r != nil && r.URL.Path == "/task" && r.Method == "GET" {
					_, err := w.Write([]byte(metadataResponse(containers)))
					require.NoError(t, err)
				}
			}))
			os.Setenv(awsutil.ECSMetadataURIEnvVar, ecsMetadataServer.URL)

			containersWithInitialStatus := []minimalContainerMetadata{}
			for _, container := range containers {
				c := &container
				c.status = "UNHEALTHY"
				containersWithInitialStatus = append(containersWithInitialStatus, *c)
			}

			assertHealthChecks(t, consulClient, containersWithInitialStatus)

			ui := cli.NewMockUi()
			log := hclog.New(nil)
			cmd := Command{
				UI:           ui,
				consulClient: consulClient,
				log:          log,
			}

			cmd.syncChecks(map[string]string{}, serviceName, essentialContainers)

			assertHealthChecks(t, consulClient, containers)
		})
	}
}

func TestFindContainersToSync(t *testing.T) {
	taskMetaContainer1 := awsutil.ECSTaskMetaContainer{
		Name: "container1",
	}

	cases := map[string]struct {
		containerNames []string
		taskMeta       awsutil.ECSTaskMeta
		missing        []string
		found          []*awsutil.ECSTaskMetaContainer
	}{
		"A container isn't in the metadata": {
			containerNames: []string{"container1"},
			taskMeta:       awsutil.ECSTaskMeta{},
			missing:        []string{"container1"},
			found:          []*awsutil.ECSTaskMetaContainer{},
		},
		"The metadata has an extra container": {
			containerNames: []string{},
			taskMeta: awsutil.ECSTaskMeta{
				Containers: []awsutil.ECSTaskMetaContainer{
					taskMetaContainer1,
				},
			},
			missing: []string{},
			found:   []*awsutil.ECSTaskMetaContainer{},
		},
		"some found and some not found": {
			containerNames: []string{"container1", "container2"},
			taskMeta: awsutil.ECSTaskMeta{
				Containers: []awsutil.ECSTaskMetaContainer{
					taskMetaContainer1,
				},
			},
			missing: []string{"container2"},
			found: []*awsutil.ECSTaskMetaContainer{
				&taskMetaContainer1,
			},
		},
	}

	for name, testData := range cases {
		t.Run(name, func(t *testing.T) {
			found, missing := findContainersToSync(testData.containerNames, testData.taskMeta)
			require.Equal(t, testData.missing, missing)
			require.Equal(t, testData.found, found)
		})
	}
}
