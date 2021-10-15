package healthsync

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestEcsHealthToConsulHealth(t *testing.T) {
	require.Equal(t, api.HealthPassing, ecsHealthToConsulHealth(ecs.HealthStatusHealthy))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(ecs.HealthStatusUnknown))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(ecs.HealthStatusUnhealthy))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(""))
}

type minimalContainerMetadata struct {
	name       string
	status     string
	expectSync bool
	missing    bool
}

type ecsServiceMetadata struct {
	family    string
	serviceID string
	taskARN   string
	taskID    string
}

func TestRunWithContainerNames(t *testing.T) {
	serviceName := "service-name"
	family := "Family"
	taskID := "TaskID"
	ecsServiceMetadata := ecsServiceMetadata{
		family:    family,
		serviceID: fmt.Sprintf("%s-%s", family, taskID),
		taskID:    taskID,
		taskARN:   fmt.Sprintf("asdf/%s", taskID),
	}

	cases := map[string]struct {
		serviceName       string
		initialContainers []minimalContainerMetadata
		initialExpChecks  map[string]string
		updatedContainers []minimalContainerMetadata
		updatedExpChecks  map[string]string
	}{
		"one expectSync healthy container": {
			initialContainers: []minimalContainerMetadata{
				{
					name:       "container1",
					status:     "HEALTHY",
					expectSync: true,
					missing:    false,
				},
			},
			initialExpChecks: map[string]string{
				"container1": api.HealthPassing,
			},
		},
		"two expectSync containers that are healthy": {
			initialContainers: []minimalContainerMetadata{
				{
					name:       "container1",
					status:     "HEALTHY",
					expectSync: true,
					missing:    false,
				},
				{
					name:       "container2",
					status:     "HEALTHY",
					expectSync: true,
					missing:    false,
				},
			},
			initialExpChecks: map[string]string{
				"container1": api.HealthPassing,
				"container2": api.HealthPassing,
			},
		},
		"two expectSync containers where one is unhealthy": {
			initialContainers: []minimalContainerMetadata{
				{
					name:       "container1",
					status:     "HEALTHY",
					expectSync: true,
					missing:    false,
				},
				{
					name:       "container2",
					status:     "UNHEALTHY",
					expectSync: true,
					missing:    false,
				},
			},
			initialExpChecks: map[string]string{
				"container1": api.HealthPassing,
				"container2": api.HealthCritical,
			},
		},
		"one expectSync container and one non-expectSync": {
			initialContainers: []minimalContainerMetadata{
				{
					name:       "container1",
					status:     "HEALTHY",
					expectSync: true,
					missing:    false,
				},
				{
					name:       "container2",
					status:     "UNHEALTHY",
					expectSync: false,
					missing:    false,
				},
			},
			initialExpChecks: map[string]string{
				"container1": api.HealthPassing,
			},
		},
		"one missing container is marked as unhealthy": {
			initialContainers: []minimalContainerMetadata{
				{
					name:       "container1",
					expectSync: true,
					missing:    true,
				},
			},
			initialExpChecks: map[string]string{
				"container1": api.HealthCritical,
			},
		},
		"missing containers synced as healthy after they appear": {
			initialContainers: []minimalContainerMetadata{
				{
					name:       "missing",
					status:     "",
					expectSync: true,
					missing:    true,
				},
			},
			initialExpChecks: map[string]string{
				"missing": api.HealthCritical,
			},
			updatedContainers: []minimalContainerMetadata{
				{
					name:       "missing",
					status:     ecs.HealthStatusHealthy,
					expectSync: true,
					missing:    false,
				},
			},
			updatedExpChecks: map[string]string{
				"missing": api.HealthPassing,
			},
		},
		"with service name specified": {
			serviceName: serviceName,
			initialContainers: []minimalContainerMetadata{
				{
					name:       "container1",
					status:     "HEALTHY",
					expectSync: true,
					missing:    false,
				},
			},
			initialExpChecks: map[string]string{
				"container1": api.HealthPassing,
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			expectedServiceName := family
			if c.serviceName != "" {
				expectedServiceName = c.serviceName
			}
			initialStage := true

			server, err := testutil.NewTestServerConfigT(t, nil)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = server.Stop()
			})

			consulClient, err := api.NewClient(&api.Config{Address: server.HTTPAddr})
			require.NoError(t, err)

			setupServiceAndChecks(t, expectedServiceName, ecsServiceMetadata, consulClient, c.initialContainers)

			var expectSyncContainers []string
			for _, container := range c.initialContainers {
				if container.expectSync {
					expectSyncContainers = append(expectSyncContainers, container.name)
				}
			}

			ecsMetadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r != nil && r.URL.Path == "/task" && r.Method == "GET" {
					if initialStage {
						_, err = w.Write([]byte(metadataResponse(t, ecsServiceMetadata, c.initialContainers)))
					} else {
						_, err = w.Write([]byte(metadataResponse(t, ecsServiceMetadata, c.updatedContainers)))
					}
					require.NoError(t, err)
				}
			}))
			os.Setenv(awsutil.ECSMetadataURIEnvVar, ecsMetadataServer.URL)

			sanityChecks := make(map[string]string)
			for _, container := range c.initialContainers {
				sanityChecks[container.name] = api.HealthCritical
			}

			config := config.Config{}
			config.Mesh.HealthSyncContainers = expectSyncContainers
			config.Mesh.Service.Name = c.serviceName

			// First sanity check that Consul is in the expected state before we start our command
			assertHealthChecks(t, expectedServiceName, ecsServiceMetadata, consulClient, c.initialContainers, sanityChecks)

			// Set up the command.
			ui := cli.NewMockUi()
			log := hclog.New(nil)
			cmd := Command{
				UI:     ui,
				log:    log,
				config: config,
			}

			// Start the command.
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(func() {
				cancel()
			})

			go func() {
				err = cmd.realRun(ctx, consulClient)
				require.NoError(t, err)
			}()

			// Wait for the initial state to converge to what we expect.
			assertHealthChecks(t, expectedServiceName, ecsServiceMetadata, consulClient, c.initialContainers, c.initialExpChecks)

			// If we're also testing updates make the updates.
			if len(c.updatedContainers) > 0 {
				// Trigger the AWS metadata API to return the updated statuses.
				initialStage = false
				assertHealthChecks(t, expectedServiceName, ecsServiceMetadata, consulClient, c.updatedContainers, c.updatedExpChecks)
			}

			cancel()

			// Ensure that checks are set to unhealthy after the context is canceled
			assertHealthChecks(t, expectedServiceName, ecsServiceMetadata, consulClient, c.initialContainers, sanityChecks)
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
		found          []awsutil.ECSTaskMetaContainer
	}{
		"A container isn't in the metadata": {
			containerNames: []string{"container1"},
			taskMeta:       awsutil.ECSTaskMeta{},
			missing:        []string{"container1"},
			found:          nil,
		},
		"The metadata has an extra container": {
			containerNames: []string{},
			taskMeta: awsutil.ECSTaskMeta{
				Containers: []awsutil.ECSTaskMetaContainer{
					taskMetaContainer1,
				},
			},
			missing: nil,
			found:   nil,
		},
		"some found and some not found": {
			containerNames: []string{"container1", "container2"},
			taskMeta: awsutil.ECSTaskMeta{
				Containers: []awsutil.ECSTaskMetaContainer{
					taskMetaContainer1,
				},
			},
			missing: []string{"container2"},
			found: []awsutil.ECSTaskMetaContainer{
				taskMetaContainer1,
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

// metadataResponse returns a JSON string that the AWS metadata endpoint
// would return given this set of containers.
func metadataResponse(t *testing.T, ecsServiceMetadata ecsServiceMetadata, containerMetadatas []minimalContainerMetadata) string {
	var taskMetaContainers []awsutil.ECSTaskMetaContainer
	for _, containerMetadata := range containerMetadatas {
		if containerMetadata.missing {
			continue
		}
		metaContainer := awsutil.ECSTaskMetaContainer{
			Name: containerMetadata.name,
			Health: awsutil.ECSTaskMetaHealth{
				Status: containerMetadata.status,
			},
		}

		taskMetaContainers = append(taskMetaContainers, metaContainer)
	}

	taskMeta := awsutil.ECSTaskMeta{
		Family:     ecsServiceMetadata.family,
		TaskARN:    ecsServiceMetadata.taskARN,
		Containers: taskMetaContainers,
	}
	json, err := json.Marshal(taskMeta)
	require.NoError(t, err)
	return string(json)
}

func setupServiceAndChecks(t *testing.T, serviceName string, ecsServiceMetadata ecsServiceMetadata, consulClient *api.Client, containers []minimalContainerMetadata) {
	checks := api.AgentServiceChecks{}
	for _, container := range containers {
		if !container.expectSync {
			continue
		}

		checks = append(checks, &api.AgentServiceCheck{
			CheckID: makeCheckID(serviceName, ecsServiceMetadata.taskID, container.name),
			TTL:     "10000h",
		})
	}

	err := consulClient.Agent().ServiceRegister(&api.AgentServiceRegistration{
		ID:   ecsServiceMetadata.serviceID,
		Name: serviceName,
		Port: 1000,
		Meta: map[string]string{
			"task-id":  ecsServiceMetadata.taskID,
			"task-arn": ecsServiceMetadata.taskARN,
			"source":   "consul-ecs",
		},
		Checks: checks,
	})
	require.NoError(t, err)
}

func assertHealthChecks(t *testing.T, serviceName string, ecsServiceMetadata ecsServiceMetadata, consulClient *api.Client, containers []minimalContainerMetadata, expChecks map[string]string) {
	retry.Run(t, func(r *retry.R) {
		filter := fmt.Sprintf(`ServiceID == "%s"`, ecsServiceMetadata.serviceID)
		checks, err := consulClient.Agent().ChecksWithFilter(filter)
		require.NoError(r, err)

		for _, container := range containers {
			checkID := makeCheckID(serviceName, ecsServiceMetadata.taskID, container.name)
			check, ok := checks[checkID]

			if !container.expectSync {
				require.False(r, ok)
				continue
			}

			require.True(r, ok)
			require.Equal(r, expChecks[container.name], check.Status)
		}
	})
}

func TestConstructServiceName(t *testing.T) {
	cmd := Command{}
	family := "family"

	serviceName := cmd.constructServiceName(family)
	require.Equal(t, family, serviceName)

	expectedServiceName := "service-name"

	cmd.config.Mesh.Service.Name = expectedServiceName
	serviceName = cmd.constructServiceName(family)
	require.Equal(t, expectedServiceName, serviceName)
}
