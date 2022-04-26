package healthsync

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestEcsHealthToConsulHealth(t *testing.T) {
	require.Equal(t, api.HealthPassing, ecsHealthToConsulHealth(ecs.HealthStatusHealthy))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(ecs.HealthStatusUnknown))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(ecs.HealthStatusUnhealthy))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(""))
}

func TestNoCLIFlagsSupported(t *testing.T) {
	ui := cli.NewMockUi()
	cmd := Command{UI: ui}
	code := cmd.Run([]string{"some-arg"})
	require.Equal(t, 1, code)
	require.Equal(t, "unexpected argument: some-arg\n", ui.ErrorWriter.String())
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

			cfg := testutil.ConsulServer(t, nil)
			consulClient, err := api.NewClient(cfg)
			require.NoError(t, err)

			setupServiceAndChecks(t, expectedServiceName, ecsServiceMetadata, consulClient, c.initialContainers)

			var expectSyncContainers []string
			for _, container := range c.initialContainers {
				if container.expectSync {
					expectSyncContainers = append(expectSyncContainers, container.name)
				}
			}

			testutil.TaskMetaServer(t, testutil.TaskMetaHandlerFn(t, func() string {
				if initialStage {
					return metadataResponse(t, ecsServiceMetadata, c.initialContainers)
				} else {
					return metadataResponse(t, ecsServiceMetadata, c.updatedContainers)
				}
			}))

			sanityChecks := make(map[string]string)
			for _, container := range c.initialContainers {
				sanityChecks[container.name] = api.HealthCritical
			}

			config := &config.Config{}
			config.HealthSyncContainers = expectSyncContainers
			config.Service.Name = c.serviceName

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

func TestLogoutSuccess(t *testing.T) {
	bootstrapDir := testutil.TempDir(t)
	tokenFilename := "test-token"
	tokenPath := filepath.Join(bootstrapDir, tokenFilename)

	// Start Consul server.
	cfg := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
	client, err := api.NewClient(cfg)
	require.NoError(t, err)

	// Login to an auth method. We can only log out of tokens created by a login.
	fakeAws := testutil.AuthMethodInit(t, client, "test-service")
	loginCmd := exec.Command(
		"consul", "login", "-type", "aws",
		"-method", config.DefaultAuthMethodName,
		"-token-sink-file", tokenPath,
		"-aws-auto-bearer-token", "-aws-include-entity",
		"-aws-sts-endpoint", fakeAws.URL+"/sts",
		"-aws-region", "fake-region",
		"-aws-access-key-id", "fake-key-id",
		"-aws-secret-access-key", "fake-secret-key",
	)
	out, err := loginCmd.CombinedOutput()
	require.NoError(t, err, "out=%s", out)
	require.FileExists(t, tokenPath)

	// Configure a client with the token.
	tokenCfg := api.DefaultConfig()
	tokenCfg.Address = cfg.Address
	tokenCfg.TokenFile = tokenPath
	tokenClient, err := api.NewClient(tokenCfg)
	require.NoError(t, err)
	_, _, err = tokenClient.ACL().TokenReadSelf(nil)
	require.NoError(t, err)

	ui := cli.NewMockUi()
	cmd := &Command{
		UI: ui,
		config: &config.Config{
			BootstrapDir:     bootstrapDir,
			ConsulHTTPAddr:   cfg.Address,
			ConsulCACertFile: cfg.TLSConfig.CAFile,
			ConsulLogin: config.ConsulLogin{
				Enabled: true,
			},
		},
	}

	err = cmd.logout(tokenFilename)
	require.NoError(t, err)

	// Ensure the token was deleted.
	tok, _, err := tokenClient.ACL().TokenReadSelf(nil)
	require.Error(t, err)
	require.Nil(t, tok)
}

func TestLogoutFailure(t *testing.T) {
	bootstrapDir := testutil.TempDir(t)
	tokenFilename := "test-token"
	tokenPath := filepath.Join(bootstrapDir, tokenFilename)

	cfg := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
	cmd := &Command{
		UI: cli.NewMockUi(),
		config: &config.Config{
			BootstrapDir:     bootstrapDir,
			ConsulHTTPAddr:   cfg.Address,
			ConsulCACertFile: cfg.TLSConfig.CAFile,
			ConsulLogin: config.ConsulLogin{
				Enabled: true,
			},
		},
	}

	t.Run("token file not found", func(t *testing.T) {
		err := cmd.logout(tokenFilename)
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating client for logout")
	})
	t.Run("invalid token", func(t *testing.T) {
		err := os.WriteFile(tokenPath, []byte("3a336524-e02f-4a7e-85f3-fe8687d20891"), 0600)
		require.NoError(t, err)
		err = cmd.logout(tokenFilename)
		require.Error(t, err)
		require.Contains(t, err.Error(), "logout failed")
	})

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
	cmd := Command{
		config: &config.Config{},
	}
	family := "family"

	serviceName := cmd.constructServiceName(family)
	require.Equal(t, family, serviceName)

	expectedServiceName := "service-name"

	cmd.config.Service.Name = expectedServiceName
	serviceName = cmd.constructServiceName(family)
	require.Equal(t, expectedServiceName, serviceName)
}
