// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	meshinit "github.com/hashicorp/consul-ecs/subcommand/mesh-init"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestEcsHealthToConsulHealth(t *testing.T) {
	require.Equal(t, api.HealthPassing, ecsHealthToConsulHealth(string(types.HealthStatusHealthy)))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(string(types.HealthStatusUnknown)))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(string(types.HealthStatusUnhealthy)))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(""))
}

// setupSyncChecksCmd runs mesh-init to register a service, then builds a Command
// with checks populated, ready for direct syncChecks calls.
func setupSyncChecksCmd(t *testing.T, serviceName string, healthSyncContainers []string, taskMeta *awsutil.ECSTaskMeta) (*Command, *api.Client, string) {
	t.Helper()

	server, cfg := testutil.ConsulServer(t, nil)
	consulClient, err := api.NewClient(cfg)
	require.NoError(t, err)

	_, serverGRPCPort := testutil.GetHostAndPortFromAddress(server.GRPCAddr)
	_, serverHTTPPort := testutil.GetHostAndPortFromAddress(server.HTTPAddr)

	consulEcsConfig := config.Config{
		BootstrapDir:         testutil.TempDir(t),
		HealthSyncContainers: healthSyncContainers,
		ConsulServers: config.ConsulServers{
			Hosts: "127.0.0.1",
			GRPC:  config.GRPCSettings{Port: serverGRPCPort},
			HTTP:  config.HTTPSettings{Port: serverHTTPPort},
			SkipServerWatch: true,
		},
		Service: config.ServiceRegistration{
			Name: serviceName,
			Port: 8080,
		},
		Proxy: &config.AgentServiceConnectProxyConfig{
			PublicListenerPort: config.DefaultPublicListenerPort,
		},
	}
	testutil.SetECSConfigEnvVar(t, &consulEcsConfig)

	ui := cli.NewMockUi()
	ctrlPlaneCmd := meshinit.Command{UI: ui}
	require.Equal(t, 0, ctrlPlaneCmd.Run(nil), ui.ErrorWriter.String())

	conf, err := config.FromEnv()
	require.NoError(t, err)

	cmd := &Command{UI: ui, config: conf, log: hclog.NewNullLogger()}

	checks, err := cmd.fetchHealthChecks(consulClient, *taskMeta)
	require.NoError(t, err)
	cmd.checks = checks

	clusterARN, err := taskMeta.ClusterARN()
	require.NoError(t, err)

	return cmd, consulClient, clusterARN
}

// TestSyncChecksDataplaneDeltaCheck verifies that a second syncChecks call with
// an unchanged consul-dataplane HEALTHY status does not issue a Catalog.Register
// write to Consul.
func TestSyncChecksDataplaneDeltaCheck(t *testing.T) {
	serviceName := "delta-check-svc"
	proxyServiceName := serviceName + "-sidecar-proxy"
	taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"

	taskMeta := &awsutil.ECSTaskMeta{Cluster: "test", TaskARN: taskARN, Family: serviceName}

	var currentTaskMetaResp atomic.Value
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusHealthy)),
	}
	s, err := constructTaskMetaResponseString(taskMeta)
	require.NoError(t, err)
	currentTaskMetaResp.Store(s)
	testutil.TaskMetaServer(t, testutil.TaskMetaHandlerFn(t, func() string {
		return currentTaskMetaResp.Load().(string)
	}))

	cmd, consulClient, clusterARN := setupSyncChecksCmd(t, serviceName, nil, taskMeta)
	healthSyncContainers := []string{config.ConsulDataplaneContainerName}
	currentStatuses := make(map[string]string)

	// Tick 1: "" → "HEALTHY", should write.
	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[config.ConsulDataplaneContainerName])

	// Capture index after tick 1.
	_, meta, err := consulClient.Health().Checks(proxyServiceName, nil)
	require.NoError(t, err)
	indexAfterTick1 := meta.LastIndex

	// Tick 2: "HEALTHY" → "HEALTHY", delta guard must suppress write.
	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[config.ConsulDataplaneContainerName])

	_, meta, err = consulClient.Health().Checks(proxyServiceName, nil)
	require.NoError(t, err)
	require.Equal(t, indexAfterTick1, meta.LastIndex, "no Consul write should occur when dataplane status is unchanged")
}

// TestSyncChecksDataplaneDoubleWriteWhenMissing verifies that when consul-dataplane
// is absent, the first tick writes UNHEALTHY and the second tick (same missing state)
// is a no-op.
func TestSyncChecksDataplaneDoubleWriteWhenMissing(t *testing.T) {
	serviceName := "double-write-svc"
	proxyServiceName := serviceName + "-sidecar-proxy"
	taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"

	taskMeta := &awsutil.ECSTaskMeta{Cluster: "test", TaskARN: taskARN, Family: serviceName}

	// consul-dataplane is absent from task metadata.
	var currentTaskMetaResp atomic.Value
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{}
	s, err := constructTaskMetaResponseString(taskMeta)
	require.NoError(t, err)
	currentTaskMetaResp.Store(s)
	testutil.TaskMetaServer(t, testutil.TaskMetaHandlerFn(t, func() string {
		return currentTaskMetaResp.Load().(string)
	}))

	cmd, consulClient, clusterARN := setupSyncChecksCmd(t, serviceName, nil, taskMeta)
	healthSyncContainers := []string{config.ConsulDataplaneContainerName}
	currentStatuses := make(map[string]string)

	// Tick 1: "" → "UNHEALTHY", should write.
	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusUnhealthy), currentStatuses[config.ConsulDataplaneContainerName])

	_, meta, err := consulClient.Health().Checks(proxyServiceName, nil)
	require.NoError(t, err)
	indexAfterTick1 := meta.LastIndex

	// Tick 2: still missing → "UNHEALTHY" == "UNHEALTHY", delta guard must suppress write.
	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusUnhealthy), currentStatuses[config.ConsulDataplaneContainerName])

	_, meta, err = consulClient.Health().Checks(proxyServiceName, nil)
	require.NoError(t, err)
	require.Equal(t, indexAfterTick1, meta.LastIndex, "second tick should not write when dataplane is still missing")
}

// TestSyncChecksContainerMissingToUnhealthy verifies that when a regular
// health-sync container transitions missing → UNHEALTHY the redundant write is
// avoided, and that a subsequent transition to HEALTHY does write.
func TestSyncChecksContainerMissingToUnhealthy(t *testing.T) {
	serviceName := "missing-to-unhealthy-svc"
	taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
	appContainer := "app-container"

	taskMeta := &awsutil.ECSTaskMeta{Cluster: "test", TaskARN: taskARN, Family: serviceName}

	var currentTaskMetaResp atomic.Value

	// Tick 1: app-container missing, consul-dataplane HEALTHY.
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusHealthy)),
	}
	s, err := constructTaskMetaResponseString(taskMeta)
	require.NoError(t, err)
	currentTaskMetaResp.Store(s)
	testutil.TaskMetaServer(t, testutil.TaskMetaHandlerFn(t, func() string {
		return currentTaskMetaResp.Load().(string)
	}))

	cmd, consulClient, clusterARN := setupSyncChecksCmd(t, serviceName, []string{appContainer}, taskMeta)
	healthSyncContainers := []string{appContainer, config.ConsulDataplaneContainerName}
	currentStatuses := make(map[string]string)

	serviceID := makeServiceID(serviceName, taskMeta.TaskID())
	appCheckID := constructCheckID(serviceID, appContainer)

	// Tick 1: app-container is missing → writes critical, stores "UNHEALTHY".
	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusUnhealthy), currentStatuses[appContainer])

	filter := "CheckID == `" + appCheckID + "`"
	appChecks, _, err := consulClient.Health().Checks(serviceName, &api.QueryOptions{Filter: filter})
	require.NoError(t, err)
	require.Len(t, appChecks, 1)
	require.Equal(t, api.HealthCritical, appChecks[0].Status)
	modifyIdxAfterTick1 := appChecks[0].ModifyIndex

	// Tick 2: app-container reappears as UNHEALTHY → delta "UNHEALTHY"=="UNHEALTHY" → no write to app-container check.
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusHealthy)),
		constructContainerResponse(appContainer, string(types.HealthStatusUnhealthy)),
	}
	s, err = constructTaskMetaResponseString(taskMeta)
	require.NoError(t, err)
	currentTaskMetaResp.Store(s)

	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusUnhealthy), currentStatuses[appContainer])

	appChecks, _, err = consulClient.Health().Checks(serviceName, &api.QueryOptions{Filter: filter})
	require.NoError(t, err)
	require.Len(t, appChecks, 1)
	require.Equal(t, modifyIdxAfterTick1, appChecks[0].ModifyIndex, "no write when app-container status unchanged")

	// Tick 3: app-container becomes HEALTHY → delta changes → writes.
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusHealthy)),
		constructContainerResponse(appContainer, string(types.HealthStatusHealthy)),
	}
	s, err = constructTaskMetaResponseString(taskMeta)
	require.NoError(t, err)
	currentTaskMetaResp.Store(s)

	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[appContainer])

	appChecks, _, err = consulClient.Health().Checks(serviceName, &api.QueryOptions{Filter: filter})
	require.NoError(t, err)
	require.Len(t, appChecks, 1)
	require.Greater(t, appChecks[0].ModifyIndex, modifyIdxAfterTick1, "write should occur when app-container transitions to HEALTHY")
	require.Equal(t, api.HealthPassing, appChecks[0].Status)
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
