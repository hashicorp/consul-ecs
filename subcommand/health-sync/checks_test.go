// Copyright IBM Corp. 2021, 2026
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
			Hosts:           "127.0.0.1",
			GRPC:            config.GRPCSettings{Port: serverGRPCPort},
			HTTP:            config.HTTPSettings{Port: serverHTTPPort},
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

// TestSyncChecksMissingHealthSyncContainerMarksDataplaneUnhealthy verifies the
// fix for the bug where a missing health-sync container (application not yet
// started) was not considered when computing the overall dataplane health,
// causing the consul-dataplane check to pass prematurely and traffic to be
// directed at a service whose application container had not yet started.
func TestSyncChecksMissingHealthSyncContainerMarksDataplaneUnhealthy(t *testing.T) {
	serviceName := "missing-hsc-svc"
	proxyServiceName := serviceName + "-sidecar-proxy"
	taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
	appContainer := "app-container"

	taskMeta := &awsutil.ECSTaskMeta{Cluster: "test", TaskARN: taskARN, Family: serviceName}

	var currentTaskMetaResp atomic.Value

	// consul-dataplane is HEALTHY but app-container has not started yet (missing).
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

	// Tick 1: app-container missing → consul-dataplane check must be CRITICAL
	// even though consul-dataplane itself reports HEALTHY.
	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusUnhealthy), currentStatuses[config.ConsulDataplaneContainerName])

	proxyChecks, _, err := consulClient.Health().Checks(proxyServiceName, nil)
	require.NoError(t, err)
	require.Len(t, proxyChecks, 1)
	require.Equal(t, api.HealthCritical, proxyChecks[0].Status,
		"proxy check must be critical while app-container is still missing")

	// Tick 2: app-container starts up HEALTHY → consul-dataplane check must become PASSING.
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusHealthy)),
		constructContainerResponse(appContainer, string(types.HealthStatusHealthy)),
	}
	s, err = constructTaskMetaResponseString(taskMeta)
	require.NoError(t, err)
	currentTaskMetaResp.Store(s)

	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[config.ConsulDataplaneContainerName])

	proxyChecks, _, err = consulClient.Health().Checks(proxyServiceName, nil)
	require.NoError(t, err)
	require.Len(t, proxyChecks, 1)
	require.Equal(t, api.HealthPassing, proxyChecks[0].Status,
		"proxy check must be passing once all containers are healthy")
}

// TestSyncChecksAppBecomesUnhealthyMidOperation verifies that when an
// application container transitions HEALTHY → UNHEALTHY after steady state,
// both the app check and the dataplane check go critical, and that recovery
// brings both back to passing.
func TestSyncChecksAppBecomesUnhealthyMidOperation(t *testing.T) {
	serviceName := "app-unhealthy-mid-svc"
	proxyServiceName := serviceName + "-sidecar-proxy"
	taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
	appContainer := "app-container"

	taskMeta := &awsutil.ECSTaskMeta{Cluster: "test", TaskARN: taskARN, Family: serviceName}

	var currentTaskMetaResp atomic.Value

	// Start with everything healthy.
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusHealthy)),
		constructContainerResponse(appContainer, string(types.HealthStatusHealthy)),
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

	// Tick 1: all healthy → passing.
	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[appContainer])
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[config.ConsulDataplaneContainerName])

	proxyChecks, _, err := consulClient.Health().Checks(proxyServiceName, nil)
	require.NoError(t, err)
	require.Len(t, proxyChecks, 1)
	require.Equal(t, api.HealthPassing, proxyChecks[0].Status)

	// Tick 2: app becomes UNHEALTHY → both app and dataplane must go critical.
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusHealthy)),
		constructContainerResponse(appContainer, string(types.HealthStatusUnhealthy)),
	}
	s, err = constructTaskMetaResponseString(taskMeta)
	require.NoError(t, err)
	currentTaskMetaResp.Store(s)

	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusUnhealthy), currentStatuses[appContainer])
	require.Equal(t, string(types.HealthStatusUnhealthy), currentStatuses[config.ConsulDataplaneContainerName])

	serviceID := makeServiceID(serviceName, taskMeta.TaskID())
	appCheckID := constructCheckID(serviceID, appContainer)
	filter := "CheckID == `" + appCheckID + "`"
	appChecks, _, err := consulClient.Health().Checks(serviceName, &api.QueryOptions{Filter: filter})
	require.NoError(t, err)
	require.Len(t, appChecks, 1)
	require.Equal(t, api.HealthCritical, appChecks[0].Status, "app check must be critical")

	proxyChecks, _, err = consulClient.Health().Checks(proxyServiceName, nil)
	require.NoError(t, err)
	require.Len(t, proxyChecks, 1)
	require.Equal(t, api.HealthCritical, proxyChecks[0].Status, "proxy check must be critical when app is unhealthy")

	// Tick 3: app recovers → both must return to passing.
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusHealthy)),
		constructContainerResponse(appContainer, string(types.HealthStatusHealthy)),
	}
	s, err = constructTaskMetaResponseString(taskMeta)
	require.NoError(t, err)
	currentTaskMetaResp.Store(s)

	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[appContainer])
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[config.ConsulDataplaneContainerName])

	proxyChecks, _, err = consulClient.Health().Checks(proxyServiceName, nil)
	require.NoError(t, err)
	require.Len(t, proxyChecks, 1)
	require.Equal(t, api.HealthPassing, proxyChecks[0].Status, "proxy check must recover to passing")
}

// TestSyncChecksBatchesRegisterInOneCall verifies that all of a tick's changed
// checks are written by a single Catalog.Register. When the app and dataplane
// containers both transition "" -> HEALTHY, the app service check, the dataplane
// service check, and the dataplane proxy check must share one ModifyIndex,
// proving they landed in a single atomic write.
func TestSyncChecksBatchesRegisterInOneCall(t *testing.T) {
	serviceName := "batch-register-svc"
	proxyServiceName := serviceName + "-sidecar-proxy"
	taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
	appContainer := "app-container"

	taskMeta := &awsutil.ECSTaskMeta{Cluster: "test", TaskARN: taskARN, Family: serviceName}

	var currentTaskMetaResp atomic.Value
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusHealthy)),
		constructContainerResponse(appContainer, string(types.HealthStatusHealthy)),
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

	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[appContainer])
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[config.ConsulDataplaneContainerName])

	serviceChecks, _, err := consulClient.Health().Checks(serviceName, nil)
	require.NoError(t, err)
	require.Len(t, serviceChecks, 2) // app service check + dataplane service check

	proxyChecks, _, err := consulClient.Health().Checks(proxyServiceName, nil)
	require.NoError(t, err)
	require.Len(t, proxyChecks, 1) // dataplane proxy check

	// A single atomic Catalog.Register commits at one Raft index, so every
	// check it touched shares the same ModifyIndex.
	idx := proxyChecks[0].ModifyIndex
	require.Equal(t, api.HealthPassing, proxyChecks[0].Status)
	for _, ch := range serviceChecks {
		require.Equal(t, api.HealthPassing, ch.Status)
		require.Equal(t, idx, ch.ModifyIndex,
			"all of a tick's checks must be written in a single Catalog.Register (same ModifyIndex)")
	}
}

// TestSyncChecksDataplaneFailsLeavesAppCheckUntouched verifies the asymmetry
// between the two failure directions. When the consul-dataplane container
// becomes UNHEALTHY while the app container stays HEALTHY, only the aggregate is
// written: the dataplane service check and the dataplane proxy check go critical
// (in a single atomic Catalog.Register), while the app's own check keeps its
// PASSING status AND its ModifyIndex, proving it was skipped as unchanged.
func TestSyncChecksDataplaneFailsLeavesAppCheckUntouched(t *testing.T) {
	serviceName := "dp-fails-svc"
	proxyServiceName := serviceName + "-sidecar-proxy"
	taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
	appContainer := "app-container"

	taskMeta := &awsutil.ECSTaskMeta{Cluster: "test", TaskARN: taskARN, Family: serviceName}

	var currentTaskMetaResp atomic.Value
	// Start with everything healthy.
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusHealthy)),
		constructContainerResponse(appContainer, string(types.HealthStatusHealthy)),
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
	dpCheckID := constructCheckID(serviceID, config.ConsulDataplaneContainerName)

	serviceCheckByID := func(id string) *api.HealthCheck {
		checks, _, err := consulClient.Health().Checks(serviceName, nil)
		require.NoError(t, err)
		for _, ch := range checks {
			if ch.CheckID == id {
				return ch
			}
		}
		t.Fatalf("service check %s not found", id)
		return nil
	}
	proxyCheck := func() *api.HealthCheck {
		checks, _, err := consulClient.Health().Checks(proxyServiceName, nil)
		require.NoError(t, err)
		require.Len(t, checks, 1)
		return checks[0]
	}

	// Tick 1: all healthy → app and dataplane checks passing.
	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[appContainer])
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[config.ConsulDataplaneContainerName])

	appAfterTick1 := serviceCheckByID(appCheckID)
	require.Equal(t, api.HealthPassing, appAfterTick1.Status)
	appIdxAfterTick1 := appAfterTick1.ModifyIndex

	// Tick 2: only the consul-dataplane container becomes UNHEALTHY; app stays HEALTHY.
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusUnhealthy)),
		constructContainerResponse(appContainer, string(types.HealthStatusHealthy)),
	}
	s, err = constructTaskMetaResponseString(taskMeta)
	require.NoError(t, err)
	currentTaskMetaResp.Store(s)

	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[appContainer],
		"app's own status is unchanged")
	require.Equal(t, string(types.HealthStatusUnhealthy), currentStatuses[config.ConsulDataplaneContainerName],
		"aggregate goes critical because the dataplane container is unhealthy")

	// The app check must be skipped: same status, same ModifyIndex.
	appAfterTick2 := serviceCheckByID(appCheckID)
	require.Equal(t, api.HealthPassing, appAfterTick2.Status,
		"app check must remain passing when only the dataplane container fails")
	require.Equal(t, appIdxAfterTick1, appAfterTick2.ModifyIndex,
		"app check must NOT be rewritten when its status is unchanged")

	// Only the two dataplane checks are written, and they share one ModifyIndex.
	dpServiceCheck := serviceCheckByID(dpCheckID)
	dpProxyCheck := proxyCheck()
	require.Equal(t, api.HealthCritical, dpServiceCheck.Status)
	require.Equal(t, api.HealthCritical, dpProxyCheck.Status)
	require.Equal(t, dpServiceCheck.ModifyIndex, dpProxyCheck.ModifyIndex,
		"the dataplane service and proxy checks must be written in a single atomic Catalog.Register")
	require.Greater(t, dpServiceCheck.ModifyIndex, appIdxAfterTick1,
		"the dataplane checks must advance while the app check stays put")
}

// TestSetChecksCriticalBatchesInOneCall covers the graceful-shutdown path:
// setChecksCritical must mark every tracked container's check critical and write
// them all in a single Catalog.Register. This is the method the SIGTERM handler
// in realRun invokes; we call it directly (the signal wiring is not under test
// here, only the logic it triggers).
func TestSetChecksCriticalBatchesInOneCall(t *testing.T) {
	serviceName := "set-critical-svc"
	proxyServiceName := serviceName + "-sidecar-proxy"
	taskARN := "arn:aws:ecs:us-east-1:123456789:task/test/abcdef"
	appContainer := "app-container"

	taskMeta := &awsutil.ECSTaskMeta{Cluster: "test", TaskARN: taskARN, Family: serviceName}

	var currentTaskMetaResp atomic.Value
	taskMeta.Containers = []awsutil.ECSTaskMetaContainer{
		constructContainerResponse(config.ConsulDataplaneContainerName, string(types.HealthStatusHealthy)),
		constructContainerResponse(appContainer, string(types.HealthStatusHealthy)),
	}
	s, err := constructTaskMetaResponseString(taskMeta)
	require.NoError(t, err)
	currentTaskMetaResp.Store(s)
	testutil.TaskMetaServer(t, testutil.TaskMetaHandlerFn(t, func() string {
		return currentTaskMetaResp.Load().(string)
	}))

	cmd, consulClient, clusterARN := setupSyncChecksCmd(t, serviceName, []string{appContainer}, taskMeta)
	healthSyncContainers := []string{appContainer, config.ConsulDataplaneContainerName}

	// First drive everything to passing so the critical transition is observable.
	currentStatuses := make(map[string]string)
	currentStatuses = cmd.syncChecks(consulClient, currentStatuses, clusterARN, healthSyncContainers)
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[appContainer])
	require.Equal(t, string(types.HealthStatusHealthy), currentStatuses[config.ConsulDataplaneContainerName])

	// Run the shutdown path directly (what the SIGTERM handler calls).
	require.NoError(t, cmd.setChecksCritical(consulClient, *taskMeta, clusterARN, healthSyncContainers))

	// Verify that all checks are critical and share one ModifyIndex.
	serviceChecks, _, err := consulClient.Health().Checks(serviceName, nil)
	require.NoError(t, err)
	require.Len(t, serviceChecks, 2) // app service check + dataplane service check

	proxyChecks, _, err := consulClient.Health().Checks(proxyServiceName, nil)
	require.NoError(t, err)
	require.Len(t, proxyChecks, 1) // dataplane proxy check

	// Every check must be critical and share one ModifyIndex (single atomic write).
	idx := proxyChecks[0].ModifyIndex
	require.Equal(t, api.HealthCritical, proxyChecks[0].Status)
	for _, ch := range serviceChecks {
		require.Equal(t, api.HealthCritical, ch.Status,
			"every container's check must be critical after setChecksCritical")
		require.Equal(t, idx, ch.ModifyIndex,
			"setChecksCritical must write all checks in a single Catalog.Register (same ModifyIndex)")
	}
}

func TestComputeOverallDataplaneHealth(t *testing.T) {
	healthy := string(types.HealthStatusHealthy)
	unhealthy := string(types.HealthStatusUnhealthy)
	dp := config.ConsulDataplaneContainerName

	// syncChecks always seeds missing containers into the input map as
	// UNHEALTHY before calling computeOverallDataplaneHealth, so the test
	// cases below model that same shape.
	cases := map[string]struct {
		resolvedStatuses map[string]string
		expected         string
	}{
		"dataplane missing from task metadata": {
			resolvedStatuses: map[string]string{dp: unhealthy},
			expected:         unhealthy,
		},
		"dataplane present but UNHEALTHY": {
			resolvedStatuses: map[string]string{dp: unhealthy},
			expected:         unhealthy,
		},
		"dataplane HEALTHY, no other containers": {
			resolvedStatuses: map[string]string{dp: healthy},
			expected:         healthy,
		},
		"dataplane HEALTHY, all other containers HEALTHY": {
			resolvedStatuses: map[string]string{dp: healthy, "app": healthy, "sidecar": healthy},
			expected:         healthy,
		},
		"dataplane HEALTHY, one other container UNHEALTHY": {
			resolvedStatuses: map[string]string{dp: healthy, "app": healthy, "sidecar": unhealthy},
			expected:         unhealthy,
		},
		// Bug2: missing health-sync container must block traffic even when dataplane is HEALTHY.
		"dataplane HEALTHY, health-sync container not yet started": {
			resolvedStatuses: map[string]string{dp: healthy, "app": unhealthy},
			expected:         unhealthy,
		},
		"dataplane HEALTHY, multiple health-sync containers missing": {
			resolvedStatuses: map[string]string{dp: healthy, "app": unhealthy, "sidecar": unhealthy},
			expected:         unhealthy,
		},
		"dataplane itself missing alongside health-sync containers": {
			resolvedStatuses: map[string]string{dp: unhealthy, "app": unhealthy},
			expected:         unhealthy,
		},
		"dataplane HEALTHY, one container UNKNOWN": {
			resolvedStatuses: map[string]string{dp: healthy, "app": string(types.HealthStatusUnknown)},
			expected:         unhealthy,
		},
		"dataplane UNKNOWN": {
			resolvedStatuses: map[string]string{dp: string(types.HealthStatusUnknown), "app": healthy},
			expected:         unhealthy,
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			result := computeOverallDataplaneHealth(tc.resolvedStatuses)
			require.Equal(t, tc.expected, result)
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
