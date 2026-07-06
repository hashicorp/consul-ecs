// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-multierror"
)

// fetchHealthChecks fetches the Consul health checks for both the service
// and proxy registrations
func (c *Command) fetchHealthChecks(consulClient *api.Client, taskMeta awsutil.ECSTaskMeta) (map[string]*api.HealthCheck, error) {
	serviceName := c.constructServiceName(taskMeta.Family)
	serviceID := makeServiceID(serviceName, taskMeta.TaskID())
	proxySvcID, proxySvcName := makeProxySvcIDAndName(serviceID, serviceName)

	healthCheckMap := make(map[string]*api.HealthCheck)
	var queryOpts *api.QueryOptions
	if c.config.IsGateway() {
		queryOpts = &api.QueryOptions{
			Namespace: c.config.Gateway.Namespace,
			Partition: c.config.Gateway.Partition,
		}
	} else {
		queryOpts = &api.QueryOptions{
			Namespace: c.config.Service.Namespace,
			Partition: c.config.Service.Partition,
		}
	}

	checks, err := getServiceHealthChecks(consulClient, serviceName, serviceID, queryOpts)
	if err != nil {
		return nil, err
	}

	for _, check := range checks {
		healthCheckMap[check.CheckID] = check
	}

	if c.config.IsGateway() {
		return healthCheckMap, nil
	}

	// Get the health checks associated with the sidecar
	checks, err = getServiceHealthChecks(consulClient, proxySvcName, proxySvcID, queryOpts)
	if err != nil {
		return nil, err
	}

	if len(checks) != 1 {
		return nil, fmt.Errorf("only one check should be associated with the sidecar proxy service")
	}

	healthCheckMap[checks[0].CheckID] = checks[0]

	return healthCheckMap, nil
}

// setChecksCritical stages every container's check as critical and writes them
// to Consul in a single Catalog.Register call.
func (c *Command) setChecksCritical(consulClient *api.Client, taskMeta awsutil.ECSTaskMeta, clusterARN string, parsedContainerNames []string) error {
	var result error
	var healthCheckBatch api.HealthChecks
	var stagedContainers []string

	for _, containerName := range parsedContainerNames {
		checks, err := c.stageContainerHealthChecks(taskMeta, containerName, string(types.HealthStatusUnhealthy))
		if err != nil {
			c.log.Warn("failed to set Consul health status to critical",
				"err", err, "container", containerName)
			result = multierror.Append(result, err)
			continue
		}
		if len(checks) == 0 {
			continue
		}
		healthCheckBatch = append(healthCheckBatch, checks...)
		stagedContainers = append(stagedContainers, containerName)
	}

	if err := c.registerChecks(consulClient, clusterARN, healthCheckBatch); err != nil {
		return multierror.Append(result, err)
	}

	// Log only after the write succeeds, so we never report a critical status
	// that was not actually committed to Consul.
	for _, containerName := range stagedContainers {
		c.log.Info("set Consul health status to critical",
			"container", containerName)
	}

	return result
}

// syncChecks fetches ECS task metadata and updates the Consul TTL checks for
// the containers in parsedContainerNames. Containers absent from task metadata
// are treated as UNHEALTHY. The consul-dataplane check reports the aggregate
// of every tracked container's status. Only checks whose status changed since
// the last tick are written, and all of a tick's changed checks are written in
// a single atomic Catalog.Register call.
func (c *Command) syncChecks(consulClient *api.Client,
	currentStatuses map[string]string,
	clusterARN string,
	parsedContainerNames []string) map[string]string {

	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		c.log.Error("unable to get task metadata", "err", err)
		return currentStatuses
	}

	containersToSync, missingContainers := findContainersToSync(parsedContainerNames, taskMeta)

	// Build the desired status for every tracked container, plus a lookup of
	// the raw ECS container records so we can include statusSince/exitCode in
	// the per-update log line below.
	resolvedStatuses := make(map[string]string, len(parsedContainerNames))
	foundContainers := make(map[string]awsutil.ECSTaskMetaContainer, len(containersToSync))
	for _, container := range containersToSync {
		resolvedStatuses[container.Name] = container.Health.Status
		foundContainers[container.Name] = container
	}
	for _, name := range missingContainers {
		resolvedStatuses[name] = string(types.HealthStatusUnhealthy)
	}

	resolvedStatuses[config.ConsulDataplaneContainerName] = computeOverallDataplaneHealth(resolvedStatuses)

	// Stage every changed container's health checks in memory, accumulate them into a
	// single healthCheckBatch, then issue one Catalog.Register for the whole tick.
	type statusChange struct {
		containerName  string
		desiredStatus  string
		previousStatus string
	}
	var (
		healthCheckBatch  api.HealthChecks // For writing (or registering) health checks (updates) to Consul
		statusChangeBatch []statusChange   // For logging containers status change after a successful write
	)
	for _, containerName := range parsedContainerNames {
		desiredStatus := resolvedStatuses[containerName]
		if desiredStatus == currentStatuses[containerName] {
			continue
		}

		checks, err := c.stageContainerHealthChecks(taskMeta, containerName, desiredStatus)
		if err != nil {
			c.log.Warn("failed to stage Consul health status",
				"err", err, "container", containerName)
			continue
		}
		if len(checks) == 0 {
			continue
		}
		healthCheckBatch = append(healthCheckBatch, checks...)
		statusChangeBatch = append(statusChangeBatch, statusChange{
			containerName:  containerName,
			desiredStatus:  desiredStatus,
			previousStatus: currentStatuses[containerName],
		})
	}

	if len(healthCheckBatch) == 0 {
		return currentStatuses
	}

	// Commit the whole tick's staged healthCheckBatch to Consul in one atomic Catalog.Register.
	// On failure we leave currentStatuses untouched so the next tick retries.
	if err := c.registerChecks(consulClient, clusterARN, healthCheckBatch); err != nil {
		c.log.Warn("failed to update Consul health status", "err", err)
		return currentStatuses
	}

	// A single Consul write happened this tick.
	// Log one line per changed container so each transition is on its own line.
	for _, change := range statusChangeBatch {
		logFields := []any{
			"container", change.containerName,
			"status", change.desiredStatus,
			"previous", change.previousStatus,
		}
		if container, ok := foundContainers[change.containerName]; ok {
			logFields = append(logFields,
				"statusSince", container.Health.StatusSince,
				"exitCode", container.Health.ExitCode,
			)
		}
		c.log.Info("container health check updated in Consul", logFields...)
		currentStatuses[change.containerName] = change.desiredStatus
	}

	return currentStatuses
}

// computeOverallDataplaneHealth returns HEALTHY only when consul-dataplane
// itself is HEALTHY and every other tracked container is HEALTHY. Callers
// must populate resolvedStatuses for every tracked container, with missing
// containers recorded as UNHEALTHY.
func computeOverallDataplaneHealth(resolvedStatuses map[string]string) string {
	if resolvedStatuses[config.ConsulDataplaneContainerName] != string(types.HealthStatusHealthy) {
		return string(types.HealthStatusUnhealthy)
	}

	for name, s := range resolvedStatuses {
		if name == config.ConsulDataplaneContainerName {
			continue
		}
		if s != string(types.HealthStatusHealthy) {
			return string(types.HealthStatusUnhealthy)
		}
	}

	return string(types.HealthStatusHealthy)
}

// stageContainerHealthChecks stages the Consul check(s) that a single container's
// status maps to and returns them, without writing to Consul.
//
// Consul registrations differ by service type:
//   - A typical service has two registrations: the service (kind "typical"),
//     which holds one check per app container plus a consul-dataplane readiness
//     check, and the sidecar proxy (kind "connect-proxy"), which holds one
//     consul-dataplane readiness check.
//   - A gateway has a single registration (no sidecar proxy) with one
//     consul-dataplane readiness check.
//
// As a result:
//   - the consul-dataplane container of a typical service (non-gateway) maps to two checks:
//     the service checks [serviceID-app + serviceID-consul-dataplane] and
//     the sidecar proxy check [proxySvcID-consul-dataplane], kept in sync together;
//   - the consul-dataplane container of a gateway service maps to a
//     single service check [gwServiceID-consul-dataplane],
//     because a gateway has no sidecar proxy registration; and
//   - every other (application) container maps to a single service check [serviceID-app].
func (c *Command) stageContainerHealthChecks(taskMeta awsutil.ECSTaskMeta, containerName, ecsHealthStatus string) (api.HealthChecks, error) {
	serviceName := c.constructServiceName(taskMeta.Family)
	serviceID := makeServiceID(serviceName, taskMeta.TaskID())

	// Every container, regardless of type, has a check on the primary
	// service (or gateway) registration.
	serviceCheck, err := c.stageCheck(serviceID, containerName, ecsHealthStatus)
	if err != nil {
		return nil, err
	}

	if containerName == config.ConsulDataplaneContainerName {
		// A gateway has no sidecar proxy, so just the serviceCheck.
		if c.config.IsGateway() {
			return api.HealthChecks{serviceCheck}, nil
		}

		// A typical service has a sidecar proxy as well, so stage the proxyCheck too &
		// return both serviceCheck and proxyCheck.
		proxySvcID, _ := makeProxySvcIDAndName(serviceID, "")
		proxyCheck, err := c.stageCheck(proxySvcID, containerName, ecsHealthStatus)
		if err != nil {
			return nil, err
		}
		return api.HealthChecks{serviceCheck, proxyCheck}, nil
	}

	return api.HealthChecks{serviceCheck}, nil
}

// stageCheck mutates the in-memory copy of the check for the given service and
// container to reflect ecsHealthStatus and returns it. It performs no network
// I/O; the caller registers the staged checks with Consul.
func (c *Command) stageCheck(serviceID, containerName, ecsHealthStatus string) (*api.HealthCheck, error) {
	checkID := constructCheckID(serviceID, containerName)
	check, ok := c.checks[checkID]
	if !ok || check == nil {
		return nil, fmt.Errorf("unable to find check with ID %s", checkID)
	}

	check.Status = ecsHealthToConsulHealth(ecsHealthStatus)
	check.Output = fmt.Sprintf("ECS health status is %q for container %q", ecsHealthStatus, checkID)
	return check, nil
}

// registerChecks writes the given health checks to the Consul catalog in a
// single Catalog.Register call. Each check carries its own ServiceID, so checks
// belonging to the service and the sidecar proxy can be registered together. It
// is a no-op when checks is empty.
func (c *Command) registerChecks(consulClient *api.Client, clusterARN string, checks api.HealthChecks) error {
	if len(checks) == 0 {
		return nil
	}

	updateCheckReq := &api.CatalogRegistration{
		Node:           clusterARN,
		SkipNodeUpdate: true,
		Checks:         checks,
	}

	_, err := consulClient.Catalog().Register(updateCheckReq, nil)
	return err
}

func getServiceHealthChecks(consulClient *api.Client, serviceName, serviceID string, opts *api.QueryOptions) (api.HealthChecks, error) {
	opts.Filter = fmt.Sprintf("ServiceID == `%s`", serviceID)
	checks, _, err := consulClient.Health().Checks(serviceName, opts)
	if err != nil {
		return nil, err
	}

	return checks, nil
}

func constructCheckID(serviceID, containerName string) string {
	return fmt.Sprintf("%s-%s", serviceID, containerName)
}

func findContainersToSync(containerNames []string, taskMeta awsutil.ECSTaskMeta) ([]awsutil.ECSTaskMetaContainer, []string) {
	var ecsContainers []awsutil.ECSTaskMetaContainer
	var missing []string

	for _, container := range containerNames {
		found := false
		for _, ecsContainer := range taskMeta.Containers {
			if ecsContainer.Name == container {
				ecsContainers = append(ecsContainers, ecsContainer)
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, container)
		}
	}
	return ecsContainers, missing
}

func ecsHealthToConsulHealth(ecsHealth string) string {
	// `HEALTHY`, `UNHEALTHY`, and `UNKNOWN` are the valid ECS health statuses.
	// This assumes that the only passing status is `HEALTHY`
	if ecsHealth != string(types.HealthStatusHealthy) {
		return api.HealthCritical
	}
	return api.HealthPassing
}
