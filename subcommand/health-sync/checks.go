// Copyright IBM Corp. 2021, 2025
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

// setChecksCritical sets checks for all of the containers to critical
func (c *Command) setChecksCritical(consulClient *api.Client, taskMeta awsutil.ECSTaskMeta, clusterARN string, parsedContainerNames []string) error {
	var result error

	taskID := taskMeta.TaskID()
	serviceName := c.constructServiceName(taskMeta.Family)

	for _, containerName := range parsedContainerNames {
		var err error
		if containerName == config.ConsulDataplaneContainerName {
			err = c.handleHealthForDataplaneContainer(consulClient, taskID, serviceName, clusterARN, containerName, string(types.HealthStatusUnhealthy))
		} else {
			checkID := constructCheckID(makeServiceID(serviceName, taskID), containerName)
			err = c.updateConsulHealthStatus(consulClient, checkID, clusterARN, string(types.HealthStatusUnhealthy))
		}

		if err == nil {
			c.log.Info("set Consul health status to critical",
				"container", containerName)
		} else {
			c.log.Warn("failed to set Consul health status to critical",
				"err", err,
				"container", containerName)
			result = multierror.Append(result, err)
		}
	}

	return result
}

// syncChecks fetches metadata for the ECS task and uses that metadata to
// update the Consul TTL checks for the containers specified in
// `parsedContainerNames`. Checks are only updated if they have changed since
// the last invocation of this function.
//
// The function follows three distinct steps:
//  1. Gather state  – fetch container health from ECS task metadata; classify
//     each container as found (with its reported status) or missing (treated
//     as UNHEALTHY).
//  2. Compute checks – derive desired Consul check status for every container,
//     including the aggregated dataplane health (HEALTHY only when dataplane,
//     all found containers, AND all health-sync containers are HEALTHY).
//  3. Update Consul  – send Catalog.Register only for checks whose desired
//     status differs from the last written status (delta guard).
func (c *Command) syncChecks(consulClient *api.Client,
	currentStatuses map[string]string,
	clusterARN string,
	parsedContainerNames []string) map[string]string {

	// ── Step 1: Gather state ────────────────────────────────────────────
	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		c.log.Error("unable to get task metadata", "err", err)
		return currentStatuses
	}

	serviceName := c.constructServiceName(taskMeta.Family)
	taskID := taskMeta.TaskID()
	serviceID := makeServiceID(serviceName, taskID)
	containersToSync, missingContainers := findContainersToSync(parsedContainerNames, taskMeta)

	// Build desired status for every container.
	// Missing containers (not yet started or crashed) are treated as UNHEALTHY.
	resolvedStatuses := make(map[string]string, len(parsedContainerNames))
	for _, container := range containersToSync {
		resolvedStatuses[container.Name] = container.Health.Status
	}
	for _, name := range missingContainers {
		resolvedStatuses[name] = string(types.HealthStatusUnhealthy)
	}

	// ── Step 2: Compute overall dataplane health ────────────────────────
	// Dataplane is HEALTHY only when it and every other container are HEALTHY
	// and no health-sync container is missing from task metadata.
	overallDataplaneHealthStatus := computeOverallDataplaneHealth(resolvedStatuses, missingContainers)
	resolvedStatuses[config.ConsulDataplaneContainerName] = overallDataplaneHealthStatus

	// ── Step 3: Update Consul (delta guard – write only on change) ──────
	for _, name := range parsedContainerNames {
		desired := resolvedStatuses[name]
		if desired == currentStatuses[name] {
			continue
		}

		var updateErr error
		if name == config.ConsulDataplaneContainerName {
			// Dataplane updates both service and proxy checks.
			updateErr = c.handleHealthForDataplaneContainer(consulClient, taskID, serviceName, clusterARN, name, desired)
		} else {
			checkID := constructCheckID(serviceID, name)
			updateErr = c.updateConsulHealthStatus(consulClient, checkID, clusterARN, desired)
		}

		if updateErr != nil {
			c.log.Warn("failed to update Consul health status",
				"err", updateErr, "container", name)
			continue
		}

		c.log.Info("container health check updated in Consul",
			"container", name,
			"status", desired,
			"previous", currentStatuses[name],
		)
		currentStatuses[name] = desired
	}

	return currentStatuses
}

// computeOverallDataplaneHealth returns the ECS health status that should be
// written to the consul-dataplane Consul check. It returns HEALTHY only when
// consul-dataplane itself is HEALTHY, every found container is HEALTHY, and no
// health-sync container is missing from task metadata (i.e. not yet started).
func computeOverallDataplaneHealth(resolvedStatuses map[string]string, missingContainers []string) string {
	status, ok := resolvedStatuses[config.ConsulDataplaneContainerName]
	if !ok || status != string(types.HealthStatusHealthy) {
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

	for _, name := range missingContainers {
		if name != config.ConsulDataplaneContainerName {
			return string(types.HealthStatusUnhealthy)
		}
	}

	return string(types.HealthStatusHealthy)
}

// handleHealthForDataplaneContainer takes care of the special handling needed for syncing
// the health of consul-dataplane container. We register two checks (one for the service
// and the other for proxy) when registering a typical service to the catalog. Updates
// should also happen twice in such cases.
func (c *Command) handleHealthForDataplaneContainer(consulClient *api.Client, taskID, serviceName, clusterARN, containerName, ecsHealthStatus string) error {
	var checkID string
	serviceID := makeServiceID(serviceName, taskID)
	if c.config.IsGateway() {
		checkID = constructCheckID(serviceID, containerName)
		return c.updateConsulHealthStatus(consulClient, checkID, clusterARN, ecsHealthStatus)
	}

	checkID = constructCheckID(serviceID, containerName)
	err := c.updateConsulHealthStatus(consulClient, checkID, clusterARN, ecsHealthStatus)
	if err != nil {
		return err
	}

	proxySvcID, _ := makeProxySvcIDAndName(serviceID, "")
	checkID = constructCheckID(proxySvcID, containerName)
	return c.updateConsulHealthStatus(consulClient, checkID, clusterARN, ecsHealthStatus)
}

func (c *Command) updateConsulHealthStatus(consulClient *api.Client, checkID string, clusterARN string, ecsHealthStatus string) error {
	consulHealthStatus := ecsHealthToConsulHealth(ecsHealthStatus)

	check, ok := c.checks[checkID]
	if !ok {
		return fmt.Errorf("unable to find check with ID %s", checkID)
	}

	check.Status = consulHealthStatus
	check.Output = fmt.Sprintf("ECS health status is %q for container %q", ecsHealthStatus, checkID)
	c.checks[checkID] = check

	updateCheckReq := &api.CatalogRegistration{
		Node:           clusterARN,
		SkipNodeUpdate: true,
		Checks:         api.HealthChecks{check},
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
