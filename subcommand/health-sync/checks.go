// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"fmt"

	"github.com/aws/aws-sdk-go/service/ecs"
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

// setChecksCritical sets checks for all of the containers to critical.
// Used during graceful shutdown (SIGTERM).
func (c *Command) setChecksCritical(consulClient *api.Client, taskMeta awsutil.ECSTaskMeta, clusterARN string, containerNames []string) error {
	var result error

	serviceName := c.constructServiceName(taskMeta.Family)
	serviceID := makeServiceID(serviceName, taskMeta.TaskID())

	// Create a map with all containers as unhealthy to get all check IDs
	containerStatuses := make(map[string]string)
	for _, name := range containerNames {
		containerStatuses[name] = ecs.HealthStatusUnhealthy
	}

	// Use computeCheckStatuses to get all check IDs
	checkStatuses := c.computeCheckStatuses(serviceID, containerNames, containerStatuses)

	// Update all checks to critical
	for checkID := range checkStatuses {
		err := c.updateConsulHealthStatus(consulClient, checkID, clusterARN, api.HealthCritical)
		if err != nil {
			c.log.Warn("failed to set Consul health status to critical", "err", err, "checkID", checkID)
			result = multierror.Append(result, err)
		} else {
			c.log.Info("set Consul health status to critical", "checkID", checkID)
		}
	}

	return result
}


// computeOverallDataplaneHealth computes the aggregate health status.
// Returns UNHEALTHY if any container is unhealthy.
func computeOverallDataplaneHealth(containerStatuses map[string]string) string {
	if len(containerStatuses) == 0 {
        // This should not be possible in practice since containerNames always
        // includes at least the dataplane container. Treat as unhealthy to be safe.
		return ecs.HealthStatusUnhealthy
	}

	for _, status := range containerStatuses {
		if status != ecs.HealthStatusHealthy {
			return ecs.HealthStatusUnhealthy
		}
	}
	return ecs.HealthStatusHealthy
}

// computeCheckStatuses computes the desired Consul health status for each check.
// Returns a map of checkID -> Consul health status (api.HealthPassing or api.HealthCritical).
func (c *Command) computeCheckStatuses(serviceID string, containerNames []string, containerStatuses map[string]string) map[string]string {
	checkStatuses := make(map[string]string)

	// Overall dataplane health is the aggregate of all container statuses
	overallHealth := ecsHealthToConsulHealth(computeOverallDataplaneHealth(containerStatuses))

	for _, name := range containerNames {
		if name == config.ConsulDataplaneContainerName {
			// Dataplane container maps to overall health on service check
			serviceCheckID := constructCheckID(serviceID, name)
			checkStatuses[serviceCheckID] = overallHealth

			// Non-gateways also have a proxy check
			if !c.config.IsGateway() {
				proxySvcID, _ := makeProxySvcIDAndName(serviceID, "")
				proxyCheckID := constructCheckID(proxySvcID, name)
				checkStatuses[proxyCheckID] = overallHealth
			}
		} else {
			// Non-dataplane containers map directly to their individual check
			checkID := constructCheckID(serviceID, name)
			checkStatuses[checkID] = ecsHealthToConsulHealth(containerStatuses[name])
		}
	}

	return checkStatuses
}

// syncChecks fetches ECS task metadata and updates Consul health checks
// for the specified containers. Checks are only updated when their status
// has changed since the last invocation.
func (c *Command) syncChecks(consulClient *api.Client,
	previousStatuses map[string]string,
	clusterARN string,
	containerNames []string) map[string]string {

	// Phase 1: Gather current container state
	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		c.log.Error("unable to get task metadata", "err", err)
		return previousStatuses
	}

	serviceName := c.constructServiceName(taskMeta.Family)
	serviceID := makeServiceID(serviceName, taskMeta.TaskID())
	containerStatuses := getContainerHealthStatuses(containerNames, taskMeta)

	// Phase 2: Turn ecs container health into consul checks
	currentStatuses := c.computeCheckStatuses(serviceID, containerNames, containerStatuses)

	// Phase 3: Update Consul for any checks that have changed
	for checkID, status := range currentStatuses {
		previousStatus := previousStatuses[checkID]
		if status == previousStatus {
			continue
		}

		err := c.updateConsulHealthStatus(consulClient, checkID, clusterARN, status)
		if err != nil {
			c.log.Warn("failed to update Consul health status", "err", err, "checkID", checkID)
			// Keep the previous status on error so we retry next cycle
			currentStatuses[checkID] = previousStatus
		} else {
			c.log.Info("health check updated in Consul", "checkID", checkID, "status", status)
		}
	}

	// Phase 4: Return current status
	return currentStatuses
}

func (c *Command) updateConsulHealthStatus(consulClient *api.Client, checkID string, clusterARN string, consulHealthStatus string) error {
	check, ok := c.checks[checkID]
	if !ok {
		return fmt.Errorf("unable to find check with ID %s", checkID)
	}

	check.Status = consulHealthStatus
	check.Output = fmt.Sprintf("Consul health status is %q for check %q", consulHealthStatus, checkID)
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

// getContainerHealthStatuses builds a map of container name to ECS health status.
// Missing containers are assigned ecs.HealthStatusUnhealthy.
func getContainerHealthStatuses(containerNames []string, taskMeta awsutil.ECSTaskMeta) map[string]string {
	statuses := make(map[string]string)

	// Build a lookup map from task metadata
	taskContainers := make(map[string]string)
	for _, container := range taskMeta.Containers {
		taskContainers[container.Name] = container.Health.Status
	}

	// Map each requested container to its status
	for _, name := range containerNames {
		if status, found := taskContainers[name]; found {
			statuses[name] = status
		} else {
			statuses[name] = ecs.HealthStatusUnhealthy
		}
	}

	return statuses
}

func ecsHealthToConsulHealth(ecsHealth string) string {
	// `HEALTHY`, `UNHEALTHY`, and `UNKNOWN` are the valid ECS health statuses.
	// This assumes that the only passing status is `HEALTHY`
	if ecsHealth != ecs.HealthStatusHealthy {
		return api.HealthCritical
	}
	return api.HealthPassing
}
