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

// setChecksCritical sets checks for all of the containers to critical
func (c *Command) setChecksCritical(consulClient *api.Client, taskMeta awsutil.ECSTaskMeta, clusterARN string, parsedContainerNames []string) error {
	var result error

	taskID := taskMeta.TaskID()
	serviceName := c.constructServiceName(taskMeta.Family)

	for _, containerName := range parsedContainerNames {
		var err error
		if containerName == config.ConsulDataplaneContainerName {
			err = c.handleHealthForDataplaneContainer(consulClient, taskID, serviceName, clusterARN, containerName, ecs.HealthStatusUnhealthy)
		} else {
			checkID := constructCheckID(makeServiceID(serviceName, taskID), containerName)
			err = c.updateConsulHealthStatus(consulClient, checkID, clusterARN, ecs.HealthStatusUnhealthy)
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
// updates the Consul TTL checks for the containers specified in
// `parsedContainerNames`. Checks are only updated if they have changed since
// the last invocation of this function.
func (c *Command) syncChecks(consulClient *api.Client,
	currentStatuses map[string]string,
	clusterARN string,
	parsedContainerNames []string) map[string]string {
	// Fetch task metadata to get latest health of the containers
	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		c.log.Error("unable to get task metadata", "err", err)
		return currentStatuses
	}

	serviceName := c.constructServiceName(taskMeta.Family)
	containersToSync, missingContainers := findContainersToSync(parsedContainerNames, taskMeta)

	// Mark the Consul health status as critical for missing containers
	for _, name := range missingContainers {
		checkID := constructCheckID(makeServiceID(serviceName, taskMeta.TaskID()), name)
		c.log.Debug("marking container as unhealthy since it wasn't found in the task metadata", "name", name)

		var err error
		if name == config.ConsulDataplaneContainerName {
			err = c.handleHealthForDataplaneContainer(consulClient, taskMeta.TaskID(), serviceName, clusterARN, name, ecs.HealthStatusUnhealthy)
		} else {
			err = c.updateConsulHealthStatus(consulClient, checkID, clusterARN, ecs.HealthStatusUnhealthy)
		}

		if err != nil {
			c.log.Error("failed to update Consul health status for missing container", "err", err, "container", name)
		} else {
			c.log.Info("container health check updated in Consul for missing container", "container", name)
			currentStatuses[name] = api.HealthCritical
		}
	}

	overallDataplaneHealth := 0
	parsedContainers := make(map[string]string)
	// iterate over parse
	for _, container := range containersToSync {
		c.log.Debug("updating Consul check from ECS container health",
			"name", container.Name,
			"status", container.Health.Status,
			"statusSince", container.Health.StatusSince,
			"exitCode", container.Health.ExitCode,
		)
		parsedContainers[container.Name] = container.Health.Status
		previousStatus := currentStatuses[container.Name]
		if container.Health.Status != previousStatus {
			var err error
			if container.Name != config.ConsulDataplaneContainerName {
				checkID := constructCheckID(makeServiceID(serviceName, taskMeta.TaskID()), container.Name)
				err = c.updateConsulHealthStatus(consulClient, checkID, clusterARN, container.Health.Status)
			}

			if err != nil {
				c.log.Warn("failed to update Consul health status", "err", err)
			} else {
				c.log.Info("container health check updated in Consul",
					"name", container.Name,
					"status", container.Health.Status,
					"statusSince", container.Health.StatusSince,
					"exitCode", container.Health.ExitCode,
				)
				currentStatuses[container.Name] = container.Health.Status
			}
		}
		if container.Name == config.ConsulDataplaneContainerName {
			if container.Health.Status == ecs.HealthStatusHealthy {
				overallDataplaneHealth = 1
			}
		}
	}

	for containerName, healthStatus := range parsedContainers {

		if containerName != config.ConsulDataplaneContainerName {
			currentContainerHealth := 0
			if healthStatus == ecs.HealthStatusHealthy {
				currentContainerHealth = 1
			}
			overallDataplaneHealth = overallDataplaneHealth & currentContainerHealth
		}
	}
	overallDataplaneHealthStatus := ecs.HealthStatusUnhealthy
	if overallDataplaneHealth == 1 {
		overallDataplaneHealthStatus = ecs.HealthStatusHealthy
	}

	err = c.handleHealthForDataplaneContainer(consulClient, taskMeta.TaskID(), serviceName, clusterARN, config.ConsulDataplaneContainerName, overallDataplaneHealthStatus)
	if err != nil {
		c.log.Warn("failed to update Consul health status", "err", err)
	} else {
		c.log.Info("container health check updated in Consul",
			"name", config.ConsulDataplaneContainerName,
			"status", overallDataplaneHealthStatus,
		)
	}
	return currentStatuses
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
	if ecsHealth != ecs.HealthStatusHealthy {
		return api.HealthCritical
	}
	return api.HealthPassing
}
