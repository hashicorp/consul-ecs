package meshinit

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-multierror"
)

const (
	consulECSCheckType = "consul-ecs-health-check"

	consulHealthSyncCheckName = "Consul ECS health check synced"

	consulDataplaneReadinessCheckName = "Consul dataplane readiness"

	// syncChecksInterval is how often we poll the container health endpoint and
	// sync the checks back to the Consul servers.
	//
	// The rate limit for the health endpoint is about 40 per second,
	// so 1 second polling seems reasonable.
	syncChecksInterval = 1 * time.Second
)

func (c *Command) constructChecks(service *api.AgentService) api.HealthChecks {
	checks := make(api.HealthChecks, 0)
	if service.Kind == api.ServiceKindTypical {
		for _, containerName := range c.config.HealthSyncContainers {
			check := &api.HealthCheck{
				CheckID:   constructCheckID(service.ID, containerName),
				Name:      consulHealthSyncCheckName,
				Type:      consulECSCheckType,
				ServiceID: service.ID,
				Namespace: service.Namespace,
				Status:    api.HealthCritical,
				Output:    healthCheckOutputReason(api.HealthCritical, service.Service),
				Notes:     fmt.Sprintf("consul-ecs created and updates this check because the %s container has an ECS health check.", containerName),
			}
			c.checks[check.CheckID] = check
			checks = append(checks, check)
		}
	}

	// Add a custom check that indicates dataplane readiness
	dataplaneCheck := &api.HealthCheck{
		CheckID:   constructCheckID(service.ID, config.ConsulDataplaneContainerName),
		Name:      consulDataplaneReadinessCheckName,
		Type:      consulECSCheckType,
		ServiceID: service.ID,
		Namespace: service.Namespace,
		Status:    api.HealthCritical,
		Output:    healthCheckOutputReason(api.HealthCritical, service.Service),
		Notes:     "consul-ecs created and updates this check to indicate consul-dataplane container's readiness",
	}
	c.checks[dataplaneCheck.CheckID] = dataplaneCheck
	checks = append(checks, dataplaneCheck)
	return checks
}

// syncChecks fetches metadata for the ECS task and uses that metadata to
// updates the Consul TTL checks for the containers specified in
// `parsedContainerNames`. Checks are only updated if they have changed since
// the last invocation of this function.
func (c *Command) syncChecks(consulClient *api.Client,
	currentStatuses map[string]string,
	serviceName string,
	clusterARN string,
	parsedContainerNames []string) map[string]string {
	// Fetch task metadata to get latest health of the containers
	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		c.log.Error("unable to get task metadata", "err", err)
		return currentStatuses
	}

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

	for _, container := range containersToSync {
		c.log.Debug("updating Consul check from ECS container health",
			"name", container.Name,
			"status", container.Health.Status,
			"statusSince", container.Health.StatusSince,
			"exitCode", container.Health.ExitCode,
		)

		previousStatus := currentStatuses[container.Name]
		if container.Health.Status != previousStatus {
			var err error
			if container.Name == config.ConsulDataplaneContainerName {
				err = c.handleHealthForDataplaneContainer(consulClient, taskMeta.TaskID(), serviceName, clusterARN, container.Name, container.Health.Status)
			} else {
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
	}

	return currentStatuses
}

// setChecksCritical sets checks for all of the containers to critical
func (c *Command) setChecksCritical(consulClient *api.Client, taskID, serviceName, clusterARN string, parsedContainerNames []string) error {
	var result error

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

func constructCheckID(serviceID, containerName string) string {
	return fmt.Sprintf("%s-%s", serviceID, containerName)
}

func healthCheckOutputReason(status, serviceName string) string {
	if status == api.HealthPassing {
		return "ECS health check passing"
	}

	return fmt.Sprintf("Service %s is not ready", serviceName)
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
