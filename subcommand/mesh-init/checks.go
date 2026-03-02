// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package meshinit

import (
	"fmt"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
)

const (
	consulECSCheckType = "consul-ecs-health-check"

	consulHealthSyncCheckName = "Consul ECS health check synced"

	consulDataplaneReadinessCheckName = "Consul dataplane readiness"
)

func (c *Command) constructChecks(service *api.AgentService) api.HealthChecks {
	checks := make(api.HealthChecks, 0)
	if service.Kind == api.ServiceKindTypical {
		for _, containerName := range c.config.HealthSyncContainers {
			checks = append(checks, &api.HealthCheck{
				CheckID:   constructCheckID(service.ID, containerName),
				Name:      consulHealthSyncCheckName,
				Type:      consulECSCheckType,
				ServiceID: service.ID,
				Namespace: service.Namespace,
				Status:    api.HealthCritical,
				Output:    healthCheckOutputReason(api.HealthCritical, service.Service),
				Notes:     fmt.Sprintf("consul-ecs created and updates this check because the %s container has an ECS health check.", containerName),
			})
		}
	}

	// Add a custom check that indicates dataplane readiness
	checks = append(checks, &api.HealthCheck{
		CheckID:   constructCheckID(service.ID, config.ConsulDataplaneContainerName),
		Name:      consulDataplaneReadinessCheckName,
		Type:      consulECSCheckType,
		ServiceID: service.ID,
		Namespace: service.Namespace,
		Status:    api.HealthCritical,
		Output:    healthCheckOutputReason(api.HealthCritical, service.Service),
		Notes:     "consul-ecs created and updates this check to indicate consul-dataplane container's readiness",
	})
	return checks
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
