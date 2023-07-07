package meshinit

import (
	"testing"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestConstructChecks(t *testing.T) {
	cases := map[string]struct {
		service              *api.AgentService
		healthSyncContainers []string
		expectedChecks       api.HealthChecks
	}{
		"construct checks for the basic service": {
			service: &api.AgentService{
				ID:      "test-service-1234",
				Service: "test-service",
				Port:    8080,
			},
			healthSyncContainers: []string{"container1", "container2"},
			expectedChecks: api.HealthChecks{
				&api.HealthCheck{
					CheckID:   constructCheckID("test-service-1234", "container1"),
					Name:      consulHealthSyncCheckName,
					Type:      consulECSCheckType,
					ServiceID: "test-service-1234",
					Status:    api.HealthCritical,
					Output:    "Service test-service is not ready",
					Notes:     "consul-ecs created and updates this check because the container1 container has an ECS health check.",
				},
				&api.HealthCheck{
					CheckID:   constructCheckID("test-service-1234", "container2"),
					Name:      consulHealthSyncCheckName,
					Type:      consulECSCheckType,
					ServiceID: "test-service-1234",
					Status:    api.HealthCritical,
					Output:    "Service test-service is not ready",
					Notes:     "consul-ecs created and updates this check because the container2 container has an ECS health check.",
				},
				&api.HealthCheck{
					CheckID:   constructCheckID("test-service-1234", config.ConsulDataplaneContainerName),
					Name:      consulDataplaneReadinessCheckName,
					Type:      consulECSCheckType,
					ServiceID: "test-service-1234",
					Status:    api.HealthCritical,
					Output:    "Service test-service is not ready",
					Notes:     "consul-ecs created and updates this check to indicate consul-dataplane container's readiness",
				},
			},
		},
		"construct checks for the sidecar proxy service": {
			service: &api.AgentService{
				ID:      "test-service-sidecar-proxy-1234",
				Service: "test-service-sidecar-proxy",
				Port:    19000,
				Kind:    api.ServiceKindConnectProxy,
			},
			expectedChecks: api.HealthChecks{
				&api.HealthCheck{
					CheckID:   constructCheckID("test-service-sidecar-proxy-1234", config.ConsulDataplaneContainerName),
					Name:      consulDataplaneReadinessCheckName,
					Type:      consulECSCheckType,
					ServiceID: "test-service-sidecar-proxy-1234",
					Status:    api.HealthCritical,
					Output:    "Service test-service-sidecar-proxy is not ready",
					Notes:     "consul-ecs created and updates this check to indicate consul-dataplane container's readiness",
				},
			},
		},
		"construct checks for gateway proxy service": {
			service: &api.AgentService{
				ID:      "gateway-proxy-1234",
				Service: "gateway-proxy",
				Port:    8443,
				Kind:    api.ServiceKindMeshGateway,
			},
			expectedChecks: api.HealthChecks{
				&api.HealthCheck{
					CheckID:   constructCheckID("gateway-proxy-1234", config.ConsulDataplaneContainerName),
					Name:      consulDataplaneReadinessCheckName,
					Type:      consulECSCheckType,
					ServiceID: "gateway-proxy-1234",
					Status:    api.HealthCritical,
					Output:    "Service gateway-proxy is not ready",
					Notes:     "consul-ecs created and updates this check to indicate consul-dataplane container's readiness",
				},
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			namespace := ""
			partition := ""
			if testutil.EnterpriseFlag() {
				namespace = "test-namespace"
				partition = "test-partition"
			}

			c.service.Namespace = namespace
			c.service.Partition = partition

			for _, expHealthCheck := range c.expectedChecks {
				expHealthCheck.Namespace = namespace
			}

			ui := cli.NewMockUi()
			cmd := Command{UI: ui}
			cmd.config = &config.Config{
				HealthSyncContainers: c.healthSyncContainers,
			}

			cmd.checks = make(map[string]*api.HealthCheck)

			require.Equal(t, c.expectedChecks, cmd.constructChecks(c.service))
		})
	}
}

func TestEcsHealthToConsulHealth(t *testing.T) {
	require.Equal(t, api.HealthPassing, ecsHealthToConsulHealth(ecs.HealthStatusHealthy))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(ecs.HealthStatusUnknown))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(ecs.HealthStatusUnhealthy))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(""))
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
