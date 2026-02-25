// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/require"
)

func TestEcsHealthToConsulHealth(t *testing.T) {
	require.Equal(t, api.HealthPassing, ecsHealthToConsulHealth(ecs.HealthStatusHealthy))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(ecs.HealthStatusUnknown))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(ecs.HealthStatusUnhealthy))
	require.Equal(t, api.HealthCritical, ecsHealthToConsulHealth(""))
}

func TestGetContainerHealthStatuses(t *testing.T) {
	cases := map[string]struct {
		containerNames []string
		taskMeta       awsutil.ECSTaskMeta
		expected       map[string]string
	}{
		"all containers present and healthy": {
			containerNames: []string{"app", "sidecar"},
			taskMeta: awsutil.ECSTaskMeta{
				Containers: []awsutil.ECSTaskMetaContainer{
					{Name: "app", Health: awsutil.ECSTaskMetaHealth{Status: ecs.HealthStatusHealthy}},
					{Name: "sidecar", Health: awsutil.ECSTaskMetaHealth{Status: ecs.HealthStatusHealthy}},
				},
			},
			expected: map[string]string{
				"app":     ecs.HealthStatusHealthy,
				"sidecar": ecs.HealthStatusHealthy,
			},
		},
		"one container unhealthy": {
			containerNames: []string{"app", "sidecar"},
			taskMeta: awsutil.ECSTaskMeta{
				Containers: []awsutil.ECSTaskMetaContainer{
					{Name: "app", Health: awsutil.ECSTaskMetaHealth{Status: ecs.HealthStatusHealthy}},
					{Name: "sidecar", Health: awsutil.ECSTaskMetaHealth{Status: ecs.HealthStatusUnhealthy}},
				},
			},
			expected: map[string]string{
				"app":     ecs.HealthStatusHealthy,
				"sidecar": ecs.HealthStatusUnhealthy,
			},
		},
		"container missing from metadata": {
			containerNames: []string{"app", "sidecar"},
			taskMeta: awsutil.ECSTaskMeta{
				Containers: []awsutil.ECSTaskMetaContainer{
					{Name: "app", Health: awsutil.ECSTaskMetaHealth{Status: ecs.HealthStatusHealthy}},
				},
			},
			expected: map[string]string{
				"app":     ecs.HealthStatusHealthy,
				"sidecar": ecs.HealthStatusUnhealthy,
			},
		},
		"all containers missing": {
			containerNames: []string{"app", "sidecar"},
			taskMeta:       awsutil.ECSTaskMeta{},
			expected: map[string]string{
				"app":     ecs.HealthStatusUnhealthy,
				"sidecar": ecs.HealthStatusUnhealthy,
			},
		},
		"empty container list": {
			containerNames: []string{},
			taskMeta: awsutil.ECSTaskMeta{
				Containers: []awsutil.ECSTaskMetaContainer{
					{Name: "app", Health: awsutil.ECSTaskMetaHealth{Status: ecs.HealthStatusHealthy}},
				},
			},
			expected: map[string]string{},
		},
		"extra containers in metadata ignored": {
			containerNames: []string{"app"},
			taskMeta: awsutil.ECSTaskMeta{
				Containers: []awsutil.ECSTaskMetaContainer{
					{Name: "app", Health: awsutil.ECSTaskMetaHealth{Status: ecs.HealthStatusHealthy}},
					{Name: "extra", Health: awsutil.ECSTaskMetaHealth{Status: ecs.HealthStatusHealthy}},
				},
			},
			expected: map[string]string{
				"app": ecs.HealthStatusHealthy,
			},
		},
		"unknown status preserved": {
			containerNames: []string{"app"},
			taskMeta: awsutil.ECSTaskMeta{
				Containers: []awsutil.ECSTaskMetaContainer{
					{Name: "app", Health: awsutil.ECSTaskMetaHealth{Status: ecs.HealthStatusUnknown}},
				},
			},
			expected: map[string]string{
				"app": ecs.HealthStatusUnknown,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result := getContainerHealthStatuses(tc.containerNames, tc.taskMeta)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestComputeOverallDataplaneHealth(t *testing.T) {
	cases := map[string]struct {
		containerStatuses map[string]string
		expected          string
	}{
		"all healthy": {
			containerStatuses: map[string]string{
				"app":     ecs.HealthStatusHealthy,
				"sidecar": ecs.HealthStatusHealthy,
			},
			expected: ecs.HealthStatusHealthy,
		},
		"one unhealthy": {
			containerStatuses: map[string]string{
				"app":     ecs.HealthStatusHealthy,
				"sidecar": ecs.HealthStatusUnhealthy,
			},
			expected: ecs.HealthStatusUnhealthy,
		},
		"one unknown": {
			containerStatuses: map[string]string{
				"app":     ecs.HealthStatusHealthy,
				"sidecar": ecs.HealthStatusUnknown,
			},
			expected: ecs.HealthStatusUnhealthy,
		},
		"all unhealthy": {
			containerStatuses: map[string]string{
				"app":     ecs.HealthStatusUnhealthy,
				"sidecar": ecs.HealthStatusUnhealthy,
			},
			expected: ecs.HealthStatusUnhealthy,
		},
		"empty map treated as unhealthy": {
			// This should not happen in practice since containerNames always
			// includes at least the dataplane container. Treated as unhealthy to be safe.
			containerStatuses: map[string]string{},
			expected:          ecs.HealthStatusUnhealthy,
		},
		"single healthy": {
			containerStatuses: map[string]string{
				"app": ecs.HealthStatusHealthy,
			},
			expected: ecs.HealthStatusHealthy,
		},
		"single unhealthy": {
			containerStatuses: map[string]string{
				"app": ecs.HealthStatusUnhealthy,
			},
			expected: ecs.HealthStatusUnhealthy,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result := computeOverallDataplaneHealth(tc.containerStatuses)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestComputeCheckStatuses(t *testing.T) {
	const (
		serviceID        = "test-service-12345"
		dataplaneContainer = config.ConsulDataplaneContainerName
	)

	// Expected check IDs for non-gateway
	serviceCheckID := constructCheckID(serviceID, dataplaneContainer)
	proxySvcID, _ := makeProxySvcIDAndName(serviceID, "")
	proxyCheckID := constructCheckID(proxySvcID, dataplaneContainer)
	appCheckID := constructCheckID(serviceID, "app")

	cases := map[string]struct {
		isGateway              bool
		containerNames         []string
		containerStatuses      map[string]string
		expectedConsulStatuses map[string]string
		expectedOutputs        map[string]string // optional, only checked if non-nil
	}{
		"non-gateway all healthy": {
			isGateway:      false,
			containerNames: []string{"app", dataplaneContainer},
			containerStatuses: map[string]string{
				"app":              ecs.HealthStatusHealthy,
				dataplaneContainer: ecs.HealthStatusHealthy,
			},
			expectedConsulStatuses: map[string]string{
				appCheckID:     api.HealthPassing,
				serviceCheckID: api.HealthPassing,
				proxyCheckID:   api.HealthPassing,
			},
			expectedOutputs: map[string]string{
				appCheckID: fmt.Sprintf("ECS health status is %q for container %q", ecs.HealthStatusHealthy, appCheckID),
			},
		},
		"non-gateway app unhealthy affects overall health": {
			isGateway:      false,
			containerNames: []string{"app", dataplaneContainer},
			containerStatuses: map[string]string{
				"app":              ecs.HealthStatusUnhealthy,
				dataplaneContainer: ecs.HealthStatusHealthy,
			},
			expectedConsulStatuses: map[string]string{
				appCheckID:     api.HealthCritical,
				serviceCheckID: api.HealthCritical,
				proxyCheckID:   api.HealthCritical,
			},
			expectedOutputs: map[string]string{
				appCheckID: fmt.Sprintf("ECS health status is %q for container %q", ecs.HealthStatusUnhealthy, appCheckID),
			},
		},
		"non-gateway dataplane unhealthy": {
			isGateway:      false,
			containerNames: []string{"app", dataplaneContainer},
			containerStatuses: map[string]string{
				"app":              ecs.HealthStatusHealthy,
				dataplaneContainer: ecs.HealthStatusUnhealthy,
			},
			expectedConsulStatuses: map[string]string{
				appCheckID:     api.HealthPassing,
				serviceCheckID: api.HealthCritical,
				proxyCheckID:   api.HealthCritical,
			},
		},
		"non-gateway dataplane only": {
			isGateway:      false,
			containerNames: []string{dataplaneContainer},
			containerStatuses: map[string]string{
				dataplaneContainer: ecs.HealthStatusHealthy,
			},
			expectedConsulStatuses: map[string]string{
				serviceCheckID: api.HealthPassing,
				proxyCheckID:   api.HealthPassing,
			},
		},
		"gateway healthy": {
			isGateway:      true,
			containerNames: []string{dataplaneContainer},
			containerStatuses: map[string]string{
				dataplaneContainer: ecs.HealthStatusHealthy,
			},
			expectedConsulStatuses: map[string]string{
				serviceCheckID: api.HealthPassing,
			},
		},
		"gateway unhealthy": {
			isGateway:      true,
			containerNames: []string{dataplaneContainer},
			containerStatuses: map[string]string{
				dataplaneContainer: ecs.HealthStatusUnhealthy,
			},
			expectedConsulStatuses: map[string]string{
				serviceCheckID: api.HealthCritical,
			},
		},
		"gateway no proxy check": {
			isGateway:      true,
			containerNames: []string{"app", dataplaneContainer},
			containerStatuses: map[string]string{
				"app":              ecs.HealthStatusHealthy,
				dataplaneContainer: ecs.HealthStatusHealthy,
			},
			expectedConsulStatuses: map[string]string{
				appCheckID:     api.HealthPassing,
				serviceCheckID: api.HealthPassing,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cmd := &Command{
				config: &config.Config{},
			}
			if tc.isGateway {
				cmd.config.Gateway = &config.GatewayRegistration{
					Kind: api.ServiceKindMeshGateway,
				}
			}

			result := cmd.computeCheckStatuses(serviceID, tc.containerNames, tc.containerStatuses)

			// Check consul statuses
			for checkID, expectedStatus := range tc.expectedConsulStatuses {
				require.Equal(t, expectedStatus, result[checkID].consulStatus, "consul status mismatch for %s", checkID)
			}

			// Check output messages if specified
			for checkID, expectedOutput := range tc.expectedOutputs {
				require.Equal(t, expectedOutput, result[checkID].output, "output mismatch for %s", checkID)
			}

			// Verify no extra checks
			require.Len(t, result, len(tc.expectedConsulStatuses))
		})
	}
}
