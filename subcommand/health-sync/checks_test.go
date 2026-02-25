// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"testing"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/require"
)

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
