// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package awsutil

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/require"
)

func TestNewAWSConfig(t *testing.T) {
	taskRegion := "bogus-east-1"
	nonTaskRegion := "some-other-region"
	taskArn := fmt.Sprintf("arn:aws:ecs:%s:123456789:task/test/abcdef", taskRegion)

	cases := map[string]struct {
		env          map[string]string
		expectRegion string
		taskArn      string
		expectError  string
	}{
		"no-env": {
			expectRegion: taskRegion,
			taskArn:      taskArn,
		},
		"no-env-and-invalid-task-arn": {
			taskArn:     "invalid-task-arn",
			expectError: `unable to determine AWS region from Task ARN: "invalid-task-arn"`,
		},
		"aws-region": {
			env:          map[string]string{"AWS_REGION": nonTaskRegion},
			taskArn:      taskArn,
			expectRegion: nonTaskRegion,
		},
	}

	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			// Use t.Setenv instead of manual os.Unset/Set
			// This ensures a clean slate and automatic cleanup
			t.Setenv("AWS_REGION", "")
			t.Setenv("AWS_DEFAULT_REGION", "")

			for k, v := range c.env {
				t.Setenv(k, v)
			}

			ecsMeta := ECSTaskMeta{
				Cluster: "test",
				TaskARN: c.taskArn,
				Family:  "task",
			}

			cfg, err := NewAWSConfig(ecsMeta, "test-caller")

			if c.expectError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), c.expectError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, c.expectRegion, cfg.Region)

			// Check that we have exactly 1 custom API option (our middleware)
			require.Len(t, cfg.APIOptions, 1, "should have registered the User-Agent middleware")
		})
	}
}

func TestECSTaskMeta(t *testing.T) {
	ecsMeta := ECSTaskMeta{
		Cluster: "test",
		TaskARN: "arn:aws:ecs:us-east-1:123456789:task/test/abcdef",
		Family:  "task",
	}

	require.Equal(t, "abcdef", ecsMeta.TaskID())

	region, err := ecsMeta.Region()
	require.NoError(t, err)
	require.Equal(t, "us-east-1", region)

	account, err := ecsMeta.AccountID()
	require.NoError(t, err)
	require.Equal(t, "123456789", account)

	clusterArn, err := ecsMeta.ClusterARN()
	require.NoError(t, err)
	require.Equal(t, "arn:aws:ecs:us-east-1:123456789:cluster/test", clusterArn)
}

func TestHasContainerStopped(t *testing.T) {
	taskMeta := ECSTaskMeta{
		Containers: []ECSTaskMetaContainer{
			{
				Name:          "container1",
				DesiredStatus: string(types.DesiredStatusRunning),
				KnownStatus:   string(types.DesiredStatusRunning),
			},
			{
				Name:          "container2",
				DesiredStatus: string(types.DesiredStatusPending),
				KnownStatus:   string(types.DesiredStatusPending),
			},
		},
	}

	require.False(t, taskMeta.HasContainerStopped("container2"))

	taskMeta.Containers[1].DesiredStatus = string(types.DesiredStatusStopped)
	taskMeta.Containers[1].KnownStatus = string(types.DesiredStatusStopped)

	require.True(t, taskMeta.HasContainerStopped("container2"))
}

func TestHasStopped(t *testing.T) {
	container := ECSTaskMetaContainer{
		Name:          "container1",
		DesiredStatus: string(types.DesiredStatusRunning),
		KnownStatus:   string(types.DesiredStatusRunning),
	}

	require.False(t, container.HasStopped())

	container.DesiredStatus = string(types.DesiredStatusStopped)
	container.KnownStatus = string(types.DesiredStatusStopped)

	require.True(t, container.HasStopped())
}

func TestIsNormalType(t *testing.T) {
	container := ECSTaskMetaContainer{
		Name:          "container1",
		DesiredStatus: string(types.DesiredStatusRunning),
		KnownStatus:   string(types.DesiredStatusRunning),
		Type:          containerTypeNormal,
	}

	require.True(t, container.IsNormalType())

	container.Type = "SOME_AWS_MANAGED_TYPE"

	require.False(t, container.IsNormalType())
}

func TestECSTaskMeta_NodeIP(t *testing.T) {
	cases := map[string]struct {
		ecsMeta   ECSTaskMeta
		expNodeIP string
	}{
		"no containers": {
			ecsMeta:   ECSTaskMeta{},
			expNodeIP: "127.0.0.1",
		},
		"no networks": {
			ecsMeta: ECSTaskMeta{
				Containers: []ECSTaskMetaContainer{{}},
			},
			expNodeIP: "127.0.0.1",
		},
		"no addresses": {
			ecsMeta: ECSTaskMeta{
				Containers: []ECSTaskMetaContainer{{
					Networks: []ECSTaskMetaNetwork{{}},
				}},
			},
			expNodeIP: "127.0.0.1",
		},
		"node ip": {
			ecsMeta: ECSTaskMeta{
				Containers: []ECSTaskMetaContainer{{
					Networks: []ECSTaskMetaNetwork{{
						IPv4Addresses: []string{"10.1.2.3"},
					}},
				}},
			},
			expNodeIP: "10.1.2.3",
		},
	}

	for _, c := range cases {
		nodeIP := c.ecsMeta.NodeIP()
		require.Equal(t, c.expNodeIP, nodeIP)
	}
}

func TestGetAWSRegion(t *testing.T) {
	t.Setenv(AWSRegionEnvVar, "")
	require.Empty(t, GetAWSRegion())

	t.Setenv(AWSRegionEnvVar, "us-west-2")
	require.Equal(t, "us-west-2", GetAWSRegion())
}
