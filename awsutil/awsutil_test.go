// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package awsutil

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

	environ := os.Environ()
	t.Cleanup(func() { restoreEnv(t, environ) })

	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {

			for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
				require.NoError(t, os.Unsetenv(k))
			}

			for k, v := range c.env {
				require.NoError(t, os.Setenv(k, v))
				t.Cleanup(func() {
					require.NoError(t, os.Unsetenv(k))
				})
			}

			ecsMeta := ECSTaskMeta{
				Cluster: "test",
				TaskARN: c.taskArn,
				Family:  "task",
			}

			cfg, err := NewAWSConfig(ecsMeta, "test-caller")

			if c.expectError != "" {
				require.Error(t, err)
				require.Equal(t, c.expectError, err.Error())
				return
			}

			require.NoError(t, err)
			require.Equal(t, c.expectRegion, cfg.Region)

			// Ensure custom User-Agent middleware (APIOptions) was added
			require.NotEmpty(t, cfg.APIOptions)
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
				DesiredStatus: "RUNNING",
				KnownStatus:   "RUNNING",
			},
			{
				Name:          "container2",
				DesiredStatus: "PENDING",
				KnownStatus:   "PENDING",
			},
		},
	}

	require.False(t, taskMeta.HasContainerStopped("container2"))

	taskMeta.Containers[1].DesiredStatus = DesiredStatusStopped
	taskMeta.Containers[1].KnownStatus = DesiredStatusStopped

	require.True(t, taskMeta.HasContainerStopped("container2"))
}

func TestHasStopped(t *testing.T) {
	container := ECSTaskMetaContainer{
		Name:          "container1",
		DesiredStatus: "RUNNING",
		KnownStatus:   "RUNNING",
	}

	require.False(t, container.HasStopped())

	container.DesiredStatus = DesiredStatusStopped
	container.KnownStatus = DesiredStatusStopped

	require.True(t, container.HasStopped())
}

func TestIsNormalType(t *testing.T) {
	container := ECSTaskMetaContainer{
		Name: "container1",
		Type: containerTypeNormal,
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

// Helper to restore environment
func restoreEnv(t *testing.T, env []string) {
	os.Clearenv()
	for _, keyvalue := range env {
		pair := strings.SplitN(keyvalue, "=", 2)
		assert.NoError(t, os.Setenv(pair[0], pair[1]))
	}
}
