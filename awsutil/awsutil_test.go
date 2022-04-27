package awsutil

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSession(t *testing.T) {
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

	// Restore the environment after these test cases.
	environ := os.Environ()
	t.Cleanup(func() { restoreEnv(t, environ) })

	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			// Ensure external environment doesn't affect us.
			for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
				require.NoError(t, os.Unsetenv(k))
			}

			// Prepare environment for each test case.
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

			sess, err := NewSession(ecsMeta, "")

			// Check an expected error
			if c.expectError != "" {
				require.Nil(t, sess)
				require.Error(t, err)
				require.Equal(t, c.expectError, err.Error())
				return
			}

			// Validate region is pulled correctly from environment or Task metadata.
			require.Equal(t, c.expectRegion, *sess.Config.Region)

			// Ensure the User-Agent request handler was added.
			// (Hacky. Only way I could figure out to detect a request handler by name)
			foundHandler := sess.Handlers.Build.Swap("UserAgentHandler", request.NamedHandler{})
			require.True(t, foundHandler)
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
	require.Nil(t, err)
	require.Equal(t, "us-east-1", region)

	account, err := ecsMeta.AccountID()
	require.NoError(t, err)
	require.Equal(t, "123456789", account)
}

// Helper to restore the environment after a test.
func restoreEnv(t *testing.T, env []string) {
	os.Clearenv()
	for _, keyvalue := range env {
		pair := strings.SplitN(keyvalue, "=", 2)
		assert.NoError(t, os.Setenv(pair[0], pair[1]))
	}
}
