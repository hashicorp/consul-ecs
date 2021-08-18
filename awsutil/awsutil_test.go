package awsutil

import (
	"fmt"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/stretchr/testify/require"
)

func TestECSTaskMeta(t *testing.T) {
	taskRegion := "bogus-east-1"
	nonTaskRegion := "some-other-region"
	ecsMeta := ECSTaskMeta{
		Cluster: "test",
		TaskARN: fmt.Sprintf("arn:aws:ecs:%s:123456789:task/test/abcdef", taskRegion),
		Family:  "task",
	}

	cases := []struct {
		name         string
		env          map[string]string
		expectRegion string
	}{
		{
			name:         "no-env",
			env:          nil,
			expectRegion: taskRegion,
		},
		{
			name:         "aws-region",
			env:          map[string]string{"AWS_REGION": nonTaskRegion},
			expectRegion: nonTaskRegion,
		},
		{
			name: "aws-default-region",
			env: map[string]string{
				// "AWS_DEFAULT_REGION is only read if AWS_SDK_LOAD_CONFIG is also set,
				// and AWS_REGION is not also set."
				"AWS_DEFAULT_REGION":  nonTaskRegion,
				"AWS_SDK_LOAD_CONFIG": "1",
			},
			expectRegion: nonTaskRegion,
		},
		{
			name: "aws-region-and-default-region",
			env: map[string]string{
				"AWS_REGION":          nonTaskRegion,
				"AWS_DEFAULT_REGION":  "should-not-use-this-one",
				"AWS_SDK_LOAD_CONFIG": "1",
			},
			expectRegion: nonTaskRegion,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			os.Clearenv()
			for k, v := range c.env {
				require.NoError(t, os.Setenv(k, v))
			}

			require.Equal(t, "abcdef", ecsMeta.TaskID())

			sess, err := NewSession(ecsMeta, "")
			require.NoError(t, err)
			require.Equal(t, c.expectRegion, *sess.Config.Region)

			// Ensure the User-Agent request handler was added.
			// (Hacky. Only way I could figure out to detect a request handler by name)
			foundHandler := sess.Handlers.Build.Swap("UserAgentHandler", request.NamedHandler{})
			require.True(t, foundHandler)
		})
	}
}
