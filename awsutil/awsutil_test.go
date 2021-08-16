package awsutil

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECSTaskMeta(t *testing.T) {
	cases := []struct {
		name         string
		env          map[string]string
		expectRegion string
	}{
		{
			name:         "no-env",
			env:          nil,
			expectRegion: "bogus-east-1",
		},
		{
			name:         "aws-region",
			env:          map[string]string{"AWS_REGION": "region-from-aws-region"},
			expectRegion: "region-from-aws-region",
		},
		{
			name:         "aws-default-region",
			env:          map[string]string{"AWS_DEFAULT_REGION": "region-from-aws-default-region"},
			expectRegion: "region-from-aws-default-region",
		},
	}

	for _, c := range cases {
		os.Clearenv()
		for k, v := range c.env {
			require.NoError(t, os.Setenv(k, v))
		}

		ecsMeta := ECSTaskMeta{
			Cluster: "test",
			TaskARN: "arn:aws:ecs:bogus-east-1:123456789:task/test/abcdef",
			Family:  "task",
		}
		require.Equal(t, "abcdef", ecsMeta.TaskID())
		require.Equal(t, c.expectRegion, ecsMeta.Region())
	}
}
