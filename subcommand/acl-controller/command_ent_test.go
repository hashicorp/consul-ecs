//go:build enterprise

package aclcontroller

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

var expPartitionedClientPolicy = fmt.Sprintf(`partition "%s" {
  node_prefix "" {
    policy = "write"
  }
  namespace_prefix "" {
    service_prefix "" {
      policy = "read"
    }
  }
}`, testPartitionName)

func TestUpsertConsulClientTokenEnt(t *testing.T) {
	cases := testCases{
		"when partitions are enabled with no token or policy": {
			existingSecret: &secretsmanager.GetSecretValueOutput{
				ARN:          aws.String("test-consul-client-token-arn"),
				Name:         aws.String("test-consul-client-token"),
				SecretString: aws.String(`{}`),
			},
			partitionsEnabled: true,
			expPolicyRules:    expPartitionedClientPolicy,
		},
	}
	testUpsertConsulClientToken(t, cases)
}

func TestUpsertPartitionEnt(t *testing.T) {
	cases := map[string]struct {
		partition       string
		createPartition bool
		err             error
	}{
		"when partitions are enabled and the configured partition already exists": {
			partition:       testPartitionName,
			createPartition: true,
		},
		"when partitions are enabled and the configured partition does not exist": {
			partition: testPartitionName,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
			if c.partition != "" {
				cfg.Partition = c.partition
			}

			consulClient, err := api.NewClient(cfg)
			require.NoError(t, err)

			if c.createPartition {
				_, _, err = consulClient.Partitions().Create(
					context.Background(),
					&api.Partition{Name: c.partition},
					nil)
				require.NoError(t, err)
			}

			cmd := Command{
				UI:                    cli.NewMockUi(),
				flagSecretNamePrefix:  "test",
				flagPartitionsEnabled: c.partition != "",
				flagPartition:         c.partition,
				log:                   hclog.NewNullLogger(),
				ctx:                   context.Background(),
			}

			err = cmd.upsertPartition(consulClient)
			if c.err == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
