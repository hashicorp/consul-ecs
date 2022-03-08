//go:build enterprise

package aclcontroller

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
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

func TestCreatePartitionEnt(t *testing.T) {
	cases := map[string]struct {
		partition       string
		createPartition bool
		err             error
	}{
		"when partitions are not enabled": {
			partition: "",
		},
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
			adminToken := "123e4567-e89b-12d3-a456-426614174000"
			testServer, err := testutil.NewTestServerConfigT(t, func(c *testutil.TestServerConfig) {
				c.ACL.Enabled = true
				c.ACL.Tokens.Master = adminToken
				c.ACL.DefaultPolicy = "deny"
			})
			require.NoError(t, err)
			defer func() { _ = testServer.Stop() }()
			testServer.WaitForLeader(t)

			clientConfig := api.DefaultConfig()
			clientConfig.Address = testServer.HTTPAddr
			clientConfig.Token = adminToken
			if c.partition != "" {
				clientConfig.Partition = c.partition
			}
			consulClient, err := api.NewClient(clientConfig)
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

			err = cmd.createPartition(consulClient)
			if c.err == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
