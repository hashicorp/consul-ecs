package aclcontroller

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/consul-ecs/controller"
	"github.com/hashicorp/consul-ecs/controller/mocks"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

const testPartitionName = "test-partition"

var expOssClientPolicy = `node_prefix "" { policy = "write" } service_prefix "" { policy = "read" }`
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

func TestUpsertConsulClientToken(t *testing.T) {
	cases := map[string]struct {
		existingSecret       *secretsmanager.GetSecretValueOutput
		createExistingToken  bool
		createExistingPolicy bool
		partitionsEnabled    bool
		expPolicyRules       string
	}{
		"when there is no token or policy": {
			existingSecret: &secretsmanager.GetSecretValueOutput{
				ARN:          aws.String("test-consul-client-token-arn"),
				Name:         aws.String("test-consul-client-token"),
				SecretString: aws.String(`{}`),
			},
			expPolicyRules: expOssClientPolicy,
		},
		"when there is an existing token and policy for the Consul client, we don't create a new one": {
			existingSecret: &secretsmanager.GetSecretValueOutput{
				ARN:          aws.String("test-consul-client-token-arn"),
				Name:         aws.String("test-consul-client-token"),
				SecretString: aws.String(`{}`),
			},
			createExistingPolicy: true,
			createExistingToken:  true,
			expPolicyRules:       expOssClientPolicy,
		},
		"when there is an existing policy but no token for the Consul client, we update the token": {
			existingSecret: &secretsmanager.GetSecretValueOutput{
				ARN:          aws.String("test-consul-client-token-arn"),
				Name:         aws.String("test-consul-client-token"),
				SecretString: aws.String(`{}`),
			},
			createExistingPolicy: true,
			createExistingToken:  false,
			expPolicyRules:       expOssClientPolicy,
		},
		"when the token in the secret doesn't exist in Consul, the secret is updated with the new value": {
			existingSecret: &secretsmanager.GetSecretValueOutput{
				ARN:          aws.String("test-consul-client-token-arn"),
				Name:         aws.String("test-consul-client-token"),
				SecretString: aws.String(`{"accessor_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","token":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}`),
			},
			expPolicyRules: expOssClientPolicy,
		},
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

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			smClient := &mocks.SMClient{Secret: c.existingSecret}

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

			if c.partitionsEnabled {
				clientConfig.Partition = testPartitionName
			}

			consulClient, err := api.NewClient(clientConfig)
			require.NoError(t, err)

			if c.partitionsEnabled {
				_, _, err := consulClient.Partitions().Create(context.Background(), &api.Partition{
					Name: testPartitionName,
				}, nil)
				require.NoError(t, err)
			}

			cmd := Command{
				UI:                        cli.NewMockUi(),
				flagConsulClientSecretARN: *c.existingSecret.ARN,
				flagSecretNamePrefix:      "test",
				flagPartitionsEnabled:     c.partitionsEnabled,
				flagPartition:             testPartitionName,
				log:                       hclog.NewNullLogger(),
			}

			policyName := "test-consul-client-policy"
			if c.createExistingPolicy {
				policy, _, err := consulClient.ACL().PolicyCreate(&api.ACLPolicy{
					Name:        policyName,
					Description: "Consul Client Token Policy for ECS",
					Rules:       `node_prefix "" { policy = "write" } service_prefix "" { policy = "read" }`,
				}, nil)
				require.NoError(t, err)

				if c.createExistingToken {
					token, _, err := consulClient.ACL().TokenCreate(&api.ACLToken{
						Description: "ECS Consul client Token",
						Policies:    []*api.ACLTokenPolicyLink{{Name: policy.Name}},
					}, nil)
					require.NoError(t, err)
					secretValue, err := json.Marshal(controller.TokenSecretJSON{AccessorID: token.AccessorID, Token: token.SecretID})
					require.NoError(t, err)
					c.existingSecret.SecretString = aws.String(string(secretValue))
				}
			}

			err = cmd.upsertConsulClientToken(consulClient, smClient)
			require.NoError(t, err)

			// Check that token and policy exist in Consul.
			policy, _, err := consulClient.ACL().PolicyReadByName(policyName, nil)
			require.NoError(t, err)
			require.NotNil(t, policy)
			require.Equal(t, c.expPolicyRules, policy.Rules)

			tokenList, _, err := consulClient.ACL().TokenList(nil)
			require.NoError(t, err)
			var foundTokens []*api.ACLToken
			for _, tokenItem := range tokenList {
				if len(tokenItem.Policies) == 1 {
					if tokenItem.Policies[0].ID == policy.ID {
						token, _, err := consulClient.ACL().TokenRead(tokenItem.AccessorID, nil)
						require.NoError(t, err)
						foundTokens = append(foundTokens, token)
					}
				}
			}
			// There should always be only one token for the client.
			require.Len(t, foundTokens, 1)

			// Check that the secret in AWS SM is the same as the token we found.
			var tokenSecret controller.TokenSecretJSON
			err = json.Unmarshal([]byte(*smClient.Secret.SecretString), &tokenSecret)
			require.NoError(t, err)
			require.Equal(t, foundTokens[0].AccessorID, tokenSecret.AccessorID)
			require.Equal(t, foundTokens[0].SecretID, tokenSecret.Token)
		})
	}
}
