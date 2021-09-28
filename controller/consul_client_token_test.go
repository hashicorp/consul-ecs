package controller

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/consul-ecs/controller/mocks"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestUpsertConsulClientToken(t *testing.T) {
	cases := map[string]struct {
		existingSecret       *secretsmanager.GetSecretValueOutput
		createExistingToken  bool
		createExistingPolicy bool
	}{
		"when there is no token or policy": {
			existingSecret: &secretsmanager.GetSecretValueOutput{
				ARN:          aws.String("test-consul-client-token-arn"),
				Name:         aws.String("test-consul-client-token"),
				SecretString: aws.String(`{}`),
			},
		},
		"when there is an existing token and policy for the Consul client, we don't create a new one": {
			existingSecret: &secretsmanager.GetSecretValueOutput{
				ARN:          aws.String("test-consul-client-token-arn"),
				Name:         aws.String("test-consul-client-token"),
				SecretString: aws.String(`{}`),
			},
			createExistingPolicy: true,
			createExistingToken:  true,
		},
		"when there is an existing policy but no token for the Consul client, we update the token": {
			existingSecret: &secretsmanager.GetSecretValueOutput{
				ARN:          aws.String("test-consul-client-token-arn"),
				Name:         aws.String("test-consul-client-token"),
				SecretString: aws.String(`{}`),
			},
			createExistingPolicy: true,
			createExistingToken:  false,
		},
		"when the token in the secret doesn't exist in Consul, the secret is updated with the new value": {
			existingSecret: &secretsmanager.GetSecretValueOutput{
				ARN:          aws.String("test-consul-client-token-arn"),
				Name:         aws.String("test-consul-client-token"),
				SecretString: aws.String(`{"accessor_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","token":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}`),
			},
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

			consulClient, err := api.NewClient(clientConfig)
			require.NoError(t, err)

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
					secretValue, err := json.Marshal(tokenSecretJSON{AccessorID: token.AccessorID, Token: token.SecretID})
					require.NoError(t, err)
					c.existingSecret.SecretString = aws.String(string(secretValue))
				}
			}

			err = UpsertConsulClientToken(consulClient, smClient, *c.existingSecret.ARN, "test", hclog.NewNullLogger())
			require.NoError(t, err)

			// Check that token and policy exist in Consul.
			policy, _, err := consulClient.ACL().PolicyReadByName(policyName, nil)
			require.NoError(t, err)
			require.NotNil(t, policy)

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
			var tokenSecret tokenSecretJSON
			err = json.Unmarshal([]byte(*smClient.Secret.SecretString), &tokenSecret)
			require.NoError(t, err)
			require.Equal(t, foundTokens[0].AccessorID, tokenSecret.AccessorID)
			require.Equal(t, foundTokens[0].SecretID, tokenSecret.Token)
		})
	}
}
