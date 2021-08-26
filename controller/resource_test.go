package controller

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/consul-ecs/controller/mocks"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestTaskList_List(t *testing.T) {
	cases := map[string]struct {
		paginateResults bool
	}{
		"without pagination": {},
		"with pagination":    {paginateResults: true},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			task1 := &ecs.Task{
				TaskArn: pointerToStr("task1"),
			}
			task2 := &ecs.Task{
				TaskArn: pointerToStr("task2"),
			}
			tl := TaskLister{ECSClient: &mocks.ECSClient{Tasks: []*ecs.Task{task1, task2}, PaginateResults: c.paginateResults}}

			tasks, err := tl.List()

			require.NoError(t, err)
			require.Len(t, tasks, 2)
			require.Equal(t, task1.TaskArn, tasks[0].(*Tasks).Task.TaskArn)
			require.Equal(t, task2.TaskArn, tasks[1].(*Tasks).Task.TaskArn)
		})
	}
}

func TestTaskTokens_Upsert(t *testing.T) {
	cases := map[string]struct {
		task                *ecs.Task
		createExistingToken bool
		existingSecret      *secretsmanager.GetSecretValueOutput
		expectTokenToExist  bool
		expectedError       string
	}{
		"task without mesh tag": {
			task: &ecs.Task{
				TaskArn: pointerToStr("task"),
				Group:   pointerToStr("service:service"),
			},
			existingSecret:     &secretsmanager.GetSecretValueOutput{Name: pointerToStr("test-service"), SecretString: pointerToStr(`{}`)},
			expectTokenToExist: false,
		},
		"task with mesh tag": {
			task: &ecs.Task{
				TaskArn: pointerToStr("task"),
				Group:   pointerToStr("service:service"),
				Tags:    []*ecs.Tag{{Key: pointerToStr(meshTag), Value: pointerToStr("true")}},
			},
			existingSecret:     &secretsmanager.GetSecretValueOutput{Name: pointerToStr("test-service"), SecretString: pointerToStr(`{}`)},
			expectTokenToExist: true,
		},
		"task with an invalid task group": {
			task: &ecs.Task{
				TaskArn: pointerToStr("task"),
				Group:   pointerToStr("invalid"),
				Tags:    []*ecs.Tag{{Key: pointerToStr(meshTag), Value: pointerToStr("true")}},
			},
			existingSecret: &secretsmanager.GetSecretValueOutput{Name: pointerToStr("test-service"), SecretString: pointerToStr(`{}`)},
			expectedError:  `could not determine service name: group "invalid" invalid`,
		},
		"when there is an existing token for the service, we don't create a new one": {
			task: &ecs.Task{
				TaskArn: pointerToStr("task"),
				Group:   pointerToStr("service:service"),
				Tags:    []*ecs.Tag{{Key: pointerToStr(meshTag), Value: pointerToStr("true")}},
			},
			// When createExistingToken is true, existingSecret will be updated with the value of the created token.
			existingSecret:      &secretsmanager.GetSecretValueOutput{Name: pointerToStr("test-service"), SecretString: pointerToStr(`{}`)},
			createExistingToken: true,
			expectTokenToExist:  true,
		},
		"when the token in the secret doesn't exist in Consul, the secret is updated with the new value": {
			task: &ecs.Task{
				TaskArn: pointerToStr("task"),
				Group:   pointerToStr("service:service"),
				Tags:    []*ecs.Tag{{Key: pointerToStr(meshTag), Value: pointerToStr("true")}},
			},
			existingSecret: &secretsmanager.GetSecretValueOutput{
				Name:         pointerToStr("test-service"),
				SecretString: pointerToStr(`{"accessor_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","token":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}`),
			},
			expectTokenToExist: true,
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
			defer testServer.Stop()
			testServer.WaitForLeader(t)

			clientConfig := api.DefaultConfig()
			clientConfig.Address = testServer.HTTPAddr
			clientConfig.Token = adminToken

			consulClient, err := api.NewClient(clientConfig)
			require.NoError(t, err)

			// Create existing token in consul and update existing secret.
			if c.createExistingToken {
				// Create token in Consul.
				token, _, err := consulClient.ACL().TokenCreate(&api.ACLToken{
					ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "service"}},
				}, nil)
				require.NoError(t, err)
				secretValue, err := json.Marshal(tokenSecretJSON{AccessorID: token.AccessorID, Token: token.SecretID})
				require.NoError(t, err)
				c.existingSecret.SecretString = pointerToStr(string(secretValue))
			}

			taskTokens := Tasks{
				SecretsManagerClient: smClient,
				ConsulClient:         consulClient,
				Cluster:              "test-cluster",
				SecretPrefix:         "test",
				Task:                 c.task,
				Log:                  hclog.NewNullLogger(),
			}

			err = taskTokens.Upsert()
			if c.expectedError != "" {
				require.EqualError(t, err, c.expectedError)
			} else {
				require.NoError(t, err)

				// Check the token in Consul.
				tokens, _, err := consulClient.ACL().TokenList(nil)
				require.NoError(t, err)
				var serviceTokens []*api.ACLToken
				for _, token := range tokens {
					if token.ServiceIdentities != nil && token.ServiceIdentities[0].ServiceName == "service" {
						token, _, err := consulClient.ACL().TokenRead(token.AccessorID, nil)
						require.NoError(t, err)
						serviceTokens = append(serviceTokens, token)
					}
				}
				if c.expectTokenToExist {
					require.Len(t, serviceTokens, 1)

					// Check the secret in SM has the contents of the consul ACL token.
					var tokenSecret tokenSecretJSON
					err = json.Unmarshal([]byte(*smClient.Secret.SecretString), &tokenSecret)
					require.NoError(t, err)
					require.Equal(t, serviceTokens[0].AccessorID, tokenSecret.AccessorID)
					require.Equal(t, serviceTokens[0].SecretID, tokenSecret.Token)
				} else {
					require.Len(t, serviceTokens, 0)
					// Expect the secret to not have changed.
					require.Equal(t, c.existingSecret, smClient.Secret)
				}
			}
		})
	}
}

func TestTaskTokens_Delete(t *testing.T) {}

func pointerToStr(s string) *string { return &s }
