package controller

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/consul-ecs/controller/mocks"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestServiceStateLister_List(t *testing.T) {
	definitionArn := aws.String("arn:aws:ecs:us-east-1:1234567890:task-definition/service1:1")
	cluster := "cluster"
	meshKey := "consul.hashicorp.com/mesh"
	meshValue := "true"
	task1 := ecs.Task{
		TaskArn:           aws.String("task1"),
		TaskDefinitionArn: definitionArn,
		Tags: []*ecs.Tag{
			{
				Key:   &meshKey,
				Value: &meshValue,
			},
		},
	}
	task2 := ecs.Task{
		TaskArn:           aws.String("task2"),
		TaskDefinitionArn: definitionArn,
		Tags: []*ecs.Tag{
			{
				Key:   &meshKey,
				Value: &meshValue,
			},
		},
	}
	nonMeshTask := ecs.Task{
		TaskArn:           aws.String("nonMeshTask"),
		TaskDefinitionArn: definitionArn,
	}
	aclToken1 := &api.ACLToken{
		Description:       fmt.Sprintf("Token for service1 service\n%s: %s", clusterTag, cluster),
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "service1"}},
	}
	aclTokenListEntry1 := &api.ACLTokenListEntry{
		Description:       fmt.Sprintf("Token for service1 service\n%s: %s", clusterTag, cluster),
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "service1"}},
	}

	aclToken3 := &api.ACLToken{
		Description:       fmt.Sprintf("Token for service3 service\n%s: %s", clusterTag, cluster),
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "service3"}},
	}
	aclTokenListEntry3 := &api.ACLTokenListEntry{
		Description:       fmt.Sprintf("Token for service3 service\n%s: %s", clusterTag, cluster),
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "service3"}},
	}

	cases := map[string]struct {
		paginateResults bool
		tasks           []ecs.Task
		expected        map[string]ServiceState
		aclTokens       []*api.ACLToken
	}{
		"no overlap between tasks, services and tokens": {
			tasks:     []ecs.Task{task1, task2},
			aclTokens: []*api.ACLToken{aclToken3},
			expected: map[string]ServiceState{
				"service1": {
					ConsulECSTasks: true,
				},
				"service3": {
					ACLTokens: []*api.ACLTokenListEntry{aclTokenListEntry3},
				},
			},
		},
		"all overlap between tasks, services and tokens": {
			tasks:     []ecs.Task{task1, task2},
			aclTokens: []*api.ACLToken{aclToken1},
			expected: map[string]ServiceState{
				"service1": {
					ConsulECSTasks: true,
					ACLTokens:      []*api.ACLTokenListEntry{aclTokenListEntry1},
				},
			},
		},
		"with pagination": {
			tasks:           []ecs.Task{task1, task2},
			paginateResults: true,
			expected: map[string]ServiceState{
				"service1": {
					ConsulECSTasks: true,
				},
			},
		},
		"with non-mesh tasks": {
			tasks:     []ecs.Task{nonMeshTask},
			aclTokens: []*api.ACLToken{aclToken1},
			expected: map[string]ServiceState{
				"service1": {
					ConsulECSTasks: false,
					ACLTokens:      []*api.ACLTokenListEntry{aclTokenListEntry1},
				},
			},
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
			t.Cleanup(func() { _ = testServer.Stop() })
			testServer.WaitForLeader(t)

			clientConfig := api.DefaultConfig()
			clientConfig.Address = testServer.HTTPAddr
			clientConfig.Token = adminToken

			consulClient, err := api.NewClient(clientConfig)
			require.NoError(t, err)

			for _, aclToken := range c.aclTokens {
				_, _, err = consulClient.ACL().TokenCreate(aclToken, nil)
				require.NoError(t, err)
			}

			var tasks []*ecs.Task

			for i := range c.tasks {
				tasks = append(tasks, &c.tasks[i])
			}

			s := ServiceStateLister{
				Log:          hclog.NewNullLogger(),
				ConsulClient: consulClient,
				ECSClient: &mocks.ECSClient{
					Tasks:           tasks,
					PaginateResults: c.paginateResults,
				}}

			resources, err := s.List()

			require.NoError(t, err)

			serviceStates := make(map[string]ServiceState)

			for _, resource := range resources {
				serviceInfo := resource.(*ServiceInfo)

				// only set the expected acl token fields
				var tokens []*api.ACLTokenListEntry
				for _, token := range serviceInfo.ServiceState.ACLTokens {
					tokens = append(tokens, &api.ACLTokenListEntry{
						Description:       token.Description,
						ServiceIdentities: token.ServiceIdentities,
					})
				}
				serviceInfo.ServiceState.ACLTokens = tokens
				serviceStates[serviceInfo.ServiceName] = serviceInfo.ServiceState
			}

			require.Equal(t, c.expected, serviceStates)
		})
	}
}

func TestReconcile(t *testing.T) {
	cluster := "test-cluster"
	aclToken1 := &api.ACLToken{
		Description:       fmt.Sprintf("Token for service1 service\n%s: %s", clusterTag, cluster),
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "service1"}},
	}

	cases := map[string]struct {
		tasks          bool
		aclTokens      []*api.ACLToken
		sutServiceName string
		expected       []*api.ACLToken
	}{
		"token should be deleted": {
			tasks:          false,
			aclTokens:      []*api.ACLToken{aclToken1},
			sutServiceName: "service1",
			expected:       nil,
		},
		"token should be added": {
			tasks:          true,
			aclTokens:      []*api.ACLToken{},
			sutServiceName: "service1",
			expected:       []*api.ACLToken{aclToken1},
		},
		"Does nothing when a task is running and a token exists for a given service": {
			tasks:          true,
			aclTokens:      []*api.ACLToken{aclToken1},
			sutServiceName: "service1",
			expected:       []*api.ACLToken{aclToken1},
		},
		"Does nothing when there are no tasks or tokens": {
			tasks:          false,
			sutServiceName: "service1",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			smClient := &mocks.SMClient{Secret: &secretsmanager.GetSecretValueOutput{Name: aws.String("test-service"), SecretString: aws.String(`{}`)}}

			adminToken := "123e4567-e89b-12d3-a456-426614174000"
			testServer, err := testutil.NewTestServerConfigT(t, func(c *testutil.TestServerConfig) {
				c.ACL.Enabled = true
				c.ACL.Tokens.Master = adminToken
				c.ACL.DefaultPolicy = "deny"
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = testServer.Stop() })
			testServer.WaitForLeader(t)

			clientConfig := api.DefaultConfig()
			clientConfig.Address = testServer.HTTPAddr
			clientConfig.Token = adminToken

			consulClient, err := api.NewClient(clientConfig)
			require.NoError(t, err)

			var beforeTokens []*api.ACLTokenListEntry
			for _, aclToken := range c.aclTokens {
				token, _, err := consulClient.ACL().TokenCreate(aclToken, nil)
				require.NoError(t, err)
				beforeTokens = append(beforeTokens, &api.ACLTokenListEntry{
					AccessorID: token.AccessorID,
				})
			}

			log := hclog.NewNullLogger()

			serviceInfo := ServiceInfo{
				SecretsManagerClient: smClient,
				ConsulClient:         consulClient,
				Cluster:              cluster,
				SecretPrefix:         "test",
				ServiceName:          c.sutServiceName,
				ServiceState: ServiceState{
					ConsulECSTasks: c.tasks,
					ACLTokens:      beforeTokens,
				},
				Log: log,
			}

			err = serviceInfo.Reconcile()
			require.NoError(t, err)

			serviceStateLister := ServiceStateLister{
				ConsulClient: consulClient,
				Log:          log,
			}

			aclTokens, err := serviceStateLister.fetchACLTokens()
			require.NoError(t, err)

			var tokens []*api.ACLToken
			for _, token := range aclTokens[c.sutServiceName] {
				tokens = append(tokens, &api.ACLToken{
					Description:       token.Description,
					ServiceIdentities: token.ServiceIdentities,
				})
			}
			require.Equal(t, len(c.expected), len(tokens))
			require.Equal(t, c.expected, tokens)
		})
	}

}

func TestRecreatingAToken(t *testing.T) {
	smClient := &mocks.SMClient{Secret: &secretsmanager.GetSecretValueOutput{Name: aws.String("test-service"), SecretString: aws.String(`{}`)}}
	adminToken := "123e4567-e89b-12d3-a456-426614174000"
	testServer, err := testutil.NewTestServerConfigT(t, func(c *testutil.TestServerConfig) {
		c.ACL.Enabled = true
		c.ACL.Tokens.Master = adminToken
		c.ACL.DefaultPolicy = "deny"
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = testServer.Stop()
	})
	testServer.WaitForLeader(t)

	clientConfig := api.DefaultConfig()
	clientConfig.Address = testServer.HTTPAddr
	clientConfig.Token = adminToken

	consulClient, err := api.NewClient(clientConfig)
	require.NoError(t, err)

	taskTokens := ServiceInfo{
		SecretsManagerClient: smClient,
		ConsulClient:         consulClient,
		Cluster:              "test-cluster",
		SecretPrefix:         "test",
		ServiceName:          "service",
		ServiceState: ServiceState{
			ConsulECSTasks: true,
		},
		Log: hclog.NewNullLogger(),
	}

	getSecretValue := func() tokenSecretJSON {
		var secret tokenSecretJSON
		err = json.Unmarshal([]byte(*smClient.Secret.SecretString), &secret)
		require.NoError(t, err)
		return secret
	}

	tokenMatchesSecret := func(secret tokenSecretJSON) {
		currToken, _, err := consulClient.ACL().TokenRead(secret.AccessorID, nil)
		require.NoError(t, err)
		require.Equal(t, secret.AccessorID, currToken.AccessorID)
		require.Equal(t, secret.Token, currToken.SecretID)
	}

	err = taskTokens.Upsert()
	require.NoError(t, err)

	originalSecret := getSecretValue()
	tokenMatchesSecret(originalSecret)

	err = taskTokens.Delete()
	require.NoError(t, err)
	require.Equal(t, originalSecret, getSecretValue(), "The secret isn't deleted")

	// Inserting a token with the same AccessorID and SecretID as the original
	// one works.
	err = taskTokens.Upsert()
	require.NoError(t, err)
	require.Equal(t, originalSecret, getSecretValue(), "The secret isn't changed")
	tokenMatchesSecret(originalSecret)
}

func TestTask_Upsert(t *testing.T) {
	cases := map[string]struct {
		createExistingToken bool
		existingSecret      *secretsmanager.GetSecretValueOutput
		expectTokenToExist  bool
		expectedError       string
	}{
		"task with mesh tag": {
			existingSecret:     &secretsmanager.GetSecretValueOutput{Name: aws.String("test-service"), SecretString: aws.String(`{}`)},
			expectTokenToExist: true,
		},
		"when there is an existing token for the service, we don't create a new one": {
			// When createExistingToken is true, existingSecret will be updated with the value of the created token.
			existingSecret:      &secretsmanager.GetSecretValueOutput{Name: aws.String("test-service"), SecretString: aws.String(`{}`)},
			createExistingToken: true,
			expectTokenToExist:  true,
		},
		"when the token in the secret doesn't exist in Consul, the secret is updated with the new value": {
			existingSecret: &secretsmanager.GetSecretValueOutput{
				Name:         aws.String("test-service"),
				SecretString: aws.String(`{"accessor_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","token":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}`),
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
			defer func() { _ = testServer.Stop() }()
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
				c.existingSecret.SecretString = aws.String(string(secretValue))
			}

			taskTokens := ServiceInfo{
				SecretsManagerClient: smClient,
				ConsulClient:         consulClient,
				Cluster:              "test-cluster",
				SecretPrefix:         "test",
				ServiceName:          "service",
				ServiceState: ServiceState{
					ConsulECSTasks: true,
				},
				Log: hclog.NewNullLogger(),
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

func TestTask_Delete(t *testing.T) {
	cases := map[string]struct {
		createExistingToken   bool
		updateExistingSecret  bool
		registerConsulService bool
	}{
		"the token for service doesn't exist in consul and the secret is empty": {
			createExistingToken:  false,
			updateExistingSecret: false,
		},
		"the token for service doesn't exist in consul and the secret has some value": {
			createExistingToken:  false,
			updateExistingSecret: true,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			existingSecret := &secretsmanager.GetSecretValueOutput{Name: aws.String("test-service"), SecretString: aws.String(`{}`)}
			smClient := &mocks.SMClient{Secret: existingSecret}
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

			// Create existing token in consul and update existing secret.
			var token *api.ACLToken
			if c.createExistingToken {
				token, _, err = consulClient.ACL().TokenCreate(&api.ACLToken{
					ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "service"}},
				}, nil)
				require.NoError(t, err)
			}
			if c.updateExistingSecret {
				if token != nil {
					secretValue, err := json.Marshal(tokenSecretJSON{AccessorID: token.AccessorID, Token: token.SecretID})
					require.NoError(t, err)
					existingSecret.SecretString = aws.String(string(secretValue))
				} else {
					secretValue, err := json.Marshal(tokenSecretJSON{AccessorID: "some-accessor-id", Token: "some-secret-id"})
					require.NoError(t, err)
					existingSecret.SecretString = aws.String(string(secretValue))
				}
			}

			anotherToken, _, err := consulClient.ACL().TokenCreate(&api.ACLToken{
				ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "another-service"}},
			}, nil)
			require.NoError(t, err)

			if c.registerConsulService {
				err := consulClient.Agent().ServiceRegister(&api.AgentServiceRegistration{
					Name: "service",
				})
				require.NoError(t, err)
			}

			taskTokens := ServiceInfo{
				SecretsManagerClient: smClient,
				ConsulClient:         consulClient,
				Cluster:              "test-cluster",
				SecretPrefix:         "test",
				ServiceName:          "service",
				ServiceState: ServiceState{
					ConsulECSTasks: true,
				},
				Log: hclog.NewNullLogger(),
			}

			err = taskTokens.Delete()
			require.NoError(t, err)

			if c.createExistingToken {
				// Check that the token is deleted from Consul.
				_, _, err = consulClient.ACL().TokenRead(token.AccessorID, nil)
				require.EqualError(t, err, "Unexpected response code: 403 (ACL not found)")
			}

			require.Equal(t, *existingSecret.SecretString, *smClient.Secret.SecretString)

			// Check that the other token is not affected.
			_, _, err = consulClient.ACL().TokenRead(anotherToken.AccessorID, nil)
			require.NoError(t, err)
		})
	}
}

func TestParseServiceNameFromTaskDefinitionARN(t *testing.T) {
	validARN := "arn:aws:ecs:us-east-1:1234567890:task-definition/service:1"
	cases := map[string]struct {
		task        ecs.Task
		serviceName string
	}{
		"invalid ARN": {
			task: ecs.Task{
				TaskDefinitionArn: aws.String("invalid"),
			},
			serviceName: "",
		},
		"parsing from the ARN": {
			task: ecs.Task{
				TaskDefinitionArn: aws.String(validARN),
			},
			serviceName: "service",
		},
		"from the tags": {
			task: ecs.Task{
				TaskDefinitionArn: aws.String(validARN),
				Tags: []*ecs.Tag{
					{
						Key:   aws.String(serviceNameTag),
						Value: aws.String("real-service-name"),
					},
				},
			},
			serviceName: "real-service-name",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			serviceName, err := serviceNameForTask(&c.task)
			if c.serviceName == "" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, c.serviceName, serviceName)
			}
		})
	}
}
