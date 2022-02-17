package controller

// These tests can run against both OSS and Enterprise Consul agents.
// By default only the OSS tests will run and Enterprise features will not be enabled.
// To run the tests with Enterprise features make sure your `consul` command is pointing
// to an Enterprise binary and pass `-enterprise` as an arg to the tests:
//	go test -- -enterprise
// Note: the tests will run against Consul Enterprise with or without the -enterprise flag.

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
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
	enterprise := enterpriseFlag()
	definitionArn := aws.String("arn:aws:ecs:us-east-1:1234567890:task-definition/service1:1")
	cluster := "cluster"
	meshKey := "consul.hashicorp.com/mesh"
	meshValue := "true"
	partitionKey := "consul.hashicorp.com/partition"
	partitionValue := "default"
	extPartitionValue := "external-partition"
	namespaceKey := "consul.hashicorp.com/namespace"
	namespaces := []string{"default", "namespace-1"}
	meshTag := &ecs.Tag{Key: &meshKey, Value: &meshValue}
	partitionTag := &ecs.Tag{Key: &partitionKey, Value: &partitionValue}
	extPartitionTag := &ecs.Tag{Key: &partitionKey, Value: &extPartitionValue}
	namespace1Tag := &ecs.Tag{Key: &namespaceKey, Value: &namespaces[0]}
	namespace2Tag := &ecs.Tag{Key: &namespaceKey, Value: &namespaces[1]}
	task1 := ecs.Task{
		TaskArn:           aws.String("task1"),
		TaskDefinitionArn: definitionArn,
		Tags:              []*ecs.Tag{meshTag},
	}
	task1Name := "service1"
	task2 := ecs.Task{
		TaskArn:           aws.String("task2"),
		TaskDefinitionArn: definitionArn,
		Tags:              []*ecs.Tag{meshTag},
	}
	task2Name := "service1"
	nonMeshTask := ecs.Task{
		TaskArn:           aws.String("nonMeshTask"),
		TaskDefinitionArn: definitionArn,
	}
	task3Name := "service3"
	task3 := ecs.Task{
		TaskArn:           aws.String("task3"),
		TaskDefinitionArn: definitionArn,
		Tags:              []*ecs.Tag{extPartitionTag},
	}
	aclToken1 := &api.ACLToken{
		Description:       fmt.Sprintf("Token for service1 service\n%s: %s", clusterTag, cluster),
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "service1"}},
	}
	aclTokenListEntry1 := &api.ACLTokenListEntry{
		Description:       fmt.Sprintf("Token for service1 service\n%s: %s", clusterTag, cluster),
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "service1"}},
	}
	aclToken2 := &api.ACLToken{
		Description:       fmt.Sprintf("Token for service1 service\n%s: %s", clusterTag, cluster),
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: "service1"}},
	}
	aclTokenListEntry2 := &api.ACLTokenListEntry{
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

	if enterprise {
		// add partitions and namespaces for enterprise testing.
		task1Name = fmt.Sprintf("%s/%s/%s", partitionValue, namespaces[0], "service1")
		task1.Tags = append(task1.Tags, partitionTag, namespace1Tag)
		task2Name = fmt.Sprintf("%s/%s/%s", partitionValue, namespaces[1], "service1")
		task2.Tags = append(task2.Tags, partitionTag, namespace2Tag)
		task3Name = fmt.Sprintf("%s/%s/%s", partitionValue, namespaces[0], "service3")
		task3.Tags = append(task3.Tags, meshTag, extPartitionTag, namespace1Tag)
		aclToken1.Partition = partitionValue
		aclToken1.Namespace = namespaces[0]
		aclTokenListEntry1.Partition = partitionValue
		aclTokenListEntry1.Namespace = namespaces[0]
		aclToken2.Partition = partitionValue
		aclToken2.Namespace = namespaces[1]
		aclTokenListEntry2.Partition = partitionValue
		aclTokenListEntry2.Namespace = namespaces[1]
		aclToken3.Partition = partitionValue
		aclToken3.Namespace = namespaces[0]
		aclTokenListEntry3.Partition = partitionValue
		aclTokenListEntry3.Namespace = namespaces[0]
	}
	cases := map[string]struct {
		paginateResults bool
		tasks           []ecs.Task
		expected        map[string]ServiceState
		aclTokens       []*api.ACLToken
	}{
		"no overlap between tasks, services and tokens": {
			tasks:     []ecs.Task{task1, task2, task3},
			aclTokens: []*api.ACLToken{aclToken3},
			expected: map[string]ServiceState{
				task1Name: {
					ConsulECSTasks: true,
				},
				task3Name: {
					ACLTokens: []*api.ACLTokenListEntry{aclTokenListEntry3},
				},
			},
		},
		"all overlap between tasks, services and tokens": {
			tasks:     []ecs.Task{task1, task2},
			aclTokens: []*api.ACLToken{aclToken1, aclToken2},
			expected: map[string]ServiceState{
				task1Name: {
					ConsulECSTasks: true,
					ACLTokens:      []*api.ACLTokenListEntry{aclTokenListEntry1},
				},
				task2Name: {
					ConsulECSTasks: true,
					ACLTokens:      []*api.ACLTokenListEntry{aclTokenListEntry2},
				},
			},
		},
		"with pagination": {
			tasks:           []ecs.Task{task1, task2},
			paginateResults: true,
			expected: map[string]ServiceState{
				task1Name: {
					ConsulECSTasks: true,
				},
			},
		},
		"with non-mesh tasks": {
			tasks:     []ecs.Task{nonMeshTask},
			aclTokens: []*api.ACLToken{aclToken1},
			expected: map[string]ServiceState{
				task1Name: {
					ConsulECSTasks: false,
					ACLTokens:      []*api.ACLTokenListEntry{aclTokenListEntry1},
				},
			},
		},
	}

	if enterprise {
		// in the enterprise case the services are qualified by their partition and namespace
		// and thus become unique entries.. add the missing expected service states.
		e := cases["no overlap between tasks, services and tokens"].expected
		e[task2Name] = ServiceState{ConsulECSTasks: true}
		e = cases["with pagination"].expected
		e[task2Name] = ServiceState{ConsulECSTasks: true}
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

			if enterprise {
				for _, ns := range namespaces {
					_, _, err = consulClient.Namespaces().Create(&api.Namespace{Name: ns}, nil)
					require.NoError(t, err)
				}
			}

			createdTokens := make(map[string]struct{})
			for _, aclToken := range c.aclTokens {
				id := fmt.Sprintf("%s/%s/%s", aclToken.Partition, aclToken.Namespace, aclToken.Description)
				if _, exists := createdTokens[id]; !exists {
					_, _, err = consulClient.ACL().TokenCreate(aclToken, nil)
					require.NoError(t, err)
					createdTokens[id] = struct{}{}
				}
			}

			var tasks []*ecs.Task

			for i := range c.tasks {
				tasks = append(tasks, &c.tasks[i])
			}

			s := ServiceStateLister{
				SecretPrefix: "test",
				Log:          hclog.NewNullLogger(),
				ConsulClient: consulClient,
				ECSClient: &mocks.ECSClient{
					Tasks:           tasks,
					PaginateResults: c.paginateResults,
				}}

			if enterprise {
				s.Partition = partitionValue
			}

			resources, err := s.List()
			require.NoError(t, err)

			serviceStates := make(map[string]ServiceState)

			for _, resource := range resources {
				serviceInfo := resource.(*ServiceInfo)

				// only set the expected acl token fields
				var tokens []*api.ACLTokenListEntry
				for _, token := range serviceInfo.ServiceState.ACLTokens {
					entry := &api.ACLTokenListEntry{
						Description:       token.Description,
						ServiceIdentities: token.ServiceIdentities,
					}
					if enterprise {
						entry.Partition = serviceInfo.Partition
						entry.Namespace = serviceInfo.Namespace
					}
					tokens = append(tokens, entry)
				}
				serviceInfo.ServiceState.ACLTokens = tokens
				serviceStates[serviceInfo.Name()] = serviceInfo.ServiceState
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

	getSecretValue := func() TokenSecretJSON {
		var secret TokenSecretJSON
		err = json.Unmarshal([]byte(*smClient.Secret.SecretString), &secret)
		require.NoError(t, err)
		return secret
	}

	tokenMatchesSecret := func(secret TokenSecretJSON) {
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
				secretValue, err := json.Marshal(TokenSecretJSON{AccessorID: token.AccessorID, Token: token.SecretID})
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
					var tokenSecret TokenSecretJSON
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
					secretValue, err := json.Marshal(TokenSecretJSON{AccessorID: token.AccessorID, Token: token.SecretID})
					require.NoError(t, err)
					existingSecret.SecretString = aws.String(string(secretValue))
				} else {
					secretValue, err := json.Marshal(TokenSecretJSON{AccessorID: "some-accessor-id", Token: "some-secret-id"})
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
		partition   string
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
	if enterpriseFlag() {
		c := cases["from the tags with partitions and namespaces"]
		c.partition = "test-partition"
		c.serviceName = "test-partition/test-namespace/real-service-name"
		c.task = ecs.Task{
			TaskDefinitionArn: aws.String(validARN),
			Tags: []*ecs.Tag{
				{
					Key:   aws.String(serviceNameTag),
					Value: aws.String("real-service-name"),
				},
				{
					Key:   aws.String(partitionTag),
					Value: aws.String("test-partition"),
				},
				{
					Key:   aws.String(namespaceTag),
					Value: aws.String("test-namespace"),
				},
			},
		}

		c = cases["from the tags with default partition and default namespace"]
		c.partition = "test-partition"
		c.serviceName = "default/default/real-service-name"
		c.task = ecs.Task{
			TaskDefinitionArn: aws.String(validARN),
			Tags: []*ecs.Tag{
				{
					Key:   aws.String(serviceNameTag),
					Value: aws.String("real-service-name"),
				},
			},
		}

		c = cases["from the tags with partitions disabled"]
		c.serviceName = "real-service-name"
		c.task = ecs.Task{
			TaskDefinitionArn: aws.String(validARN),
			Tags: []*ecs.Tag{
				{
					Key:   aws.String(serviceNameTag),
					Value: aws.String("real-service-name"),
				},
				{
					Key:   aws.String(partitionTag),
					Value: aws.String("test-partition"),
				},
				{
					Key:   aws.String(namespaceTag),
					Value: aws.String("test-namespace"),
				},
			},
		}
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			l := ServiceStateLister{
				Partition: c.partition,
			}
			serviceName, err := l.serviceNameForTask(&c.task)
			if c.serviceName == "" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, c.serviceName, serviceName)
			}
		})
	}
}

func TestQualifiedNames(t *testing.T) {
	cases := map[string]struct {
		partition   string
		namespace   string
		serviceName string
		qname       string
	}{
		"only service name": {
			serviceName: "test-service",
			qname:       "test-service",
		},
		"with service name partition and namespace": {
			partition:   "test-partition",
			namespace:   "test-namespace",
			serviceName: "test-service",
			qname:       "test-partition/test-namespace/test-service",
		},
		"with service name and partition only": {
			partition:   "default",
			serviceName: "test-service",
			qname:       "test-service",
		},
		"with service name and namespace only": {
			namespace:   "default",
			serviceName: "test-service",
			qname:       "test-service",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			qname := qualifiedName(c.partition, c.namespace, c.serviceName)
			require.Equal(t, c.qname, qname)
			require.Equal(t, c.serviceName, serviceName(qname))
			if len(c.partition) > 0 && len(c.namespace) > 0 {
				require.Equal(t, c.partition, partition(qname))
				require.Equal(t, c.namespace, namespace(qname))
			} else {
				require.Equal(t, "", partition(qname))
				require.Equal(t, "", namespace(qname))
			}
		})
	}
}

func TestCreateNamespaces(t *testing.T) {
	cases := map[string]struct {
		partition string
		expNS     []string
		resources map[string]*ServiceInfo
	}{
		"with partitions disabled": {
			expNS: []string{"default"},
			resources: map[string]*ServiceInfo{
				"resource1": {
					Partition: "default",
					Namespace: "test-namespace",
				},
			},
		},
		"with resources in default namespace": {
			partition: "default",
			expNS:     []string{"default"},
			resources: map[string]*ServiceInfo{
				"resource1": {
					Partition: "default",
					Namespace: "default",
				},
			},
		},
		"with resources in different namespaces": {
			partition: "default",
			expNS:     []string{"default", "namespace-1", "namespace-2"},
			resources: map[string]*ServiceInfo{
				"resource1": {
					Partition: "default",
					Namespace: "",
				},
				"resource2": {
					Partition: "default",
					Namespace: "namespace-1",
				},
				"resource3": {
					Partition: "default",
					Namespace: "namespace-1",
				},
				"resource4": {
					Partition: "default",
					Namespace: "namespace-2",
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
			clientConfig.Partition = c.partition

			consulClient, err := api.NewClient(clientConfig)
			require.NoError(t, err)

			if !enterpriseFlag() {
				c.partition = ""
				c.expNS = make([]string, 0)
			}

			s := ServiceStateLister{
				Log:          hclog.NewNullLogger(),
				ConsulClient: consulClient,
				Partition:    c.partition,
			}

			if c.partition == "" {
				// list all existing namespaces and ensure that no new ones are created
				c.expNS = listNamespaces(consulClient)
			}

			// create the namespaces and ensure they exist
			s.createNamespaces(c.resources)
			obsNS := listNamespaces(consulClient)
			require.ElementsMatch(t, c.expNS, obsNS)
		})
	}
}

func listNamespaces(consulClient *api.Client) []string {
	// list all existing namespaces and ensure that no new ones are created
	names := make([]string, 0)
	ns, _, err := consulClient.Namespaces().List(nil)
	if err != nil {
		return names
	}
	for _, n := range ns {
		names = append(names, n.Name)
	}
	return names
}

func enterpriseFlag() bool {
	re := regexp.MustCompile("^-+enterprise$")
	for _, a := range os.Args {
		if re.Match([]byte(strings.ToLower(a))) {
			return true
		}
	}
	return false
}
