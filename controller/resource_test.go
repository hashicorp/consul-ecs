package controller

// These tests can run against both OSS and Enterprise Consul.
// By default only the OSS tests will run and Enterprise features will not be enabled.
//
// To run the tests against an OSS Consul agent, make sure that the `consul` command is
// pointing to an OSS binary and run the tests as normal:
//
//	go test
//
// To run the tests against an Enterprise Consul agent, make sure that the `consul` command is
// pointing to an Enterprise binary and pass `-enterprise` as an arg to the tests:
//
//	go test -- -enterprise
//
// Note: the tests will not run against Consul Enterprise without the -enterprise flag.

import (
	"context"
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
	"github.com/hashicorp/go-uuid"
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
		Description: fmt.Sprintf("Token for service1 service\n%s: %s", clusterTag, cluster),
	}
	aclTokenListEntry1 := &api.ACLTokenListEntry{
		Description: fmt.Sprintf("Token for service1 service\n%s: %s", clusterTag, cluster),
	}
	aclToken2 := &api.ACLToken{
		Description: fmt.Sprintf("Token for service1 service\n%s: %s", clusterTag, cluster),
	}
	aclTokenListEntry2 := &api.ACLTokenListEntry{
		Description: fmt.Sprintf("Token for service1 service\n%s: %s", clusterTag, cluster),
	}
	aclToken3 := &api.ACLToken{
		Description: fmt.Sprintf("Token for service3 service\n%s: %s", clusterTag, cluster),
	}
	aclTokenListEntry3 := &api.ACLTokenListEntry{
		Description: fmt.Sprintf("Token for service3 service\n%s: %s", clusterTag, cluster),
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
		aclToken1.Description = fmt.Sprintf("Token for %s/%s/service1 service\n%s: %s", partitionValue, namespaces[0], clusterTag, cluster)
		aclTokenListEntry1.Partition = partitionValue
		aclTokenListEntry1.Namespace = namespaces[0]
		aclTokenListEntry1.Description = fmt.Sprintf("Token for %s/%s/service1 service\n%s: %s", partitionValue, namespaces[0], clusterTag, cluster)
		aclToken2.Partition = partitionValue
		aclToken2.Namespace = namespaces[1]
		aclToken2.Description = fmt.Sprintf("Token for %s/%s/service1 service\n%s: %s", partitionValue, namespaces[1], clusterTag, cluster)
		aclTokenListEntry2.Partition = partitionValue
		aclTokenListEntry2.Namespace = namespaces[1]
		aclTokenListEntry2.Description = fmt.Sprintf("Token for %s/%s/service1 service\n%s: %s", partitionValue, namespaces[1], clusterTag, cluster)
		aclToken3.Partition = partitionValue
		aclToken3.Namespace = namespaces[0]
		aclToken3.Description = fmt.Sprintf("Token for %s/%s/service3 service\n%s: %s", partitionValue, namespaces[0], clusterTag, cluster)
		aclTokenListEntry3.Partition = partitionValue
		aclTokenListEntry3.Namespace = namespaces[0]
		aclTokenListEntry3.Description = fmt.Sprintf("Token for %s/%s/service3 service\n%s: %s", partitionValue, namespaces[0], clusterTag, cluster)
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
			consulClient := initConsul(t)

			if enterprise {
				for _, ns := range namespaces {
					_, _, err := consulClient.Namespaces().Create(&api.Namespace{Name: ns}, nil)
					require.NoError(t, err)
				}
			}

			createdTokens := make(map[string]struct{})
			for _, aclToken := range c.aclTokens {
				id := fmt.Sprintf("%s/%s/%s", aclToken.Partition, aclToken.Namespace, aclToken.Description)
				if _, exists := createdTokens[id]; !exists {
					_, _, err := consulClient.ACL().TokenCreate(aclToken,
						&api.WriteOptions{Partition: aclToken.Partition, Namespace: aclToken.Namespace})
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
				},
			}

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
						Description: token.Description,
						Policies:    token.Policies,
						Partition:   token.Partition,
						Namespace:   token.Namespace,
					}
					tokens = append(tokens, entry)
				}
				serviceInfo.ServiceState.ACLTokens = tokens
				serviceStates[serviceInfo.QName.String()] = serviceInfo.ServiceState
			}

			require.Equal(t, c.expected, serviceStates)
		})
	}
}

func TestReconcile(t *testing.T) {
	cluster := "test-cluster"
	aclToken1 := &api.ACLToken{
		Description: fmt.Sprintf("Token for service1 service\n%s: %s", clusterTag, cluster),
	}
	aclPolicy1 := &api.ACLPolicy{
		Name:        "service1-service",
		Description: fmt.Sprintf("Policy for service1 service\n%s: %s", clusterTag, cluster),
	}
	cases := map[string]struct {
		tasks            bool
		aclTokens        []*api.ACLToken
		aclPolicies      []*api.ACLPolicy
		sutServiceName   string
		expectedTokens   []*api.ACLToken
		expectedPolicies []*api.ACLPolicy
	}{
		"ACLs should be deleted": {
			tasks:            false,
			aclTokens:        []*api.ACLToken{aclToken1},
			aclPolicies:      []*api.ACLPolicy{aclPolicy1},
			sutServiceName:   "service1",
			expectedTokens:   nil,
			expectedPolicies: nil,
		},
		"ACLs should be added": {
			tasks:            true,
			aclTokens:        []*api.ACLToken{},
			aclPolicies:      []*api.ACLPolicy{},
			sutServiceName:   "service1",
			expectedTokens:   []*api.ACLToken{aclToken1},
			expectedPolicies: []*api.ACLPolicy{aclPolicy1},
		},
		"Does nothing when a task is running and ACLs exists for a given service": {
			tasks:            true,
			aclTokens:        []*api.ACLToken{aclToken1},
			aclPolicies:      []*api.ACLPolicy{aclPolicy1},
			sutServiceName:   "service1",
			expectedTokens:   []*api.ACLToken{aclToken1},
			expectedPolicies: []*api.ACLPolicy{aclPolicy1},
		},
		"Does nothing when there are no tasks or tokens": {
			tasks:          false,
			sutServiceName: "service1",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			smClient := &mocks.SMClient{Secret: &secretsmanager.GetSecretValueOutput{Name: aws.String("test-service"), SecretString: aws.String(`{}`)}}
			consulClient := initConsul(t)

			writeOpts := &api.WriteOptions{}
			if enterpriseFlag() {
				c.sutServiceName = "default/default/service1"

				aclToken1.Partition = "default"
				aclToken1.Namespace = "default"
				aclToken1.Description = fmt.Sprintf("Token for default/default/service1 service\n%s: %s", clusterTag, cluster)

				aclPolicy1.Partition = "default"
				aclPolicy1.Namespace = "default"
				aclPolicy1.Description = fmt.Sprintf("Policy for default/default/service1 service\n%s: %s", clusterTag, cluster)

				writeOpts.Partition = "default"
				writeOpts.Namespace = "default"
			}

			var beforePolicies []*api.ACLPolicyListEntry
			for _, aclPolicy := range c.aclPolicies {
				policy, _, err := consulClient.ACL().PolicyCreate(aclPolicy, writeOpts)
				require.NoError(t, err)
				beforePolicies = append(beforePolicies, &api.ACLPolicyListEntry{
					ID: policy.ID,
				})
			}
			var beforeTokens []*api.ACLTokenListEntry
			for _, aclToken := range c.aclTokens {
				token, _, err := consulClient.ACL().TokenCreate(aclToken, writeOpts)
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
				QName:                QNameFromString(c.sutServiceName),
				ServiceState: ServiceState{
					ConsulECSTasks: c.tasks,
					ACLPolicies:    beforePolicies,
					ACLTokens:      beforeTokens,
				},
				Log: log,
			}

			err := serviceInfo.Reconcile()
			require.NoError(t, err)

			serviceStateLister := ServiceStateLister{
				ConsulClient: consulClient,
				Log:          log,
			}

			aclState, err := serviceStateLister.fetchACLState()
			require.NoError(t, err)

			var policies []*api.ACLPolicy
			var tokens []*api.ACLToken
			if state, ok := aclState[c.sutServiceName]; ok {
				for _, policy := range state.ACLPolicies {
					policies = append(policies, &api.ACLPolicy{
						Name:        policy.Name,
						Description: policy.Description,
						Partition:   policy.Partition,
						Namespace:   policy.Namespace,
					})
				}
				for _, token := range state.ACLTokens {
					tokens = append(tokens, &api.ACLToken{
						Partition:   token.Partition,
						Namespace:   token.Namespace,
						Description: token.Description,
					})
				}
			}
			require.Equal(t, len(c.expectedPolicies), len(policies))
			require.Equal(t, len(c.expectedTokens), len(tokens))
			require.Equal(t, c.expectedPolicies, policies)
			require.Equal(t, c.expectedTokens, tokens)
		})
	}

}

func TestRecreatingAToken(t *testing.T) {
	smClient := &mocks.SMClient{Secret: &secretsmanager.GetSecretValueOutput{Name: aws.String("test-service"), SecretString: aws.String(`{}`)}}
	consulClient := initConsul(t)

	taskTokens := ServiceInfo{
		SecretsManagerClient: smClient,
		ConsulClient:         consulClient,
		Cluster:              "test-cluster",
		SecretPrefix:         "test",
		QName:                QNameFromString("service"),
		ServiceState: ServiceState{
			ConsulECSTasks: true,
		},
		Log: hclog.NewNullLogger(),
	}

	getSecretValue := func() TokenSecretJSON {
		var secret TokenSecretJSON
		err := json.Unmarshal([]byte(*smClient.Secret.SecretString), &secret)
		require.NoError(t, err)
		return secret
	}

	tokenMatchesSecret := func(secret TokenSecretJSON) {
		currToken, _, err := consulClient.ACL().TokenRead(secret.AccessorID, nil)
		require.NoError(t, err)
		require.Equal(t, secret.AccessorID, currToken.AccessorID)
		require.Equal(t, secret.Token, currToken.SecretID)
	}

	err := taskTokens.Upsert()
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
			consulClient := initConsul(t)

			taskTokens := ServiceInfo{
				SecretsManagerClient: smClient,
				ConsulClient:         consulClient,
				Cluster:              "test-cluster",
				SecretPrefix:         "test",
				QName:                QNameFromString("service"),
				ServiceState: ServiceState{
					ConsulECSTasks: true,
				},
				Log: hclog.NewNullLogger(),
			}

			// Create existing token in consul and update existing secret.
			if c.createExistingToken {
				// Create token in Consul.
				token, _, err := consulClient.ACL().TokenCreate(&api.ACLToken{Description: taskTokens.aclDescription("Token")}, nil)
				require.NoError(t, err)
				secretValue, err := json.Marshal(TokenSecretJSON{AccessorID: token.AccessorID, Token: token.SecretID})
				require.NoError(t, err)
				c.existingSecret.SecretString = aws.String(string(secretValue))
			}

			err := taskTokens.Upsert()
			if c.expectedError != "" {
				require.EqualError(t, err, c.expectedError)
			} else {
				require.NoError(t, err)

				// Check the token in Consul.
				tokens, _, err := consulClient.ACL().TokenList(nil)
				require.NoError(t, err)
				var serviceTokens []*api.ACLToken
				for _, token := range tokens {
					if token.Description == taskTokens.aclDescription("Token") {
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
			consulClient := initConsul(t)

			taskTokens := ServiceInfo{
				SecretsManagerClient: smClient,
				ConsulClient:         consulClient,
				Cluster:              "test-cluster",
				SecretPrefix:         "test",
				QName:                QNameFromString("service"),
				ServiceState: ServiceState{
					ConsulECSTasks: true,
				},
				Log: hclog.NewNullLogger(),
			}

			// Create existing token in consul and update existing secret.
			var err error
			var token *api.ACLToken
			if c.createExistingToken {
				token, _, err = consulClient.ACL().TokenCreate(&api.ACLToken{Description: taskTokens.aclDescription("Token")}, nil)
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
				require.Equal(t, c.serviceName, serviceName.String())
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
			qname := NewQName(c.partition, c.namespace, c.serviceName)
			require.Equal(t, c.qname, qname.String())
			require.Equal(t, c.serviceName, qname.Name())
			if len(c.partition) > 0 && len(c.namespace) > 0 {
				require.Equal(t, c.partition, qname.Partition())
				require.Equal(t, c.namespace, qname.Namespace())
			} else {
				require.Equal(t, "", qname.Partition())
				require.Equal(t, "", qname.Namespace())
			}
		})
	}
}

func TestReconcileNamespaces(t *testing.T) {
	cases := map[string]struct {
		partition string
		expNS     map[string][]string
		resources map[string]*ServiceInfo
	}{
		"with partitions disabled": {
			expNS: map[string][]string{"default": {"default"}},
			resources: map[string]*ServiceInfo{
				"resource1": {QName: NewQName("default", "test-namespace", "service")},
			},
		},
		"with resources in default namespace": {
			partition: "default",
			expNS:     map[string][]string{"default": {"default"}},
			resources: map[string]*ServiceInfo{
				"resource1": {QName: NewQName("default", "default", "service")},
			},
		},
		"with resources in different namespaces": {
			partition: "default",
			expNS: map[string][]string{
				"default": {"default", "namespace-1", "namespace-2"},
			},
			resources: map[string]*ServiceInfo{
				"resource1": {QName: NewQName("default", "default", "service-1")},
				"resource2": {QName: NewQName("default", "namespace-1", "service-1")},
				"resource3": {QName: NewQName("default", "namespace-1", "service-2")},
				"resource4": {QName: NewQName("default", "namespace-2", "service-1")},
			},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			consulClient := initConsul(t)

			if !enterpriseFlag() {
				c.partition = ""
				c.expNS = make(map[string][]string)
			}

			s := ServiceStateLister{
				Log:          hclog.NewNullLogger(),
				ConsulClient: consulClient,
				Partition:    c.partition,
			}

			if c.partition == "" {
				// list all existing namespaces and ensure that no new ones are created
				c.expNS = listNamespaces(t, consulClient)
			}

			resourcesIF := make([]Resource, 0, len(c.resources))
			for _, r := range c.resources {
				resourcesIF = append(resourcesIF, r)
			}

			// create the namespaces and cross-namespace policies
			// this does nothing if enterprise features are not enabled
			require.NoError(t, s.ReconcileNamespaces(resourcesIF))

			if c.partition != "" {
				// if partitions are enabled ensure that the cross-namespace read policy exists
				rules, err := getPolicyRules(t, consulClient, c.partition, DefaultNamespace, xnsPolicyName)
				require.NoError(t, err)
				require.Equal(t, fmt.Sprintf(xnsPolicyTpl, c.partition), rules)
			}

			obsNS := listNamespaces(t, consulClient)
			require.Equal(t, c.expNS, obsNS)
		})
	}
}

func TestTaskLifecycle(t *testing.T) {
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

	cases := map[string]struct {
		partition       string
		enterpriseOnly  bool
		paginateResults bool
		tasks           []*ecs.Task
		expServices     []*ServiceInfo
	}{
		"no tasks": {
			partition:   "default",
			tasks:       []*ecs.Task{},
			expServices: []*ServiceInfo{},
		},
		"multiple services": {
			partition: "default",
			tasks: []*ecs.Task{
				{
					TaskArn:           aws.String("task1"),
					TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-1:1234567890:task-definition/service1:1"),
					Tags:              []*ecs.Tag{meshTag, partitionTag, namespace1Tag},
				},
				{
					TaskArn:           aws.String("task2"),
					TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-1:1234567890:task-definition/service2:1"),
					Tags:              []*ecs.Tag{meshTag, partitionTag, namespace1Tag},
				},
				{
					TaskArn:           aws.String("task3"),
					TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-1:1234567890:task-definition/service3:1"),
					Tags:              []*ecs.Tag{meshTag, partitionTag, namespace2Tag},
				},
			},
			expServices: []*ServiceInfo{
				{
					QName: NewQName("default", namespaces[0], "service1"),
					ServiceState: ServiceState{
						ConsulECSTasks: true,
						ACLPolicies: []*api.ACLPolicyListEntry{
							{
								Partition:   "default",
								Namespace:   namespaces[0],
								Name:        "service1-service",
								Description: "Policy for default/default/service1 service\nconsul.hashicorp.com/cluster: cluster",
							},
						},
						ACLTokens: []*api.ACLTokenListEntry{
							{
								Partition:   "default",
								Namespace:   namespaces[0],
								Description: "Token for default/default/service1 service\nconsul.hashicorp.com/cluster: cluster",
							},
						},
					},
				},
				{
					QName: NewQName("default", namespaces[0], "service2"),
					ServiceState: ServiceState{
						ConsulECSTasks: true,
						ACLPolicies: []*api.ACLPolicyListEntry{
							{
								Partition:   "default",
								Namespace:   namespaces[0],
								Name:        "service2-service",
								Description: "Policy for default/default/service2 service\nconsul.hashicorp.com/cluster: cluster",
							},
						},
						ACLTokens: []*api.ACLTokenListEntry{
							{
								Partition:   "default",
								Namespace:   namespaces[0],
								Description: "Token for default/default/service2 service\nconsul.hashicorp.com/cluster: cluster",
							},
						},
					},
				},
				{
					QName: NewQName("default", namespaces[1], "service3"),
					ServiceState: ServiceState{
						ConsulECSTasks: true,
						ACLPolicies: []*api.ACLPolicyListEntry{
							{
								Partition:   "default",
								Namespace:   namespaces[1],
								Name:        "service3-service",
								Description: "Policy for default/namespace-1/service3 service\nconsul.hashicorp.com/cluster: cluster",
							},
						},
						ACLTokens: []*api.ACLTokenListEntry{{
							Partition:   "default",
							Namespace:   namespaces[1],
							Description: "Token for default/namespace-1/service3 service\nconsul.hashicorp.com/cluster: cluster",
						},
						},
					},
				},
			},
		},
		"multiple services with the same name in different namespaces": {
			partition:      "default",
			enterpriseOnly: true, // services with the same name must be separated by partition/namespace
			tasks: []*ecs.Task{
				{
					TaskArn:           aws.String("task1"),
					TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-1:1234567890:task-definition/service1:1"),
					Tags:              []*ecs.Tag{meshTag, partitionTag, namespace1Tag},
				},
				{
					TaskArn:           aws.String("task2"),
					TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-1:1234567890:task-definition/service1:1"),
					Tags:              []*ecs.Tag{meshTag, partitionTag, namespace2Tag},
				},
				{
					TaskArn:           aws.String("external"),
					TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-1:1234567890:task-definition/service1:1"),
					Tags:              []*ecs.Tag{meshTag, extPartitionTag, namespace2Tag},
				},
				{
					TaskArn:           aws.String("non-mesh"),
					TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-1:1234567890:task-definition/service1:1"),
					Tags:              []*ecs.Tag{},
				},
			},
			expServices: []*ServiceInfo{
				{
					QName: NewQName("default", namespaces[0], "service1"),
					ServiceState: ServiceState{
						ConsulECSTasks: true,
						ACLPolicies: []*api.ACLPolicyListEntry{
							{
								Partition:   "default",
								Namespace:   namespaces[0],
								Name:        "service1-service",
								Description: "Policy for default/default/service1 service\nconsul.hashicorp.com/cluster: cluster",
							},
						},
						ACLTokens: []*api.ACLTokenListEntry{
							{
								Partition:   "default",
								Namespace:   namespaces[0],
								Description: "Token for default/default/service1 service\nconsul.hashicorp.com/cluster: cluster",
							},
						},
					},
				},
				{
					QName: NewQName("default", namespaces[1], "service1"),
					ServiceState: ServiceState{
						ConsulECSTasks: true,
						ACLPolicies: []*api.ACLPolicyListEntry{
							{
								Partition:   "default",
								Namespace:   namespaces[1],
								Name:        "service1-service",
								Description: "Policy for default/namespace-1/service1 service\nconsul.hashicorp.com/cluster: cluster",
							},
						},
						ACLTokens: []*api.ACLTokenListEntry{{
							Partition:   "default",
							Namespace:   namespaces[1],
							Description: "Token for default/namespace-1/service1 service\nconsul.hashicorp.com/cluster: cluster",
						},
						},
					},
				},
			},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {

			enterprise := enterpriseFlag()
			if !enterprise {
				if c.enterpriseOnly {
					t.Skip("enterprise only test")
				}
				c.partition = ""
			}

			consulClient := initConsul(t)

			lister := ServiceStateLister{
				ECSClient:    &mocks.ECSClient{Tasks: c.tasks, PaginateResults: c.paginateResults},
				ConsulClient: consulClient,
				Cluster:      cluster,
				SecretPrefix: "prefix",
				Partition:    c.partition,
				Log:          hclog.NewNullLogger(),
			}

			for _, service := range c.expServices {
				// set expected values for inherited service fields
				service.SecretsManagerClient = lister.SecretsManagerClient
				service.ConsulClient = lister.ConsulClient
				service.Cluster = lister.Cluster
				service.SecretPrefix = lister.SecretPrefix
				service.Log = lister.Log

				// if this is not an enterprise test then zero out partition and namespaces
				if !enterprise {
					lister.Partition = ""
					service.QName = NewQName("", "", service.QName.Name())
					for _, policy := range service.ServiceState.ACLPolicies {
						policy.Partition = ""
						policy.Namespace = ""
						policy.Description = fmt.Sprintf("Policy for %s service\nconsul.hashicorp.com/cluster: cluster", service.QName.Name())
					}
					for _, token := range service.ServiceState.ACLTokens {
						token.Partition = ""
						token.Namespace = ""
						token.Description = fmt.Sprintf("Token for %s service\nconsul.hashicorp.com/cluster: cluster", service.QName.Name())
					}
				}
			}

			// get cluster ACL state before the test
			beforePolicies, beforeTokens, err := listACLs(consulClient, c.partition)
			require.NoError(t, err)

			// list all resources
			resources, err := lister.List()
			require.NoError(t, err)

			// call ReconcileNamespaces to prepare all the namespaces
			require.NoError(t, lister.ReconcileNamespaces(resources))

			for _, r := range resources {
				s := r.(*ServiceInfo)

				// use a unique secret for each service
				accessorID, err := uuid.GenerateUUID()
				require.NoError(t, err)
				secretID, err := uuid.GenerateUUID()
				require.NoError(t, err)
				s.SecretsManagerClient = &mocks.SMClient{Secret: &secretsmanager.GetSecretValueOutput{
					Name:         aws.String(s.QName.String()),
					SecretString: aws.String(fmt.Sprintf(`{"accessor_id":"%s","token":"%s"}`, accessorID, secretID)),
				}}

				// call Reconcile() to create policies and tokens for each service
				require.NoError(t, s.Reconcile())
			}

			// call List() to get updated cluster state
			resources, err = lister.List()
			require.NoError(t, err)

			// inspect the state of each service reported by the controller
			obsServices := make([]*ServiceInfo, 0, len(resources))
			for _, r := range resources {
				s := r.(*ServiceInfo)

				// set only the expected ACL fields in the service state
				var policies []*api.ACLPolicyListEntry
				for _, policy := range s.ServiceState.ACLPolicies {
					policies = append(policies, &api.ACLPolicyListEntry{
						Partition:   policy.Partition,
						Namespace:   policy.Namespace,
						Name:        policy.Name,
						Description: policy.Description,
					})
				}
				s.ServiceState.ACLPolicies = policies

				var tokens []*api.ACLTokenListEntry
				for _, token := range s.ServiceState.ACLTokens {
					tokens = append(tokens, &api.ACLTokenListEntry{
						Partition:   token.Partition,
						Namespace:   token.Namespace,
						Description: token.Description,
					})
				}
				s.ServiceState.ACLTokens = tokens

				obsServices = append(obsServices, s)
			}

			// check for expected services with attached policies and tokens
			require.Equal(t, len(c.expServices), len(obsServices))
			require.ElementsMatch(t, c.expServices, obsServices)

			// remove all the ECS tasks
			lister.ECSClient = &mocks.ECSClient{}
			resources, err = lister.List()
			require.NoError(t, err)

			// call Reconcile() to remove policies and tokens
			for _, r := range resources {
				s := r.(*ServiceInfo)
				require.NoError(t, s.Reconcile())
			}

			// ensure cluster state matches previous
			newPolicies, afterTokens, err := listACLs(consulClient, c.partition)
			afterPolicies := make([]*api.ACLPolicyListEntry, 0, len(newPolicies))
			for _, p := range newPolicies {
				// we don't (currently) clean up namespaces nor their policies, so ignore them
				if p.Name != "cross-namespace-read" && p.Name != "namespace-management" {
					afterPolicies = append(afterPolicies, p)
				}
			}
			require.NoError(t, err)
			require.Equal(t, beforePolicies, afterPolicies)
			require.Equal(t, beforeTokens, afterTokens)
		})
	}
}

// helper func that initializes a Consul test server and returns a Consul API client.
func initConsul(t *testing.T) *api.Client {
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
	return consulClient
}

// listNamespaces is a helper func that returns a list of namespaces mapped to partition.
func listNamespaces(t *testing.T, consulClient *api.Client) map[string][]string {
	names := make(map[string][]string)

	if !enterpriseFlag() {
		return names
	}

	// list all existing namespaces and map them to partition
	partitions, _, err := consulClient.Partitions().List(context.Background(), nil)
	require.NoError(t, err)
	for _, p := range partitions {
		ns, _, err := consulClient.Namespaces().List(&api.QueryOptions{Partition: p.Name})
		require.NoError(t, err)
		for _, n := range ns {
			names[p.Name] = append(names[p.Name], n.Name)
		}
	}
	return names
}

// helper func that lists all policies and tokens within all namespaces in a partition
func listACLs(consulClient *api.Client, partition string) ([]*api.ACLPolicyListEntry, []*api.ACLTokenListEntry, error) {
	var err error
	policies := make([]*api.ACLPolicyListEntry, 0)
	tokens := make([]*api.ACLTokenListEntry, 0)
	opts := &api.QueryOptions{Partition: partition}
	var namespaces []*api.Namespace

	if enterpriseFlag() {
		// only list namespaces in enterprise tests
		namespaces, _, err = consulClient.Namespaces().List(opts)
		if err != nil {
			return policies, tokens, err
		}
	} else {
		namespaces = append(namespaces, &api.Namespace{})
	}

	for _, ns := range namespaces {
		opts.Namespace = ns.Name
		aclPolicies, _, err := consulClient.ACL().PolicyList(opts)
		if err != nil {
			return policies, tokens, err
		}
		policies = append(policies, aclPolicies...)

		aclTokens, _, err := consulClient.ACL().TokenList(opts)
		if err != nil {
			return policies, tokens, err
		}
		tokens = append(tokens, aclTokens...)
	}
	return policies, tokens, nil
}

func getPolicyRules(t *testing.T, consulClient *api.Client, partition, namespace, name string) (string, error) {
	policy, _, err := consulClient.ACL().PolicyReadByName(name,
		&api.QueryOptions{Partition: partition, Namespace: namespace})
	if err != nil || policy == nil {
		return "", err
	}

	return policy.Rules, nil
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
