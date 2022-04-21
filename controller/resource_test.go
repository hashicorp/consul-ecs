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
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

func TestServiceStateLister_List(t *testing.T) {
	t.Parallel()
	enterprise := enterpriseFlag()
	cluster := "cluster"
	meshKey := "consul.hashicorp.com/mesh"
	meshValue := "true"
	partitionKey := "consul.hashicorp.com/partition"
	namespaceKey := "consul.hashicorp.com/namespace"
	namespaces := []string{"default", "namespace-1"}
	meshTag := &ecs.Tag{Key: &meshKey, Value: &meshValue}
	nonMeshTag := &ecs.Tag{}

	makeTask := func(taskName, serviceName, partition, namespace string, tags ...*ecs.Tag) (ecs.Task, ServiceName, *api.ACLToken, *api.ACLTokenListEntry) {
		if enterprise {
			tags = append(tags, &ecs.Tag{Key: &partitionKey, Value: &partition})
			tags = append(tags, &ecs.Tag{Key: &namespaceKey, Value: &namespace})
		}
		task := ecs.Task{
			TaskArn:           aws.String(taskName),
			TaskDefinitionArn: aws.String(fmt.Sprintf("arn:aws:ecs:us-east-1:1234567890:task-definition/%s:1", serviceName)),
			Tags:              tags,
		}
		name := ServiceName{Name: serviceName}
		token := &api.ACLToken{}
		tokenListEntry := &api.ACLTokenListEntry{}
		if enterprise {
			name.Partition = partition
			name.Namespace = namespace
			name.ACLNamespace = DefaultNamespace
			token.Partition = partition
			token.Namespace = DefaultNamespace
			tokenListEntry.Partition = partition
			tokenListEntry.Namespace = DefaultNamespace
		}
		info := ServiceInfo{Cluster: cluster, ServiceName: name}
		token.Description = info.aclDescription("Token")
		tokenListEntry.Description = info.aclDescription("Token")
		return task, name, token, tokenListEntry
	}
	task1, task1Name, aclToken1, aclTokenListEntry1 := makeTask("task1", "service1", "default", "default", meshTag)
	task2, task2Name, aclToken2, aclTokenListEntry2 := makeTask("task2", "service1", "default", "namespace-1", meshTag)
	nonMeshTask, _, _, _ := makeTask("nonMeshTask", "service1", "default", "default", nonMeshTag)
	_, task3Name, aclToken3, aclTokenListEntry3 := makeTask("task3", "service3", "default", "default", nonMeshTag)
	task4, _, _, _ := makeTask("task4", "service4", "external-partition", "default", meshTag)
	cases := map[string]struct {
		paginateResults bool
		tasks           []ecs.Task
		expected        map[ServiceName]ServiceState
		aclTokens       []*api.ACLToken
		partition       string
	}{
		"no overlap between tasks, services and tokens": {
			tasks:     []ecs.Task{task1, task2},
			partition: "default",
			aclTokens: []*api.ACLToken{aclToken3},
			expected: map[ServiceName]ServiceState{
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
			partition: "default",
			aclTokens: []*api.ACLToken{aclToken1, aclToken2},
			expected: map[ServiceName]ServiceState{
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
			partition:       "default",
			paginateResults: true,
			expected: map[ServiceName]ServiceState{
				task1Name: {
					ConsulECSTasks: true,
				},
			},
		},
		"with non-mesh tasks": {
			tasks:     []ecs.Task{nonMeshTask},
			partition: "default",
			aclTokens: []*api.ACLToken{aclToken1},
			expected: map[ServiceName]ServiceState{
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
			t.Parallel()
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

			var partition string
			if enterprise {
				// for the enterprise case, set the partition and add in the task that
				// belongs to an external partition.
				partition = c.partition
				tasks = append(tasks, &task4)
			}

			s := ServiceStateLister{
				SecretPrefix: "test",
				Log:          hclog.NewNullLogger(),
				ConsulClient: consulClient,
				ECSClient: &mocks.ECSClient{
					Tasks:           tasks,
					PaginateResults: c.paginateResults,
				},
				Partition: partition,
			}

			resources, err := s.List()
			require.NoError(t, err)

			serviceStates := make(map[ServiceName]ServiceState)

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
				serviceStates[serviceInfo.ServiceName] = serviceInfo.ServiceState
			}

			require.Equal(t, c.expected, serviceStates)
		})
	}
}

func TestReconcile(t *testing.T) {
	t.Parallel()
	cluster := "test-cluster"
	aclToken1 := &api.ACLToken{}
	aclPolicy1 := &api.ACLPolicy{Name: "service1-service"}
	cases := map[string]struct {
		tasks            bool
		aclTokens        []*api.ACLToken
		aclPolicies      []*api.ACLPolicy
		sutServiceName   ServiceName
		expectedTokens   []*api.ACLToken
		expectedPolicies []*api.ACLPolicy
	}{
		"ACLs should be deleted": {
			tasks:            false,
			aclTokens:        []*api.ACLToken{aclToken1},
			aclPolicies:      []*api.ACLPolicy{aclPolicy1},
			sutServiceName:   ServiceName{Name: "service1"},
			expectedTokens:   nil,
			expectedPolicies: nil,
		},
		"ACLs should be added": {
			tasks:            true,
			aclTokens:        []*api.ACLToken{},
			aclPolicies:      []*api.ACLPolicy{},
			sutServiceName:   ServiceName{Name: "service1"},
			expectedTokens:   []*api.ACLToken{aclToken1},
			expectedPolicies: []*api.ACLPolicy{aclPolicy1},
		},
		"Does nothing when a task is running and ACLs exists for a given service": {
			tasks:            true,
			aclTokens:        []*api.ACLToken{aclToken1},
			aclPolicies:      []*api.ACLPolicy{aclPolicy1},
			sutServiceName:   ServiceName{Name: "service1"},
			expectedTokens:   []*api.ACLToken{aclToken1},
			expectedPolicies: []*api.ACLPolicy{aclPolicy1},
		},
		"Does nothing when there are no tasks or tokens": {
			tasks:          false,
			sutServiceName: ServiceName{Name: "service1"},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			smClient := &mocks.SMClient{Secret: &secretsmanager.GetSecretValueOutput{Name: aws.String("test-service"), SecretString: aws.String(`{}`)}}
			consulClient := initConsul(t)

			writeOpts := &api.WriteOptions{}
			if enterpriseFlag() {
				c.sutServiceName.Partition = "default"
				c.sutServiceName.Namespace = "default"
				c.sutServiceName.ACLNamespace = "default"

				aclToken1.Partition = "default"
				aclToken1.Namespace = "default"

				aclPolicy1.Partition = "default"
				aclPolicy1.Namespace = "default"

				writeOpts.Partition = "default"
				writeOpts.Namespace = "default"
			}

			info := ServiceInfo{Cluster: cluster, ServiceName: c.sutServiceName}
			aclToken1.Description = info.aclDescription("Token")
			aclPolicy1.Name = info.policyName()
			aclPolicy1.Description = info.aclDescription("Policy")

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
			serviceStateLister := ServiceStateLister{
				ConsulClient: consulClient,
				Partition:    c.sutServiceName.Partition,
				Log:          log,
			}

			serviceInfo := ServiceInfo{
				SecretsManagerClient: smClient,
				ConsulClient:         consulClient,
				Cluster:              cluster,
				SecretPrefix:         "test",
				ServiceName:          c.sutServiceName,
				ServiceState: ServiceState{
					ConsulECSTasks: c.tasks,
					ACLPolicies:    beforePolicies,
					ACLTokens:      beforeTokens,
				},
				Log: log,
			}

			if enterpriseFlag() {
				// for enterprise testing we need to create the cross-namespace policy
				require.NoError(t, serviceStateLister.ReconcileNamespaces([]Resource{&serviceInfo}))
			}

			err := serviceInfo.Reconcile()
			require.NoError(t, err)

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
	t.Parallel()
	smClient := &mocks.SMClient{Secret: &secretsmanager.GetSecretValueOutput{Name: aws.String("test-service"), SecretString: aws.String(`{}`)}}
	consulClient := initConsul(t)

	taskTokens := ServiceInfo{
		SecretsManagerClient: smClient,
		ConsulClient:         consulClient,
		Cluster:              "test-cluster",
		SecretPrefix:         "test",
		ServiceName:          ServiceName{Name: "service"},
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
	t.Parallel()
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
			t.Parallel()
			smClient := &mocks.SMClient{Secret: c.existingSecret}
			consulClient := initConsul(t)

			taskTokens := ServiceInfo{
				SecretsManagerClient: smClient,
				ConsulClient:         consulClient,
				Cluster:              "test-cluster",
				SecretPrefix:         "test",
				ServiceName:          ServiceName{Name: "service"},
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
	t.Parallel()
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
			t.Parallel()
			existingSecret := &secretsmanager.GetSecretValueOutput{Name: aws.String("test-service"), SecretString: aws.String(`{}`)}
			smClient := &mocks.SMClient{Secret: existingSecret}
			consulClient := initConsul(t)

			taskTokens := ServiceInfo{
				SecretsManagerClient: smClient,
				ConsulClient:         consulClient,
				Cluster:              "test-cluster",
				SecretPrefix:         "test",
				ServiceName:          ServiceName{Name: "service"},
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
	t.Parallel()
	validARN := "arn:aws:ecs:us-east-1:1234567890:task-definition/service:1"
	cases := map[string]struct {
		task        ecs.Task
		serviceName ServiceName
		partition   string
	}{
		"invalid ARN": {
			task: ecs.Task{
				TaskDefinitionArn: aws.String("invalid"),
			},
			serviceName: ServiceName{},
		},
		"parsing from the ARN": {
			task: ecs.Task{
				TaskDefinitionArn: aws.String(validARN),
			},
			serviceName: ServiceName{Name: "service"},
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
			serviceName: ServiceName{Name: "real-service-name"},
		},
	}
	if enterpriseFlag() {
		c := cases["add"]
		c.partition = "test-partition"
		c.serviceName = ServiceName{Name: "real-service-name", Partition: "test-partition", Namespace: "test-namespace", ACLNamespace: "default"}
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
		cases["from the tags with partitions and namespaces"] = c

		c = cases["add"]
		c.partition = "default"
		c.serviceName = ServiceName{Name: "real-service-name", Partition: "default", Namespace: "default", ACLNamespace: "default"}
		c.task = ecs.Task{
			TaskDefinitionArn: aws.String(validARN),
			Tags: []*ecs.Tag{
				{
					Key:   aws.String(serviceNameTag),
					Value: aws.String("real-service-name"),
				},
			},
		}
		cases["from the tags with default partition and default namespace"] = c

		c = cases["add"]
		c.serviceName = ServiceName{Name: "real-service-name"}
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
		cases["from the tags with partitions disabled"] = c

		c = cases["add"]
		c.partition = "default"
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
			},
		}
		cases["error when only partition tag provided"] = c

		c = cases["add"]
		c.partition = "default"
		c.task = ecs.Task{
			TaskDefinitionArn: aws.String(validARN),
			Tags: []*ecs.Tag{
				{
					Key:   aws.String(serviceNameTag),
					Value: aws.String("real-service-name"),
				},
				{
					Key:   aws.String(namespaceTag),
					Value: aws.String("test-namespace"),
				},
			},
		}
		cases["error when only namespace tag provided"] = c
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l := ServiceStateLister{
				Partition: c.partition,
			}
			serviceName, err := l.serviceNameForTask(&c.task)
			if c.serviceName.Name == "" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, c.serviceName, serviceName)
			}
		})
	}
}

func TestReconcileNamespaces(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		partition string
		expNS     map[string][]string
		resources map[string]*ServiceInfo
	}{
		"with partitions disabled": {
			expNS: map[string][]string{"default": {"default"}},
			resources: map[string]*ServiceInfo{
				"resource1": {ServiceName: ServiceName{Name: "service", Partition: "default", Namespace: "test-namespace"}},
			},
		},
		"with resources in default namespace": {
			partition: "default",
			expNS:     map[string][]string{"default": {"default"}},
			resources: map[string]*ServiceInfo{
				"resource1": {ServiceName: ServiceName{Name: "service", Partition: "default", Namespace: "default"}},
			},
		},
		"with resources in different namespaces": {
			partition: "default",
			expNS: map[string][]string{
				"default": {"default", "namespace-1", "namespace-2"},
			},
			resources: map[string]*ServiceInfo{
				"resource1": {ServiceName: ServiceName{Name: "service-1", Partition: "default", Namespace: "default"}},
				"resource2": {ServiceName: ServiceName{Name: "service-1", Partition: "default", Namespace: "namespace-1"}},
				"resource3": {ServiceName: ServiceName{Name: "service-2", Partition: "default", Namespace: "namespace-1"}},
				"resource4": {ServiceName: ServiceName{Name: "service-1", Partition: "default", Namespace: "namespace-2"}},
			},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
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
	t.Parallel()
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
					ServiceName: ServiceName{Name: "service1", Partition: "default", Namespace: namespaces[0], ACLNamespace: "default"},
					ServiceState: ServiceState{
						ConsulECSTasks: true,
						ACLPolicies: []*api.ACLPolicyListEntry{
							{
								Partition: "default",
								Namespace: "default",
								Name:      "service1-service",
							},
						},
						ACLTokens: []*api.ACLTokenListEntry{
							{
								Partition: "default",
								Namespace: "default",
							},
						},
					},
				},
				{
					ServiceName: ServiceName{Name: "service2", Partition: "default", Namespace: namespaces[0], ACLNamespace: "default"},
					ServiceState: ServiceState{
						ConsulECSTasks: true,
						ACLPolicies: []*api.ACLPolicyListEntry{
							{
								Partition: "default",
								Namespace: "default",
								Name:      "service2-service",
							},
						},
						ACLTokens: []*api.ACLTokenListEntry{
							{
								Partition: "default",
								Namespace: "default",
							},
						},
					},
				},
				{
					ServiceName: ServiceName{Name: "service3", Partition: "default", Namespace: namespaces[1], ACLNamespace: "default"},
					ServiceState: ServiceState{
						ConsulECSTasks: true,
						ACLPolicies: []*api.ACLPolicyListEntry{
							{
								Partition: "default",
								Namespace: "default",
								Name:      "service3-service",
							},
						},
						ACLTokens: []*api.ACLTokenListEntry{{
							Partition: "default",
							Namespace: "default",
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
					ServiceName: ServiceName{Name: "service1", Partition: "default", Namespace: namespaces[0], ACLNamespace: "default"},
					ServiceState: ServiceState{
						ConsulECSTasks: true,
						ACLPolicies: []*api.ACLPolicyListEntry{
							{
								Partition: "default",
								Namespace: "default",
								Name:      "service1-service",
							},
						},
						ACLTokens: []*api.ACLTokenListEntry{
							{
								Partition: "default",
								Namespace: "default",
							},
						},
					},
				},
				{
					ServiceName: ServiceName{Name: "service1", Partition: "default", Namespace: namespaces[1], ACLNamespace: "default"},
					ServiceState: ServiceState{
						ConsulECSTasks: true,
						ACLPolicies: []*api.ACLPolicyListEntry{
							{
								Partition: "default",
								Namespace: "default",
								Name:      "service1-service",
							},
						},
						ACLTokens: []*api.ACLTokenListEntry{{
							Partition: "default",
							Namespace: "default",
						},
						},
					},
				},
			},
		},
	}
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			t.Parallel()

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
					service.ServiceName.Partition = ""
					service.ServiceName.Namespace = ""
					service.ServiceName.ACLNamespace = ""
					for _, policy := range service.ServiceState.ACLPolicies {
						policy.Partition = ""
						policy.Namespace = ""
					}
					for _, token := range service.ServiceState.ACLTokens {
						token.Partition = ""
						token.Namespace = ""
					}
				}

				for _, policy := range service.ServiceState.ACLPolicies {
					policy.Name = service.policyName()
					policy.Description = service.aclDescription("Policy")
				}
				for _, token := range service.ServiceState.ACLTokens {
					token.Description = service.aclDescription("Token")
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
					Name:         aws.String(s.ServiceName.Name),
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

func TestACLDescriptions(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		cluster     string
		serviceName ServiceName
	}{
		"with partitions": {
			cluster:     "c1",
			serviceName: ServiceName{Name: "s1", Partition: "p1", Namespace: "n1", ACLNamespace: "default"},
		},
		"without partitions": {
			cluster:     "c1",
			serviceName: ServiceName{Name: "s1"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := &ServiceInfo{
				Cluster:     c.cluster,
				ServiceName: c.serviceName,
			}
			desc := s.aclDescription("Token")
			l := ServiceStateLister{Cluster: c.cluster, Partition: c.serviceName.Partition}
			require.Equal(t, c.serviceName, l.serviceNameFromDescription(desc))
		})
	}
}

// helper func that initializes a Consul test server and returns a Consul API client.
func initConsul(t *testing.T) *api.Client {
	cfg := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	return client
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
