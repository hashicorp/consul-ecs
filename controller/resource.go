package controller

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
)

const meshTag = "consul.hashicorp.com/mesh"
const serviceNameTag = "consul.hashicorp.com/service-name"

// Included in ACL token description.
const clusterTag = "consul.hashicorp.com/cluster"

// ResourceLister is an interface for listing Resources.
type ResourceLister interface {
	List() ([]Resource, error)
}

// Resource is a generic type that needs to be reconciled by the Controller.
// It offers Upsert and Delete functions to reconcile itself with an external state.
type Resource interface {
	Reconcile(bool) error
}

// ServiceStateLister is an implementation of ResourceLister that constructs ServiceInfo
type ServiceStateLister struct {
	// ECSClient is the AWS ECS client to be used by the ServiceStateLister.
	ECSClient ecsiface.ECSAPI
	// SecretsManagerClient is the AWS Secrets Manager client to be used by the ServiceStateLister.
	SecretsManagerClient secretsmanageriface.SecretsManagerAPI
	// ConsulClient is the Consul client to be used by the ServiceStateLister.
	ConsulClient *api.Client

	// Cluster is the name or the ARN of the ECS cluster.
	Cluster string
	// SecretPrefix is the prefix to determine names of resources in Consul or AWS.
	SecretPrefix string

	// Log is the logger for the ServiceStateLister.
	Log hclog.Logger
}

// List returns a mapping from inferred service names to the ACL tokens, ECS
// tasks and existence of a Consul service.
func (s ServiceStateLister) List() ([]Resource, error) {
	var resources []Resource
	buildingResources := make(map[string]*ServiceInfo)

	tasks, err := s.fetchECSTasks()

	if err != nil {
		return nil, err
	}

	for name := range tasks {
		if _, ok := buildingResources[name]; !ok {
			buildingResources[name] = s.newServiceInfo(name, ServiceState{ConsulECSTasks: true})
		} else {
			buildingResources[name].ServiceState.ConsulECSTasks = true
		}
	}

	aclTokens, err := s.fetchACLTokens()

	if err != nil {
		return resources, err
	}

	for name, tokens := range aclTokens {
		if _, ok := buildingResources[name]; !ok {
			buildingResources[name] = s.newServiceInfo(name, ServiceState{ACLTokens: tokens})
		} else {
			buildingResources[name].ServiceState.ACLTokens = tokens
		}
	}

	for _, resource := range buildingResources {
		resources = append(resources, resource)
	}

	return resources, nil
}

// fetchECSTasks retrieves all of the ECS tasks that are managed by consul-ecs
// for the given cluster and returns a mapping that shows if a task is running
// for each service name.
func (s ServiceStateLister) fetchECSTasks() (map[string]struct{}, error) {
	resources := make(map[string]struct{})
	// nextToken is to handle paginated responses from AWS.
	var nextToken *string

	// This isn't an infinite loop, instead this is a "do while" loop
	// because we'll break out of it as soon as nextToken is nil.
	for {
		taskListOutput, err := s.ECSClient.ListTasks(&ecs.ListTasksInput{
			Cluster:   aws.String(s.Cluster),
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing tasks: %w", err)
		}
		nextToken = taskListOutput.NextToken

		tasks, err := s.ECSClient.DescribeTasks(&ecs.DescribeTasksInput{
			Cluster: aws.String(s.Cluster),
			Tasks:   taskListOutput.TaskArns,
			Include: []*string{aws.String("TAGS")},
		})
		if err != nil {
			return nil, fmt.Errorf("describing tasks: %w", err)
		}
		for _, task := range tasks.Tasks {
			if task == nil {
				s.Log.Info("task is nil")
				continue
			}

			if !isMeshTask(task) {
				s.Log.Info("skipping non-mesh task", "task-arn", task.TaskArn)
				continue
			}

			serviceName, err := serviceNameForTask(task)

			if err != nil {
				s.Log.Error("couldn't get service name from task", "task-arn", task.TaskArn, "tags", task.Tags, "err", err)
				continue
			}

			resources[serviceName] = struct{}{}
		}
		if nextToken == nil {
			break
		}
	}
	return resources, nil
}

// fetchACLTokens retrieves all of the ACL tokens from Consul and
// returns a mapping from service name to the ACL tokens that service has.
func (s ServiceStateLister) fetchACLTokens() (map[string][]*api.ACLTokenListEntry, error) {
	aclTokens := make(map[string][]*api.ACLTokenListEntry)

	tokenList, _, err := s.ConsulClient.ACL().TokenList(nil)
	if err != nil {
		return aclTokens, err
	}

	for _, token := range tokenList {
		if isInCluster(s.Cluster, token) && len(token.ServiceIdentities) == 1 {
			serviceName := token.ServiceIdentities[0].ServiceName
			if _, ok := aclTokens[serviceName]; !ok {
				aclTokens[serviceName] = []*api.ACLTokenListEntry{token}
			} else {
				aclTokens[serviceName] = append(aclTokens[serviceName], token)
			}
		}
	}

	return aclTokens, nil
}

func (s ServiceStateLister) newServiceInfo(name string, serviceState ServiceState) *ServiceInfo {
	return &ServiceInfo{
		SecretsManagerClient: s.SecretsManagerClient,
		ConsulClient:         s.ConsulClient,
		Cluster:              s.Cluster,
		Log:                  s.Log,
		SecretPrefix:         s.SecretPrefix,
		ServiceName:          name,
		ServiceState:         serviceState,
	}
}

// ServiceState contains all of the information needed to determine if an ACL
// token should be created for a Consul service or if an ACL token should be
// deleted.
type ServiceState struct {
	ConsulECSTasks bool
	ACLTokens      []*api.ACLTokenListEntry
}

type ServiceInfo struct {
	SecretsManagerClient secretsmanageriface.SecretsManagerAPI
	ConsulClient         *api.Client

	Cluster      string
	SecretPrefix string
	ServiceName  string
	ServiceState ServiceState

	Log hclog.Logger
}

// tokenSecretJSON is the struct that represents JSON of the token secrets
// stored in Secrets Manager.
type tokenSecretJSON struct {
	AccessorID string `json:"accessor_id"`
	Token      string `json:"token"`
}

// Reconcile inserts or deletes ACL tokens based on their ServiceState.
func (s *ServiceInfo) Reconcile(canDelete bool) error {
	state := s.ServiceState
	if len(state.ACLTokens) == 0 && state.ConsulECSTasks {
		return s.Upsert()
	}

	if !state.ConsulECSTasks && len(state.ACLTokens) > 0 && canDelete {
		return s.Delete()
	}

	return nil
}

// Upsert creates a token for the task if one doesn't already exist
// and updates the secret with the contents of the token.
func (s *ServiceInfo) Upsert() error {
	currSecret, err := s.upsertSecret()
	if err != nil {
		return fmt.Errorf("upserting secret: %w", err)
	}

	currToken, _, err := s.ConsulClient.ACL().TokenRead(currSecret.AccessorID, nil)

	if err != nil && !isACLNotFoundError(err) {
		return fmt.Errorf("reading existing token: %w", err)
	}

	// If there is already a token for this service in Consul, exit early.
	if currToken != nil {
		s.Log.Info("token already exists; skipping token creation", "id", s.ServiceName)
		return nil
	}

	// Otherwise, create one.
	err = s.createServiceToken(currSecret)
	if err != nil {
		return fmt.Errorf("updating service token: %w", err)
	}

	return nil
}

// Delete removes the token for the given ServiceInfo.
func (s *ServiceInfo) Delete() error {
	for _, token := range s.ServiceState.ACLTokens {
		_, err := s.ConsulClient.ACL().TokenDelete(token.AccessorID, nil)
		if err != nil {
			return fmt.Errorf("deleting token: %w", err)
		}
		s.Log.Info("token deleted successfully", "service", s.ServiceName)
	}

	return nil
}

// upsertSecret updates the AWS secret for the given service has a Token and
// AccessorID if it is unset. If the secret is already set, this does nothing.
func (s *ServiceInfo) upsertSecret() (tokenSecretJSON, error) {
	var currSecret tokenSecretJSON
	secretName := s.secretName()

	// Get current secret from AWS.
	currSecretValue, err := s.SecretsManagerClient.GetSecretValue(&secretsmanager.GetSecretValueInput{SecretId: aws.String(secretName)})
	if err != nil {
		return currSecret, fmt.Errorf("retrieving secret: %w", err)
	}
	err = json.Unmarshal([]byte(*currSecretValue.SecretString), &currSecret)
	if err != nil {
		return currSecret, fmt.Errorf("unmarshalling secret value: %w", err)
	}

	if len(currSecret.AccessorID) > 0 && len(currSecret.Token) > 0 {
		return currSecret, nil
	}

	accessorID, err := uuid.GenerateUUID()
	if err != nil {
		return currSecret, err
	}

	secretID, err := uuid.GenerateUUID()
	if err != nil {
		return currSecret, err
	}

	newSecret := tokenSecretJSON{Token: secretID, AccessorID: accessorID}
	serviceSecretValue, err := json.Marshal(newSecret)
	if err != nil {
		return newSecret, err
	}

	s.Log.Info("updating secret", "name", secretName)
	_, err = s.SecretsManagerClient.UpdateSecret(&secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(s.secretName()),
		SecretString: aws.String(string(serviceSecretValue)),
	})
	if err != nil {
		return newSecret, fmt.Errorf("updating secret: %s", err)
	}
	s.Log.Info("secret successfully set", "name", secretName)

	return newSecret, err
}

// createServiceToken inserts an ACL token into Consul. The AccessorID and
// SecretID are set based on the AWS secret.
func (s *ServiceInfo) createServiceToken(secret tokenSecretJSON) error {
	s.Log.Info("creating service token", "id", s.ServiceName)
	// Create ACL token for envoy to register the service.
	_, _, err := s.ConsulClient.ACL().TokenCreate(&api.ACLToken{
		AccessorID:        secret.AccessorID,
		SecretID:          secret.Token,
		Description:       fmt.Sprintf("Token for %s service\n%s: %s", s.ServiceName, clusterTag, s.Cluster),
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: s.ServiceName}},
	}, nil)
	if err != nil {
		return fmt.Errorf("creating ACL token: %s", err)
	}
	s.Log.Info("service token created successfully", "service", s.ServiceName)

	return nil
}

// Task definition ARN looks like this: arn:aws:ecs:us-east-1:1234567890:task-definition/service:1
func serviceNameForTask(t *ecs.Task) (string, error) {
	if serviceName := tagValue(t.Tags, serviceNameTag); serviceName != "" {
		return serviceName, nil
	}
	taskDefArn := *t.TaskDefinitionArn
	splits := strings.Split(taskDefArn, "/")
	if len(splits) != 2 {
		return "", fmt.Errorf("cannot determine task family from task definition ARN: %q", taskDefArn)
	}
	taskFamilyAndRevision := splits[1]
	splits = strings.Split(taskFamilyAndRevision, ":")
	if len(splits) != 2 {
		return "", fmt.Errorf("cannot determine task family from task definition ARN: %q", taskDefArn)
	}
	return splits[0], nil
}

func (t *ServiceInfo) secretName() string {
	return fmt.Sprintf("%s-%s", t.SecretPrefix, t.ServiceName)
}

func isInCluster(clusterName string, token *api.ACLTokenListEntry) bool {
	return strings.Contains(token.Description, fmt.Sprintf("%s: %s", clusterTag, clusterName))
}

func isMeshTask(t *ecs.Task) bool {
	return tagValue(t.Tags, meshTag) == "true"
}

func tagValue(tags []*ecs.Tag, key string) string {
	for _, t := range tags {
		if t.Key != nil && *t.Key == key {
			if t.Value == nil {
				return ""
			}
			return *t.Value
		}
	}
	return ""
}

func isACLNotFoundError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Unexpected response code: 403 (ACL not found)")
}
