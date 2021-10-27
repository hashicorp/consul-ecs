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
)

const meshTag = "consul.hashicorp.com/mesh"
const serviceNameTag = "consul.hashicorp.com/service-name"

// ResourceID represents the ID of the resource.
type ResourceID string

// ResourceLister is an interface for listing Resources.
type ResourceLister interface {
	List() ([]Resource, error)
}

// Resource is a generic type that needs to be reconciled by the Controller.
// It offers Upsert and Delete functions to reconcile itself with an external state.
type Resource interface {
	ID() (ResourceID, error)
	Upsert() error
	Delete() error
}

// TaskLister is an implementation of ResourceLister that lists ECS tasks.
type TaskLister struct {
	// ECSClient is the AWS ECS client to be used by the TaskLister.
	ECSClient ecsiface.ECSAPI
	// SecretsManagerClient is the AWS Secrets Manager client to be used by the TaskLister.
	SecretsManagerClient secretsmanageriface.SecretsManagerAPI
	// ConsulClient is the Consul client to be used by the TaskLister.
	// TaskLister doesn't need to talk to Consul, but it passes this client
	// to each Resource it creates.
	ConsulClient *api.Client

	// Cluster is the name or the ARN of the ECS cluster.
	Cluster string
	// SecretPrefix is the prefix to determine names of resources in Consul or AWS.
	SecretPrefix string

	// Log is the logger for the TaskLister.
	Log hclog.Logger
}

// List lists all tasks for the Cluster.
func (t TaskLister) List() ([]Resource, error) {
	var resources []Resource
	// nextToken is to handle paginated responses from AWS.
	var nextToken *string

	// This isn't an infinite loop, instead this is a "do while" loop
	// because we'll break out of it as soon as nextToken is nil.
	for {
		taskListOutput, err := t.ECSClient.ListTasks(&ecs.ListTasksInput{
			Cluster:   aws.String(t.Cluster),
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing tasks: %w", err)
		}
		nextToken = taskListOutput.NextToken

		tasks, err := t.ECSClient.DescribeTasks(&ecs.DescribeTasksInput{
			Cluster: aws.String(t.Cluster),
			Tasks:   taskListOutput.TaskArns,
			Include: []*string{aws.String("TAGS")},
		})
		if err != nil {
			return nil, fmt.Errorf("describing tasks: %w", err)
		}
		for _, task := range tasks.Tasks {
			// Add task only if it's not nil.
			if task != nil {
				resources = append(resources, &Task{
					SecretsManagerClient: t.SecretsManagerClient,
					ConsulClient:         t.ConsulClient,
					Cluster:              t.Cluster,
					Log:                  t.Log,
					SecretPrefix:         t.SecretPrefix,
					Task:                 *task,
				})
			}
		}
		if nextToken == nil {
			break
		}
	}
	return resources, nil
}

type Task struct {
	SecretsManagerClient secretsmanageriface.SecretsManagerAPI
	ConsulClient         *api.Client

	Cluster      string
	SecretPrefix string
	Task         ecs.Task

	Log hclog.Logger
}

// ID returns Task definition ARN or error if it cannot be determined from the Task.
// We're using task definition ARN instead of the Task ARN because we consider tasks
// for the same definition to be equivalent in terms of their Upsert and Delete behavior,
// and so there's no reason to process subsequent tasks with the same task definition.
func (t *Task) ID() (ResourceID, error) {
	// This should never be the case, but we are checking it anyway.
	if t.Task.TaskDefinitionArn == nil {
		return "", fmt.Errorf("cannot determine ID: task definition ARN is nil")
	}

	return ResourceID(*t.Task.TaskDefinitionArn), nil
}

// tokenSecretJSON is the struct that represents JSON of the token secrets
// stored in Secrets Manager.
type tokenSecretJSON struct {
	AccessorID string `json:"accessor_id"`
	Token      string `json:"token"`
}

// Upsert creates a token for the task if one doesn't already exist
// and updates the secret with the contents of the token.
func (t *Task) Upsert() error {
	serviceName, err := t.serviceNameForTask()
	if err != nil {
		return fmt.Errorf("could not determine service name: %w", err)
	}

	if !t.isMeshTask() {
		t.Log.Info("skipping non-mesh task", "id", serviceName)
		return nil
	}

	secretName := t.secretName(serviceName)

	// Get current secret from AWS.
	currSecretValue, err := t.SecretsManagerClient.GetSecretValue(&secretsmanager.GetSecretValueInput{SecretId: aws.String(secretName)})
	if err != nil {
		return fmt.Errorf("retrieving secret: %w", err)
	}
	var currSecret tokenSecretJSON
	err = json.Unmarshal([]byte(*currSecretValue.SecretString), &currSecret)
	if err != nil {
		return fmt.Errorf("unmarshalling secret value: %w", err)
	}

	var currToken *api.ACLToken
	// If we already have an accessor ID, we'll check if this token exists in Consul first.
	// We don't care if the token value is empty or not in this case.
	// If token value is empty, then it's an empty secret, and we should update it with the token.
	// If token value is non-empty it indicates that something is corrupted, and we should update the token.
	if currSecret.AccessorID != "" {
		// Read the token with this Accessor ID from Consul.
		currToken, _, err = t.ConsulClient.ACL().TokenRead(currSecret.AccessorID, nil)

		if err != nil && !isACLNotFoundError(err) {
			return fmt.Errorf("reading existing token: %w", err)
		}
	}

	// If there is already a token for this service in Consul, exit early.
	if currToken != nil {
		t.Log.Info("token already exists; skipping token creation", "id", serviceName)
		return nil
	}

	// Otherwise, create one.
	err = t.updateServiceToken(serviceName, secretName)
	if err != nil {
		return fmt.Errorf("updating service token: %w", err)
	}

	return nil
}

func (t *Task) Delete() error {
	if !t.isMeshTask() {
		t.Log.Info("skipping non-mesh task", "id", *t.Task.TaskDefinitionArn)
		return nil
	}

	serviceName, err := t.serviceNameForTask()
	if err != nil {
		return fmt.Errorf("parsing service name: %w", err)
	}

	// If a service still exists in Consul, it could be because this task is
	// being upgraded (e.g. from task definition version 1 to version 2),
	// and in that case, we don't want to delete the token prematurely.
	// In a rare case, if the task family is being deleted permanently,
	// and we call this function before the service is deregistered, we will also skip
	// token deletion. That is intentional since it's safer to keep the token in Consul.
	services, _, err := t.ConsulClient.Catalog().Service(serviceName, "", nil)
	if err != nil {
		return fmt.Errorf("getting service from Consul: %w", err)
	}
	if len(services) != 0 {
		t.Log.Info("skipping because service still exists", "id", *t.Task.TaskDefinitionArn)
		return nil
	}

	tokenList, _, err := t.ConsulClient.ACL().TokenList(nil)
	if err != nil {
		return fmt.Errorf("listing tokens: %w", err)
	}

	for _, tokenEntry := range tokenList {
		token, _, err := t.ConsulClient.ACL().TokenRead(tokenEntry.AccessorID, nil)
		if err != nil {
			return fmt.Errorf("reading token: %w", err)
		}

		if len(token.ServiceIdentities) == 1 && token.ServiceIdentities[0].ServiceName == serviceName {
			t.Log.Info("deleting token", "service", serviceName)
			_, err = t.ConsulClient.ACL().TokenDelete(token.AccessorID, nil)
			if err != nil {
				return fmt.Errorf("deleting token: %w", err)
			}
			t.Log.Info("token deleted successfully", "service", serviceName)
		}
	}

	secretName := t.secretName(serviceName)
	t.Log.Info("updating secret", "name", secretName, "service", serviceName)
	_, err = t.SecretsManagerClient.UpdateSecret(&secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String(`{}`),
	})
	if err != nil {
		return fmt.Errorf("updating secret: %s", err)
	}
	t.Log.Info("secret updated successfully", "name", secretName, "service", serviceName)

	return nil
}

// updateServiceToken create a token in Consul and updates AWS secret with token's contents.
func (t *Task) updateServiceToken(serviceName, secretName string) error {
	t.Log.Info("creating service token", "id", serviceName)
	// Create ACL token for envoy to register the service.
	serviceToken, _, err := t.ConsulClient.ACL().TokenCreate(&api.ACLToken{
		Description:       fmt.Sprintf("Token for %s service", serviceName),
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: serviceName}},
	}, nil)
	if err != nil {
		return fmt.Errorf("creating envoy token: %s", err)
	}
	t.Log.Info("service token created successfully", "service", serviceName)

	serviceSecretValue, err := json.Marshal(tokenSecretJSON{Token: serviceToken.SecretID, AccessorID: serviceToken.AccessorID})
	if err != nil {
		return err
	}

	t.Log.Info("updating secret", "name", secretName)
	_, err = t.SecretsManagerClient.UpdateSecret(&secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String(string(serviceSecretValue)),
	})
	if err != nil {
		return fmt.Errorf("updating secret: %s", err)
	}
	t.Log.Info("secret updated successfully", "name", secretName)

	return nil
}

// Task definition ARN looks like this: arn:aws:ecs:us-east-1:1234567890:task-definition/service:1
func (t *Task) serviceNameForTask() (string, error) {
	if serviceName := t.serviceName(); serviceName != "" {
		return serviceName, nil
	}
	taskDefArn := *t.Task.TaskDefinitionArn
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

func (t *Task) secretName(serviceName string) string {
	return fmt.Sprintf("%s-%s", t.SecretPrefix, serviceName)
}

func (t *Task) isMeshTask() bool {
	return tagValue(t.Task.Tags, meshTag) == "true"
}

func (t *Task) serviceName() string {
	return tagValue(t.Task.Tags, serviceNameTag)
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
