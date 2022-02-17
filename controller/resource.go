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

// Tag definitions
const (
	meshTag        = "consul.hashicorp.com/mesh"
	serviceNameTag = "consul.hashicorp.com/service-name"

	// Included in ACL token description.
	clusterTag = "consul.hashicorp.com/cluster"

	// Consul Enterprise support for partitions and namespaces
	partitionTag = "consul.hashicorp.com/partition"
	namespaceTag = "consul.hashicorp.com/namespace"
)

const (
	// DefaultPartition is the name of the default Consul partition.
	DefaultPartition = "default"
	// DefaultNamespace is the name of the default Consul namespace.
	DefaultNamespace = "default"
)

// ResourceLister is an interface for listing Resources.
type ResourceLister interface {
	List() ([]Resource, error)
}

// Resource is a generic type that needs to be reconciled by the Controller.
// It offers Upsert and Delete functions to reconcile itself with an external state.
type Resource interface {
	Reconcile() error
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

	// Partition is the partition that is used by the ServiceStateLister [Consul Enterprise].
	Partition string

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

	if err = s.createNamespaces(buildingResources); err != nil {
		return resources, err
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
				s.Log.Info("skipping non-mesh task", "task-arn", *task.TaskArn)
				continue
			}

			serviceName, err := s.serviceNameForTask(task)

			if err != nil {
				s.Log.Error("couldn't get service name from task", "task-arn", task.TaskArn, "tags", task.Tags, "err", err)
				continue
			}

			if partition(serviceName) != s.Partition {
				s.Log.Info("skipping task in external partition", partition(serviceName), "task-arn", *task.TaskArn)
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

	var err error
	namespaces := make([]*api.Namespace, 0)

	if s.Partition != "" {
		// if partitions are enabled then list the namespaces.
		namespaces, _, err = s.ConsulClient.Namespaces().List(nil)
		if err != nil {
			return aclTokens, err
		}
	} else {
		// partitions aren't enabled so just use an empty namespace when listing tokens.
		namespaces = append(namespaces, &api.Namespace{})
	}

	// list tokens from all namespaces
	for _, ns := range namespaces {
		tokenList, _, err := s.ConsulClient.ACL().TokenList(&api.QueryOptions{
			Partition: ns.Partition,
			Namespace: ns.Name,
		})
		if err != nil {
			return aclTokens, err
		}

		for _, token := range tokenList {
			if isInCluster(s.Cluster, token) && len(token.ServiceIdentities) == 1 {
				qname := s.serviceName(
					token.Partition,
					token.Namespace,
					token.ServiceIdentities[0].ServiceName,
				)
				if _, ok := aclTokens[qname]; !ok {
					aclTokens[qname] = []*api.ACLTokenListEntry{token}
				} else {
					aclTokens[qname] = append(aclTokens[qname], token)
				}
			}
		}
	}

	return aclTokens, nil
}

func (s ServiceStateLister) newServiceInfo(qname string, serviceState ServiceState) *ServiceInfo {
	return &ServiceInfo{
		SecretsManagerClient: s.SecretsManagerClient,
		ConsulClient:         s.ConsulClient,
		Cluster:              s.Cluster,
		Log:                  s.Log,
		SecretPrefix:         s.SecretPrefix,
		Partition:            partition(qname),
		Namespace:            namespace(qname),
		ServiceName:          serviceName(qname),
		ServiceState:         serviceState,
	}
}

// Task definition ARN looks like this: arn:aws:ecs:us-east-1:1234567890:task-definition/service:1
func (s ServiceStateLister) serviceNameForTask(t *ecs.Task) (string, error) {
	partition := tagValue(t.Tags, partitionTag)
	namespace := tagValue(t.Tags, namespaceTag)
	if serviceName := tagValue(t.Tags, serviceNameTag); serviceName != "" {
		return s.serviceName(partition, namespace, serviceName), nil
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
	return s.serviceName(partition, namespace, splits[0]), nil
}

func (s ServiceStateLister) serviceName(p, n, t string) string {
	if s.Partition != "" {
		// If partitions are enabled and the partition or namespace are
		// empty then set them to "default" per Consul Enterprise.
		if p == "" {
			p = DefaultPartition
		}
		if n == "" {
			n = DefaultNamespace
		}
	} else {
		p = ""
		n = ""
	}
	return qualifiedName(p, n, t)
}

// createNamespaces ensures that the namespace for each service exists in the
// Consul cluster if it does not already.
func (s ServiceStateLister) createNamespaces(resources map[string]*ServiceInfo) error {
	if s.Partition == "" {
		return nil
	}

	// create list of unique namespaces from all resource namespaces
	ns := make(map[string]struct{}, len(resources))
	for _, info := range resources {
		if info.Namespace != "" {
			ns[info.Namespace] = struct{}{}
		}
	}

	// retrieve the list of existing namespaces
	existingNS, _, err := s.ConsulClient.Namespaces().List(nil)
	if err != nil {
		return err
	}

	// create any namespaces that do not already exist
	failed := make([]string, 0, len(ns))
	for n := range ns {
		exists := false
		for _, e := range existingNS {
			if e.Name == n {
				exists = true
				break
			}
		}
		if !exists {
			s.Log.Info("creating namespace", n)
			_, _, err = s.ConsulClient.Namespaces().Create(&api.Namespace{Name: n}, nil)
			if err != nil {
				s.Log.Error("failed to create namespace", n, err)
				failed = append(failed, n)
			}
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("namespace creation failed for %s", strings.Join(failed, ","))
	}
	return nil
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
	Partition    string
	Namespace    string
	ServiceName  string
	ServiceState ServiceState

	Log hclog.Logger
}

// TokenSecretJSON is the struct that represents JSON of the token secrets
// stored in Secrets Manager.
type TokenSecretJSON struct {
	AccessorID string `json:"accessor_id"`
	Token      string `json:"token"`
}

// Reconcile inserts or deletes ACL tokens based on their ServiceState.
func (s *ServiceInfo) Reconcile() error {
	state := s.ServiceState
	if len(state.ACLTokens) == 0 && state.ConsulECSTasks {
		return s.Upsert()
	}

	if !state.ConsulECSTasks && len(state.ACLTokens) > 0 {
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

	if err != nil && !IsACLNotFoundError(err) {
		return fmt.Errorf("reading existing token: %w", err)
	}

	// If there is already a token for this service in Consul, exit early.
	if currToken != nil {
		s.Log.Info("token already exists; skipping token creation", "id", s.Name())
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
		s.Log.Info("token deleted successfully", "service", s.Name())
	}

	return nil
}

// upsertSecret updates the AWS secret for the given service has a Token and
// AccessorID if it is unset. If the secret is already set, this does nothing.
func (s *ServiceInfo) upsertSecret() (TokenSecretJSON, error) {
	var currSecret TokenSecretJSON
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

	newSecret := TokenSecretJSON{Token: secretID, AccessorID: accessorID}
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
func (s *ServiceInfo) createServiceToken(secret TokenSecretJSON) error {
	s.Log.Info("creating service token", "id", s.Name())
	// Create ACL token for envoy to register the service.
	_, _, err := s.ConsulClient.ACL().TokenCreate(&api.ACLToken{
		AccessorID:        secret.AccessorID,
		SecretID:          secret.Token,
		Description:       fmt.Sprintf("Token for %s service\n%s: %s", s.Name(), clusterTag, s.Cluster),
		ServiceIdentities: []*api.ACLServiceIdentity{{ServiceName: s.ServiceName}},
		Partition:         partition(s.Partition),
		Namespace:         namespace(s.Namespace),
	}, nil)
	if err != nil {
		return fmt.Errorf("creating ACL token: %s", err)
	}
	s.Log.Info("service token created successfully", "service", s.Name())

	return nil
}

func (s *ServiceInfo) secretName() string {
	if s.Namespace == "" || s.Namespace == DefaultNamespace {
		return fmt.Sprintf("%s-%s", s.SecretPrefix, s.ServiceName)
	} else {
		return fmt.Sprintf("%s-%s-%s", s.SecretPrefix, s.ServiceName, s.Namespace)
	}
}

// Name returns the fully qualified name of the service which
// includes the partition and namespace, if they are present.
func (s *ServiceInfo) Name() string {
	return qualifiedName(s.Partition, s.Namespace, s.ServiceName)
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

// IsACLNotFoundError returns true if the ACL is not found.
func IsACLNotFoundError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Unexpected response code: 403 (ACL not found)")
}

// qualifiedName returns a fully qualified name in the form
// 	<partition>/<namespace>/<service>
// If partitions are enabled. If partitions are not enabled it returns
// service name s.
func qualifiedName(p, n, s string) string {
	if p != "" && n != "" {
		return fmt.Sprintf("%s/%s/%s", p, n, s)
	} else {
		return s
	}
}

// partition returns the partition from the qualified name.
// It returns the empty string if the name does not contain
// a partition and namespace.
func partition(qname string) string {
	parts := strings.SplitN(qname, "/", 3)
	if len(parts) > 2 {
		return parts[0]
	}
	return ""
}

// namespace returns the namespace from the qualified name.
// It returns the empty string if the name does not contain
// a partition and namespace.
func namespace(qname string) string {
	parts := strings.SplitN(qname, "/", 3)
	if len(parts) > 2 {
		return parts[1]
	}
	return ""
}

// serviceName returns the service name from the qualified name.
func serviceName(qname string) string {
	parts := strings.SplitN(qname, "/", 3)
	return parts[len(parts)-1]
}
