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
	// List all Resources.
	List() ([]Resource, error)

	// ReconcileNamespaces ensures that all requisite namespaces exist.
	ReconcileNamespaces([]Resource) error
}

// Resource is a generic type that needs to be reconciled by the Controller.
type Resource interface {
	// GetNamespace indicates the namespace that this resource belongs to [Consul Enterprise].
	// It returns the empty string if namespaces are not enabled.
	GetNamespace() string

	// Reconcile offers Upsert and Delete functions to reconcile itself with an external state.
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
	// If partition and namespace support are not enabled then this is set to the empty string.
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

	for name, qname := range tasks {
		if _, ok := buildingResources[name]; !ok {
			buildingResources[name] = s.newServiceInfo(qname, ServiceState{ConsulECSTasks: true})
		} else {
			buildingResources[name].ServiceState.ConsulECSTasks = true
		}
	}

	aclState, err := s.fetchACLState()
	if err != nil {
		return resources, err
	}

	for name, state := range aclState {
		if _, ok := buildingResources[name]; !ok {
			buildingResources[name] = s.newServiceInfo(
				QNameFromString(name),
				ServiceState{ACLPolicies: state.ACLPolicies, ACLTokens: state.ACLTokens},
			)
		} else {
			buildingResources[name].ServiceState.ACLPolicies = state.ACLPolicies
			buildingResources[name].ServiceState.ACLTokens = state.ACLTokens
		}
	}

	for _, resource := range buildingResources {
		resources = append(resources, resource)
	}

	return resources, nil
}

// fetchECSTasks retrieves all of the ECS tasks that are managed by consul-ecs
// for the given cluster and returns a mapping that shows if a task is running
// for each qualified service name.
func (s ServiceStateLister) fetchECSTasks() (map[string]QName, error) {
	resources := make(map[string]QName)
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

			if serviceName.Partition() != s.Partition {
				s.Log.Info("skipping task in external partition", serviceName.Partition(), "task-arn", *task.TaskArn)
				continue
			}

			resources[serviceName.String()] = serviceName
		}
		if nextToken == nil {
			break
		}
	}
	return resources, nil
}

// fetchACLState retrieves all of the ACL policies and tokens from Consul and
// returns a mapping from service name to the ACL tokens that service has.
func (s ServiceStateLister) fetchACLState() (map[string]*ServiceState, error) {
	aclState := make(map[string]*ServiceState)

	var err error
	namespaces := make([]*api.Namespace, 0)

	opts := &api.QueryOptions{Partition: s.Partition}

	if PartitionsEnabled(s.Partition) {
		// if partitions are enabled then list the namespaces.
		namespaces, _, err = s.ConsulClient.Namespaces().List(opts)
		if err != nil {
			return aclState, err
		}
	} else {
		// partitions aren't enabled so just use an empty namespace when listing ACL info.
		namespaces = append(namespaces, &api.Namespace{})
	}

	// list ACL policies and tokens from all namespaces and map them to qualified service name
	for _, ns := range namespaces {
		opts.Namespace = ns.Name

		policyList, _, err := s.ConsulClient.ACL().PolicyList(opts)
		if err != nil {
			return aclState, err
		}

		for _, policy := range policyList {
			if isInCluster(s.Cluster, policy.Description) {
				qname := serviceNameFromDescription(policy.Description)
				if state, ok := aclState[qname]; ok {
					state.ACLPolicies = append(state.ACLPolicies, policy)
				} else {
					aclState[qname] = &ServiceState{ACLPolicies: []*api.ACLPolicyListEntry{policy}}
				}
			}
		}

		tokenList, _, err := s.ConsulClient.ACL().TokenList(opts)
		if err != nil {
			return aclState, err
		}

		for _, token := range tokenList {
			//if isInCluster(s.Cluster, token.Description) && len(token.Policies) == 1 {
			if isInCluster(s.Cluster, token.Description) {
				qname := serviceNameFromDescription(token.Description)
				if state, ok := aclState[qname]; ok {
					state.ACLTokens = append(state.ACLTokens, token)
				} else {
					aclState[qname] = &ServiceState{ACLTokens: []*api.ACLTokenListEntry{token}}
				}
			}
		}
	}

	return aclState, nil
}

// prepareNamespaces ensures that for every service in the cluster the namespace
// exists and the cross-partition/cross-namespace read policy exists.
func (s ServiceStateLister) ReconcileNamespaces(resources []Resource) error {
	if !PartitionsEnabled(s.Partition) {
		return nil
	}

	// create the cross-namespace read policy
	if err := s.upsertCrossNSPolicy(); err != nil {
		return err
	}

	// retrieve the list of unique namespaces from the map of services
	ns := uniqueNamespaces(resources)
	if len(ns) < 2 {
		// only the default namespace exists, so nothing to do
		return nil
	}

	if err := s.createNamespaces(ns); err != nil {
		return err
	}

	return nil
}

// upsertCrossNSPolicy creates the cross-namespace read policy in the local
// partition and default namespace, if it does not already exist.
func (s ServiceStateLister) upsertCrossNSPolicy() error {
	policy, _, err := s.ConsulClient.ACL().PolicyReadByName(
		xnsPolicyName,
		&api.QueryOptions{Partition: s.Partition, Namespace: DefaultNamespace},
	)
	if err != nil && !IsACLNotFoundError(err) {
		return fmt.Errorf("reading cross-namespace policy: %w", err)
	}

	if policy != nil {
		// the policy already exists so return.
		return nil
	}

	// create the policy in the local partition and default namespace.
	_, _, err = s.ConsulClient.ACL().PolicyCreate(&api.ACLPolicy{
		Name:        xnsPolicyName,
		Description: xnsPolicyDesc,
		Partition:   s.Partition,
		Namespace:   DefaultNamespace,
		Rules:       fmt.Sprintf(xnsPolicyTpl, s.Partition),
	}, nil)
	if err != nil {
		return fmt.Errorf("creating cross-namespace policy: %w", err)
	}

	s.Log.Info("created cross-namespace policy", xnsPolicyName)
	return nil
}

// createNamespaces creates each namespace in the list.
// It also attaches the cross-namespace read policy to the namespace so that
// each token created in the namespace inherits that policy.
//
// It does nothing for namespaces that already exist.
func (s ServiceStateLister) createNamespaces(ns []string) error {
	// retrieve the list of existing namespaces
	existingNS, _, err := s.ConsulClient.Namespaces().List(&api.QueryOptions{Partition: s.Partition})
	if err != nil {
		return err
	}

	// create any namespaces that do not already exist
	create := make([]string, 0, len(ns))
	for _, n := range ns {
		for _, e := range existingNS {
			if e.Name != n {
				create = append(create, n)
				break
			}
		}
	}
	failed := make([]string, 0, len(create))
	for _, n := range create {
		s.Log.Info("creating namespace", n)
		_, _, err = s.ConsulClient.Namespaces().Create(&api.Namespace{
			Partition: s.Partition,
			Name:      n,
			ACLs:      &api.NamespaceACLConfig{PolicyDefaults: []api.ACLLink{{Name: xnsPolicyName}}},
		}, nil)
		if err != nil {
			s.Log.Error("creating namespace", n, err)
			failed = append(failed, n)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("namespace creation failed for %s", strings.Join(failed, ","))
	}
	return nil
}

func (s ServiceStateLister) newServiceInfo(serviceName QName, serviceState ServiceState) *ServiceInfo {
	return &ServiceInfo{
		SecretsManagerClient: s.SecretsManagerClient,
		ConsulClient:         s.ConsulClient,
		Cluster:              s.Cluster,
		Log:                  s.Log,
		SecretPrefix:         s.SecretPrefix,
		QName:                serviceName,
		ServiceState:         serviceState,
	}
}

// Task definition ARN looks like this: arn:aws:ecs:us-east-1:1234567890:task-definition/service:1
func (s ServiceStateLister) serviceNameForTask(t *ecs.Task) (QName, error) {
	var partition, namespace string
	if PartitionsEnabled(s.Partition) {
		partition = tagValue(t.Tags, partitionTag)
		namespace = tagValue(t.Tags, namespaceTag)
	}
	if serviceName := tagValue(t.Tags, serviceNameTag); serviceName != "" {
		return NewQName(partition, namespace, serviceName), nil
	}
	taskDefArn := *t.TaskDefinitionArn
	splits := strings.Split(taskDefArn, "/")
	if len(splits) != 2 {
		return QName{}, fmt.Errorf("cannot determine task family from task definition ARN: %q", taskDefArn)
	}
	taskFamilyAndRevision := splits[1]
	splits = strings.Split(taskFamilyAndRevision, ":")
	if len(splits) != 2 {
		return QName{}, fmt.Errorf("cannot determine task family from task definition ARN: %q", taskDefArn)
	}
	return NewQName(partition, namespace, splits[0]), nil
}

// ServiceState contains all of the information needed to determine if an ACL
// token should be created for a Consul service or if an ACL token should be
// deleted.
type ServiceState struct {
	ConsulECSTasks bool
	ACLTokens      []*api.ACLTokenListEntry
	ACLPolicies    []*api.ACLPolicyListEntry
}

type ServiceInfo struct {
	SecretsManagerClient secretsmanageriface.SecretsManagerAPI
	ConsulClient         *api.Client

	Cluster      string
	SecretPrefix string
	QName        QName
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
	if (len(state.ACLTokens) == 0 || len(state.ACLPolicies) == 0) && state.ConsulECSTasks {
		return s.Upsert()
	}

	if !state.ConsulECSTasks && (len(state.ACLTokens) > 0 || len(state.ACLPolicies) > 0) {
		return s.Delete()
	}

	return nil
}

// Upsert creates a service policy and token for the task if one doesn't already exist
// and updates the secret with the contents of the token.
func (s *ServiceInfo) Upsert() error {
	opts := &api.QueryOptions{Partition: s.QName.Partition(), Namespace: s.QName.Namespace()}

	// policy

	currPolicy, _, err := s.ConsulClient.ACL().PolicyReadByName(s.policyName(), opts)
	if err != nil && !IsACLNotFoundError(err) {
		return fmt.Errorf("reading service policy: %w", err)
	}

	// if the policy doesn't already exist, create it.
	if currPolicy == nil {
		if err = s.createServicePolicy(); err != nil {
			return fmt.Errorf("creating service policy: %w", err)
		}
	}

	// token

	currSecret, err := s.upsertSecret()
	if err != nil {
		return fmt.Errorf("upserting secret: %w", err)
	}

	currToken, _, err := s.ConsulClient.ACL().TokenRead(currSecret.AccessorID, opts)

	if err != nil && !IsACLNotFoundError(err) {
		return fmt.Errorf("reading existing token: %w", err)
	}

	// If there is already a token for this service in Consul, exit early.
	if currToken != nil {
		s.Log.Info("token already exists; skipping token creation", "id", s.QName)
		return nil
	}

	// Otherwise, create one.
	if err = s.createServiceToken(currSecret); err != nil {
		return fmt.Errorf("creating service token: %w", err)
	}

	return nil
}

// Delete removes the service policy and token for the given ServiceInfo.
func (s *ServiceInfo) Delete() error {
	opts := &api.WriteOptions{Partition: s.QName.Partition(), Namespace: s.QName.Namespace()}

	for _, token := range s.ServiceState.ACLTokens {
		_, err := s.ConsulClient.ACL().TokenDelete(token.AccessorID, opts)
		if err != nil {
			return fmt.Errorf("deleting token: %w", err)
		}
		s.Log.Info("token deleted successfully", "service", s.QName)
	}

	for _, policy := range s.ServiceState.ACLPolicies {
		_, err := s.ConsulClient.ACL().PolicyDelete(policy.ID, opts)
		if err != nil {
			return fmt.Errorf("deleting policy: %w", err)
		}
		s.Log.Info("policy deleted successfully", "policy", s.policyName())
	}

	return nil
}

// GetNamespace returns the namespace that the service belongs to.
// It returns the empty string if namespaces are not enabled.
func (s *ServiceInfo) GetNamespace() string {
	return s.QName.Namespace()
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

// createServicePolicy
func (s *ServiceInfo) createServicePolicy() error {
	s.Log.Info("creating service policy", "name", s.policyName())
	_, _, err := s.ConsulClient.ACL().PolicyCreate(&api.ACLPolicy{
		Name:        s.policyName(),
		Description: s.aclDescription("Policy"),
		Partition:   s.QName.Partition(),
		Namespace:   s.QName.Namespace(),
		Rules:       s.policy(),
	}, nil)
	if err != nil {
		return fmt.Errorf("creating service policy: %w", err)
	}
	s.Log.Info("created service policy", "name", s.policyName())
	return nil
}

// createServiceToken inserts an ACL token into Consul. The AccessorID and
// SecretID are set based on the AWS secret.
func (s *ServiceInfo) createServiceToken(secret TokenSecretJSON) error {
	s.Log.Info("creating service token", "id", s.QName)
	// Create ACL token for envoy to register the service.
	_, _, err := s.ConsulClient.ACL().TokenCreate(&api.ACLToken{
		AccessorID:  secret.AccessorID,
		SecretID:    secret.Token,
		Description: s.aclDescription("Token"),
		Policies:    []*api.ACLTokenPolicyLink{&api.ACLLink{Name: s.policyName()}},
		Partition:   s.QName.Partition(),
		Namespace:   s.QName.Namespace(),
	}, nil)
	if err != nil {
		return fmt.Errorf("creating ACL token: %s", err)
	}
	s.Log.Info("service token created successfully", "service", s.QName)

	return nil
}

func (s *ServiceInfo) secretName() string {
	if s.QName.Namespace() == "" || s.QName.Namespace() == DefaultNamespace {
		return fmt.Sprintf("%s-%s", s.SecretPrefix, s.QName.Name())
	} else {
		return fmt.Sprintf("%s-%s-%s", s.SecretPrefix, s.QName.Name(), s.QName.Namespace())
	}
}

func (s *ServiceInfo) aclDescription(d string) string {
	return fmt.Sprintf("%s for %s service\n%s: %s", d, s.QName, clusterTag, s.Cluster)
}

func (s *ServiceInfo) policyName() string {
	return fmt.Sprintf("%s-service", s.QName.Name())
}

func (s *ServiceInfo) policy() string {
	if PartitionsEnabled(s.QName.Partition()) {
		return fmt.Sprintf(entServicePolicyTpl, s.QName.Partition(), s.QName.Namespace(), s.QName.Name())
	} else {
		return fmt.Sprintf(ossServicePolicyTpl, s.QName.Name())
	}
}

func isInCluster(clusterName, description string) bool {
	return strings.Contains(description, fmt.Sprintf("%s: %s", clusterTag, clusterName))
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

// serviceNameFromDescription returns the fully qualified service name from the
// description field of a token or policy created by the ACL controller.
func serviceNameFromDescription(d string) string {
	// description is of the form: "<Policy|Token> for <name> service..."
	parts := strings.Split(d, " ")
	if len(parts) > 3 {
		return parts[2]
	}
	return ""
}

// PartitionsEnabled indicates if support for partitions and namespaces is enabled.
func PartitionsEnabled(p string) bool {
	return p != ""
}

// uniqueNamespaces returns the set of unique namespaces from the list of Resources.
func uniqueNamespaces(resources []Resource) []string {
	u := make([]string, 0, len(resources))
	ns := make(map[string]struct{})
	for _, r := range resources {
		n := r.GetNamespace()
		if _, exists := ns[n]; !exists && n != "" {
			ns[n] = struct{}{}
			u = append(u, n)
		}
	}
	return u
}
