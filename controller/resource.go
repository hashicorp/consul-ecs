// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controller

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
)

// Tag definitions
const (
	meshTag = "consul.hashicorp.com/mesh"

	// Included in ACL token description.
	clusterTag = "consul.hashicorp.com/cluster"
	taskIdTag  = "consul.hashicorp.com/task-id"

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

type TaskID string

// ResourceLister is an interface for listing Resources.
type ResourceLister interface {
	// List all Resources.
	List() ([]Resource, error)

	// ReconcileNamespaces ensures that all requisite namespaces exist.
	ReconcileNamespaces([]Resource) error
}

// Resource is a generic type that needs to be reconciled by the Controller.
type Resource interface {
	// Namespace indicates the namespace that this resource belongs to [Consul Enterprise].
	// It returns the empty string if namespaces are not enabled.
	Namespace() string

	// IsPresent checks if the given resource is found in the response
	// returned by ECS
	IsPresent() bool

	// ID returns the taskID of the resource
	ID() TaskID

	// Reconcile offers functions to reconcile itself with an external state.
	Reconcile() error
}

// TaskStateLister is an implementation of ResourceLister.
type TaskStateLister struct {
	// ECSClient is the AWS ECS client to be used by the ServiceStateLister.
	ECSClient ecsiface.ECSAPI

	// SetupConsulClientFn sets up a consul client on demand.
	SetupConsulClientFn func() (*api.Client, error)

	// ClusterARN is the name or the ARN of the ECS cluster.
	ClusterARN string

	// Partition is the partition that is used by the ServiceStateLister [Consul Enterprise].
	// If partition and namespace support are not enabled then this is set to the empty string.
	Partition string

	// Log is the logger for the ServiceStateLister.
	Log hclog.Logger
}

// List returns resources to be reconciled.
// - Namespaces which may need to be created
// - Tokens which may need to be cleaned up
func (s TaskStateLister) List() ([]Resource, error) {
	var resources []Resource

	consulClient, err := s.SetupConsulClientFn()
	if err != nil {
		return nil, err
	}

	buildingResources, err := s.fetchECSTasks()
	if err != nil {
		return nil, err
	}

	aclState, err := s.fetchACLState(consulClient)
	if err != nil {
		return resources, err
	}

	for id, state := range aclState {
		if _, ok := buildingResources[id]; !ok {
			buildingResources[id] = state
		} else {
			buildingResources[id].ACLTokens = append(buildingResources[id].ACLTokens, state.ACLTokens...)
		}
	}

	serviceState, err := s.fetchServiceStateForTasks(consulClient)
	if err != nil {
		return resources, err
	}

	for id, state := range serviceState {
		if _, ok := buildingResources[id]; !ok {
			buildingResources[id] = state
		} else {
			buildingResources[id].Service = state.Service
		}
	}

	for _, resource := range buildingResources {
		resources = append(resources, resource)
	}

	return resources, nil
}

// fetchECSTasks retrieves all of the ECS tasks that are managed by consul-ecs
// for the current cluster (s.ClusterARN) and returns a set of tasks found. Tasks which are not
// tagged with the current partition (s.Partition) are ignored.
func (s TaskStateLister) fetchECSTasks() (map[TaskID]*TaskState, error) {
	resources := make(map[TaskID]*TaskState)

	// nextToken is to handle paginated responses from AWS.
	var nextToken *string

	// This isn't an infinite loop, instead this is a "do while" loop
	// because we'll break out of it as soon as nextToken is nil.
	for {
		taskListOutput, err := s.ECSClient.ListTasks(&ecs.ListTasksInput{
			Cluster:   aws.String(s.ClusterARN),
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing tasks: %w", err)
		}
		nextToken = taskListOutput.NextToken

		tasks, err := s.ECSClient.DescribeTasks(&ecs.DescribeTasksInput{
			Cluster: aws.String(s.ClusterARN),
			Tasks:   taskListOutput.TaskArns,
			Include: []*string{aws.String("TAGS")},
		})
		if err != nil {
			return nil, fmt.Errorf("describing tasks: %w", err)
		}
		for _, task := range tasks.Tasks {
			if task == nil {
				s.Log.Warn("task is nil")
				continue
			}

			if !isMeshTask(task) {
				s.Log.Debug("skipping non-mesh task", "task-arn", *task.TaskArn)
				continue
			}

			state, err := s.taskStateFromTask(task)
			if err != nil {
				s.Log.Error("skipping task", "task-arn", *task.TaskArn, "tags", task.Tags, "err", err)
				continue
			}

			if state.Partition != s.Partition {
				s.Log.Debug("skipping task in external partition", "partition", state.Partition, "task-arn", *task.TaskArn)
				continue
			}

			resources[state.TaskID] = state
		}
		if nextToken == nil {
			break
		}
	}
	return resources, nil
}

// fetchACLState retrieves all of the ACL tokens from Consul (in this partition)
// and returns a mapping from task id to the ACL tokens created by the task.
func (s TaskStateLister) fetchACLState(consulClient *api.Client) (map[TaskID]*TaskState, error) {
	aclState := make(map[TaskID]*TaskState)

	var err error
	var namespaces []*api.Namespace

	opts := &api.QueryOptions{Partition: s.Partition}
	if partitionsEnabled(s.Partition) {
		// if partitions are enabled then list the namespaces.
		namespaces, _, err = consulClient.Namespaces().List(opts)
		if err != nil {
			return nil, err
		}
	} else {
		// partitions aren't enabled so just use an empty namespace when listing ACL info.
		// when an empty namespace is used, Consul defaults to the `default` namespace.
		namespaces = append(namespaces, &api.Namespace{})
	}

	// list tokens from all namespaces and map them by task id
	for _, ns := range namespaces {
		opts.Namespace = ns.Name

		tokenList, _, err := consulClient.ACL().TokenList(opts)
		if err != nil {
			return nil, err
		}

		for _, token := range tokenList {
			state, err := s.taskStateFromToken(token)
			if err != nil {
				s.Log.Debug("ignoring token", "token", token.AccessorID, "description", token.Description, "err", err)
				continue
			}
			if s.ClusterARN != state.ClusterARN {
				continue
			}
			if found, ok := aclState[state.TaskID]; ok {
				found.ACLTokens = append(found.ACLTokens, token)
			} else {
				aclState[state.TaskID] = state
			}

		}
	}

	return aclState, nil
}

func (s TaskStateLister) fetchServiceStateForTasks(consulClient *api.Client) (map[TaskID]*TaskState, error) {
	opts := &api.QueryOptions{Partition: s.Partition}
	if s.Partition != "" {
		opts.Namespace = "*" // wildcard to fetch services from all namespaces
	}
	services, _, err := consulClient.Catalog().NodeServiceList(s.ClusterARN, opts)
	if err != nil {
		return nil, fmt.Errorf("fetching list of services for the given node %s: %w", s.ClusterARN, err)
	}

	var result error
	serviceState := make(map[TaskID]*TaskState)
	for _, service := range services.Services {
		taskID, err := getTaskIDFromServiceMeta(service)
		if err != nil {
			s.Log.Error(err.Error())
			result = multierror.Append(result, err)
			continue
		}

		state := s.newTaskState(taskID, s.ClusterARN)
		state.Service = service
		serviceState[taskID] = state
	}

	return serviceState, result
}

// ReconcileNamespaces ensures that for every service in the cluster the namespace
// exists and the cross-partition/cross-namespace read policy exists.
func (s TaskStateLister) ReconcileNamespaces(resources []Resource) error {
	if !partitionsEnabled(s.Partition) {
		return nil
	}

	consulClient, err := s.SetupConsulClientFn()
	if err != nil {
		return err
	}

	// create the cross-namespace read policy
	if err := s.upsertCrossNSPolicy(consulClient); err != nil {
		return err
	}

	// create namespaces that do not exist
	if err := s.createNamespaces(consulClient, resources); err != nil {
		return err
	}

	return nil
}

// upsertCrossNSPolicy creates the cross-namespace read policy in the local
// partition and default namespace, if it does not already exist.
func (s TaskStateLister) upsertCrossNSPolicy(consulClient *api.Client) error {
	policy, _, err := consulClient.ACL().PolicyReadByName(
		xnsPolicyName,
		&api.QueryOptions{Partition: s.Partition, Namespace: DefaultNamespace},
	)
	if err != nil && !IsACLNotFoundError(err) {
		return fmt.Errorf("reading cross-namespace policy: %w", err)
	}

	if policy == nil {
		// create the policy in the local partition and default namespace.
		_, _, err = consulClient.ACL().PolicyCreate(&api.ACLPolicy{
			Name:        xnsPolicyName,
			Description: xnsPolicyDesc,
			Partition:   s.Partition,
			Namespace:   DefaultNamespace,
			Rules:       fmt.Sprintf(xnsPolicyTpl, s.Partition),
		}, nil)
		if err != nil {
			return fmt.Errorf("creating cross-namespace policy: %w", err)
		}
		s.Log.Info("created cross-namespace policy", "name", xnsPolicyName)
	}

	// update the default namespace with the cross-namespace policy, if necessary
	ns, _, err := consulClient.Namespaces().Read(
		DefaultNamespace, &api.QueryOptions{Partition: s.Partition},
	)
	if err != nil {
		return fmt.Errorf("fetching default namespace: %w", err)
	}

	// check if the namespace already has the cross-ns policy
	if ns.ACLs == nil {
		ns.ACLs = &api.NamespaceACLConfig{}
	}
	for _, link := range ns.ACLs.PolicyDefaults {
		if link.Name == xnsPolicyName {
			s.Log.Debug("default namespace contains default policy; skipping update", "policy", link.Name)
			return nil
		}
	}

	// update the default namespace with the cross-namespace policy
	ns.ACLs.PolicyDefaults = append(ns.ACLs.PolicyDefaults, api.ACLLink{Name: xnsPolicyName})
	_, _, err = consulClient.Namespaces().Update(
		ns, &api.WriteOptions{Partition: s.Partition},
	)
	if err != nil {
		return fmt.Errorf("updating default namespace with cross-namespace policy: %w", err)
	}
	s.Log.Info("updated default namespace with default policy", "policy", xnsPolicyName)

	return nil
}

// createNamespaces creates namespaces for the Resources in the list.
// It also attaches the cross-namespace read policy to the namespace so that
// each token created in the namespace inherits that policy.
//
// It does nothing for namespaces that already exist.
func (s TaskStateLister) createNamespaces(consulClient *api.Client, resources []Resource) error {

	// create the set of all namespaces in the list of resources.
	ns := make(map[string]struct{})
	for _, r := range resources {
		// Ignore empty string namespaces. This is the case for a Resource constructed from an ACL
		// token, since tokens should not affect namespace creation.
		if name := r.Namespace(); name != "" {
			ns[name] = struct{}{}
		}
	}

	// retrieve the list of existing namespaces
	existingNS, _, err := consulClient.Namespaces().List(&api.QueryOptions{Partition: s.Partition})
	if err != nil {
		return err
	}

	// prune the set of namespaces down to the set that needs to be created
	for _, n := range existingNS {
		delete(ns, n.Name)
	}

	// create the namespaces that do not exist
	var result error
	for n := range ns {
		s.Log.Info("creating namespace", "name", n)
		_, _, err = consulClient.Namespaces().Create(&api.Namespace{
			Name: n,
			ACLs: &api.NamespaceACLConfig{PolicyDefaults: []api.ACLLink{{Name: xnsPolicyName}}},
		}, &api.WriteOptions{Partition: s.Partition})
		if err != nil {
			s.Log.Error("failed to create namespace", "name", n)
			result = multierror.Append(result, err)
		}
	}
	return result
}

func (s TaskStateLister) newTaskState(taskId TaskID, clusterArn string) *TaskState {
	return &TaskState{
		SetupConsulClientFn: s.SetupConsulClientFn,
		Log:                 s.Log,
		TaskID:              taskId,
		ClusterARN:          clusterArn,
	}
}

func (s TaskStateLister) taskStateFromTask(t *ecs.Task) (*TaskState, error) {
	var partition, namespace string
	if partitionsEnabled(s.Partition) {
		partition = tagValue(t.Tags, partitionTag)
		namespace = tagValue(t.Tags, namespaceTag)
		if partition == "" && namespace == "" {
			// if the partition and namespace tags are both missing then use the Consul enterprise defaults
			partition = DefaultPartition
			namespace = DefaultNamespace
		} else if (partition == "" && namespace != "") || (partition != "" && namespace == "") {
			// both partition and namespace tags must be provided
			return nil, fmt.Errorf("task definition requires both partition and namespace tags")
		}
	}
	taskId := awsutil.ParseTaskID(*t.TaskArn)
	if taskId == "" {
		return nil, fmt.Errorf("cannot determine task id from task arn")
	}

	ts := s.newTaskState(TaskID(taskId), *t.ClusterArn)
	ts.ECSTaskFound = true
	ts.Partition = partition
	ts.NS = namespace
	return ts, nil
}

func (s TaskStateLister) taskStateFromToken(token *api.ACLTokenListEntry) (*TaskState, error) {
	meta, err := parseTokenDescription(token.Description)
	if err != nil {
		return nil, err
	}

	ts := s.newTaskState(meta.TaskID, meta.Cluster)
	ts.ACLTokens = []*api.ACLTokenListEntry{token}
	// Do not set the partition or namespace based on the token.
	// We don't create namespaces based on the token, and the token struct
	// includes the partition/namespace if the token needs to be deleted.
	return ts, nil
}

// parseTokenDescription parses a Consul ACL token description.
// This parses "metadata" set by `consul login -meta` which is included
// as a JSON object in the the token description, ex:
//
//	token created via login: {"consul.hashicorp.com/cluster":"my-cluster","consul.hashicorp.com/task-id":"123456"}
func parseTokenDescription(d string) (tokenMeta, error) {
	var meta tokenMeta
	jsonStr := strings.Replace(d, "token created via login:", "", 1)
	err := json.Unmarshal([]byte(jsonStr), &meta)
	if err != nil {
		return tokenMeta{}, err
	}
	if meta.TaskID == "" || meta.Cluster == "" {
		return tokenMeta{}, fmt.Errorf("task or cluster missing from token description")
	}
	return meta, nil
}

type tokenMeta struct {
	TaskID  TaskID `json:"consul.hashicorp.com/task-id"`
	Cluster string `json:"consul.hashicorp.com/cluster"`
}

// TaskState contains the information needed to reconcile a task.
type TaskState struct {
	SetupConsulClientFn func() (*api.Client, error)

	// TaskID is the id of the ECS task.
	TaskID TaskID
	// ClusterARN is the ECS cluster.
	ClusterARN string
	// Partition that the task belongs to [Consul Enterprise].
	Partition string
	// Namespace that the task belongs to [Consul Enterprise].
	NS string

	// ECSTaskFound indicates whether an ECS task was found for this task id.
	ECSTaskFound bool
	// ACLTokens are the Consul ACL tokens found for this task id.
	ACLTokens []*api.ACLTokenListEntry
	// Consul Service associated with this ECS task
	Service *api.AgentService

	Log hclog.Logger
}

// Reconcile deletes ACL tokens and removes the service from Catalog
// based on the TaskState.
func (t *TaskState) Reconcile() error {
	if t.IsPresent() {
		return nil
	}

	consulClient, err := t.SetupConsulClientFn()
	if err != nil {
		return err
	}

	var result error
	if len(t.ACLTokens) > 0 {
		err := t.Delete(consulClient)
		if err != nil {
			result = multierror.Append(result, err)
		}
	}

	if t.Service != nil {
		err := t.DeregisterService(consulClient)
		if err != nil {
			result = multierror.Append(result, err)
		}
	}

	return result
}

func (t *TaskState) IsPresent() bool {
	return t.ECSTaskFound
}

// Delete removes the service token for the given ServiceInfo.
func (t *TaskState) Delete(consulClient *api.Client) error {
	for _, token := range t.ACLTokens {
		opts := &api.WriteOptions{Partition: token.Partition, Namespace: token.Namespace}
		_, err := consulClient.ACL().TokenDelete(token.AccessorID, opts)
		if err != nil {
			return fmt.Errorf("deleting token: %w", err)
		}
		t.Log.Info("token deleted successfully", "token", token.Description)
	}
	return nil
}

// DeregisterService removes the service from the Consul catalog
func (t *TaskState) DeregisterService(consulClient *api.Client) error {
	opts := &api.WriteOptions{Partition: t.Partition, Namespace: t.Service.Namespace}
	deregInput := &api.CatalogDeregistration{
		Node:      t.ClusterARN,
		ServiceID: t.Service.ID,
		Partition: t.Partition,
		Namespace: t.Service.Namespace,
	}

	_, err := consulClient.Catalog().Deregister(deregInput, opts)
	if err != nil {
		return fmt.Errorf("deregistering service with ID %s: %w", t.Service.ID, err)
	}
	return nil
}

// Namespace returns the namespace that the service belongs to.
// It returns the empty string if namespaces are not enabled.
func (t *TaskState) Namespace() string {
	if t.IsPresent() {
		return t.NS
	}
	return ""
}

// ID returns the taskID of the resource
func (t *TaskState) ID() TaskID {
	return t.TaskID
}

// IsACLNotFoundError returns true if the ACL is not found.
func IsACLNotFoundError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Unexpected response code: 403 (ACL not found)")
}

func getTaskIDFromServiceMeta(service *api.AgentService) (TaskID, error) {
	taskID, ok := service.Meta["task-id"]
	if !ok {
		return "", fmt.Errorf("could not find taskID for the given service %s", service.ID)
	}

	return TaskID(taskID), nil
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

// partitionsEnabled indicates if support for partitions and namespaces is enabled.
func partitionsEnabled(p string) bool {
	return p != ""
}
