package aclcontroller

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"text/template"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/controller"
	"github.com/hashicorp/consul-ecs/logging"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/mapstructure"
)

const (
	flagIAMRolePath       = "iam-role-path"
	flagPartition         = "partition"
	flagPartitionsEnabled = "partitions-enabled"

	consulCACertEnvVar = "CONSUL_CACERT_PEM"

	// Binding rules don't support a '/' character, so we need compatible IAM role tag names.
	authMethodServiceNameTag = "consul.hashicorp.com.service-name"
	authMethodNamespaceTag   = "consul.hashicorp.com.namespace"

	// anonTokenID is the well-known ID for the anonymous ACL token.
	anonTokenID    = "00000000-0000-0000-0000-000000000002"
	anonPolicyName = "anonymous-token-policy"
	anonPolicyDesc = "Anonymous token Policy"
)

type Command struct {
	UI                    cli.Ui
	flagIAMRolePath       string
	flagPartition         string
	flagPartitionsEnabled bool

	log     hclog.Logger
	flagSet *flag.FlagSet
	once    sync.Once
	ctx     context.Context

	logging.LogOpts
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagIAMRolePath, flagIAMRolePath, "", "IAM roles at this path will be trusted by the IAM Auth method created by the controller")
	c.flagSet.StringVar(&c.flagPartition, flagPartition, "", "The Consul partition name that the ACL controller will use for ACL resources. If not provided will default to the `default` partition [Consul Enterprise]")
	c.flagSet.BoolVar(&c.flagPartitionsEnabled, flagPartitionsEnabled, false, "Enables support for Consul partitions and namespaces [Consul Enterprise]")

	logging.Merge(c.flagSet, c.LogOpts.Flags())
	c.ctx = context.Background()
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)

	if err := c.flagSet.Parse(args); err != nil {
		return 1
	}

	c.log = c.LogOpts.Logger()

	err := c.run()
	if err != nil {
		c.log.Error(err.Error())
		return 1
	}
	return 0
}

func (c *Command) run() error {
	ecsMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		return err
	}
	clusterArn, err := ecsMeta.ClusterARN()
	if err != nil {
		return err
	}
	c.log.Info("cluster arn determined", "cluster-arn", clusterArn)

	clientSession, err := awsutil.NewSession(ecsMeta, "controller")
	if err != nil {
		return err
	}

	// Set up ECS client.
	ecsClient := ecs.New(clientSession)

	cfg := api.DefaultConfig()
	if caCert := os.Getenv(consulCACertEnvVar); caCert != "" {
		cfg.TLSConfig = api.TLSConfig{
			CAPem: []byte(caCert),
		}
	}

	consulClient, err := api.NewClient(cfg)
	if err != nil {
		return err
	}

	if err := c.upsertConsulResources(consulClient, ecsMeta); err != nil {
		return err
	}

	taskStateLister := &controller.TaskStateLister{
		ECSClient:    ecsClient,
		ConsulClient: consulClient,
		ClusterARN:   clusterArn,
		Partition:    c.flagPartition,
		Log:          c.log,
	}
	ctrl := controller.Controller{
		Resources:       taskStateLister,
		PollingInterval: controller.DefaultPollingInterval,
		Log:             c.log,
	}

	ctrl.Run(c.ctx)

	return nil
}

func (c *Command) Synopsis() string {
	return "ECS ACL controller"
}

func (c *Command) Help() string {
	return ""
}

// upsertConsulResources creates the necessary resources in Consul if they do not exist.
// This includes the partition, client role and policy, client and service token auth methods,
// and the necessary binding rules.
// If mesh federation via mesh gateways is enabled the anonymous token will be updated with the
// necessary read permissions.
func (c *Command) upsertConsulResources(consulClient *api.Client, ecsMeta awsutil.ECSTaskMeta) error {
	account, err := ecsMeta.AccountID()
	if err != nil {
		return err
	}
	path := strings.Trim(c.flagIAMRolePath, "/")
	if path != "" {
		path += "/"
	}
	boundArnPattern := fmt.Sprintf("arn:aws:iam::%s:role/%s*", account, path)

	clientAuthMethod := &api.ACLAuthMethod{
		Name:        "iam-ecs-client-token",
		Type:        "aws-iam",
		Description: "AWS IAM auth method for ECS client tokens",
		Config: map[string]interface{}{
			// Trust a wildcard - any roles at a path.
			"BoundIAMPrincipalARNs": []string{boundArnPattern},
			// Must be true to use a wildcard
			"EnableIAMEntityDetails": true,
		},
	}
	serviceAuthMethod := &api.ACLAuthMethod{
		Name:        "iam-ecs-service-token",
		Type:        "aws-iam",
		Description: "AWS IAM auth method for ECS service tokens",
		Config: map[string]interface{}{
			// Trust a wildcard - any roles at a path.
			"BoundIAMPrincipalARNs": []string{boundArnPattern},
			// Must be true to use wildcard and tags
			"EnableIAMEntityDetails": true,
			"IAMEntityTags": []string{
				authMethodServiceNameTag,
				authMethodNamespaceTag,
			},
		},
	}
	if c.flagPartitionsEnabled {
		serviceAuthMethod.NamespaceRules = append(serviceAuthMethod.NamespaceRules,
			&api.ACLAuthMethodNamespaceRule{
				Selector:      fmt.Sprintf(`entity_tags["%s"] != ""`, authMethodNamespaceTag),
				BindNamespace: fmt.Sprintf(`${entity_tags.%s}`, authMethodNamespaceTag),
			},
		)
	}

	roleName := "consul-ecs-client-role"
	policyName := "consul-ecs-client-policy"
	clientBindingRule := &api.ACLBindingRule{
		Description: "Bind a policy for Consul clients on ECS",
		AuthMethod:  clientAuthMethod.Name,
		BindType:    api.BindingRuleBindTypeRole,
		BindName:    roleName,
	}

	serviceBindingRule := &api.ACLBindingRule{
		Description: "Bind a service identity from IAM role tag for ECS",
		AuthMethod:  serviceAuthMethod.Name,
		BindType:    api.BindingRuleBindTypeService,
		BindName:    fmt.Sprintf(`${entity_tags.%s}`, authMethodServiceNameTag),
	}

	agentSelf, err := consulClient.Agent().Self()
	if err != nil {
		return fmt.Errorf("failed to get Consul agent self config: %w", err)
	}
	var agentConfig AgentConfig
	err = mapstructure.Decode(agentSelf, &agentConfig)
	if err != nil {
		return fmt.Errorf("failed to decode Consul agent self config: %w", err)
	}

	if c.flagPartitionsEnabled {
		if c.flagPartition == "" {
			// if an explicit partition was not provided use the default partition.
			c.flagPartition = controller.DefaultPartition
		}
		if err := c.upsertPartition(consulClient); err != nil {
			return err
		}
	} else if c.flagPartition != "" {
		return fmt.Errorf("partition flag provided without partitions-enabled flag")
	}

	if err := c.upsertConsulClientRole(consulClient, roleName, policyName); err != nil {
		return err
	}
	if err := c.upsertAuthMethod(consulClient, clientAuthMethod); err != nil {
		return err
	}
	if err := c.upsertAuthMethod(consulClient, serviceAuthMethod); err != nil {
		return err
	}
	if err := c.upsertBindingRule(consulClient, clientBindingRule); err != nil {
		return err
	}
	if err := c.upsertBindingRule(consulClient, serviceBindingRule); err != nil {
		return err
	}
	if err := c.upsertAnonymousTokenPolicy(consulClient, agentConfig); err != nil {
		return err
	}
	return nil
}

// upsertPartition ensures the partition that the controller is managing
// exists when partition use is enabled. If the partition does not exist
// it is created. If the partition already exists or partition management
// is not enabled then this function does nothing and returns.
// A non-nil error is returned if the operation fails.
func (c *Command) upsertPartition(consulClient *api.Client) error {
	// check if the partition already exists.
	partitions, _, err := consulClient.Partitions().List(c.ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to list partitions: %s", err)
	}
	for _, p := range partitions {
		if p.Name == c.flagPartition {
			c.log.Info("found existing partition", "partition", p.Name)
			return nil
		}
	}
	// the partition doesn't exist, so create it.
	_, _, err = consulClient.Partitions().Create(c.ctx, &api.Partition{Name: c.flagPartition}, nil)
	if err != nil {
		return fmt.Errorf("failed to create partition %s: %s", c.flagPartition, err)
	}
	c.log.Info("created partition", "partition", c.flagPartition)
	return nil
}

var ossClientPolicy = `
node_prefix "" { policy = "write" }
service_prefix "" { policy = "read" }
mesh  = "write"
`

var partitionedClientPolicyTpl = `partition "%s" {
  node_prefix "" {
    policy = "write"
  }
  namespace_prefix "" {
    service_prefix "" {
      policy = "read"
    }
  }
}`

// upsertConsulClientRole creates or updates the Consul ACL role for the client token.
func (c *Command) upsertConsulClientRole(consulClient *api.Client, roleName, policyName string) error {
	if err := c.upsertClientPolicy(consulClient, policyName); err != nil {
		return err
	}
	if err := c.upsertClientRole(consulClient, roleName, policyName); err != nil {
		return err
	}
	return nil
}

// upsertClientPolicy creates the ACL policy for the Consul client, if the policy does not exist.
func (c *Command) upsertClientPolicy(consulClient *api.Client, policyName string) error {
	// If the policy already exists, we're done.
	_, _, err := consulClient.ACL().PolicyReadByName(policyName, c.queryOptions())
	if err != nil && !controller.IsACLNotFoundError(err) {
		return fmt.Errorf("reading Consul client ACL policy: %w", err)
	} else if err == nil {
		c.log.Info("ACL policy already exists; skipping policy creation", "name", policyName)
		return nil
	}

	// Otherwise, the policy is not found, so create it.
	c.log.Info("creating ACL policy", "name", policyName)
	rules := ossClientPolicy
	if c.flagPartitionsEnabled {
		// If partitions are enabled then create a policy that supports partitions
		rules = fmt.Sprintf(partitionedClientPolicyTpl, c.flagPartition)
	}
	_, _, err = consulClient.ACL().PolicyCreate(&api.ACLPolicy{
		Name:        policyName,
		Description: "Consul Client Token Policy for ECS",
		Rules:       rules,
	}, c.writeOptions())
	if err != nil {
		return fmt.Errorf("creating Consul client ACL policy: %w", err)
	}
	c.log.Info("ACL policy created successfully", "name", policyName)
	return nil
}

// upsertClientRole creates the ACL role for the Consul client, if the role does not exist.
func (c *Command) upsertClientRole(consulClient *api.Client, roleName, policyName string) error {
	// If the role already exists, we're done.
	role, _, err := consulClient.ACL().RoleReadByName(roleName, c.queryOptions())
	if err != nil && !controller.IsACLNotFoundError(err) {
		return fmt.Errorf("reading Consul client ACL role: %w", err)
	} else if err == nil && role != nil { // returns role=nil and err=nil if not found
		c.log.Info("ACL role already exists; skipping role creation", "name", roleName)

		if len(role.Policies) == 0 {
			c.log.Info("updating ACL role with policy", "role", roleName, "policy", policyName)
			role.Policies = []*api.ACLLink{{Name: policyName}}
			_, _, err := consulClient.ACL().RoleUpdate(role, c.writeOptions())
			if err != nil {
				return fmt.Errorf("updating Consul client ACL role: %s", err)
			}
			c.log.Info("update ACL role successfully", "name", roleName)
		}
		return nil
	}

	c.log.Info("creating ACL role", "name", roleName)
	_, _, err = consulClient.ACL().RoleCreate(&api.ACLRole{
		Name:        roleName,
		Description: "Consul Client Token Role for ECS",
		Policies: []*api.ACLLink{
			{
				Name: policyName,
			},
		},
	}, c.writeOptions())
	if err != nil {
		return fmt.Errorf("creating Consul client ACL role: %w", err)
	}
	c.log.Info("ACL role created successfully", "name", roleName)

	return nil
}

// upsertAuthMethod will create the auth method if it does not already exist. If the auth method
// already exists, it will merge the two lists of BoundIAMPrincipalARNs and update the auth method
// if necessary.
//
// Note: there is a race if two controllers do a simultaneous read-write of the auth method. This
// should be rare, so there's no mitigation against this for now.
func (c *Command) upsertAuthMethod(consulClient *api.Client, authMethod *api.ACLAuthMethod) error {
	method, _, err := consulClient.ACL().AuthMethodRead(authMethod.Name, c.queryOptions())
	if err != nil && !controller.IsACLNotFoundError(err) {
		return fmt.Errorf("reading ACL auth method: %w", err)
	} else if err == nil && method != nil { // returns err=nil and method=nil if not found

		// note: `method.Config` is a map of interface{} values. The BoundIAMPrincipalARNs is always a slice of
		//       strings, but could be either []interface{} or []string. We convert to []string to merge the
		//       two slices together. forceStringSlice will ignore any non-string values in those slices (not
		//       that we should run into that, but with a warning if we ever encounter that).
		currentPrincipals, err := forceStringSlice(method.Config["BoundIAMPrincipalARNs"])
		if err != nil {
			c.log.Warn("incorrect type for BoundIAMPrincipalARNs", "auth-method", method.Name, "msg", err.Error())
		}

		ourPrincipals, err := forceStringSlice(authMethod.Config["BoundIAMPrincipalARNs"])
		if err != nil {
			c.log.Warn("incorrect type for BoundIAMPrincipalARNs", "auth-method", method.Name, "msg", err.Error())
		}

		// Merge current principals with possibly new/other principals, and dedupe.
		principals := uniqueStrings(append(currentPrincipals, ourPrincipals...))

		if reflect.DeepEqual(principals, currentPrincipals) {
			c.log.Info("ACL auth method already exists; skipping upsert", "name", authMethod.Name)
			return nil
		}

		c.log.Info("ACL auth method exists; updating BoundIAMPrincipalARNs",
			"name", authMethod.Name, "current-arns", fmt.Sprint(currentPrincipals), "our-arns", fmt.Sprint(principals))
		authMethod.Config["BoundIAMPrincipalARNs"] = principals

		method, _, err = consulClient.ACL().AuthMethodUpdate(authMethod, c.writeOptions())
		if err != nil {
			return fmt.Errorf("updating ACL auth method: %w", err)
		}
		c.log.Info("ACL auth method updated successfully", "name", method.Name)
	} else {
		c.log.Info("creating ACL auth method", "name", authMethod.Name)
		method, _, err = consulClient.ACL().AuthMethodCreate(authMethod, c.writeOptions())
		if err != nil {
			return fmt.Errorf("creating ACL auth method: %w", err)
		}
		c.log.Info("ACL auth method created successfully", "name", method.Name)
	}
	return nil
}

func uniqueStrings(strs []string) []string {
	if len(strs) == 0 {
		return nil
	}

	unique := make(map[string]struct{}, len(strs))
	for _, s := range strs {
		unique[s] = struct{}{}
	}

	result := make([]string, 0, len(unique))
	for s := range unique {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

func forceStringSlice(val interface{}) ([]string, error) {
	switch slice := val.(type) {
	case nil:
		return nil, nil
	case []string:
		return slice, nil
	case []interface{}:
		var result []string
		var err error
		for _, arnVal := range slice {
			if arn, ok := arnVal.(string); ok {
				result = append(result, arn)
			} else {
				err = fmt.Errorf("[]interface{} slice contains non-string values")
				// ignore non-string values! this works for our purposes.
				// we don't expect to encounter this case, but still return an error message to detect it.
			}
		}
		return result, err
	}
	return nil, fmt.Errorf("value of type %T is not a []string", val)
}

func (c *Command) upsertBindingRule(consulClient *api.Client, bindingRule *api.ACLBindingRule) error {
	method := bindingRule.AuthMethod

	rules, _, err := consulClient.ACL().BindingRuleList(method, c.queryOptions())
	if err != nil {
		return fmt.Errorf("listing ACL binding rules for auth method %s: %w", method, err)
	}
	if len(rules) > 0 {
		// For now, we just expect at least one binding rule to exist.
		// TODO: Can we create the rule with a client-generated ID?
		c.log.Info("ACL binding rule created successfully", "method", method,
			"bind-type", rules[0].BindType, "bind-name", rules[0].BindName)
		return nil
	}

	rule, _, err := consulClient.ACL().BindingRuleCreate(bindingRule, c.writeOptions())
	if err != nil {
		return fmt.Errorf("create ACL binding rule: %w", err)
	}
	c.log.Info("ACL binding rule created successfully", "method", method,
		"bind-type", rule.BindType, "bind-name", rule.BindName)

	return nil
}

// upsertAnonymousTokenPolicy ensures that the anonymous ACL token has the correct permissions
// to allow cross-DC communication via mesh gateways.
// If the ACL controller is in the primary datacenter then we need to update the anonymous token
// with service:read and node:read.
// Tokens are stripped from cross DC API calls so cross DC API calls use the anonymous
// token. Mesh gateway proxies use the anonymous token to talk cross-DC and they require
// service:read and node:read.
// The anonymous token is global so it is replicated from the primary DC to all secondary
// DCs, which is why we only update it if this is the primary datacenter.
func (c *Command) upsertAnonymousTokenPolicy(consulClient *api.Client, agentConfig AgentConfig) error {
	consulDC, primaryDC, err := c.consulDatacenterList(agentConfig)
	if err != nil {
		return fmt.Errorf("failed to list Consul datacenters: %w", err)
	}

	// Always configure the anonymous token. This is required for mesh-gateway traffic.
	// For simplicity we configure this even if there are no mesh gateways in the datacenter.
	if consulDC != primaryDC {
		return nil
	}

	c.log.Info("Configuring anonymous token", "datacenter", consulDC, "primary-datacenter", primaryDC)

	// This controller may not be running in the default partition.
	// If the default partition is not an ECS cluster (and not a consul-k8s cluster)
	// the anonymous token won't be configured correctly. In order to ensure that,
	// we will always configure the anonymous token in the default partition so that
	// mesh gateways actually work across partitions.
	var qopts *api.QueryOptions
	var wopts *api.WriteOptions
	if c.flagPartitionsEnabled {
		qopts = &api.QueryOptions{
			Namespace: controller.DefaultPartition,
			Partition: controller.DefaultNamespace,
		}
		wopts = &api.WriteOptions{
			Namespace: controller.DefaultPartition,
			Partition: controller.DefaultNamespace,
		}
	}

	// Read the anonymous token. We don't pass query options here because the token is global.
	// The token and policy exist in the default partition and namespace.
	// The accessor ID for the anonymous token is well-known so we don't need to find it.
	token, _, err := consulClient.ACL().TokenRead(anonTokenID, qopts)
	if err != nil {
		return fmt.Errorf("failed to read anonymous token: %w", err)
	}

	// Check to see if the anonymous policy is already attached. If it is then we're done.
	for _, link := range token.Policies {
		if link.Name == anonPolicyName {
			c.log.Info("Anonymous token policy is already attached, skipping token update.")
			return nil
		}
	}

	// Read the policy and create it in the default partition and namespace, if it does not exist.
	policy, _, err := consulClient.ACL().PolicyReadByName(anonPolicyName, qopts)
	if err == nil {
		c.log.Info("Anonymous token policy already exists, skipping policy creation", "name", anonPolicyName)
	} else if err != nil && controller.IsACLNotFoundError(err) {
		// The policy is not found, so create it.
		c.log.Info("creating ACL policy", "name", anonPolicyName)
		rules, err := c.anonymousPolicyRules()
		if err != nil {
			return fmt.Errorf("failed to generate anonymous token policy rules: %w", err)
		}
		policy, _, err = consulClient.ACL().PolicyCreate(&api.ACLPolicy{
			Name:        anonPolicyName,
			Description: anonPolicyDesc,
			Rules:       rules,
		}, wopts)
		if err != nil {
			return fmt.Errorf("failed to create anonymous token policy: %w", err)
		}
		c.log.Info("ACL policy created successfully", "name", anonPolicyName)
	} else {
		return fmt.Errorf("failed to read anonymous token policy: %w", err)
	}

	// Attach the anonymous policy and update the token.
	token.Policies = append(token.Policies, &api.ACLTokenPolicyLink{Name: policy.Name})
	_, _, err = consulClient.ACL().TokenUpdate(token, wopts)
	if err != nil {
		return fmt.Errorf("failed to update anonymous token: %w", err)
	}

	c.log.Info("Successfully configured the anonymous token")
	return nil
}

func (c *Command) queryOptions() *api.QueryOptions {
	if c.flagPartitionsEnabled {
		return &api.QueryOptions{Partition: c.flagPartition}
	}
	return nil
}

func (c *Command) writeOptions() *api.WriteOptions {
	if c.flagPartitionsEnabled {
		return &api.WriteOptions{Partition: c.flagPartition}
	}
	return nil
}

// consulDatacenterList returns the current datacenter name and the primary datacenter using the
// /agent/self API endpoint.
func (c *Command) consulDatacenterList(agentConfig AgentConfig) (string, string, error) {
	if agentConfig.Config.Datacenter == "" {
		return "", "", fmt.Errorf("agent config does not contain Config.Datacenter key: %+v", agentConfig)
	}
	if agentConfig.Config.PrimaryDatacenter == "" && agentConfig.DebugConfig.PrimaryDatacenter == "" {
		return "", "", fmt.Errorf("both Config.PrimaryDatacenter and DebugConfig.PrimaryDatacenter are empty: %+v", agentConfig)
	}
	if agentConfig.Config.PrimaryDatacenter != "" {
		return agentConfig.Config.Datacenter, agentConfig.Config.PrimaryDatacenter, nil
	} else {
		return agentConfig.Config.Datacenter, agentConfig.DebugConfig.PrimaryDatacenter, nil
	}
}

type AgentConfig struct {
	Config      Config
	DebugConfig Config
}

type Config struct {
	Datacenter        string `mapstructure:"Datacenter"`
	PrimaryDatacenter string `mapstructure:"PrimaryDatacenter"`
}

type templateData struct {
	Enterprise bool
}

func (c *Command) templateData() templateData {
	return templateData{Enterprise: c.flagPartitionsEnabled}
}

func (c *Command) anonymousPolicyRules() (string, error) {
	rules := `
{{- if .Enterprise }}
partition_prefix "" {
  namespace_prefix "" {
{{- end }}
    node_prefix "" {
      policy = "read"
    }
    service_prefix "" {
      policy = "read"
    }
{{- if .Enterprise }}
  }
}
{{- end }}
`
	return RenderTemplate(rules, c.templateData())
}

// RenderTemplate parses and executes the template t against the given data source.
func RenderTemplate(t string, data interface{}) (string, error) {
	parsed, err := template.New("root").Parse(strings.TrimSpace(t))
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = parsed.Execute(&buf, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
