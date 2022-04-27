package aclcontroller

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/controller"
	"github.com/hashicorp/consul-ecs/logging"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

const (
	flagIAMRolePath           = "iam-role-path"
	flagConsulClientSecretARN = "consul-client-secret-arn"
	flagSecretNamePrefix      = "secret-name-prefix"
	flagPartition             = "partition"
	flagPartitionsEnabled     = "partitions-enabled"

	consulCACertEnvVar = "CONSUL_CACERT_PEM"

	// Binding rules don't support a '/' character, so we need compatible IAM role
	// tag names for the auth method until we can address this in Consul.
	authMethodServiceNameTag = "consul.hashicorp.com.service-name"
	authMethodNamespaceTag   = "consul.hashicorp.com.namespace"
)

type Command struct {
	UI                        cli.Ui
	flagIAMRolePath           string
	flagConsulClientSecretARN string
	flagSecretNamePrefix      string
	flagPartition             string
	flagPartitionsEnabled     bool

	log     hclog.Logger
	flagSet *flag.FlagSet
	once    sync.Once
	ctx     context.Context

	logging.LogOpts
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagIAMRolePath, flagIAMRolePath, "", "IAM roles at this path will be trusted by the IAM Auth method created by the controller")
	c.flagSet.StringVar(&c.flagConsulClientSecretARN, flagConsulClientSecretARN, "", "ARN of AWS Secrets Manager secret for Consul client")
	c.flagSet.StringVar(&c.flagSecretNamePrefix, flagSecretNamePrefix, "", "The prefix for secret names stored in AWS Secrets Manager")
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
	cluster := ecsMeta.Cluster
	c.log.Info("cluster name determined", "cluster", cluster)

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
	smClient := secretsmanager.New(clientSession, nil)

	if c.flagIAMRolePath != "" {
		if err := c.upsertConsulResources(consulClient, ecsMeta); err != nil {
			return err
		}
	} else {
		// TODO: Remove this old behavior once fully switched to the auth method.
		if c.flagPartitionsEnabled {
			if c.flagPartition == "" {
				// if an explicit partition was not provided use the default partition.
				c.flagPartition = controller.DefaultPartition
			}
			if err = c.upsertPartition(consulClient); err != nil {
				return err
			}
		} else if c.flagPartition != "" {
			return fmt.Errorf("partition flag provided without partitions-enabled flag")
		}

		err = c.upsertConsulClientToken(consulClient, smClient)
		if err != nil {
			return err
		}
	}

	serviceStateLister := &controller.ServiceStateLister{
		ECSClient:            ecsClient,
		SecretsManagerClient: smClient,
		ConsulClient:         consulClient,
		Cluster:              cluster,
		SecretPrefix:         c.flagSecretNamePrefix,
		Partition:            c.flagPartition,
		Log:                  c.log,
	}
	ctrl := controller.Controller{
		Resources:       serviceStateLister,
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

var ossClientPolicy = `node_prefix "" { policy = "write" } service_prefix "" { policy = "read" }`
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

func (c *Command) upsertAuthMethod(consulClient *api.Client, authMethod *api.ACLAuthMethod) error {

	method, _, err := consulClient.ACL().AuthMethodRead(authMethod.Name, c.queryOptions())
	if err != nil && !controller.IsACLNotFoundError(err) {
		return fmt.Errorf("reading ACL auth method: %w", err)
	} else if err == nil && method != nil { // returns err=nil and method=nil if not found
		c.log.Info("ACL auth method already exists; skipping creation", "name", authMethod.Name)
		return nil
	}

	c.log.Info("creating ACL auth method", "name", authMethod.Name)
	method, _, err = consulClient.ACL().AuthMethodCreate(authMethod, c.writeOptions())
	if err != nil {
		return fmt.Errorf("creating ACL auth method: %w", err)
	}
	c.log.Info("ACL auth method created successfully", "name", method.Name)

	return nil
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

// upsertConsulClientToken creates or updates ACL policy and token for the Consul client in Consul.
// It then saves the created token in AWS Secrets Manager in the secret provided by secretARN from the Command.
func (c *Command) upsertConsulClientToken(consulClient *api.Client, smClient secretsmanageriface.SecretsManagerAPI) error {
	// Read the secret from AWS.
	currSecretValue, err := smClient.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(c.flagConsulClientSecretARN),
	})
	if err != nil {
		return fmt.Errorf("retrieving Consul client secret: %w", err)
	}

	// Unmarshal the secret value JSON.
	var currSecret controller.TokenSecretJSON
	err = json.Unmarshal([]byte(*currSecretValue.SecretString), &currSecret)
	if err != nil {
		return fmt.Errorf("unmarshalling Consul client secret value JSON: %w", err)
	}

	var currToken *api.ACLToken

	// If the secret is not empty, check if Consul already has a token with this AccessorID.
	if currSecret.AccessorID != "" {
		currToken, _, err = consulClient.ACL().TokenRead(currSecret.AccessorID, c.queryOptions())
		if err != nil && !controller.IsACLNotFoundError(err) {
			return fmt.Errorf("reading token: %w", err)
		}
	}

	// Exit if current token is found in Consul.
	if currToken != nil {
		return nil
	}
	// Otherwise, we need to create one.
	// First, we need to check if the policy for the Consul client already exists.
	// If it does, we will skip policy creation.
	policyName := fmt.Sprintf("%s-consul-client-policy", c.flagSecretNamePrefix)
	policy, _, err := consulClient.ACL().PolicyReadByName(policyName, c.queryOptions())

	// When policy is not found, Consul returns ACL not found error.
	if controller.IsACLNotFoundError(err) {
		// Create a policy for the Consul clients.
		c.log.Info("creating ACL policy", "name", policyName)

		rules := ossClientPolicy
		if c.flagPartitionsEnabled {
			// If partitions are enabled then create a policy that supports partitions
			rules = fmt.Sprintf(partitionedClientPolicyTpl, c.flagPartition)
		}
		policy, _, err = consulClient.ACL().PolicyCreate(&api.ACLPolicy{
			Name:        policyName,
			Description: "Consul Client Token Policy for ECS",
			Rules:       rules,
		}, c.writeOptions())
		if err != nil {
			return fmt.Errorf("creating Consul client ACL policy: %w", err)
		}
		c.log.Info("ACL policy created successfully", "name", policyName)
	} else if err != nil {
		return fmt.Errorf("reading Consul client ACL policy: %w", err)
	} else {
		c.log.Info("ACL policy already exists; skipping policy creation", "name", policyName)
	}

	c.log.Info("creating Consul client ACL token")
	token, _, err := consulClient.ACL().TokenCreate(&api.ACLToken{
		Description: "ECS Consul client Token",
		Policies:    []*api.ACLTokenPolicyLink{{Name: policy.Name}},
	}, c.writeOptions())
	if err != nil {
		return fmt.Errorf("creating Consul client ACL token: %w", err)
	}
	c.log.Info("Consul client ACL token created successfully")

	clientSecret, err := json.Marshal(controller.TokenSecretJSON{Token: token.SecretID, AccessorID: token.AccessorID})
	if err != nil {
		return fmt.Errorf("marshalling Consul client token: %w", err)
	}

	// Finally, update the AWS Secret with the new values of the token.
	c.log.Info("updating secret", "arn", c.flagConsulClientSecretARN)
	_, err = smClient.UpdateSecret(&secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(c.flagConsulClientSecretARN),
		SecretString: aws.String(string(clientSecret)),
	})
	if err != nil {
		return fmt.Errorf("updating secret: %s", err)
	}
	c.log.Info("secret updated successfully", "arn", c.flagConsulClientSecretARN)
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
