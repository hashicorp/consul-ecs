package aclcontroller

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/controller"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

const (
	flagConsulClientSecretARN = "consul-client-secret-arn"
	flagSecretNamePrefix      = "secret-name-prefix"
	flagPartition             = "partition"
	flagPartitionsEnabled     = "partitions-enabled"

	consulCACertEnvVar = "CONSUL_CACERT_PEM"
)

type Command struct {
	UI                        cli.Ui
	flagConsulClientSecretARN string
	flagSecretNamePrefix      string
	flagPartition             string
	flagPartitionsEnabled     bool

	log     hclog.Logger
	flagSet *flag.FlagSet
	once    sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagConsulClientSecretARN, flagConsulClientSecretARN, "", "ARN of AWS Secrets Manager secret for Consul client")
	c.flagSet.StringVar(&c.flagSecretNamePrefix, flagSecretNamePrefix, "", "The prefix for secret names stored in AWS Secrets Manager")
	c.flagSet.StringVar(&c.flagPartition, flagPartition, "default", "The Consul partition name that the ACL controller will use for ACL resources. If not provided will default to the `default` partition [Consul Enterprise]")
	c.flagSet.BoolVar(&c.flagPartitionsEnabled, flagPartitionsEnabled, false, "Enables Consul partitions and namespaces [Consul Enterprise]")

	c.log = hclog.New(nil)
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)
	if err := c.flagSet.Parse(args); err != nil {
		return 1
	}

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
	if c.flagPartitionsEnabled {
		cfg.Partition = c.flagPartition
	}

	consulClient, err := api.NewClient(cfg)
	if err != nil {
		return err
	}

	smClient := secretsmanager.New(clientSession, nil)

	err = c.upsertConsulClientToken(consulClient, smClient)
	if err != nil {
		return err
	}

	serviceStateLister := &controller.ServiceStateLister{
		ECSClient:            ecsClient,
		SecretsManagerClient: smClient,
		ConsulClient:         consulClient,
		Cluster:              cluster,
		SecretPrefix:         c.flagSecretNamePrefix,
		Log:                  c.log,
	}
	ctrl := controller.Controller{
		Resources:       serviceStateLister,
		PollingInterval: controller.DefaultPollingInterval,
		Log:             c.log,
	}

	ctrl.Run(context.Background())

	return nil
}

func (c *Command) Synopsis() string {
	return "ECS ACL controller"
}

func (c *Command) Help() string {
	return ""
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
		currToken, _, err = consulClient.ACL().TokenRead(currSecret.AccessorID, nil)
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
	policy, _, err := consulClient.ACL().PolicyReadByName(policyName, nil)

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
		}, nil)
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
	}, nil)
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
