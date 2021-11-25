package aclcontroller

import (
	"context"
	"flag"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/controller"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

const (
	flagConsulClientSecretARN = "consul-client-secret-arn"
	flagSecretNamePrefix      = "secret-name-prefix"

	consulCACertEnvVar = "CONSUL_CACERT_PEM"
)

type Command struct {
	UI                        cli.Ui
	flagConsulClientSecretARN string
	flagSecretNamePrefix      string

	log     hclog.Logger
	flagSet *flag.FlagSet
	once    sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagConsulClientSecretARN, flagConsulClientSecretARN, "", "ARN of AWS Secrets Manager secret for Consul client")
	c.flagSet.StringVar(&c.flagSecretNamePrefix, flagSecretNamePrefix, "", "The prefix for secret names stored in AWS Secrets Manager")

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

	consulClient, err := api.NewClient(cfg)
	if err != nil {
		return err
	}

	smClient := secretsmanager.New(clientSession, nil)

	err = controller.UpsertConsulClientToken(consulClient, smClient, c.flagConsulClientSecretARN, c.flagSecretNamePrefix, c.log)
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
		Resources:             serviceStateLister,
		UpsertPollingInterval: controller.DefaultUpsertPollingInterval,
		DeletePollingInterval: controller.DefaultDeletePollingInterval,
		Log:                   c.log,
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
