package controller

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
	flagAgentSecretARN   = "agent-secret-arn"
	flagSecretNamePrefix = "secret-name-prefix"

	consulCACertEnvVar = "CONSUL_CACERT_PEM"
)

type Command struct {
	UI                   cli.Ui
	flagAgentSecretARN   string
	flagSecretNamePrefix string

	log     hclog.Logger
	flagSet *flag.FlagSet
	once    sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagAgentSecretARN, flagAgentSecretARN, "", "ARN of AWS Secrets Manager secret")
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

	err = controller.UpsertConsulClientToken(consulClient, smClient, c.flagAgentSecretARN, c.flagSecretNamePrefix, c.log)
	if err != nil {
		return err
	}

	taskTokens := &controller.TaskLister{
		ECSClient:            ecsClient,
		SecretsManagerClient: smClient,
		ConsulClient:         consulClient,
		Cluster:              cluster,
		SecretPrefix:         c.flagSecretNamePrefix,
		Log:                  c.log,
	}
	ctrl := controller.Controller{
		Resources:       taskTokens,
		PollingInterval: controller.DefaultPollingInterval,
		Log:             c.log,
	}

	ctrl.Run(context.Background())

	return nil
}

func (c *Command) Synopsis() string {
	return "ECS controller"
}

func (c *Command) Help() string {
	return ""
}
