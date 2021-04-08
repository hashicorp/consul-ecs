package controller

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

const (
	meshTag                     = "consul.hashicorp.com/mesh"
	flagTLS                     = "tls"
	flagAgentSecretARN          = "agent-secret-arn"
	flagConsulServerServiceName = "consul-server-service-name"
	aclTokenEnvVar              = "CONSUL_HTTP_TOKEN"
)

type Command struct {
	UI                          cli.Ui
	flagTLS                     bool
	flagAgentSecretARN          string
	flagConsulServerServiceName string

	ecsClient *ecs.ECS
	log       hclog.Logger

	flagSet *flag.FlagSet
	once    sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.BoolVar(&c.flagTLS, flagTLS, false, "If Consul has TLS enabled")
	c.flagSet.StringVar(&c.flagAgentSecretARN, flagAgentSecretARN, "", "ARN of AWS Secrets Manager secret")
	c.flagSet.StringVar(&c.flagConsulServerServiceName, flagConsulServerServiceName, "", "Name of Consul server ECS service")

	c.log = hclog.New(nil)
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)
	if err := c.flagSet.Parse(args); err != nil {
		return 1
	}

	err := c.realRun()
	if err != nil {
		c.log.Error(err.Error())
		return 1
	}
	return 0
}

func (c *Command) realRun() error {
	ecsMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		return err
	}
	cluster := ecsMeta.Cluster
	c.log.Info("cluster name determined", "cluster", cluster)

	// Set up ECS client.
	clientSession, err := session.NewSession()
	if err != nil {
		return err
	}
	c.ecsClient = ecs.New(clientSession)

	// Discover server IP.
	var serverIP string
	taskARNs, err := c.ecsClient.ListTasks(&ecs.ListTasksInput{
		Cluster:     aws.String(cluster),
		ServiceName: aws.String(c.flagConsulServerServiceName),
	})
	if err != nil {
		return fmt.Errorf("listing task arns: %s", err)
	}
	if len(taskARNs.TaskArns) == 0 {
		return fmt.Errorf("no tasks for service %s found", c.flagConsulServerServiceName)
	}
	err = backoff.RetryNotify(func() error {
		tasks, err := c.ecsClient.DescribeTasks(&ecs.DescribeTasksInput{
			Cluster: aws.String(cluster),
			Tasks:   taskARNs.TaskArns,
		})
		if err != nil {
			return err
		}
		if len(tasks.Tasks) == 0 {
			return fmt.Errorf("task describe came back with 0 tasks")
		}
		taskARN := *tasks.Tasks[0].TaskArn

		for _, container := range tasks.Tasks[0].Containers {
			if *container.Name == "consul-server" {
				if len(container.NetworkInterfaces) == 0 {
					return fmt.Errorf("container %q in task %q has no network interfaces", *container.Name, taskARN)
				}
				for _, netInterface := range container.NetworkInterfaces {
					if netInterface.PrivateIpv4Address == nil || *netInterface.PrivateIpv4Address == "" {
						return fmt.Errorf("container %q in task %q has network interface with no private ipv4 address set", *container.Name, taskARN)
					}
					serverIP = *netInterface.PrivateIpv4Address
					break
				}
			}
			if serverIP != "" {
				break
			}
		}
		if serverIP == "" {
			return fmt.Errorf("task %s has no consul-server container", taskARN)
		}
		return nil
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(c.log))
	if err != nil {
		return err
	}
	c.log.Info("discovered server ip", "ip", serverIP)

	// Ensure agent secret created.
	// todo: create agent token
	secManClient := secretsmanager.New(clientSession, nil)
	type agentSecretJSON struct {
		AgentToken string `json:"agent_token"`
	}
	agentSecret, err := json.Marshal(agentSecretJSON{AgentToken: os.Getenv(aclTokenEnvVar)})
	if err != nil {
		return err
	}

	currSecretValue, err := secManClient.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(c.flagAgentSecretARN),
	})
	if err != nil {
		return fmt.Errorf("retrieving secret: %s", err)
	}
	if currSecretValue.String() != string(agentSecret) {
		c.log.Info("updating secret", "arn", c.flagAgentSecretARN)
		_, err := secManClient.UpdateSecret(&secretsmanager.UpdateSecretInput{
			SecretId:     aws.String(c.flagAgentSecretARN),
			SecretString: aws.String(string(agentSecret)),
		})
		if err != nil {
			return fmt.Errorf("updating secret: %s", err)
		}
		c.log.Info("secret updated successfully", "arn", c.flagAgentSecretARN)
	}

	// Reconcile in a loop.
	for {
		err := c.reconcile(cluster, serverIP)
		if err != nil {
			c.log.Error(err.Error())
		}
		time.Sleep(10 * time.Second)
	}
}

// todo: memory leak
var seen = make(map[string]bool)

func (c *Command) reconcile(cluster string, serverIP string) error {
	// List tasks.
	taskARNs, err := c.ecsClient.ListTasks(&ecs.ListTasksInput{
		Cluster: aws.String(cluster),
	})
	if err != nil {
		return fmt.Errorf("listing task arns: %s", err)
	}

	tasks, err := c.ecsClient.DescribeTasks(&ecs.DescribeTasksInput{
		Cluster: aws.String(cluster),
		Tasks:   taskARNs.TaskArns,
		Include: []*string{aws.String("TAGS")},
	})
	if err != nil {
		return fmt.Errorf("describing tasks: %s", err)
	}

	consulSvrClient, err := api.NewClient(&api.Config{
		Address: fmt.Sprintf("https://%s:8501", serverIP),
		Token:   os.Getenv(aclTokenEnvVar),
		TLSConfig: api.TLSConfig{
			InsecureSkipVerify: true, //todo
		},
	})
	if err != nil {
		return fmt.Errorf("constructing server client: %s", err)
	}

	for _, task := range tasks.Tasks {
		taskARN := *task.TaskArn
		if _, ok := seen[taskARN]; ok {
			c.log.Debug("ignoring seen task", "arn", taskARN)
			continue
		}

		c.log.Info("processing new task", "arn", taskARN)
		err := c.reconcileTask(consulSvrClient, task)
		if err != nil {
			c.log.Error("reconcile err", "err", err.Error(), "arn", taskARN)
			continue
		}
		seen[taskARN] = true
	}
	return nil
}

func (c *Command) reconcileTask(consulSvrClient *api.Client, task *ecs.Task) error {
	taskARN := *task.TaskArn

	meshTask := tagValue(task.Tags, meshTag) == "true"
	if !meshTask {
		c.log.Info("skipping non-mesh task", "arn", taskARN)
		return nil
	}

	var taskIP string
	var hostname string
	for _, container := range task.Containers {
		if *container.Name == "consul-client" {
			if len(container.NetworkInterfaces) == 0 {
				return fmt.Errorf("container %q in task %q has no network interfaces", *container.Name, taskARN)
			}
			if container.RuntimeId == nil {
				return fmt.Errorf("container %q in task %q has nil runtime id", *container.Name, taskARN)
			}
			for _, netInterface := range container.NetworkInterfaces {
				if netInterface.PrivateIpv4Address == nil || *netInterface.PrivateIpv4Address == "" {
					return fmt.Errorf("container %q in task %q has network interface with no private ipv4 address set", *container.Name, taskARN)
				}
				taskIP = *netInterface.PrivateIpv4Address
				hostname = *container.RuntimeId
				break
			}
		}
		if taskIP != "" {
			break
		}
	}
	if taskIP == "" {
		return fmt.Errorf("mesh task has no consul-client container")
	}

	c.log.Debug("constructing consul client", "arn", taskARN)
	address := fmt.Sprintf("%s:8500", taskIP)
	scheme := "http"
	var rootToken string
	if c.flagTLS {
		address = fmt.Sprintf("%s:8501", taskIP)
		scheme = "https"
		rootToken = os.Getenv(aclTokenEnvVar)
	}
	consulClient, err := api.NewClient(&api.Config{
		Address: address,
		// todo: actually get tls cert properly: need to use CA cert to talk to servers
		// to get the client ca cert.
		TLSConfig: api.TLSConfig{InsecureSkipVerify: true},
		Scheme:    scheme,
		Token:     rootToken,
	})
	if err != nil {
		return fmt.Errorf("constructing consul client: %s", err)
	}

	// Service name is based on the group which looks like "service:<service name>".
	groupSplit := strings.Split(*task.Group, ":")
	if len(groupSplit) != 2 {
		return fmt.Errorf("could not deterine service name: group %q invalid", *task.Group)
	}
	serviceName := groupSplit[1]

	// Create ACL token for envoy to register the service.
	agentToken, _, err := consulSvrClient.ACL().TokenCreate(&api.ACLToken{
		Description: fmt.Sprintf("Token for the %s agent for %s service", hostname, serviceName),
		ServiceIdentities: []*api.ACLServiceIdentity{
			{
				ServiceName: serviceName,
			},
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("creating envoy token: %s", err)
	}
	_, err = consulClient.Agent().UpdateReplicationACLToken(agentToken.SecretID, nil)
	if err != nil {
		return fmt.Errorf("updating agent token: %s", err)
	}
	c.log.Info("replication token updated", "name", serviceName, "task-ip", taskIP)
	return nil
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

func taskARNToID(arn *string) string {
	if arn == nil {
		return ""
	}
	split := strings.Split(*arn, "/")
	if len(split) == 0 {
		return ""
	}
	return split[len(split)-1]
}

func (c *Command) Synopsis() string {
	return "ECS controller"
}

func (c *Command) Help() string {
	return ""
}

type ThreeTimesBackOff struct {
	iterations int
}

func (t ThreeTimesBackOff) NextBackOff() time.Duration {
	if t.iterations == 3 {
		return backoff.Stop
	}
	t.iterations = t.iterations + 1
	return 1 * time.Second
}

func (t ThreeTimesBackOff) Reset() {
	t.iterations = 0
}

func retryLogger(log hclog.Logger) backoff.Notify {
	return func(err error, duration time.Duration) {
		log.Error(err.Error(), "retry", duration.String())
	}
}
