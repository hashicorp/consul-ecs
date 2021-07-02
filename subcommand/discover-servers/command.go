package meshinit

import (
	"flag"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

const (
	flagServiceName = "service-name"
	flagOutputFile  = "out"
)

type Command struct {
	UI              cli.Ui
	flagServiceName string
	flagOutputFile  string

	ecsClient *ecs.ECS
	log       hclog.Logger

	flagSet *flag.FlagSet
	once    sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagServiceName, flagServiceName, "", "Name of ECS service of Consul servers")
	c.flagSet.StringVar(&c.flagOutputFile, flagOutputFile, "", "File to write Consul server IP to")

	c.log = hclog.New(nil)
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)
	if err := c.flagSet.Parse(args); err != nil {
		return 1
	}

	if c.flagServiceName == "" {
		c.UI.Error(fmt.Sprintf("-%s must be set", flagServiceName))
		return 1
	}

	if c.flagOutputFile == "" {
		c.UI.Error(fmt.Sprintf("-%s must be set", flagOutputFile))
		return 1
	}

	log := hclog.New(nil)
	err := c.realRun(log)
	if err != nil {
		log.Error(err.Error())
		return 1
	}
	return 0
}

func (c *Command) realRun(log hclog.Logger) error {
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
	clientSession.Handlers.Build.PushBackNamed(awsutil.UserAgentHandler("discover"))
	c.ecsClient = ecs.New(clientSession)

	var taskARNs *ecs.ListTasksOutput
	err = backoff.RetryNotify(func() error {
		var err error
		taskARNs, err = c.ecsClient.ListTasks(&ecs.ListTasksInput{
			Cluster:     aws.String(cluster),
			ServiceName: aws.String(c.flagServiceName),
		})
		if err != nil {
			return fmt.Errorf("listing task arns: %s", err)
		}

		if len(taskARNs.TaskArns) == 0 {
			return fmt.Errorf("no tasks for service %s found", c.flagServiceName)
		}
		return nil
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(log))
	if err != nil {
		return err
	}

	var serverIP string
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
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(log))
	if err != nil {
		return err
	}

	c.log.Info("discovered IP", "ip", serverIP, "out", c.flagOutputFile)
	return ioutil.WriteFile(c.flagOutputFile, []byte(serverIP), 0644)
}

func retryLogger(log hclog.Logger) backoff.Notify {
	return func(err error, duration time.Duration) {
		log.Error(err.Error(), "retry", duration.String())
	}
}

func (c *Command) Synopsis() string {
	return "Discovers Consul servers running as ECS tasks"
}

func (c *Command) Help() string {
	return ""
}
