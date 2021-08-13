package healthsync

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

const (
	flagContainerName = "container-name"
)

type Command struct {
	UI cli.Ui

	flagContainerName string

	consulClient      *api.Client
	log               hclog.Logger

	flagSet *flag.FlagSet
	once    sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagContainerName, flagContainerName, "", "Name of container to sync to the service")

	c.log = hclog.New(nil)
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)
	if err := c.flagSet.Parse(args); err != nil {
		return 1
	}


	if c.flagContainerName == "" {
		c.UI.Error(fmt.Sprintf("-%v must be set", flagContainerName))
		return 1
	}

	if err := c.realRun(); err != nil {
		c.log.Error(err.Error())
		return 1
	}

	return 0
}

func (c *Command) realRun() error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	// Don't need to do anything for now. Just catch the SIGTERM so we don't exit.
	// And, print when we receive the SIGTERM
	go func() {
		for sig := range sigs {
			c.log.Info("signal received", "signal", sig)
		}
	}()

	consulClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("constructing consul client: %s", err)
	}
	c.consulClient = consulClient


	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		return err
	}

	// Duplicate code from mesh-init. Service ID must match here and in mesh-init.
	serviceName := taskMeta.Family
	serviceId := fmt.Sprintf("%s-%s", serviceName, taskMeta.TaskID())
	c.log.Info("discovered service", "serviceId", serviceId)

	var currentStatus string

	for {
		container := findContainer(c.flagContainerName, taskMeta)
		if container == nil {
			c.UI.Error(fmt.Sprintf("container %s not found in task meta", c.flagContainerName))
			time.Sleep(10 * time.Second)
			continue
		}

		c.log.Info("container health",
			"name", container.Name,
			"status", container.Health.Status,
			"statusSince", container.Health.StatusSince,
			"exitCode", container.Health.ExitCode,
		)

		if container.Health.Status != currentStatus {
			err = c.updateConsulHealthStatus(serviceId, container.Health.Status)
			if err != nil {
				c.UI.Error(fmt.Sprintf("failed to update Consul health status: %s", err.Error()))
			} else {
				currentStatus = container.Health.Status
			}
		}
		time.Sleep(10 * time.Second)

		taskMeta, err = awsutil.ECSTaskMetadata()
		if err != nil {
			c.log.Error(err.Error())
		}
	}
}

func findContainer(name string, taskMeta awsutil.ECSTaskMeta) *awsutil.ECSTaskMetaContainer {
	for _, container := range taskMeta.Containers {
		if container.Name == name {
			return &container
		}
	}
	return nil
}

func (c *Command) updateConsulHealthStatus(serviceID, ecsHealthStatus string) error {
	c.log.Info(fmt.Sprintf("updating consul health status for service %q", serviceID))
	// Translate ECS health status to a Consul health status.
	//   HEALTHY   -> passing
	//   UNHEALTHY -> critical
	//   UNKNOWN   -> critical
	consulHealthStatus := api.HealthPassing
	if ecsHealthStatus != "HEALTHY" {
		consulHealthStatus = api.HealthCritical
	}

	checkID := fmt.Sprintf("%s-ecs-health-sync", serviceID)

	// Largely borrowing from consul-k8s:
	// https://github.com/hashicorp/consul-k8s/blob/81c05aa0197645bf4db7ec348e84b795853747c2/connect-inject/endpoints_controller.go#L291
	filter := fmt.Sprintf("CheckID == `%s`", checkID)
	checks, err := c.consulClient.Agent().ChecksWithFilter(filter)
	if err != nil {
		return fmt.Errorf("listing consul health checks: %w", err)
	}

	c.log.Info(fmt.Sprintf("existing check? %v", checks[checkID]))

	if checks[checkID] == nil {
		// If the TTL check doesn't exist, register it.
		err = c.consulClient.Agent().CheckRegister(&api.AgentCheckRegistration{
			ID: checkID,
			Name: checkID,
			Notes: "Synced from ECS container health status",
			ServiceID: serviceID,
			AgentServiceCheck: api.AgentServiceCheck{
				TTL: "10000h",  // ?
				Status: consulHealthStatus,
				SuccessBeforePassing: 1,
				FailuresBeforeCritical: 1,
			},
		})
		if err != nil {
			return fmt.Errorf("registering consul health check for service %q", serviceID)
		}
	} else {
		// Consul check already exists - update it
		reason := fmt.Sprintf("ECS health status is %q for service %q", ecsHealthStatus, serviceID)

		err = c.consulClient.Agent().UpdateTTL(checkID, reason, consulHealthStatus)
		if err != nil {
			return fmt.Errorf("updating health check: %w", err)
		}
	}
	return nil
}


func (c *Command) Synopsis() string {
	return "Syncs ECS container health to Consul"
}

func (c *Command) Help() string {
	return ""
}
