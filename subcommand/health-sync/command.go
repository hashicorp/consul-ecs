package healthsync

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

const (
	flagContainerNames = "container-names"
	// The rate limit is about 40 per second, so 1 second pulling seems reasonable
	pollInterval = 1 * time.Second
)

type Command struct {
	UI                 cli.Ui
	flagContainerNames string
	consulClient       *api.Client
	log                hclog.Logger
	flagSet            *flag.FlagSet
	once               sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagContainerNames, flagContainerNames, "", "Comma-separated list of container names for which to sync health status into Consul")
	c.log = hclog.New(nil)
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)
	if err := c.flagSet.Parse(args); err != nil {
		return 1
	}

	// There is nothing to do, so successfully exit
	if len(c.flagContainerNames) == 0 {
		c.UI.Error(fmt.Sprintf("-%v doesn't have a value. exiting", flagContainerNames))
		return 0
	}

	if err := c.realRun(); err != nil {
		c.log.Error(err.Error())
		return 1
	}

	return 0
}

func (c *Command) realRun() error {
	ctx := context.Background()

	c.ignoreSIGTERM()

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

	currentStatuses := map[string]string{}
	parsedContainerNames := strings.Split(c.flagContainerNames, ",")

	for {
		select {
		case <-time.After(pollInterval):
			currentStatuses = c.syncChecks(currentStatuses, serviceName, parsedContainerNames)
		case <-ctx.Done():
			return nil
		}
	}
}

func (c *Command) ignoreSIGTERM() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	// Don't need to do anything for now. Just catch the SIGTERM so we don't exit.
	// And, print when we receive the SIGTERM
	go func() {
		for sig := range sigs {
			c.log.Info("signal received", "signal", sig)
		}
	}()
}

// syncChecks fetches metadata for the ECS task and uses that metadata to
// updates the Consul TTL checks for the containers specified in
// `parsedContainerNames`. Checks are only updated if they have changed since
// the last invocation of this function.
func (c *Command) syncChecks(currentStatuses map[string]string, serviceName string, parsedContainerNames []string) map[string]string {
	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		c.log.Error(err.Error())
		return currentStatuses
	}
	containersToSync, missingContainers := findContainersToSync(parsedContainerNames, taskMeta)
	for _, name := range missingContainers {
		c.UI.Warn(fmt.Sprintf("container %s not found in task metadata", name))
	}

	for _, container := range containersToSync {
		c.log.Info("Updating Consul TTL check from ECS container health",
			"name", container.Name,
			"status", container.Health.Status,
			"statusSince", container.Health.StatusSince,
			"exitCode", container.Health.ExitCode,
		)

		previousStatus := currentStatuses[container.Name]
		if container.Health.Status != previousStatus {
			err = c.updateConsulHealthStatus(serviceName, container)
			if err != nil {
				c.log.Info(fmt.Sprintf("failed to update Consul health status: %s", err.Error()))
			} else {
				c.log.Info(fmt.Sprintf("Container %s health check updated in Consul", container.Name))
				currentStatuses[container.Name] = container.Health.Status
			}
		}
	}

	return currentStatuses
}

func findContainersToSync(containerNames []string, taskMeta awsutil.ECSTaskMeta) ([]*awsutil.ECSTaskMetaContainer, []string) {
	ecsContainers := []*awsutil.ECSTaskMetaContainer{}
	missing := []string{}

ContainerNames:
	for _, container := range containerNames {
		for _, ecsContainer := range taskMeta.Containers {
			if ecsContainer.Name == container {
				ecsContainers = append(ecsContainers, &ecsContainer)
				continue ContainerNames
			}
		}
		missing = append(missing, container)
	}
	return ecsContainers, missing
}

func ecsHealthToConsulHealth(ecsHealth string) string {
	// `HEALTHY`, `UNHEALTHY`, and `UNKNOWN` are the valid ECS health statuses.
	// This assumes that the only passing status is `HEALTHY`
	if ecsHealth != "HEALTHY" {
		return api.HealthCritical
	}
	return api.HealthPassing
}

func makeCheckID(serviceName, containerName string) string {
	return fmt.Sprintf("%s-%s-ecs-health-sync", serviceName, containerName)
}

func (c *Command) updateConsulHealthStatus(serviceName string, container *awsutil.ECSTaskMetaContainer) error {
	ecsHealthStatus := container.Health.Status

	consulHealthStatus := ecsHealthToConsulHealth(ecsHealthStatus)
	checkID := makeCheckID(serviceName, container.Name)

	reason := fmt.Sprintf("ECS health status is %q for container %q", ecsHealthStatus, container.Name)

	err := c.consulClient.Agent().UpdateTTL(checkID, reason, consulHealthStatus)
	if err != nil {
		return fmt.Errorf("updating health check: %w", err)
	}

	return nil
}

func (c *Command) Synopsis() string {
	return "Syncs ECS container health to Consul"
}

func (c *Command) Help() string {
	return ""
}
