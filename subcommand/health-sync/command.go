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

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

const (
	flagHealthSyncContainers = "health-sync-containers"
	// pollingInterval is how often we poll the container health endpoint.
	// The rate limit is about 40 per second, so 1 second polling seems reasonable.
	pollInterval = 1 * time.Second
)

type Command struct {
	UI                       cli.Ui
	flagHealthSyncContainers string
	log                      hclog.Logger
	flagSet                  *flag.FlagSet
	once                     sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagHealthSyncContainers, flagHealthSyncContainers, "", "Comma-separated list of container names for which to sync health status into Consul")
	c.log = hclog.New(nil)
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)
	if err := c.flagSet.Parse(args); err != nil {
		return 1
	}

	// We expect this command to be invoked with a list of containers
	// so error out if the list is empty.
	if len(c.flagHealthSyncContainers) == 0 {
		c.UI.Error(fmt.Sprintf("-%v doesn't have a value. exiting", flagHealthSyncContainers))
		return 1
	}

	consulClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		c.UI.Error(fmt.Sprintf("constructing consul client: %s", err))
		return 1
	}

	// This context will eventually be passed to `ignoreSIGTERM` so it can
	// immediately update the statuses in Consul and cancel the loop that
	// repeatedly calls `syncChecks`.
	ctx := context.Background()

	if err := c.realRun(ctx, consulClient); err != nil {
		c.log.Error("error running main", "err", err)
		return 1
	}

	return 0
}

func (c *Command) realRun(ctx context.Context, consulClient *api.Client) error {
	c.ignoreSIGTERM()

	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		return err
	}

	// Duplicate code from mesh-init. Service ID must match here and in mesh-init.
	serviceName := taskMeta.Family

	currentStatuses := make(map[string]string)
	parsedContainerNames := strings.Split(c.flagHealthSyncContainers, ",")

	for {
		select {
		case <-time.After(pollInterval):
			currentStatuses = c.syncChecks(consulClient, currentStatuses, serviceName, parsedContainerNames)
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
			c.log.Info("signal received, ignoring", "signal", sig)
		}
	}()
}

// syncChecks fetches metadata for the ECS task and uses that metadata to
// updates the Consul TTL checks for the containers specified in
// `parsedContainerNames`. Checks are only updated if they have changed since
// the last invocation of this function.
func (c *Command) syncChecks(consulClient *api.Client, currentStatuses map[string]string, serviceName string, parsedContainerNames []string) map[string]string {
	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		c.log.Error("unable to get task metadata", "err", err)
		return currentStatuses
	}

	containersToSync, missingContainers := findContainersToSync(parsedContainerNames, taskMeta)
	for _, name := range missingContainers {
		checkID := makeCheckID(serviceName, taskMeta.TaskID(), name)
		c.log.Debug("marking container as unhealthy since it wasn't found in the task metadata", "name", name)
		err = updateConsulHealthStatus(consulClient, checkID, ecs.HealthStatusUnhealthy)
		if err != nil {
			c.log.Error("failed to update Consul health status for missing container", "err", err, "container", name)
		} else {
			c.log.Info("Container health check updated in Consul for missing container", "container", name)
			currentStatuses[name] = api.HealthCritical
		}
	}

	for _, container := range containersToSync {
		c.log.Debug("Updating Consul TTL check from ECS container health",
			"name", container.Name,
			"status", container.Health.Status,
			"statusSince", container.Health.StatusSince,
			"exitCode", container.Health.ExitCode,
		)

		previousStatus := currentStatuses[container.Name]
		if container.Health.Status != previousStatus {
			checkID := makeCheckID(serviceName, taskMeta.TaskID(), container.Name)
			err = updateConsulHealthStatus(consulClient, checkID, container.Health.Status)

			if err != nil {
				c.log.Warn("failed to update Consul health status", "err", err)
			} else {
				c.log.Info("Container health check updated in Consul",
					"name", container.Name,
					"status", container.Health.Status,
					"statusSince", container.Health.StatusSince,
					"exitCode", container.Health.ExitCode,
				)
				currentStatuses[container.Name] = container.Health.Status
			}
		}
	}

	return currentStatuses
}

func findContainersToSync(containerNames []string, taskMeta awsutil.ECSTaskMeta) ([]awsutil.ECSTaskMetaContainer, []string) {
	var ecsContainers []awsutil.ECSTaskMetaContainer
	var missing []string

	for _, container := range containerNames {
		found := false
		for _, ecsContainer := range taskMeta.Containers {
			if ecsContainer.Name == container {
				ecsContainers = append(ecsContainers, ecsContainer)
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, container)
		}
	}
	return ecsContainers, missing
}

func ecsHealthToConsulHealth(ecsHealth string) string {
	// `HEALTHY`, `UNHEALTHY`, and `UNKNOWN` are the valid ECS health statuses.
	// This assumes that the only passing status is `HEALTHY`
	if ecsHealth != ecs.HealthStatusHealthy {
		return api.HealthCritical
	}
	return api.HealthPassing
}

func makeCheckID(serviceName, taskID, containerName string) string {
	return fmt.Sprintf("%s-%s-%s-consul-ecs", serviceName, taskID, containerName)
}

func updateConsulHealthStatus(consulClient *api.Client, checkID string, ecsHealthStatus string) error {
	consulHealthStatus := ecsHealthToConsulHealth(ecsHealthStatus)

	reason := fmt.Sprintf("ECS health status is %q for task %q", ecsHealthStatus, checkID)

	return consulClient.Agent().UpdateTTL(checkID, reason, consulHealthStatus)
}

func (c *Command) Synopsis() string {
	return "Syncs ECS container health to Consul"
}

func (c *Command) Help() string {
	return ""
}
