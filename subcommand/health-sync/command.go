package healthsync

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/logging"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/cli"
)

const (
	// pollingInterval is how often we poll the container health endpoint.
	// The rate limit is about 40 per second, so 1 second polling seems reasonable.
	pollInterval = 1 * time.Second
)

type Command struct {
	UI     cli.Ui
	config *config.Config
	log    hclog.Logger
}

func (c *Command) Run(args []string) int {
	if len(args) > 0 {
		c.UI.Error(fmt.Sprintf("unexpected argument: %s", args[0]))
		return 1
	}

	conf, err := config.FromEnv()
	if err != nil {
		c.UI.Error(fmt.Sprintf("invalid config: %s", err))
		return 1
	}
	c.config = conf

	c.log = logging.FromConfig(c.config).Logger()

	cfg := api.DefaultConfig()
	if c.config.AuthMethod.Enabled {
		// This file will already have been written by mesh-init.
		cfg.TokenFile = filepath.Join(c.config.BootstrapDir, config.ServiceTokenFilename)
	}

	consulClient, err := api.NewClient(cfg)
	if err != nil {
		c.UI.Error(fmt.Sprintf("constructing consul client: %s", err))
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())

	c.ignoreSIGTERM(cancel)

	if err := c.realRun(ctx, consulClient); err != nil {
		c.log.Error("error running main", "err", err)
		return 1
	}

	return 0
}

func (c *Command) realRun(ctx context.Context, consulClient *api.Client) error {
	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		return err
	}
	healthSyncContainers := c.config.HealthSyncContainers
	serviceName := c.constructServiceName(taskMeta.Family)

	currentStatuses := make(map[string]string)

	for {
		select {
		case <-time.After(pollInterval):
			currentStatuses = c.syncChecks(consulClient, currentStatuses, serviceName, healthSyncContainers)
		case <-ctx.Done():
			return c.setChecksCritical(consulClient, taskMeta.TaskID(), serviceName, healthSyncContainers)
		}
	}
}

// ignoreSIGTERM logs when the SIGTERM occurs and then calls the cancel context
// function
func (c *Command) ignoreSIGTERM(cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	// Don't need to do anything for now. Just catch the SIGTERM so we don't exit.
	// And, print when we receive the SIGTERM
	go func() {
		for sig := range sigs {
			c.log.Info("signal received, ignoring", "signal", sig)
			cancel()
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

// setChecksCritical sets checks for all of the containers to critical
func (c *Command) setChecksCritical(consulClient *api.Client, taskID string, serviceName string, parsedContainerNames []string) error {
	var result error

	for _, containerName := range parsedContainerNames {
		checkID := makeCheckID(serviceName, taskID, containerName)
		err := updateConsulHealthStatus(consulClient, checkID, api.HealthCritical)

		if err == nil {
			c.log.Info("set Consul health status to critical",
				"container", containerName)
		} else {
			c.log.Warn("failed to set Consul health status to critical",
				"err", err,
				"container", containerName)
			result = multierror.Append(result, err)
		}
	}

	return result
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

func (c *Command) constructServiceName(family string) string {
	if serviceName := c.config.Service.Name; serviceName != "" {
		return serviceName
	}

	return family
}

func (c *Command) Synopsis() string {
	return "Syncs ECS container health to Consul"
}

func (c *Command) Help() string {
	return ""
}
