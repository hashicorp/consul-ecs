package controlplane

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
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-multierror"
)

const (
	// pollingInterval is how often we poll the container health endpoint.
	// The rate limit is about 40 per second, so 1 second polling seems reasonable.
	pollInterval = 1 * time.Second
)

func (c *Command) runHealthSync(ctx context.Context, consulClient *api.Client) error {
	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		return err
	}
	healthSyncContainers := c.config.HealthSyncContainers
	svcReg, err := ConstructServiceRegistration(c.config, taskMeta)
	if err != nil {
		return err
	}

	currentStatuses := make(map[string]string)

	proxyReg := ConstructProxyRegistration(c.config, svcReg)
	var proxyStatus string

	for {
		select {
		case <-time.After(pollInterval):
			taskMeta, err = awsutil.ECSTaskMetadata()
			if err != nil {
				c.log.Error("unable to get task metadata", "err", err)
			} else {
				currentStatuses = c.syncChecks(consulClient, taskMeta, currentStatuses, svcReg, healthSyncContainers)
				proxyStatus = c.syncProxyCheck(consulClient, taskMeta, proxyStatus, proxyReg)
			}
		case <-ctx.Done():
			result := c.setProxyCheckCritical(consulClient, proxyReg)
			if err := c.setChecksCritical(consulClient, svcReg); err != nil {
				result = multierror.Append(result, err)
			}
			if c.config.ConsulLogin.Enabled {
				if err := c.logout(config.ServiceTokenFilename); err != nil {
					result = multierror.Append(result, err)
				}
				if err := c.logout(config.ClientTokenFilename); err != nil {
					result = multierror.Append(result, err)
				}
			}
			return result
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
func (c *Command) syncChecks(consulClient *api.Client, taskMeta awsutil.ECSTaskMeta, currentStatuses map[string]string, svcReg *api.CatalogRegistration, parsedContainerNames []string) map[string]string {
	newStatuses := map[string]string{}
	for k, v := range currentStatuses {
		newStatuses[k] = v
	}

	containersToSync, missingContainers := findContainersToSync(parsedContainerNames, taskMeta)
	for _, name := range missingContainers {
		if newStatuses[name] != api.HealthCritical {
			c.log.Info("will update health for container not found in task", "container", name, "status", api.HealthCritical)
			newStatuses[name] = api.HealthCritical
		}
	}

	for _, container := range containersToSync {
		c.log.Debug("found ECS container health",
			"name", container.Name,
			"status", container.Health.Status,
			"statusSince", container.Health.StatusSince,
			"exitCode", container.Health.ExitCode,
		)

		previousStatus := newStatuses[container.Name]
		if container.Health.Status != previousStatus {
			c.log.Info("will update health for container",
				"name", container.Name,
				"status", container.Health.Status,
				"statusSince", container.Health.StatusSince,
				"exitCode", container.Health.ExitCode,
			)
			newStatuses[container.Name] = container.Health.Status
		}
	}

	needsUpdate := false
	for name := range newStatuses {
		if newStatuses[name] != currentStatuses[name] {
			needsUpdate = true
		}
	}

	if needsUpdate {
		err := updateConsulHealthChecks(consulClient, svcReg, newStatuses)
		if err != nil {
			c.log.Warn("failed to update health status in Consul", "err", err.Error())
			// on failure, forget the new statuses seen here. otherwise, we'll
			// see no change in status on the next attempt, and will not retry the update.
			return currentStatuses
		} else {
			c.log.Info("successfully updated service health status in Consul")
		}
	}
	return newStatuses
}

// syncProxyCheck syncs the status of the sidecar-proxy container into Consul
func (c *Command) syncProxyCheck(consulClient *api.Client, taskMeta awsutil.ECSTaskMeta, currentStatus string, proxyReg *api.CatalogRegistration) string {
	var container *awsutil.ECSTaskMetaContainer
	for _, c := range taskMeta.Containers {
		if c.Name == "sidecar-proxy" {
			container = &c
			break
		}
	}

	if container == nil {
		c.log.Error("sidecar-proxy container not found")
		return currentStatus
	}

	c.log.Debug("found ECS container health",
		"name", container.Name,
		"status", container.Health.Status,
		"statusSince", container.Health.StatusSince,
		"exitCode", container.Health.ExitCode,
	)

	if container.Health.Status == currentStatus {
		// status unchanged.
		return currentStatus
	} else if container.Health.Status == "" {
		// health status is unknown. either:
		//
		// * The ECS health check has not yet run, so we do nothing for now. Eventually,
		//   the check should run and we'll get a status value.
		// * Or, there is no ECS health check defined for the sidecar-proxy container.
		//   We'll require a health check IS defined for the sidecar-proxy container (and our
		//   terraform modules define the check). If the user doesn't define a health check,
		//   then we'll hit this case and we do nothing. This will leave the proxy in its initial
		//   status (critical).
		return currentStatus
	}

	c.log.Info("will update health for container",
		"name", container.Name,
		"status", container.Health.Status,
		"statusSince", container.Health.StatusSince,
		"exitCode", container.Health.ExitCode,
	)

	proxyReg.Check.Output = fmt.Sprintf("ECS health status is %q for container %q",
		container.Health.Status, container.Name)
	proxyReg.Check.Status = ecsHealthToConsulHealth(container.Health.Status)

	_, err := consulClient.Catalog().Register(proxyReg, nil)
	if err != nil {
		c.log.Error("failed to update proxy health status in Consul", "err", err.Error())
	} else {
		c.log.Info("successfully updated sidecar-proxy health status in Consul")
		currentStatus = container.Health.Status
	}
	return currentStatus

}

func (c *Command) setProxyCheckCritical(consulClient *api.Client, proxyReg *api.CatalogRegistration) error {
	proxyReg.Check.Status = api.HealthCritical
	proxyReg.Check.Output = "ECS task stopped."
	proxyReg.SkipNodeUpdate = true
	_, err := consulClient.Catalog().Register(proxyReg, nil)
	if err != nil {
		return fmt.Errorf("setting proxy check to critical: %w", err)
	}
	return nil
}

// setChecksCritical sets checks for all of the containers to critical
func (c *Command) setChecksCritical(consulClient *api.Client, svcReg *api.CatalogRegistration) error {
	var result error

	for _, check := range svcReg.Checks {
		check.Status = api.HealthCritical
		check.Output = "ECS task stopped."
	}
	svcReg.SkipNodeUpdate = true
	if _, err := consulClient.Catalog().Register(svcReg, nil); err != nil {
		result = multierror.Append(result, fmt.Errorf("setting service checks to critical: %w", err))
	}

	// Deregister the service instance
	//
	// TODO: Instead of immediately de-registering the node, do we need to wait until the application has stopped
	//		 to support graceful shutdown? See the envoy-entrypoint command, which supports this already.
	//       I don't think so. Because it was okay previously to do the consul leave, which deregisters everything
	//		 from Consul.
	//
	// We specify only the Node so that Consul registers the node and its associated services and checks.
	// Since ECS uses 1 node per service, so this is perfect for us.
	//
	// I think this is generally okay, but each node name on ECS is based on the task IP (e.g. ip-10-1-2-3.ec2.internal)
	// and it's possible these IPs are reused. Two nodes would share a node name if one task failed to deregister
	// and then a new task is later assigned that ip and registers as the same node name. In that case, deregistering
	// the node and all associated service instances would be fine, since it would cleanup the old node too.
	c.log.Info("deregistering service", "node", svcReg.Node, "service-id", svcReg.Service.ID)
	_, err := consulClient.Catalog().Deregister(&api.CatalogDeregistration{
		Node:      svcReg.Node,
		ServiceID: svcReg.Service.ID,
		// TODO:
		//Datacenter: "",
		//Namespace:  "",
		//Partition:  "",
	}, nil)
	if result != nil {
		result = multierror.Append(result, fmt.Errorf("deregistering service: %w", err))
	}

	return result
}

// logout calls POST /acl/logout to destroy the token in the given file.
// The given file should be relative path of a file in the bootstrap directory.
func (c *Command) logout(tokenFile string) error {
	tokenFile = filepath.Join(c.config.BootstrapDir, tokenFile)
	c.log.Info("log out token", "file", tokenFile)
	cfg := api.DefaultConfig()
	cfg.Address = c.config.ConsulServers.HTTPAddr()
	cfg.TLSConfig.CAFile = c.config.ConsulServers.CACertFile
	cfg.TokenFile = tokenFile

	client, err := api.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("creating client for logout: %w", err)
	}
	_, err = client.ACL().Logout(nil)
	if err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}
	return nil
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

func updateConsulHealthChecks(consulClient *api.Client, svcReg *api.CatalogRegistration, currentStatuses map[string]string) error {
	for container, ecsHealthStatus := range currentStatuses {
		checkId := CheckID(svcReg.Service.ID, container)
		for _, check := range svcReg.Checks {
			if check.CheckID == checkId {
				check.Status = ecsHealthToConsulHealth(ecsHealthStatus)
				check.Output = fmt.Sprintf("ECS health status is %q for container %q", ecsHealthStatus, container)
			}
		}
	}

	svcReg.SkipNodeUpdate = true

	_, err := consulClient.Catalog().Register(svcReg, nil)
	return err
}
