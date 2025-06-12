// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/logging"
	"github.com/hashicorp/consul-server-connection-manager/discovery"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/cli"
)

const (
	// syncChecksInterval is how often we poll the container health endpoint.
	// The rate limit is about 40 per second, so 1 second polling seems reasonable.
	syncChecksInterval = 1 * time.Second
)

type Command struct {
	UI     cli.Ui
	config *config.Config
	log    hclog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	sigs   chan os.Signal
	once   sync.Once

	checks           map[string]*api.HealthCheck
	dataplaneMonitor *dataplaneMonitor
	watcherCh        <-chan discovery.State

	// Following fields are only needed for unit tests

	// health-sync signals to this channel whenever it has completed
	// all the prerequisites before entering the reconciliation loop.
	doneChan chan struct{}

	// health-sync waits for someone to signal to this channel before
	// entering the checks reconcilation loop.
	proceedChan chan struct{}

	// Indicates that the command is run from a unit test
	isTestEnv bool
}

func (c *Command) init() {
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.sigs = make(chan os.Signal, 1)
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)
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
	c.dataplaneMonitor = newDataplaneMonitor(c.ctx, c.log)

	if err := c.realRun(); err != nil {
		c.log.Error("error running main", "err", err)
		return 1
	}

	return 0
}

func (c *Command) realRun() error {
	signal.Notify(c.sigs, syscall.SIGTERM)
	defer c.cleanup()

	go c.dataplaneMonitor.run()

	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		return err
	}

	clusterARN, err := taskMeta.ClusterARN()
	if err != nil {
		return err
	}

	serverConnMgrCfg, err := c.config.ConsulServerConnMgrConfig(taskMeta)
	if err != nil {
		return fmt.Errorf("constructing server connection manager config: %w", err)
	}

	watcher, err := discovery.NewWatcher(c.ctx, serverConnMgrCfg, c.log)
	if err != nil {
		return fmt.Errorf("unable to create consul server watcher: %w", err)
	}

	go watcher.Run()
	defer watcher.Stop()

	state, err := watcher.State()
	if err != nil {
		return fmt.Errorf("unable to fetch consul server watcher state: %w", err)
	}

	consulClient, err := c.setupConsulAPIClient(state)
	if err != nil {
		return fmt.Errorf("unable to setup Consul API client: %w", err)
	}

	if !c.isTestEnv {
		c.watcherCh = watcher.Subscribe()
	}

	var healthSyncContainers []string
	healthSyncContainers = append(healthSyncContainers, c.config.HealthSyncContainers...)
	healthSyncContainers = append(healthSyncContainers, config.ConsulDataplaneContainerName)
	currentHealthStatuses := make(map[string]string)

	c.checks, err = c.fetchHealthChecks(consulClient, taskMeta)
	if err != nil {
		return fmt.Errorf("unable to fetch checks before the reconciliation loop %w", err)
	}

	if c.isTestEnv {
		close(c.doneChan)
		<-c.proceedChan
	}

	// shuttingDown flag to prevent syncChecks after SIGTERM
	shuttingDown := false

	for {
		select {
		case <-time.After(syncChecksInterval):
			if !shuttingDown {
				currentHealthStatuses = c.syncChecks(consulClient, currentHealthStatuses, clusterARN, healthSyncContainers)
			}
		case watcherState := <-c.watcherCh:
			c.log.Info("Switching to Consul server", "address", watcherState.Address.String())
			client, err := c.setupConsulAPIClient(watcherState)
			if err != nil {
				c.log.Error("error re-configuring consul client %s", err.Error())
			} else {
				consulClient = client
			}
		case <-c.sigs:
			shuttingDown = true
			c.log.Info("Received SIGTERM. Beginning graceful shutdown by first marking all checks as critical.")
			err := c.setChecksCritical(consulClient, taskMeta, clusterARN, healthSyncContainers)
			if err != nil {
				c.log.Error("Error marking the status of checks as critical: %s", err.Error())
			}
		case <-c.dataplaneMonitor.done():
			var result error
			c.log.Info("Dataplane has successfully shutdown. Deregistering services and terminating health-sync")

			if c.config.IsGateway() {
				err = c.deregisterGatewayProxy(consulClient, taskMeta, clusterARN)
				if err != nil {
					c.log.Error("error deregistering gateway %s", err.Error())
					result = multierror.Append(result, err)
				}
			} else {
				err = c.deregisterServiceAndProxy(consulClient, taskMeta, clusterARN)
				if err != nil {
					c.log.Error("error deregistering service and proxy %s", err.Error())
					result = multierror.Append(result, err)
				}
			}

			if c.config.ConsulLogin.Enabled {
				_, err = consulClient.ACL().Logout(nil)
				if err != nil {
					c.log.Error("error logging out of consul %s", err.Error())
					result = multierror.Append(result, err)
				}
			}

			return result
		}
	}
}

func (c *Command) Synopsis() string {
	return "Syncs ECS container's health status into Consul"
}

func (c *Command) Help() string {
	return ""
}

func (c *Command) cleanup() {
	c.cancel()
}

func (c *Command) setupConsulAPIClient(state discovery.State) (*api.Client, error) {
	if c.isTestEnv && c.config.ConsulLogin.Enabled {
		tokenFile := filepath.Join(c.config.BootstrapDir, config.ServiceTokenFilename)
		err := os.WriteFile(tokenFile, []byte(state.Token), 0644)
		if err != nil {
			return nil, err
		}
	}

	// Client config for the client that talks directly to the server agent
	cfg := c.config.ClientConfig()
	cfg.Address = net.JoinHostPort(state.Address.IP.String(), strconv.FormatInt(int64(c.config.ConsulServers.HTTP.Port), 10))
	if state.Token != "" {
		cfg.Token = state.Token
	}

	return api.NewClient(cfg)
}

func (c *Command) deregisterServiceAndProxy(consulClient *api.Client, taskMeta awsutil.ECSTaskMeta, clusterARN string) error {
	var result error
	serviceName := c.constructServiceName(taskMeta.Family)
	taskID := taskMeta.TaskID()
	serviceID := makeServiceID(serviceName, taskID)

	service := c.config.Service.ToConsulType()

	err := deregisterConsulService(consulClient, serviceID, service.Namespace, service.Partition, clusterARN)
	if err != nil {
		result = multierror.Append(result, err)
	}

	// Proxy deregistration
	proxySvcID, _ := makeProxySvcIDAndName(serviceID, serviceName)
	err = deregisterConsulService(consulClient, proxySvcID, service.Namespace, service.Partition, clusterARN)
	if err != nil {
		result = multierror.Append(result, err)
	}

	return result
}

func (c *Command) deregisterGatewayProxy(consulClient *api.Client, taskMeta awsutil.ECSTaskMeta, clusterARN string) error {
	gatewaySvcName := c.constructServiceName(taskMeta.Family)
	taskID := taskMeta.TaskID()
	gatewaySvcID := makeServiceID(gatewaySvcName, taskID)

	gatewaySvc := c.config.Gateway.ToConsulType()

	return deregisterConsulService(consulClient, gatewaySvcID, gatewaySvc.Namespace, gatewaySvc.Partition, clusterARN)
}

func (c *Command) constructServiceName(family string) string {
	var configName string
	if c.config.IsGateway() {
		configName = c.config.Gateway.Name
	} else {
		configName = c.config.Service.Name
	}

	if configName == "" {
		return strings.ToLower(family)
	}
	return configName
}

func makeServiceID(serviceName, taskID string) string {
	return fmt.Sprintf("%s-%s", serviceName, taskID)
}

func makeProxySvcIDAndName(serviceID, serviceName string) (string, string) {
	fmtStr := "%s-sidecar-proxy"
	return fmt.Sprintf(fmtStr, serviceID), fmt.Sprintf(fmtStr, serviceName)
}

func deregisterConsulService(client *api.Client, svcID, namespace, partition, node string) error {
	deregInput := &api.CatalogDeregistration{
		Node:      node,
		ServiceID: svcID,
		Namespace: namespace,
		Partition: partition,
	}

	_, err := client.Catalog().Deregister(deregInput, nil)
	return err
}
