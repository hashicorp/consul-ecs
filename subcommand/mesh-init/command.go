// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package meshinit

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/logging"
	"github.com/hashicorp/consul-server-connection-manager/discovery"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

type Command struct {
	UI     cli.Ui
	config *config.Config
	log    hclog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	sigs   chan os.Signal
	once   sync.Once

	isHealthy bool
	checks    map[string]*api.HealthCheck

	// Following fields are only needed for unit tests

	// control plane signals to this channel whenever it has completed
	// registration of service and proxy to the server. Used only for unit tests
	doneChan chan struct{}

	// control plane waits for someone to signal to this channel before
	// entering the checks reconcilation loop. Used only for unit tests
	proceedChan chan struct{}

	// Indicates that the command is run from a unit test
	isTestEnv bool

	// Health check address assigned via unit tests
	healthCheckListenerAddr string
}

func (c *Command) init() {
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.sigs = make(chan os.Signal, 1)
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)

	// Register and start health check handler.
	go c.registerHealthCheckHandler()

	if len(args) > 0 {
		c.UI.Error(fmt.Sprintf("unexpected argument: %v", args[0]))
		return 1
	}

	config, err := config.FromEnv()
	if err != nil {
		c.UI.Error(fmt.Sprintf("invalid config: %s", err))
		return 1
	}
	c.config = config

	c.log = logging.FromConfig(c.config).Logger()

	err = c.realRun()
	if err != nil {
		c.log.Error(err.Error())
		return 1
	}
	return 0
}

func (c *Command) realRun() error {
	signal.Notify(c.sigs, syscall.SIGTERM)
	defer c.cleanup()

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
		return fmt.Errorf("constructing server connection manager config: %s", err)
	}

	watcher, err := discovery.NewWatcher(c.ctx, serverConnMgrCfg, c.log)
	if err != nil {
		return fmt.Errorf("unable to create consul server watcher: %s", err)
	}

	go watcher.Run()
	defer watcher.Stop()

	state, err := watcher.State()
	if err != nil {
		return fmt.Errorf("unable to fetch consul server watcher state: %s", err)
	}

	if c.config.ConsulLogin.Enabled {
		// If enabled write the ACL token to a shared volume so that consul-dataplane
		// can reuse it later on whenever it starts up
		tokenFile := filepath.Join(c.config.BootstrapDir, config.ServiceTokenFilename)
		err = os.WriteFile(tokenFile, []byte(state.Token), 0644)
		if err != nil {
			return err
		}

		c.log.Info("wrote ACL token to shared volume", "token-file", tokenFile)
	}

	// Client config for the client that talks directly to the server agent
	cfg := c.config.ClientConfig()
	cfg.Address = net.JoinHostPort(state.Address.IP.String(), strconv.FormatInt(int64(c.config.ConsulServers.HTTPPort), 10))
	if state.Token != "" {
		// In case the token is not replicated across the consul server followers, we might get a
		// `ACL token not found` error till the replication completes. Server connection manager
		// already implements a sleep that should mitigate this. If not, we should reintroduce the
		// `waitForReplication` method removed in https://github.com/hashicorp/consul-ecs/pull/143
		cfg.Token = state.Token
	}

	consulClient, err := api.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("constructing consul client from config: %s", err)
	}

	c.checks = make(map[string]*api.HealthCheck)

	var serviceRegistration, proxyRegistration *api.CatalogRegistration
	if c.config.Gateway != nil && c.config.Gateway.Kind != "" {
		proxyRegistration = c.constructGatewayProxyRegistration(taskMeta, clusterARN)
	} else {
		serviceRegistration = c.constructServiceRegistration(taskMeta, clusterARN)
		proxyRegistration = c.constructProxyRegistration(serviceRegistration, taskMeta, clusterARN)
	}

	if serviceRegistration != nil {
		// No need to register the service for gateways.
		err = backoff.RetryNotify(func() error {
			c.log.Info("registering service")
			_, regErr := consulClient.Catalog().Register(serviceRegistration, nil)
			return regErr
		}, backoff.NewConstantBackOff(1*time.Second), retryLogger(c.log))
		if err != nil {
			return err
		}

		c.log.Info("service registered successfully", "name", serviceRegistration.Service.Service, "id", serviceRegistration.Service.ID)
	}

	// Register the proxy.
	err = backoff.RetryNotify(func() error {
		c.log.Info("registering proxy", "kind", proxyRegistration.Service.Kind)
		_, regErr := consulClient.Catalog().Register(proxyRegistration, nil)
		return regErr
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(c.log))
	if err != nil {
		return err
	}

	c.log.Info("proxy registered successfully", "name", proxyRegistration.Service.Service, "id", proxyRegistration.Service.ID)

	err = c.copyECSBinaryToSharedVolume()
	if err != nil {
		return err
	}

	// Marking the control plane healthy so that ECS can start
	// other containers within the task depending on this.
	c.isHealthy = true

	serviceName := c.constructServiceName(taskMeta.Family)
	currentHealthStatuses := make(map[string]string)

	healthSyncContainers := make([]string, 0)
	healthSyncContainers = append(healthSyncContainers, c.config.HealthSyncContainers...)
	healthSyncContainers = append(healthSyncContainers, config.ConsulDataplaneContainerName)

	if c.isTestEnv {
		close(c.doneChan)
		<-c.proceedChan
	}

	// TODO: Handle graceful shutdown
	for {
		select {
		case <-time.After(syncChecksInterval):
			currentHealthStatuses = c.syncChecks(consulClient, currentHealthStatuses, serviceName, clusterARN, healthSyncContainers)
		case <-c.sigs:
			c.log.Debug("Received SIGTERM. Ignoring it for now and marking all the checks for the registered service as critical in the Consul server.")

			err := c.setChecksCritical(consulClient, taskMeta.TaskID(), serviceName, clusterARN, healthSyncContainers)
			if err != nil {
				c.log.Error("Error marking the status of checks as critical: %s", err.Error())
			}
		case <-c.ctx.Done():
			// TODO: Handle consul logout and service/proxy deregistration once dataplane shuts down
			return nil
		}
	}
}

func (c *Command) Synopsis() string {
	return "Initializes a mesh app"
}

func (c *Command) Help() string {
	return ""
}

func (c *Command) cleanup() {
	signal.Stop(c.sigs)
	// Cancel background goroutines
	c.cancel()
}

func retryLogger(log hclog.Logger) backoff.Notify {
	return func(err error, duration time.Duration) {
		log.Error(err.Error(), "retry", duration.String())
	}
}

// registerHealthCheckHandler registers a custom health check handler
// that indicates the control plane's readiness. The endpoint becomes
// healthy when the control plane successfully registers the service
// and proxy configurations and writes the dataplane's configuration
// to a shared volume.
func (c *Command) registerHealthCheckHandler() {
	mux := http.NewServeMux()
	mux.HandleFunc("/consul-ecs/health", c.handleHealthCheck)
	var handler http.Handler = mux

	listenerBindAddr := ":10000"
	if c.healthCheckListenerAddr != "" {
		listenerBindAddr = c.healthCheckListenerAddr
	}
	c.UI.Info(fmt.Sprintf("Listening on %q...", listenerBindAddr))
	if err := http.ListenAndServe(listenerBindAddr, handler); err != nil {
		c.UI.Error(fmt.Sprintf("Error listening: %s", err))
	}
}

func (c *Command) handleHealthCheck(rw http.ResponseWriter, _ *http.Request) {
	if !c.isHealthy {
		c.UI.Error("[GET /consul-ecs/health] consul-ecs control plane is not yet healthy")
		rw.WriteHeader(500)
		return
	}
	rw.WriteHeader(204)
}

// constructServiceName returns the service name for registration with Consul.
// This will use the config-provided name or, if not specified, default to the task family name.
// A lower case service name is required since the auth method relies on tokens with a service identity,
// and Consul service identities must be lower case:
//
// - The config-provided is validated by jsonschema to be lower case
// - When defaulting to the task family, this automatically lowercases the task family name
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

// constructServiceRegistration returns the service registration request body.
// May return an error due to invalid inputs from the config file.
func (c *Command) constructServiceRegistration(taskMeta awsutil.ECSTaskMeta, clusterARN string) *api.CatalogRegistration {
	serviceName := c.constructServiceName(taskMeta.Family)
	taskID := taskMeta.TaskID()
	serviceID := makeServiceID(serviceName, taskID)

	fullMeta := mergeMeta(map[string]string{
		"task-id":  taskID,
		"task-arn": taskMeta.TaskARN,
		"source":   "consul-ecs",
	}, c.config.Service.Meta)

	service := c.config.Service.ToConsulType()
	service.ID = serviceID
	service.Service = serviceName
	service.Meta = fullMeta

	return c.constructCatalogRegistrationPayload(service, taskMeta, clusterARN)
}

// constructProxyRegistration returns the proxy registration request body.
func (c *Command) constructProxyRegistration(serviceRegistration *api.CatalogRegistration, taskMeta awsutil.ECSTaskMeta, clusterARN string) *api.CatalogRegistration {
	proxySvcID, proxySvcName := makeProxySvcIDAndName(serviceRegistration.Service.ID, serviceRegistration.Service.Service)
	proxyService := &api.AgentService{
		ID:                proxySvcID,
		Service:           proxySvcName,
		Kind:              api.ServiceKindConnectProxy,
		Port:              c.config.Proxy.GetPublicListenerPort(),
		Meta:              serviceRegistration.Service.Meta,
		Tags:              serviceRegistration.Service.Tags,
		Proxy:             c.config.Proxy.ToConsulType(),
		Partition:         serviceRegistration.Service.Partition,
		Namespace:         serviceRegistration.Service.Namespace,
		Weights:           serviceRegistration.Service.Weights,
		EnableTagOverride: serviceRegistration.Service.EnableTagOverride,
	}

	proxyService.Proxy.DestinationServiceID = serviceRegistration.Service.ID
	proxyService.Proxy.DestinationServiceName = serviceRegistration.Service.Service
	proxyService.Proxy.LocalServicePort = serviceRegistration.Service.Port

	return c.constructCatalogRegistrationPayload(proxyService, taskMeta, clusterARN)
}

func (c *Command) constructGatewayProxyRegistration(taskMeta awsutil.ECSTaskMeta, clusterARN string) *api.CatalogRegistration {
	serviceName := c.constructServiceName(taskMeta.Family)

	taskID := taskMeta.TaskID()
	serviceID := makeServiceID(serviceName, taskID)

	gatewaySvc := c.config.Gateway.ToConsulType()
	gatewaySvc.ID = serviceID
	gatewaySvc.Service = serviceName
	gatewaySvc.Meta = mergeMeta(map[string]string{
		"task-id":  taskID,
		"task-arn": taskMeta.TaskARN,
		"source":   "consul-ecs",
	}, c.config.Gateway.Meta)

	taggedAddresses := make(map[string]api.ServiceAddress)

	// Default the LAN port if it was not provided.
	gatewaySvc.Port = config.DefaultGatewayPort

	if c.config.Gateway.LanAddress != nil {
		lanAddr := c.config.Gateway.LanAddress.ToConsulType()
		// If a LAN address is provided then use that and add the LAN address to the tagged addresses.
		if lanAddr.Port > 0 {
			gatewaySvc.Port = lanAddr.Port
		}
		if lanAddr.Address != "" {
			gatewaySvc.Address = lanAddr.Address
			taggedAddresses[config.TaggedAddressLAN] = lanAddr
		}
	}

	// TODO if assign_public_ip is set and the WAN address is not provided then
	// we need to find the Public IP of the task (or LB) and use that for the WAN address.
	if c.config.Gateway.WanAddress != nil {
		wanAddr := c.config.Gateway.WanAddress.ToConsulType()
		if wanAddr.Address != "" {
			if wanAddr.Port == 0 {
				wanAddr.Port = gatewaySvc.Port
			}
			taggedAddresses[config.TaggedAddressWAN] = wanAddr
		}
	}
	if len(taggedAddresses) > 0 {
		gatewaySvc.TaggedAddresses = taggedAddresses
	}

	return c.constructCatalogRegistrationPayload(gatewaySvc, taskMeta, clusterARN)
}

func (c *Command) constructCatalogRegistrationPayload(service *api.AgentService, taskMeta awsutil.ECSTaskMeta, clusterARN string) *api.CatalogRegistration {
	return &api.CatalogRegistration{
		Node:           clusterARN,
		NodeMeta:       getNodeMeta(),
		Address:        taskMeta.NodeIP(),
		Service:        service,
		Checks:         c.constructChecks(service),
		Partition:      service.Partition,
		SkipNodeUpdate: true,
	}
}

// copyECSBinaryToSharedVolume copies the consul-ecs binary to a volume.
// This can be later used to perform health checks against envoy's public
// listener port with the `netdial` command
func (c *Command) copyECSBinaryToSharedVolume() error {
	ex, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(ex)
	if err != nil {
		return err
	}

	copyConsulECSBinary := path.Join(c.config.BootstrapDir, "consul-ecs")
	err = os.WriteFile(copyConsulECSBinary, data, 0755)
	if err != nil {
		return err
	}
	c.log.Info("copied binary", "file", copyConsulECSBinary)
	return nil
}

func getNodeMeta() map[string]string {
	return map[string]string{
		config.SyntheticNode: "true",
	}
}

func makeServiceID(serviceName, taskID string) string {
	return fmt.Sprintf("%s-%s", serviceName, taskID)
}

func makeProxySvcIDAndName(serviceID, serviceName string) (string, string) {
	fmtStr := "%s-sidecar-proxy"
	return fmt.Sprintf(fmtStr, serviceID), fmt.Sprintf(fmtStr, serviceName)
}

func mergeMeta(m1, m2 map[string]string) map[string]string {
	result := make(map[string]string)

	for k, v := range m1 {
		result[k] = v
	}

	for k, v := range m2 {
		result[k] = v
	}

	return result
}
