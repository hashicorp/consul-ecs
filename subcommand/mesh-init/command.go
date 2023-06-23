// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package meshinit

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
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

const (
	envoyBoostrapConfigFilename = "envoy-bootstrap.json"
	raftReplicationTimeout      = 2 * time.Second
	tokenReadPollingInterval    = 100 * time.Millisecond
)

type Command struct {
	UI     cli.Ui
	config *config.Config
	log    hclog.Logger
}

func (c *Command) Run(args []string) int {
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		return err
	}

	cfg := api.DefaultConfig()

	// TODO: This client needs to be removed when we start
	// registering services directly talking to the server
	consulClient, err := api.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("constructing consul client: %s", err)
	}

	serverConnMgrCfg, err := c.config.ConsulServerConnMgrConfig(taskMeta)
	if err != nil {
		return fmt.Errorf("constructing server connection manager config: %s", err)
	}

	watcher, err := discovery.NewWatcher(ctx, serverConnMgrCfg, c.log)
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

		// Temporary workaround so that unit tests relying on the
		// previous version of the client (that talks through agents)
		// can pass.
		// TODO: Remove this after getting rid of the older version of the client
		cfg.TokenFile = tokenFile

		c.log.Info("wrote ACL token to shared volume", "token-file", tokenFile)
	}

	// Client config for the V2 client that talks directly to the
	// server agent
	consulClientCfg := c.config.ClientConfig()
	consulClientCfg.Address = fmt.Sprintf("%s:%d", state.Address.IP.String(), c.config.ConsulServers.HTTPPort)
	if state.Token != "" {
		// In case the token is not replicated across the consul server followers, we might get a
		// `ACL token not found` error till the replication completes. Server connection manager
		// already implements a sleep that should mitigate this. If not, we should reintroduce the
		// `waitForReplication` method removed in https://github.com/hashicorp/consul-ecs/pull/143
		consulClientCfg.Token = state.Token
	}

	_, err = api.NewClient(consulClientCfg)
	if err != nil {
		return fmt.Errorf("constructing consul client from config: %s", err)
	}

	var serviceRegistration, proxyRegistration *api.AgentServiceRegistration
	if c.config.Gateway != nil && c.config.Gateway.Kind != "" {
		proxyRegistration = c.constructGatewayProxyRegistration(taskMeta)
	} else {
		serviceRegistration, err = c.constructServiceRegistration(taskMeta)
		if err != nil {
			return err
		}
		proxyRegistration = c.constructProxyRegistration(serviceRegistration)
	}

	if serviceRegistration != nil {
		// No need to register the service for gateways.
		err = backoff.RetryNotify(func() error {
			c.log.Info("registering service")
			return consulClient.Agent().ServiceRegister(serviceRegistration)
		}, backoff.NewConstantBackOff(1*time.Second), retryLogger(c.log))
		if err != nil {
			return err
		}

		c.log.Info("service registered successfully", "name", serviceRegistration.Name, "id", serviceRegistration.ID)
	}

	// Register the proxy.
	err = backoff.RetryNotify(func() error {
		c.log.Info("registering proxy", "kind", proxyRegistration.Kind)
		return consulClient.Agent().ServiceRegister(proxyRegistration)
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(c.log))
	if err != nil {
		return err
	}

	c.log.Info("proxy registered successfully", "name", proxyRegistration.Name, "id", proxyRegistration.ID)

	// Run consul envoy -bootstrap to generate bootstrap file.
	cmdArgs := []string{
		"consul", "connect", "envoy", "-proxy-id", proxyRegistration.ID, "-bootstrap", "-grpc-addr=localhost:8502",
	}
	if c.config.Gateway != nil && c.config.Gateway.Kind != "" {
		kind := strings.ReplaceAll(string(c.config.Gateway.Kind), "-gateway", "")
		cmdArgs = append(cmdArgs, "-gateway", kind)
	}
	if c.config.ConsulLogin.Enabled {
		cmdArgs = append(cmdArgs, "-token-file", cfg.TokenFile)
	}
	if proxyRegistration.Partition != "" {
		// Partition/namespace support is enabled so augment the connect command.
		cmdArgs = append(cmdArgs,
			"-partition", proxyRegistration.Partition,
			"-namespace", proxyRegistration.Namespace)
	}

	c.log.Info("Running", "cmd", cmdArgs)
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}

	envoyBootstrapFile := path.Join(c.config.BootstrapDir, envoyBoostrapConfigFilename)
	err = os.WriteFile(envoyBootstrapFile, out, 0444)
	if err != nil {
		return err
	}

	c.log.Info("envoy bootstrap config written", "file", envoyBootstrapFile)

	// Copy this binary to a volume for use in the sidecar-proxy container.
	// This copies to the same place as we write the envoy bootstrap file, for now.
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

func (c *Command) Synopsis() string {
	return "Initializes a mesh app"
}

func (c *Command) Help() string {
	return ""
}

func retryLogger(log hclog.Logger) backoff.Notify {
	return func(err error, duration time.Duration) {
		log.Error(err.Error(), "retry", duration.String())
	}
}

func constructChecks(serviceID string, checks []config.AgentServiceCheck, healthSyncContainers []string) ([]config.AgentServiceCheck, error) {
	if len(checks) > 0 && len(healthSyncContainers) > 0 {
		return nil, fmt.Errorf("only one of service.checks or healthSyncContainers should be set")
	}

	if len(healthSyncContainers) > 0 {
		for _, containerName := range healthSyncContainers {
			checks = append(checks, config.AgentServiceCheck{
				CheckID: fmt.Sprintf("%s-%s-consul-ecs", serviceID, containerName),
				Name:    "consul ecs synced",
				Notes:   fmt.Sprintf("consul-ecs created and updates this check because the %s container is essential and has an ECS health check.", containerName),
				TTL:     "100000h",
			})
		}
	}
	return checks, nil
}

// constructServiceName returns the service name for registration with Consul.
// This will use the config-provided name or, if not specified, default to the task family name.
// A lower case service name is required since the auth method relies on tokens with a service identity,
// and Consul service identities must be lower case:
//
// - The config-provided is validated by jsonschema to be lower case
// - When defaulting to the task family, this automatically lowercases the task family name
func (c *Command) constructServiceName(family string) string {
	configName := c.config.Service.Name
	if configName == "" {
		return strings.ToLower(family)
	}
	return configName
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

// constructServiceRegistration returns the service registration request body.
// May return an error due to invalid inputs from the config file.
func (c *Command) constructServiceRegistration(taskMeta awsutil.ECSTaskMeta) (*api.AgentServiceRegistration, error) {
	serviceName := c.constructServiceName(taskMeta.Family)
	taskID := taskMeta.TaskID()
	serviceID := fmt.Sprintf("%s-%s", serviceName, taskID)
	checks, err := constructChecks(serviceID, c.config.Service.Checks, c.config.HealthSyncContainers)
	if err != nil {
		return nil, err
	}

	fullMeta := mergeMeta(map[string]string{
		"task-id":  taskID,
		"task-arn": taskMeta.TaskARN,
		"source":   "consul-ecs",
	}, c.config.Service.Meta)

	serviceRegistration := c.config.Service.ToConsulType()
	serviceRegistration.ID = serviceID
	serviceRegistration.Name = serviceName
	serviceRegistration.Meta = fullMeta
	serviceRegistration.Checks = nil
	for _, check := range checks {
		serviceRegistration.Checks = append(serviceRegistration.Checks, check.ToConsulType())
	}
	return serviceRegistration, nil
}

// constructProxyRegistration returns the proxy registration request body.
func (c *Command) constructProxyRegistration(serviceRegistration *api.AgentServiceRegistration) *api.AgentServiceRegistration {
	proxyRegistration := &api.AgentServiceRegistration{}
	proxyRegistration.ID = fmt.Sprintf("%s-sidecar-proxy", serviceRegistration.ID)
	proxyRegistration.Name = fmt.Sprintf("%s-sidecar-proxy", serviceRegistration.Name)
	proxyRegistration.Kind = api.ServiceKindConnectProxy
	proxyRegistration.Port = c.config.Proxy.GetPublicListenerPort()
	proxyRegistration.Meta = serviceRegistration.Meta
	proxyRegistration.Tags = serviceRegistration.Tags
	proxyRegistration.Proxy = c.config.Proxy.ToConsulType()
	proxyRegistration.Proxy.DestinationServiceName = serviceRegistration.Name
	proxyRegistration.Proxy.DestinationServiceID = serviceRegistration.ID
	proxyRegistration.Proxy.LocalServicePort = serviceRegistration.Port
	proxyRegistration.Checks = []*api.AgentServiceCheck{
		{
			Name:                           "Proxy Public Listener",
			TCP:                            fmt.Sprintf("127.0.0.1:%d", proxyRegistration.Port),
			Interval:                       "10s",
			DeregisterCriticalServiceAfter: "10m",
		},
		{
			Name:         "Destination Alias",
			AliasService: serviceRegistration.ID,
		},
	}
	proxyRegistration.Partition = serviceRegistration.Partition
	proxyRegistration.Namespace = serviceRegistration.Namespace
	proxyRegistration.Weights = serviceRegistration.Weights
	proxyRegistration.EnableTagOverride = serviceRegistration.EnableTagOverride
	return proxyRegistration
}

func (c *Command) constructGatewayProxyRegistration(taskMeta awsutil.ECSTaskMeta) *api.AgentServiceRegistration {
	serviceName := c.config.Gateway.Name
	if serviceName == "" {
		serviceName = taskMeta.Family
	}

	taskID := taskMeta.TaskID()
	serviceID := fmt.Sprintf("%s-%s", serviceName, taskID)

	gwRegistration := c.config.Gateway.ToConsulType()
	gwRegistration.ID = serviceID
	gwRegistration.Name = serviceName
	gwRegistration.Meta = mergeMeta(map[string]string{
		"task-id":  taskID,
		"task-arn": taskMeta.TaskARN,
		"source":   "consul-ecs",
	}, c.config.Gateway.Meta)

	taggedAddresses := make(map[string]api.ServiceAddress)

	// Default the LAN port if it was not provided.
	gwRegistration.Port = config.DefaultGatewayPort

	if c.config.Gateway.LanAddress != nil {
		lanAddr := c.config.Gateway.LanAddress.ToConsulType()
		// If a LAN address is provided then use that and add the LAN address to the tagged addresses.
		if lanAddr.Port > 0 {
			gwRegistration.Port = lanAddr.Port
		}
		if lanAddr.Address != "" {
			gwRegistration.Address = lanAddr.Address
			taggedAddresses[config.TaggedAddressLAN] = lanAddr
		}
	}

	// TODO if assign_public_ip is set and the WAN address is not provided then
	// we need to find the Public IP of the task (or LB) and use that for the WAN address.
	if c.config.Gateway.WanAddress != nil {
		wanAddr := c.config.Gateway.WanAddress.ToConsulType()
		if wanAddr.Address != "" {
			if wanAddr.Port == 0 {
				wanAddr.Port = gwRegistration.Port
			}
			taggedAddresses[config.TaggedAddressWAN] = wanAddr
		}
	}
	if len(taggedAddresses) > 0 {
		gwRegistration.TaggedAddresses = taggedAddresses
	}

	// Health check the task's IP, or the LAN address if specified.
	healthCheckAddr := api.ServiceAddress{
		Address: taskMeta.NodeIP(),
		Port:    gwRegistration.Port,
	}
	if gwRegistration.Address != "" {
		healthCheckAddr.Address = gwRegistration.Address
	}

	gwRegistration.Checks = []*api.AgentServiceCheck{
		{
			Name:                           fmt.Sprintf("%s listener", gwRegistration.Kind),
			TCP:                            net.JoinHostPort(healthCheckAddr.Address, fmt.Sprint(healthCheckAddr.Port)),
			Interval:                       "10s",
			DeregisterCriticalServiceAfter: "10m",
		},
	}
	return gwRegistration
}
