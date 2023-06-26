// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package meshinit

import (
	"context"
	"fmt"
	"os"
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

	clusterARN, err := taskMeta.ClusterARN()
	if err != nil {
		return err
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

		c.log.Info("wrote ACL token to shared volume", "token-file", tokenFile)
	}

	// Client config for the client that talks directly to the server agent
	cfg := c.config.ClientConfig()
	cfg.Address = fmt.Sprintf("%s:%d", state.Address.IP.String(), c.config.ConsulServers.HTTPPort)
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

// constructServiceRegistration returns the service registration request body.
// May return an error due to invalid inputs from the config file.
func (c *Command) constructServiceRegistration(taskMeta awsutil.ECSTaskMeta, clusterARN string) *api.CatalogRegistration {
	serviceName := c.constructServiceName(taskMeta.Family)
	taskID := taskMeta.TaskID()
	serviceID := fmt.Sprintf("%s-%s", serviceName, taskID)

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
	proxyService := &api.AgentService{
		ID:                fmt.Sprintf("%s-sidecar-proxy", serviceRegistration.Service.ID),
		Service:           fmt.Sprintf("%s-sidecar-proxy", serviceRegistration.Service.Service),
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
	serviceName := c.config.Gateway.Name
	if serviceName == "" {
		serviceName = taskMeta.Family
	}

	taskID := taskMeta.TaskID()
	serviceID := fmt.Sprintf("%s-%s", serviceName, taskID)

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

func getNodeMeta() map[string]string {
	return map[string]string{
		config.SyntheticNode:    "true",
		config.ECSSyntheticNode: "true",
	}
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
