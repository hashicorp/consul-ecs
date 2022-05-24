package meshinit

import (
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
	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		return err
	}

	cfg := api.DefaultConfig()

	if c.config.ConsulLogin.Enabled {
		// If enabled, login to the auth method to obtain an ACL token.
		tokenFile := filepath.Join(c.config.BootstrapDir, config.ServiceTokenFilename)
		if err := c.loginToAuthMethod(tokenFile, taskMeta); err != nil {
			return err
		}
		cfg.TokenFile = tokenFile

		// The just-created token is not immediately replicated to Consul server followers.
		// Mitigate against this by waiting for the token in stale consistency mode.
		if err := c.waitForTokenReplication(tokenFile); err != nil {
			return err
		}
	}

	consulClient, err := api.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("constructing consul client: %s", err)
	}

	var serviceRegistration, proxyRegistration *api.AgentServiceRegistration
	if c.config.Gateway != nil && c.config.Gateway.Kind != "" {
		proxyRegistration, err = c.constructGatewayProxyRegistration(taskMeta)
		if err != nil {
			return err
		}
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

// loginToAuthMethod runs a 'consul login' command to obtain a token.
// The login command is skipped if LogintOptions is not set in the
// consul-ecs config JSON, in order to support non-ACL deployments.
func (c *Command) loginToAuthMethod(tokenFile string, taskMeta awsutil.ECSTaskMeta) error {
	loginOpts, err := c.constructLoginCmd(tokenFile, taskMeta)
	if err != nil {
		return err
	}

	return backoff.RetryNotify(func() error {
		// We'll get errors until the consul binary is copied to the volume ("fork/exec: text file busy")
		c.log.Debug("login", "cmd", fmt.Sprint(loginOpts))
		cmd := exec.Command("consul", loginOpts...)
		out, err := cmd.CombinedOutput()
		// TODO: Distinguish unrecoverable errors, like lack of permission to log in.
		if out != nil && err != nil {
			c.log.Error("login", "output", string(out))
		} else if out != nil {
			c.log.Debug("login", "output", string(out))
		}
		if err != nil {
			c.log.Error(err.Error())
			return err
		}
		c.log.Info("login success")
		return nil
	}, backoff.NewConstantBackOff(2*time.Second), retryLogger(c.log))
}

func (c *Command) waitForTokenReplication(tokenFile string) error {
	// A workaround to check that the ACL token is replicated to other Consul servers.
	// Code borrowed from: https://github.com/hashicorp/consul-k8s/pull/887
	//
	// This problem can potentially occur because of:
	//
	// - Replication lag: After a token is created on the Consul server leader it may take up to
	//   100ms (typically) for the token to be replicated to server followers:
	//   https://www.consul.io/docs/install/performance#read-write-tuning
	// - Stale consistency mode: Consul clients may connect to a Consul server follower, which may
	//   have stale state, in order to reduce load on the server leader.
	// - Negative caching: When a Consul server validates a token, if the server does know about the
	//   token (e.g. due to replication lag), then an "ACL not found" response is cached. By default,
	//   the cache time is 30s: https://www.consul.io/docs/agent/config/config-files#acl_token_ttl.
	// - Sticky connections: Consul clients maintain a connection to a single Consul server, and
	//   these connections are only rebalanced every 2-3 mins.
	//
	// Therefore, an "ACL not found" error may be cached just after token creation. When this
	// happens, the token will be unusable for the acl_token_ttl (30s by default). Retrying requests
	// won't help since client likely won't change Consul servers for a potentially longer time
	// (2-3 min). If you are running 3 Consul servers, you have a 2/3 chance to hit a follower and
	// encounter this problem, so this is a potentially frequent problem.
	//
	// We don't want to delay start up by the "long" cache time (default 30s). Instead, we wait
	// for the token to be read successfully in stale consistency mode, which should take <=100ms since
	// that is the typical Raft replication time.
	//
	// The does not eliminate this problem completely. It's still possible for this call and the
	// next call to reach different servers and those servers to have different states from each
	// other, but this is unlikely since clients use sticky connections.

	// Mesh-init talks to the local Consul client agent (for now). We need this to hit the Consul
	// server(s) directly.
	newCfg := api.DefaultConfig()
	newCfg.Address = c.config.ConsulHTTPAddr
	newCfg.TLSConfig.CAFile = c.config.ConsulCACertFile
	newCfg.TokenFile = tokenFile

	client, err := api.NewClient(newCfg)
	if err != nil {
		return err
	}

	c.log.Info("Checking that the ACL token exists when reading it in the stale consistency mode")
	// Use raft timeout and polling interval to determine the number of retries.
	numTokenReadRetries := uint64(raftReplicationTimeout.Milliseconds() / tokenReadPollingInterval.Milliseconds())
	err = backoff.Retry(func() error {
		_, _, err := client.ACL().TokenReadSelf(&api.QueryOptions{AllowStale: true})
		if err != nil {
			c.log.Error("Unable to read ACL token; retrying", "err", err)
		}
		return err
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(tokenReadPollingInterval), numTokenReadRetries))
	if err != nil {
		c.log.Error("Unable to read ACL token from a Consul server; "+
			"please check that your server cluster is healthy", "err", err)
		return err
	}
	c.log.Info("Successfully read ACL token from the server")
	return nil
}

func (c *Command) constructLoginCmd(tokenFile string, taskMeta awsutil.ECSTaskMeta) ([]string, error) {
	method := c.config.ConsulLogin.Method
	if method == "" {
		method = config.DefaultAuthMethodName
	}
	region, err := taskMeta.Region()
	if err != nil {
		return nil, err
	}

	loginOpts := []string{
		"login", "-type", "aws", "-method", method,
		// NOTE: If -http-addr and -ca-file are empty strings, Consul ignores them.
		// The -http-addr flag will default to the local Consul client.
		"-http-addr", c.config.ConsulHTTPAddr,
		"-ca-file", c.config.ConsulCACertFile,
		"-token-sink-file", tokenFile,
		"-meta", fmt.Sprintf("consul.hashicorp.com/task-id=%s", taskMeta.TaskID()),
		"-meta", fmt.Sprintf("consul.hashicorp.com/cluster=%s", taskMeta.Cluster),
		"-aws-region", region,
		"-aws-auto-bearer-token",
	}
	if c.config.ConsulLogin.IncludeEntity {
		loginOpts = append(loginOpts, "-aws-include-entity")
	}
	if len(c.config.ConsulLogin.ExtraLoginFlags) > 0 {
		loginOpts = append(loginOpts, c.config.ConsulLogin.ExtraLoginFlags...)
	}
	return loginOpts, nil
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

func (c *Command) constructServiceName(family string) string {
	configName := c.config.Service.Name
	if configName == "" {
		return family
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
	proxyRegistration.Port = 20000
	proxyRegistration.Meta = serviceRegistration.Meta
	proxyRegistration.Tags = serviceRegistration.Tags
	proxyRegistration.Proxy = c.config.Proxy.ToConsulType()
	proxyRegistration.Proxy.DestinationServiceName = serviceRegistration.Name
	proxyRegistration.Proxy.DestinationServiceID = serviceRegistration.ID
	proxyRegistration.Proxy.LocalServicePort = serviceRegistration.Port
	proxyRegistration.Checks = []*api.AgentServiceCheck{
		{
			Name:                           "Proxy Public Listener",
			TCP:                            "127.0.0.1:20000",
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

func (c *Command) constructGatewayProxyRegistration(taskMeta awsutil.ECSTaskMeta) (*api.AgentServiceRegistration, error) {
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
	// we need to find the Public IP of the task and use that for the WAN address.
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

	// Health check localhost (default) or the LAN address if specified.
	healthCheckAddr := api.ServiceAddress{
		Address: taskMeta.NodeIP(),
		Port:    gwRegistration.Port,
	}
	if gwRegistration.Address != "" {
		healthCheckAddr.Address = gwRegistration.Address
	}

	// TODO if the WAN address is provided, should add a health check for the WAN addr as well?
	gwRegistration.Checks = []*api.AgentServiceCheck{
		{
			Name:                           fmt.Sprintf("%s listener", gwRegistration.Kind),
			TCP:                            net.JoinHostPort(healthCheckAddr.Address, fmt.Sprint(healthCheckAddr.Port)),
			Interval:                       "10s",
			DeregisterCriticalServiceAfter: "10m",
		},
	}
	return gwRegistration, nil
}
