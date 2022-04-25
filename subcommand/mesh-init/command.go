package meshinit

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
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
	}

	consulClient, err := api.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("constructing consul client: %s", err)
	}

	serviceRegistration, err := c.constructServiceRegistration(taskMeta)
	if err != nil {
		return err
	}
	err = backoff.RetryNotify(func() error {
		c.log.Info("registering service")
		return consulClient.Agent().ServiceRegister(serviceRegistration)
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(c.log))
	if err != nil {
		return err
	}

	// Register the proxy.
	proxyRegistration := c.constructProxyRegistration(serviceRegistration)
	err = backoff.RetryNotify(func() error {
		c.log.Info("registering proxy")
		return consulClient.Agent().ServiceRegister(proxyRegistration)
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(c.log))
	if err != nil {
		return err
	}

	c.log.Info("service and proxy registered successfully", "name", serviceRegistration.Name, "id", serviceRegistration.ID)

	// Run consul envoy -bootstrap to generate bootstrap file.
	connectArgs := []string{"connect", "envoy", "-proxy-id", proxyRegistration.ID, "-bootstrap", "-grpc-addr=localhost:8502"}
	if c.config.ConsulLogin.Enabled {
		connectArgs = append(connectArgs, "-token-file", cfg.TokenFile)
	}
	if serviceRegistration.Partition != "" {
		// Partition/namespace support is enabled so augment the connect command.
		connectArgs = append(connectArgs,
			"-partition", serviceRegistration.Partition,
			"-namespace", serviceRegistration.Namespace)
	}

	cmd := exec.Command("consul", connectArgs...)
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
	loginOpts := c.constructLoginCmd(tokenFile, taskMeta)

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

func (c *Command) constructLoginCmd(tokenFile string, taskMeta awsutil.ECSTaskMeta) []string {
	method := c.config.ConsulLogin.Method
	if method == "" {
		method = config.DefaultAuthMethodName
	}
	loginOpts := []string{
		"login", "-type", "aws", "-method", method,
		// NOTE: If http-addr and ca-file are empty strings, Consul ignores them.
		// It will default to using the logging in with local Consul client.
		"-http-addr", c.config.ConsulHTTPAddr,
		"-ca-file", c.config.ConsulCACertFile,
		"-token-sink-file", tokenFile,
		"-meta", fmt.Sprintf("consul.hashicorp.com/task-id=%s", taskMeta.TaskID()),
		"-meta", fmt.Sprintf("consul.hashicorp.com/cluster=%s", taskMeta.Cluster),
		"-aws-auto-bearer-token",
	}
	if c.config.ConsulLogin.IncludeEntity {
		loginOpts = append(loginOpts, "-aws-include-entity")
	}
	if len(c.config.ConsulLogin.ExtraLoginFlags) > 0 {
		loginOpts = append(loginOpts, c.config.ConsulLogin.ExtraLoginFlags...)
	}
	return loginOpts
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
				Notes:   "consul-ecs created and updates this check because the ${containerName} container is essential and has an ECS health check.",
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
