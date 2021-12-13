package meshinit

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
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
	once   sync.Once
	log    hclog.Logger
}

func (c *Command) init() {
	c.log = hclog.New(nil)
}

func (c *Command) Run(_ []string) int {
	c.once.Do(c.init)

	config, err := config.FromEnv()
	if err != nil {
		c.UI.Error(fmt.Sprintf("invalid config: %s", err))
		return 1
	}
	c.config = config

	if c.config.Mesh.BootstrapDir == "" {
		c.UI.Error("config value mesh.bootstrapDir must be set")
		return 1
	}

	err = c.realRun()
	if err != nil {
		c.log.Error(err.Error())
		return 1
	}
	return 0
}

func (c *Command) realRun() error {
	cfg := api.DefaultConfig()
	consulClient, err := api.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("constructing consul client: %s", err)
	}
	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		return err
	}

	serviceName := c.constructServiceName(taskMeta.Family)

	// Register the service.
	taskID := taskMeta.TaskID()
	serviceID := fmt.Sprintf("%s-%s", serviceName, taskID)

	checks, err := constructChecks(serviceID, c.config.Mesh.Service.Checks, c.config.Mesh.HealthSyncContainers)
	if err != nil {
		return err
	}

	fullMeta := mergeMeta(map[string]string{
		"task-id":  taskID,
		"task-arn": taskMeta.TaskARN,
		"source":   "consul-ecs",
	}, c.config.Mesh.Service.Meta)

	serviceRegistration := c.config.Mesh.Service.ToConsulType()
	serviceRegistration.ID = serviceID
	serviceRegistration.Name = serviceName
	serviceRegistration.Meta = fullMeta
	serviceRegistration.Checks = nil
	for _, check := range checks {
		serviceRegistration.Checks = append(serviceRegistration.Checks, check.ToConsulType())
	}

	err = backoff.RetryNotify(func() error {
		c.log.Info("registering service")
		return consulClient.Agent().ServiceRegister(serviceRegistration)
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(c.log))
	if err != nil {
		return err
	}

	// Register the proxy.
	proxyRegistration := c.config.Mesh.Sidecar.ToConsulType()
	proxyRegistration.ID = fmt.Sprintf("%s-sidecar-proxy", serviceRegistration.ID)
	proxyRegistration.Name = fmt.Sprintf("%s-sidecar-proxy", serviceRegistration.Name)
	proxyRegistration.Kind = api.ServiceKindConnectProxy
	proxyRegistration.Port = 20000
	proxyRegistration.Meta = serviceRegistration.Meta
	proxyRegistration.Tags = serviceRegistration.Tags
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
			AliasService: serviceID,
		},
	}
	proxyRegistration.Namespace = serviceRegistration.Namespace
	proxyRegistration.Weights = serviceRegistration.Weights
	proxyRegistration.EnableTagOverride = serviceRegistration.EnableTagOverride

	err = backoff.RetryNotify(func() error {
		c.log.Info("registering proxy")
		return consulClient.Agent().ServiceRegister(proxyRegistration)
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(c.log))
	if err != nil {
		return err
	}

	c.log.Info("service and proxy registered successfully", "name", serviceRegistration.Name, "id", serviceRegistration.ID)

	// Run consul envoy -bootstrap to generate bootstrap file.
	cmd := exec.Command("consul", "connect", "envoy", "-proxy-id", proxyRegistration.ID, "-bootstrap", "-grpc-addr=localhost:8502")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}

	envoyBootstrapFile := path.Join(c.config.Mesh.BootstrapDir, envoyBoostrapConfigFilename)
	err = ioutil.WriteFile(envoyBootstrapFile, out, 0444)
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
	data, err := ioutil.ReadFile(ex)
	if err != nil {
		return err
	}

	copyConsulECSBinary := path.Join(c.config.Mesh.BootstrapDir, "consul-ecs")
	err = ioutil.WriteFile(copyConsulECSBinary, data, 0755)
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
		return nil, fmt.Errorf("only one of mesh.checks or mesh.healthSyncContainers should be set")
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
	configName := c.config.Mesh.Service.Name
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
