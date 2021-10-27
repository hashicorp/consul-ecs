package meshinit

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

const (
	flagEnvoyBootstrapDir    = "envoy-bootstrap-dir"
	flagPort                 = "port"
	flagTags                 = "tags"
	flagMeta                 = "meta"
	flagServiceName          = "service-name"
	flagUpstreams            = "upstreams"
	flagChecks               = "checks"
	flagHealthSyncContainers = "health-sync-containers"

	envoyBoostrapConfigFilename = "envoy-bootstrap.json"
)

type Command struct {
	UI cli.Ui

	flagEnvoyBootstrapDir    string
	flagPort                 int
	flagServiceName          string
	flagTags                 string
	flagMeta                 string
	flagUpstreams            string
	flagChecks               string
	flagHealthSyncContainers string

	flagSet *flag.FlagSet
	once    sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagEnvoyBootstrapDir, flagEnvoyBootstrapDir, "",
		"Directory for Envoy startup files. The envoy-bootstrap.json and the consul-ecs binary are written here.")
	c.flagSet.IntVar(&c.flagPort, flagPort, 0, "Port service runs on")
	c.flagSet.StringVar(&c.flagUpstreams, flagUpstreams, "", "Upstreams in form <name>:<port>,...")
	c.flagSet.StringVar(&c.flagChecks, flagChecks, "", "List of Consul checks in JSON form")
	c.flagSet.StringVar(&c.flagHealthSyncContainers, flagHealthSyncContainers, "",
		"A comma separated list of container names that need Consul TTL checks")
	c.flagSet.StringVar(&c.flagTags, flagTags, "", "Tags for the Consul service as a comma separated string")
	c.flagSet.StringVar(&c.flagMeta, flagMeta, "", "Metadata for the Consul service as a JSON string")
	c.flagSet.StringVar(&c.flagServiceName, flagServiceName, "",
		"Name of the service that will be registered with Consul. If not provided, the task family will be used as the service name.")
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)
	if err := c.flagSet.Parse(args); err != nil {
		return 1
	}
	if c.flagEnvoyBootstrapDir == "" {
		c.UI.Error(fmt.Sprintf("-%s must be set", flagEnvoyBootstrapDir))
		return 1
	}

	log := hclog.New(nil)
	err := c.realRun(log)
	if err != nil {
		log.Error(err.Error())
		return 1
	}
	return 0
}

func (c *Command) realRun(log hclog.Logger) error {
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

	checks, err := constructChecks(serviceID, c.flagChecks, c.flagHealthSyncContainers)

	if err != nil {
		return err
	}

	tags, err := c.constructTags()

	if err != nil {
		return err
	}

	meta, err := c.constructMeta()

	if err != nil {
		return err
	}

	fullMeta := mergeMeta(map[string]string{
		"task-id":  taskID,
		"task-arn": taskMeta.TaskARN,
		"source":   "consul-ecs",
	}, meta)

	err = backoff.RetryNotify(func() error {
		log.Info("registering service")
		return consulClient.Agent().ServiceRegister(&api.AgentServiceRegistration{
			ID:     serviceID,
			Name:   serviceName,
			Port:   c.flagPort,
			Tags:   tags,
			Meta:   fullMeta,
			Checks: checks,
		})
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(log))
	if err != nil {
		return err
	}

	var upstreams []api.Upstream
	if c.flagUpstreams != "" {
		upstreamDef := strings.Split(c.flagUpstreams, ",")
		for _, u := range upstreamDef {
			svcAndPort := strings.Split(u, ":")
			if len(svcAndPort) != 2 {
				return fmt.Errorf("upstream definition %q invalid", u)
			}
			upstreamPort, err := strconv.Atoi(svcAndPort[1])
			if err != nil {
				return fmt.Errorf("upstream definition %q invalid: %s", u, err)
			}
			upstreams = append(upstreams, api.Upstream{
				DestinationType: "service",
				DestinationName: svcAndPort[0],
				LocalBindPort:   upstreamPort,
			})
		}
	}

	// Register the proxy.
	proxyID := fmt.Sprintf("%s-sidecar-proxy", serviceID)

	err = backoff.RetryNotify(func() error {
		log.Info("registering proxy")
		return consulClient.Agent().ServiceRegister(&api.AgentServiceRegistration{
			ID:   proxyID,
			Name: fmt.Sprintf("%s-sidecar-proxy", serviceName),
			Port: 20000,
			Kind: api.ServiceKindConnectProxy,
			Proxy: &api.AgentServiceConnectProxyConfig{
				DestinationServiceName: serviceName,
				DestinationServiceID:   serviceID,
				LocalServicePort:       c.flagPort,
				Upstreams:              upstreams,
			},
			Checks: api.AgentServiceChecks{
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
			},
			Meta: fullMeta,
			Tags: tags,
		})
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(log))
	if err != nil {
		return err
	}

	log.Info("service and proxy registered successfully", "name", serviceName, "id", serviceID)

	// Run consul envoy -bootstrap to generate bootstrap file.
	cmd := exec.Command("consul", "connect", "envoy", "-proxy-id", proxyID, "-bootstrap", "-grpc-addr=localhost:8502")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}

	envoyBootstrapFile := path.Join(c.flagEnvoyBootstrapDir, envoyBoostrapConfigFilename)
	err = ioutil.WriteFile(envoyBootstrapFile, out, 0444)
	if err != nil {
		return err
	}

	log.Info("envoy bootstrap config written", "file", envoyBootstrapFile)

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

	copyConsulEcsFile := path.Join(c.flagEnvoyBootstrapDir, "consul-ecs")
	err = ioutil.WriteFile(copyConsulEcsFile, data, 0755)
	if err != nil {
		return err
	}
	log.Info("copied binary", "file", copyConsulEcsFile)
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

func constructChecks(serviceID, encodedChecks, encodedHealthSyncContainers string) (api.AgentServiceChecks, error) {
	var checks api.AgentServiceChecks

	if encodedChecks != "" {
		err := json.Unmarshal([]byte(encodedChecks), &checks)
		if err != nil {
			return checks, fmt.Errorf("unmarshalling checks: %w", err)
		}
	}

	if len(checks) > 0 && encodedHealthSyncContainers != "" {
		return checks, fmt.Errorf("both -%s and -%s can't be passed", flagChecks, flagHealthSyncContainers)
	}

	if encodedHealthSyncContainers != "" {
		defaultCheckContainers := strings.Split(encodedHealthSyncContainers, ",")
		for _, containerName := range defaultCheckContainers {
			checks = append(checks, &api.AgentServiceCheck{
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
	if c.flagServiceName == "" {
		return family
	}

	return c.flagServiceName
}

func (c *Command) constructTags() ([]string, error) {
	var tags []string
	if len(c.flagTags) == 0 {
		return tags, nil
	}
	tags = strings.Split(c.flagTags, ",")
	return tags, nil
}

func (c *Command) constructMeta() (map[string]string, error) {
	meta := make(map[string]string)

	if c.flagMeta == "" {
		return meta, nil
	}

	err := json.Unmarshal([]byte(c.flagMeta), &meta)

	if err != nil {
		return meta, err
	}

	return meta, nil
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
