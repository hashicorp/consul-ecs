package meshinit

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
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
	flagEnvoyBootstrapFile = "envoy-bootstrap-file"
	flagPort               = "port"
	flagUpstreams          = "upstreams"
	flagTLS                = "tls"
)

type Command struct {
	UI cli.Ui

	flagEnvoyBootstrapFile string
	flagPort               int
	flagUpstreams          string
	flagTLS                bool

	flagSet *flag.FlagSet
	once    sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagEnvoyBootstrapFile, flagEnvoyBootstrapFile, "", "File to write bootstrap config to")
	c.flagSet.IntVar(&c.flagPort, flagPort, 0, "Port service runs on")
	c.flagSet.StringVar(&c.flagUpstreams, flagUpstreams, "", "Upstreams in form <name>:<port>,...")
	c.flagSet.BoolVar(&c.flagTLS, flagTLS, false, "Whether to enable TLS")
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)
	if err := c.flagSet.Parse(args); err != nil {
		return 1
	}
	if c.flagEnvoyBootstrapFile == "" {
		c.UI.Error(fmt.Sprintf("-%s must be set", flagEnvoyBootstrapFile))
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

	// Register the service.
	taskID := taskARNToID(taskMeta.TaskARN)
	serviceName := taskMeta.Family
	serviceID := fmt.Sprintf("%s-%s", serviceName, taskID)

	err = backoff.RetryNotify(func() error {
		log.Info("registering service")
		return consulClient.Agent().ServiceRegister(&api.AgentServiceRegistration{
			ID:   serviceID,
			Name: serviceName,
			Port: c.flagPort,
			Meta: map[string]string{
				"task-id":  taskID,
				"task-arn": taskMeta.TaskARN,
				"source":   "consul-ecs",
			},
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
			Meta: map[string]string{
				"task-id":  taskID,
				"task-arn": taskMeta.TaskARN,
				"source":   "consul-ecs",
			},
		})
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(log))
	if err != nil {
		return err
	}

	log.Info("service and proxy registered successfully", "name", serviceName, "id", serviceID)

	// Grab CA root from the Consul server if TLS is enabled.
	var caRootFile *os.File
	if c.flagTLS {
		log.Info("retrieving CA roots from Consul")
		var activeRoot string
		err = backoff.RetryNotify(func() error {
			caRoots, _, err := consulClient.Agent().ConnectCARoots(nil)
			if err != nil {
				log.Error("error retrieving CA roots from Consul", "err", err)
				return err
			}

			activeRoot, err = getActiveRoot(caRoots)
			if err != nil {
				log.Error("could not get an active root", "err", err)
				return err
			}

			return nil
		}, backoff.NewConstantBackOff(1*time.Second), retryLogger(log))

		caRootFile, err = ioutil.TempFile("", "")
		if err != nil {
			log.Error("failed to create temp file", "err", err)
			return err
		}

		err = ioutil.WriteFile(caRootFile.Name(), []byte(activeRoot), 0644)
		if err != nil {
			log.Error("error writing CA file", "err", err)
			return err
		}
	}

	// Run consul envoy -bootstrap to generate bootstrap file.
	envoyBootstrapCmdArgs := []string{"connect", "envoy", "-proxy-id", proxyID, "-bootstrap"}
	if c.flagTLS {
		envoyBootstrapCmdArgs = append(envoyBootstrapCmdArgs, "-ca-file", caRootFile.Name(), "-grpc-addr=https://localhost:8502")
	} else {
		envoyBootstrapCmdArgs = append(envoyBootstrapCmdArgs, "-grpc-addr=localhost:8502")
	}
	cmd := exec.Command("consul", envoyBootstrapCmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}

	err = ioutil.WriteFile(c.flagEnvoyBootstrapFile, out, 0444)
	if err != nil {
		return err
	}

	log.Info("envoy bootstrap config written", "file", c.flagEnvoyBootstrapFile)
	return nil
}

// getActiveRoot returns the currently active root
// from the roots list, otherwise returns error.
// Borrowed from consul-k8s:
// https://github.com/hashicorp/consul-k8s/blob/e9d866ddc1a1c070bc78901471d8f198096472ed/subcommand/get-consul-client-ca/command.go#L104-L118
func getActiveRoot(roots *api.CARootList) (string, error) {
	if roots == nil {
		return "", fmt.Errorf("ca root list is nil")
	}
	if roots.Roots == nil {
		return "", fmt.Errorf("ca roots is nil")
	}
	if len(roots.Roots) == 0 {
		return "", fmt.Errorf("the list of root CAs is empty")
	}

	for _, root := range roots.Roots {
		if root.Active {
			return root.RootCertPEM, nil
		}
	}
	return "", fmt.Errorf("none of the roots were active")
}

func taskARNToID(arn string) string {
	split := strings.Split(arn, "/")
	if len(split) == 0 {
		return ""
	}
	return split[len(split)-1]
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
