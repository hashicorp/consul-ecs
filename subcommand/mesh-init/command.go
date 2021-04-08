package meshinit

import (
	"encoding/json"
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
	flagTLS                = "tls"
	flagCACert             = "ca-cert"
	flagTokensJSONFile     = "tokens-json-file"
	flagPort               = "port"
	flagUpstreams          = "upstreams"
)

type Command struct {
	UI cli.Ui

	flagEnvoyBootstrapFile string
	flagTLS                bool
	flagCACert             string
	flagTokensJSONFile     string
	flagPort               int
	flagUpstreams          string

	flagSet *flag.FlagSet
	once    sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagEnvoyBootstrapFile, flagEnvoyBootstrapFile, "", "File to write bootstrap config to")
	c.flagSet.StringVar(&c.flagCACert, flagCACert, "", "Path to Consul CA cert")
	c.flagSet.StringVar(&c.flagTokensJSONFile, flagTokensJSONFile, "", "Path to Consul agent's token persistence file")
	c.flagSet.IntVar(&c.flagPort, flagPort, 0, "Port service runs on")
	c.flagSet.BoolVar(&c.flagTLS, flagTLS, false, "If Consul has TLS enabled")
	c.flagSet.StringVar(&c.flagUpstreams, flagUpstreams, "", "Upstreams in form <name>:<port>,...")
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
	var token string
	if c.flagTLS {
		// okay because localhost
		cfg.TLSConfig.InsecureSkipVerify = true
		cfg.Address = "localhost:8501"
		cfg.Scheme = "https"

		type tokensFile struct {
			Replication string `json:"replication"`
		}
		var tokensFileData tokensFile

		// Read token file. Need to wait for it to be written.
		err := backoff.RetryNotify(func() error {
			tokensFileBytes, err := ioutil.ReadFile(c.flagTokensJSONFile)
			if err != nil {
				return err
			}
			err = json.Unmarshal(tokensFileBytes, &tokensFileData)
			if err != nil {
				return backoff.Permanent(err)
			}
			return nil
		}, backoff.NewConstantBackOff(1*time.Second), retryLogger(log))
		if err != nil {
			return err
		}

		cfg.Token = tokensFileData.Replication
		token = tokensFileData.Replication
	}

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

	for i := 0; i < 3; i++ {
		log.Info("attempting to register svc")
		err = consulClient.Agent().ServiceRegister(&api.AgentServiceRegistration{
			ID:   serviceID,
			Name: serviceName,
			Port: c.flagPort,
			Meta: map[string]string{
				"task-id":  taskID,
				"task-arn": taskMeta.TaskARN,
				"source":   "consul-ecs",
			},
		})
		if err != nil {
			log.Error("registering svc", "err", err.Error())
		} else {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("unable to register service: %s", err)
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
	for i := 0; i < 3; i++ {
		log.Info("attempting to register svc proxy", "arn", taskMeta.TaskARN)
		err = consulClient.Agent().ServiceRegister(&api.AgentServiceRegistration{
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
		if err != nil {
			log.Error("registering proxy", "err", err.Error())
		} else {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("unable to register sidecar proxy: %s", err)
	}
	log.Info("service registered successfully", "name", serviceName, "id", serviceID)

	// Run consul envoy -bootstrap to generate bootstrap file.
	cmd := exec.Command("/consul/consul", "connect", "envoy", "-proxy-id", proxyID, "-bootstrap", "-token", token)
	cmd.Env = append(os.Environ(), "CONSUL_HTTP_SSL_VERIFY=false", "CONSUL_GRPC_ADDR=https://localhost:8502", "CONSUL_HTTP_ADDR=https://localhost:8501")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}

	// hack: fix TLS for now to disable cert verification connections to consul client
	withoutWhitespace := strings.ReplaceAll(string(out), " ", "")
	withoutWhitespace = strings.ReplaceAll(withoutWhitespace, "\n", "")
	json := strings.Replace(withoutWhitespace, `"trusted_ca":{"inline_string":""}`, "", 1)

	err = ioutil.WriteFile(c.flagEnvoyBootstrapFile, []byte(json), 0444)
	if err != nil {
		return err
	}

	log.Info("envoy bootstrap config written", "file", c.flagEnvoyBootstrapFile)

	return nil
}

func retryLogger(log hclog.Logger) backoff.Notify {
	return func(err error, duration time.Duration) {
		log.Error(err.Error(), "retry", duration.String())
	}
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
