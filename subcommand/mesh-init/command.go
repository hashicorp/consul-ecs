// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package meshinit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/cenkalti/backoff/v4"
	iamauth "github.com/hashicorp/consul-awsauth"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/logging"
	"github.com/hashicorp/consul-server-connection-manager/discovery"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-rootcerts"
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

	ctx    context.Context
	cancel context.CancelFunc
	sigs   chan os.Signal
	once   sync.Once

	dataplaneContainerMonitor *DataplaneContainerMonitor
}

type CatalogServices struct {
	ID        string
	Name      string
	Namespace string
}

func (c *Command) init() {
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.sigs = make(chan os.Signal, 1)
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)
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

	c.dataplaneContainerMonitor = NewDataplaneContainerMonitor(c.log, c.ctx)
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

	// Let it monitor. It will only wake up for SIGTERMS
	go c.dataplaneContainerMonitor.Run()

	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		return err
	}

	clusterARN, err := taskMeta.ClusterARN()
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

	serverManagerConfig := discovery.Config{
		Addresses: c.config.ConsulServers.Hosts,
	}

	c.UI.Info("Got the address of consul server " + c.config.ConsulServers.Hosts)

	if c.config.ConsulServers.GRPCPort != 0 {
		serverManagerConfig.GRPCPort = int(c.config.ConsulServers.GRPCPort)
	}

	if c.config.ConsulServers.TLS {
		tlsConfig := &tls.Config{}
		caCert := os.Getenv("CONSUL_CACERT_PEM")
		if caCert != "" {
			err := rootcerts.ConfigureTLS(tlsConfig, &rootcerts.Config{
				CACertificate: []byte(caCert),
			})
			if err != nil {
				return err
			}
		}
		serverManagerConfig.TLS = tlsConfig
	}

	watcher, err := discovery.NewWatcher(c.ctx, serverManagerConfig, c.log)
	if err != nil {
		c.UI.Error(fmt.Sprintf("unable to create Consul server watcher: %s", err))
		return err
	}

	go watcher.Run()
	defer watcher.Stop()

	state, err := watcher.State()
	if err != nil {
		c.UI.Error(fmt.Sprintf("unable to start Consul server watcher: %s", err))
		return err
	}

	// Add Partition, Namespace, DC
	apiCfg := &api.Config{
		Scheme: "http",
	}

	if c.config.ConsulServers.EnableHTTPS {
		apiCfg.Scheme = "https"
		caCert := os.Getenv("CONSUL_CACERT_PEM")
		if c.config.ConsulServers.TLS {
			// !strings.HasPrefix(f.Addresses, "exec=")
			apiCfg.TLSConfig = api.TLSConfig{
				Address: c.config.ConsulServers.Hosts,
				CAPem:   []byte(caCert),
			}
		}
	}

	apiCfg.Address = fmt.Sprintf("%s:%d", state.Address.IP.String(), c.config.ConsulServers.HTTPPort)

	consulServerClient, err := api.NewClient(apiCfg)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error setting up consul server client: %s", err))
		return err
	}

	consulServices, _, err := consulServerClient.Catalog().Services(nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error fetching services from consul server client: %s", err))
		return err
	}

	c.UI.Info("Printing services from Consul server")
	for k, _ := range consulServices {
		c.UI.Info("Service Name " + k)
	}

	// consulClient, err := api.NewClient(cfg)
	// if err != nil {
	// 	return fmt.Errorf("constructing consul client: %s", err)
	// }

	var serviceRegistration *api.CatalogRegistration
	var proxyRegistration *api.CatalogRegistration
	// TODO: Revisit gateways
	if c.config.Gateway != nil && c.config.Gateway.Kind != "" {
		proxyRegistration = c.constructGatewayProxyRegistration(taskMeta)
	} else {
		serviceRegistration, err = c.constructServiceRegistration(taskMeta, clusterARN)
		if err != nil {
			return err
		}
		proxyRegistration = c.constructProxyRegistration(serviceRegistration, clusterARN, taskMeta.TaskID())
	}

	if serviceRegistration != nil {
		// No need to register the service for gateways.
		err = backoff.RetryNotify(func() error {
			c.log.Info("registering service with the server client")
			_, regErr := consulServerClient.Catalog().Register(serviceRegistration, nil)
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
		_, regErr := consulServerClient.Catalog().Register(proxyRegistration, nil)
		return regErr
	}, backoff.NewConstantBackOff(1*time.Second), retryLogger(c.log))
	if err != nil {
		return err
	}

	c.log.Info("proxy registered successfully", "name", proxyRegistration.Service.Service, "id", proxyRegistration.Service.ID)

	dataplaneConfigFile := path.Join(c.config.BootstrapDir, "dataplane.json")
	dpCfg := &dataplaneConfig{
		Addresses: c.config.ConsulServers.Hosts,
		GRPCPort:  c.config.ConsulServers.GRPCPort,
		NodeName:  clusterARN,
		ServiceID: proxyRegistration.Service.ID,
	}

	if c.config.ConsulServers.TLS {
		// Write the consul server cert pem to the volume
		caCert := os.Getenv("CONSUL_CACERT_PEM")
		certPEMFile := path.Join(c.config.BootstrapDir, "ca-cert.pem")
		err = os.WriteFile(certPEMFile, []byte(caCert), 0444)
		if err != nil {
			return err
		}
		c.log.Info("copied binary", "file", certPEMFile)

		dpCfg.TLS = &dataplaneTLSConfig{
			disabled:    false,
			caCertsPath: certPEMFile,
		}
	}

	jsonData, err := dpCfg.GenerateJSON()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error in generating JSON %s", err.Error()))
		return err
	}
	err = os.WriteFile(dataplaneConfigFile, jsonData, 0444)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error writing to data plane config %s", err.Error()))
		return err
	}

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

	currentStatuses := make(map[string]string)
	parsedContainerNames := make([]string, 0)
	parsedContainerNames = append(parsedContainerNames, "consul-dataplane")
	parsedContainerNames = append(parsedContainerNames, c.config.HealthSyncContainers...)

	checkIDToName := make(map[string]string, 0)
	checksToVerify := make(api.HealthChecks, 0)
	if serviceRegistration != nil {
		checksToVerify = append(checksToVerify, serviceRegistration.Checks...)
	}
	if proxyRegistration != nil {
		checksToVerify = append(checksToVerify, proxyRegistration.Checks...)
	}
	for _, check := range checksToVerify {
		checkIDToName[check.CheckID] = check.Name
	}

	// Non blocking listen
	go func() {
		http.HandleFunc("/health", healthCheck)
		http.ListenAndServe(":10000", nil)
	}()

	c.log.Info("Server listening to port 10000")

	var (
		serviceName      string
		serviceID        string
		serviceNamespace string
	)
	if serviceRegistration != nil {
		serviceName = serviceRegistration.Service.Service
		serviceID = serviceRegistration.Service.ID
		serviceNamespace = serviceRegistration.Service.Namespace
	} else if proxyRegistration != nil {
		serviceName = proxyRegistration.Service.Service
		serviceID = proxyRegistration.Service.ID
		serviceNamespace = proxyRegistration.Service.Namespace
	}

	for {
		select {
		case <-time.After(1 * time.Second):
			currentStatuses = c.syncChecks(consulServerClient, currentStatuses, serviceName, serviceID, serviceNamespace, clusterARN, parsedContainerNames, checkIDToName)
		case sig := <-c.sigs:
			switch sig {
			case syscall.SIGTERM, syscall.SIGCHLD, syscall.SIGURG:
				c.UI.Info("Received sigterm. Will set checks to critical and ignore the signal")
				err := c.setChecksCritical(consulServerClient, taskMeta.TaskID(), serviceName, serviceID, serviceNamespace, clusterARN, parsedContainerNames, checkIDToName)
				// if c.config.ConsulLogin.Enabled {
				// 	// if err := c.logout(config.ServiceTokenFilename); err != nil {
				// 	// 	result = multierror.Append(result, err)
				// 	// }
				// 	// if err := c.logout(config.ClientTokenFilename); err != nil {
				// 	// 	result = multierror.Append(result, err)
				// 	// }
				// }
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error setting checks to critical %s", err.Error()))
				}
			default:
				// TODO: Identify what to do here
				c.UI.Info("Got a non terminating signal")
			}
		case _, ok := <-c.dataplaneContainerMonitor.Done():
			if ok {
				c.UI.Info("Deregistering services and terminating control plane")

				// Deregister service
				if serviceRegistration != nil {
					svcDeReg := &api.CatalogDeregistration{
						Node:      clusterARN,
						ServiceID: serviceRegistration.Service.ID,
						Namespace: serviceRegistration.Service.Namespace,
					}
					_, err := consulServerClient.Catalog().Deregister(svcDeReg, nil)
					if err != nil {
						c.UI.Error(fmt.Sprintf("Error deregistering svc %s", err.Error()))
					}
				}

				if proxyRegistration != nil {
					proxySvcDeReg := &api.CatalogDeregistration{
						Node:      clusterARN,
						ServiceID: proxyRegistration.Service.ID,
						Namespace: proxyRegistration.Service.Namespace,
					}
					_, err := consulServerClient.Catalog().Deregister(proxySvcDeReg, nil)
					if err != nil {
						c.UI.Error(fmt.Sprintf("Error deregistering proxy %s", err.Error()))
					}
				}
			}
			return nil
		}
	}
}

func (c *Command) cleanup() {
	signal.Stop(c.sigs)
	// Cancel background goroutines
	c.cancel()
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	io.WriteString(w, "Healthy\n")
}

func (c *Command) syncChecks(consulClient *api.Client, currentStatuses map[string]string, serviceName, serviceID, namespace, clusterARN string, parsedContainerNames []string, checkIDToName map[string]string) map[string]string {
	taskMeta, err := awsutil.ECSTaskMetadata()
	if err != nil {
		c.log.Error("unable to get task metadata", "err", err)
		return currentStatuses
	}

	containersToSync, missingContainers := findContainersToSync(parsedContainerNames, taskMeta)
	for _, name := range missingContainers {
		c.UI.Info("Found missing container to sync " + name)
		checkID := makeCheckID(serviceName, taskMeta.TaskID(), name)
		c.log.Debug("marking container as unhealthy since it wasn't found in the task metadata", "name", name)
		_, err = updateConsulHealthStatus(consulClient, serviceID, serviceName, namespace, clusterARN, checkID, ecs.HealthStatusUnhealthy, checkIDToName)
		if err != nil {
			c.log.Error("failed to update Consul health status for missing container", "err", err, "container", name)
		} else {
			c.log.Info("container health check updated in Consul for missing container", "container", name)
			currentStatuses[name] = api.HealthCritical
		}
	}

	for _, container := range containersToSync {
		c.log.Debug("updating Consul TTL check from ECS container health",
			"name", container.Name,
			"status", container.Health.Status,
			"statusSince", container.Health.StatusSince,
			"exitCode", container.Health.ExitCode,
		)

		previousStatus := currentStatuses[container.Name]
		if container.Health.Status != previousStatus {
			checkID := makeCheckID(serviceName, taskMeta.TaskID(), container.Name)
			c.UI.Info("FOund proper container to sync with check ID " + checkID)
			_, err = updateConsulHealthStatus(consulClient, serviceID, serviceName, namespace, clusterARN, checkID, container.Health.Status, checkIDToName)

			if err != nil {
				c.log.Warn("failed to update Consul health status", "err", err)
			} else {
				c.log.Info("container health check updated in Consul",
					"name", container.Name,
					"status", container.Health.Status,
					"statusSince", container.Health.StatusSince,
					"exitCode", container.Health.ExitCode,
				)
				currentStatuses[container.Name] = container.Health.Status
			}
		}
	}

	return currentStatuses
}

// setChecksCritical sets checks for all of the containers to critical
func (c *Command) setChecksCritical(consulClient *api.Client, taskID string, serviceName, serviceID, namespace, clusterARN string, parsedContainerNames []string, checkIDToName map[string]string) error {
	var result error

	for _, containerName := range parsedContainerNames {
		checkID := makeCheckID(serviceName, taskID, containerName)
		_, err := updateConsulHealthStatus(consulClient, serviceID, serviceName, namespace, clusterARN, checkID, api.HealthCritical, checkIDToName)

		if err == nil {
			c.log.Info("set Consul health status to critical",
				"container", containerName)
		} else {
			c.log.Warn("failed to set Consul health status to critical",
				"err", err,
				"container", containerName)
			result = multierror.Append(result, err)
		}
	}

	return result
}

func findContainersToSync(containerNames []string, taskMeta awsutil.ECSTaskMeta) ([]awsutil.ECSTaskMetaContainer, []string) {
	var ecsContainers []awsutil.ECSTaskMetaContainer
	var missing []string

	for _, container := range containerNames {
		found := false
		for _, ecsContainer := range taskMeta.Containers {
			if ecsContainer.Name == container {
				ecsContainers = append(ecsContainers, ecsContainer)
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, container)
		}
	}
	return ecsContainers, missing
}

func ecsHealthToConsulHealth(ecsHealth string) string {
	// `HEALTHY`, `UNHEALTHY`, and `UNKNOWN` are the valid ECS health statuses.
	// This assumes that the only passing status is `HEALTHY`
	if ecsHealth != ecs.HealthStatusHealthy {
		return api.HealthCritical
	}
	return api.HealthPassing
}

func updateConsulHealthStatus(consulClient *api.Client, serviceID, serviceName, namespace, clusterARN, checkID, ecsHealthStatus string, checkIDToName map[string]string) (*api.WriteMeta, error) {
	consulHealthStatus := ecsHealthToConsulHealth(ecsHealthStatus)

	reason := fmt.Sprintf("ECS health status is %q for task %q", ecsHealthStatus, checkID)

	reg := &api.CatalogRegistration{
		Node:           clusterARN,
		SkipNodeUpdate: true,
		Checks: api.HealthChecks{
			&api.HealthCheck{
				Name:      checkIDToName[checkID],
				Node:      clusterARN,
				CheckID:   checkID,
				ServiceID: serviceID,
				Namespace: namespace,
				Status:    consulHealthStatus,
				Type:      "consul-ecs-readiness",
				Output:    healthCheckOutputReason(consulHealthStatus, reason),
			},
		},
	}
	return consulClient.Catalog().Register(reg, nil)
}

// loginToAuthMethod runs a 'consul login' command to obtain a token.
// The login command is skipped if LogintOptions is not set in the
// consul-ecs config JSON, in order to support non-ACL deployments.
func (c *Command) loginToAuthMethod(tokenFile string, taskMeta awsutil.ECSTaskMeta) error {
	return backoff.RetryNotify(func() error {
		c.log.Debug("login attempt")

		// We need to retry creating the client here, because there's a race between this
		// and the consul-client container writing the ca cert file.
		cfg := api.DefaultConfig()
		cfg.Address = c.config.ConsulHTTPAddr
		cfg.TLSConfig.CAFile = c.config.ConsulCACertFile

		client, err := api.NewClient(cfg)
		if err != nil {
			return err
		}

		// We rerun createAWSBearerToken every iteration of this loop to ensure we have a valid
		// bearer token, since we retry forever and since the token may expire during that time.
		//
		// The bearer token includes signed AWS API request(s), and the signature expires after a
		// short time (maybe 15 minutes). The AWS credentials used for signing also expire after
		// some longer period (probably after a few hours after they are first generated). On ECS,
		// credentials for the task IAM role are fetched from
		// 169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI} which caches and returns the same
		// set of credentials until they expire, after which it returns new credentials.
		//
		// So we should be safe from accumulating a bunch of temporary tokens or other garbage.
		bearerToken, err := c.createAWSBearerToken(taskMeta)
		if err != nil {
			return err
		}

		// We use this for gateways, too.
		partition := c.config.Service.Partition
		if partition == "" && c.config.Gateway != nil {
			partition = c.config.Gateway.Partition
		}

		tok, _, err := client.ACL().Login(
			c.constructLoginParams(bearerToken, taskMeta),
			&api.WriteOptions{Partition: partition},
		)
		if err != nil {
			c.log.Error(err.Error())
			return err
		}

		err = os.WriteFile(tokenFile, []byte(tok.SecretID), 0644)
		if err != nil {
			return err
		}

		c.log.Info("login success", "accessor-id", tok.AccessorID, "token-file", tokenFile)
		return nil
	}, backoff.NewConstantBackOff(2*time.Second), retryLogger(c.log))
}

func (c *Command) constructLoginParams(bearerToken string, taskMeta awsutil.ECSTaskMeta) *api.ACLLoginParams {
	method := c.config.ConsulLogin.Method
	if method == "" {
		method = config.DefaultAuthMethodName
	}
	meta := mergeMeta(
		map[string]string{
			"consul.hashicorp.com/task-id": taskMeta.TaskID(),
			"consul.hashicorp.com/cluster": taskMeta.Cluster,
		},
		c.config.ConsulLogin.Meta,
	)
	return &api.ACLLoginParams{
		AuthMethod:  method,
		BearerToken: bearerToken,
		Meta:        meta,
	}
}

func (c *Command) createAWSBearerToken(taskMeta awsutil.ECSTaskMeta) (string, error) {
	l := c.config.ConsulLogin

	region := l.Region
	if region == "" {
		r, err := taskMeta.Region()
		if err != nil {
			return "", err
		}
		region = r
	}

	cfg := aws.Config{
		Region: aws.String(region),
		// More detailed error message to help debug credential discovery.
		CredentialsChainVerboseErrors: aws.Bool(true),
	}

	// support explicit creds for unit tests
	if l.AccessKeyID != "" {
		cfg.Credentials = credentials.NewStaticCredentials(
			l.AccessKeyID, l.SecretAccessKey, "",
		)
	}

	// Session loads creds from standard sources (env vars, file, EC2 metadata, ...)
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: cfg,
		// Allow loading from config files by default:
		//   ~/.aws/config or AWS_CONFIG_FILE
		//   ~/.aws/credentials or AWS_SHARED_CREDENTIALS_FILE
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return "", err
	}

	if sess.Config.Credentials == nil {
		return "", fmt.Errorf("AWS credentials not found")
	}

	loginData, err := iamauth.GenerateLoginData(&iamauth.LoginInput{
		Creds:                  sess.Config.Credentials,
		IncludeIAMEntity:       l.IncludeEntity,
		STSEndpoint:            l.STSEndpoint,
		STSRegion:              region,
		Logger:                 hclog.New(nil),
		ServerIDHeaderValue:    l.ServerIDHeaderValue,
		ServerIDHeaderName:     config.IAMServerIDHeaderName,
		GetEntityMethodHeader:  config.GetEntityMethodHeader,
		GetEntityURLHeader:     config.GetEntityURLHeader,
		GetEntityHeadersHeader: config.GetEntityHeadersHeader,
		GetEntityBodyHeader:    config.GetEntityBodyHeader,
	})
	if err != nil {
		return "", err
	}

	loginDataJson, err := json.Marshal(loginData)
	if err != nil {
		return "", err
	}
	return string(loginDataJson), err
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

func constructChecks(serviceID, serviceName, taskID, namespace string, healthSyncContainers []string) api.HealthChecks {
	var checks api.HealthChecks
	checks = make(api.HealthChecks, 0)
	for _, containerName := range healthSyncContainers {
		checks = append(checks, &api.HealthCheck{
			CheckID:   makeCheckID(serviceName, taskID, containerName),
			Name:      "consul ecs synced",
			Notes:     fmt.Sprintf("consul-ecs created and updates this check because the %s container is essential and has an ECS health check.", containerName),
			Type:      "consul-ecs-readiness",
			ServiceID: serviceID,
			Output:    healthCheckOutputReason("critical", serviceName),
		})
	}

	checks = append(checks, &api.HealthCheck{
		CheckID:   makeCheckID(serviceName, taskID, "consul-dataplane"),
		Name:      "Consul dataplane readiness",
		Type:      "consul-ecs-readiness",
		ServiceID: serviceID,
		Namespace: namespace,
		Status:    "critical",
		Output:    healthCheckOutputReason("critical", serviceName),
	})
	return checks
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
func (c *Command) constructServiceRegistration(taskMeta awsutil.ECSTaskMeta, clusterARN string) (*api.CatalogRegistration, error) {
	serviceName := c.constructServiceName(taskMeta.Family)
	taskID := taskMeta.TaskID()
	serviceID := fmt.Sprintf("%s-%s", serviceName, taskID)

	fullMeta := mergeMeta(map[string]string{
		"task-id":  taskID,
		"task-arn": taskMeta.TaskARN,
		"source":   "consul-ecs",
	}, c.config.Service.Meta)

	serviceRegistration := c.config.Service.ToConsulType()
	serviceRegistration.Node = clusterARN
	serviceRegistration.Address = taskMeta.NodeIP()
	serviceRegistration.Service.ID = serviceID
	serviceRegistration.Service.Service = serviceName
	serviceRegistration.Service.Meta = fullMeta
	serviceRegistration.Checks = constructChecks(serviceID, serviceName, taskID, c.config.Service.Namespace, c.config.HealthSyncContainers)
	return serviceRegistration, nil
}

func healthCheckOutputReason(status string, serviceName string) string {
	if status == api.HealthPassing {
		return "ECS health check passing"
	}

	return fmt.Sprintf("Service %s is not ready", serviceName)
}

// constructProxyRegistration returns the proxy registration request body.
func (c *Command) constructProxyRegistration(serviceRegistration *api.CatalogRegistration, clusterARN, taskID string) *api.CatalogRegistration {
	proxyRegistration := &api.CatalogRegistration{}
	proxyRegistration.Service = &api.AgentService{
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

	proxyRegistration.Service.Proxy.DestinationServiceName = serviceRegistration.Service.Service
	proxyRegistration.Service.Proxy.DestinationServiceID = serviceRegistration.Service.ID
	proxyRegistration.Service.Proxy.LocalServicePort = serviceRegistration.Service.Port
	// proxyRegistration.Checks = api.HealthChecks{
	// 	&api.HealthCheck{
	// 		CheckID:   makeCheckID(proxyRegistration.Service.Service, taskID, "dataplane"),
	// 		Name:      "Consul dataplane readiness",
	// 		Type:      "consul-ecs-readiness",
	// 		ServiceID: proxyRegistration.Service.ID,
	// 		Namespace: serviceRegistration.Service.Namespace,
	// 		Status:    "critical",
	// 		Output:    healthCheckOutputReason("critical", proxyRegistration.Service.Service),
	// 	},
	// }
	proxyRegistration.Partition = serviceRegistration.Partition
	proxyRegistration.SkipNodeUpdate = true
	proxyRegistration.NodeMeta = map[string]string{
		"synthetic-node": "true",
	}
	proxyRegistration.Node = clusterARN
	return proxyRegistration
}

func makeCheckID(serviceName string, taskID string, containerName string) string {
	return fmt.Sprintf("%s-%s-%s-consul-ecs", serviceName, taskID, containerName)
}

func (c *Command) constructGatewayProxyRegistration(taskMeta awsutil.ECSTaskMeta) *api.CatalogRegistration {
	serviceName := c.config.Gateway.Name
	if serviceName == "" {
		serviceName = taskMeta.Family
	}

	taskID := taskMeta.TaskID()
	serviceID := fmt.Sprintf("%s-%s", serviceName, taskID)

	gwRegistration := c.config.Gateway.ToConsulType()
	gwRegistration.Address = taskMeta.NodeIP()
	gwRegistration.Service.ID = serviceID
	gwRegistration.Service.Service = serviceName
	gwRegistration.Service.Meta = mergeMeta(map[string]string{
		"task-id":  taskID,
		"task-arn": taskMeta.TaskARN,
		"source":   "consul-ecs",
	}, c.config.Gateway.Meta)

	taggedAddresses := make(map[string]api.ServiceAddress)

	// Default the LAN port if it was not provided.
	gwRegistration.Service.Port = config.DefaultGatewayPort

	if c.config.Gateway.LanAddress != nil {
		lanAddr := c.config.Gateway.LanAddress.ToConsulType()
		// If a LAN address is provided then use that and add the LAN address to the tagged addresses.
		if lanAddr.Port > 0 {
			gwRegistration.Service.Port = lanAddr.Port
		}
		if lanAddr.Address != "" {
			gwRegistration.Service.Address = lanAddr.Address
			taggedAddresses[config.TaggedAddressLAN] = lanAddr
		}
	}

	// TODO if assign_public_ip is set and the WAN address is not provided then
	// we need to find the Public IP of the task (or LB) and use that for the WAN address.
	if c.config.Gateway.WanAddress != nil {
		wanAddr := c.config.Gateway.WanAddress.ToConsulType()
		if wanAddr.Address != "" {
			if wanAddr.Port == 0 {
				wanAddr.Port = gwRegistration.Service.Port
			}
			taggedAddresses[config.TaggedAddressWAN] = wanAddr
		}
	}
	if len(taggedAddresses) > 0 {
		gwRegistration.Service.TaggedAddresses = taggedAddresses
	}

	gwRegistration.Checks = api.HealthChecks{
		&api.HealthCheck{
			CheckID:   makeCheckID(serviceName, taskID, "consul-dataplane"),
			Name:      "Consul dataplane readiness",
			Type:      "consul-ecs-readiness",
			ServiceID: serviceID,
			Namespace: gwRegistration.Service.Namespace,
			Status:    "critical",
			Output:    healthCheckOutputReason("critical", serviceName),
		},
	}
	return gwRegistration
}
