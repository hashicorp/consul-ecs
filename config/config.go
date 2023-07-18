package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	iamauth "github.com/hashicorp/consul-awsauth"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-server-connection-manager/discovery"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-rootcerts"
)

const (
	defaultGRPCPort    = 8503
	defaultHTTPPort    = 8501
	defaultIAMRolePath = "/consul-ecs/"

	// Cert used for internal RPC communication to the servers
	consulGRPCCACertPemEnvVar = "CONSUL_GRPC_CACERT_PEM"

	// Cert used for securing HTTP traffic towards the server
	consulHTTPSCertPemEnvVar = "CONSUL_HTTPS_CACERT_PEM"
)

type TLSSettings struct {
	Enabled       bool
	CaCertFile    string
	TLSServerName string
}

func (c *Config) ConsulServerConnMgrConfig(taskMeta awsutil.ECSTaskMeta) (discovery.Config, error) {
	cfg := discovery.Config{
		Addresses: c.ConsulServers.Hosts,
		GRPCPort:  c.ConsulServers.GRPC.Port,
	}

	grpcTLSSettings := c.ConsulServers.GetGRPCTLSSettings()
	if grpcTLSSettings.Enabled {
		tlsConfig := &tls.Config{}

		caCert := os.Getenv(consulGRPCCACertPemEnvVar)
		if caCert != "" {
			err := rootcerts.ConfigureTLS(tlsConfig, &rootcerts.Config{
				CACertificate: []byte(caCert),
			})
			if err != nil {
				return discovery.Config{}, err
			}
		} else if grpcTLSSettings.CaCertFile != "" {
			err := rootcerts.ConfigureTLS(tlsConfig, &rootcerts.Config{
				CAFile: grpcTLSSettings.CaCertFile,
			})
			if err != nil {
				return discovery.Config{}, err
			}
		}

		cfg.TLS = tlsConfig
		cfg.TLS.ServerName = grpcTLSSettings.TLSServerName
	}

	if c.ConsulLogin.Enabled {
		credentials, err := c.getDiscoveryCredentials(taskMeta)
		if err != nil {
			return discovery.Config{}, err
		}

		cfg.Credentials = credentials
	}

	if c.ConsulServers.SkipServerWatch {
		cfg.ServerWatchDisabled = true
	}

	return cfg, nil
}

func (c *Config) ClientConfig() *api.Config {
	cfg := &api.Config{
		Namespace: c.getNamespace(),
		Partition: c.getPartition(),
		Scheme:    "http",
	}

	httpTLSSettings := c.ConsulServers.getHTTPTLSSettings()
	if c.ConsulServers.HTTP.EnableHTTPS {
		cfg.Scheme = "https"
		cfg.TLSConfig = api.TLSConfig{}

		caCert := os.Getenv(consulHTTPSCertPemEnvVar)
		if caCert != "" {
			cfg.TLSConfig.CAPem = []byte(caCert)
		} else if httpTLSSettings.CaCertFile != "" {
			cfg.TLSConfig.CAFile = httpTLSSettings.CaCertFile
		}

		if httpTLSSettings.TLSServerName != "" {
			cfg.TLSConfig.Address = httpTLSSettings.TLSServerName
		} else if !strings.HasPrefix(c.ConsulServers.Hosts, "exec=") {
			cfg.TLSConfig.Address = c.ConsulServers.Hosts
		}
	}

	return cfg
}

func (c *Config) IsGateway() bool {
	return c.Gateway != nil && c.Gateway.Kind != ""
}

func (c *ConsulServers) GetGRPCTLSSettings() *TLSSettings {
	enableTLS := c.Defaults.EnableTLS
	if c.GRPC.EnableTLS != nil {
		enableTLS = *c.GRPC.EnableTLS
	}

	caCertFile := c.Defaults.CaCertFile
	if c.GRPC.CaCertFile != "" {
		caCertFile = c.GRPC.CaCertFile
	}

	tlsServerName := c.Defaults.TLSServerName
	if c.GRPC.TLSServerName != "" {
		tlsServerName = c.GRPC.TLSServerName
	}

	return &TLSSettings{
		Enabled:       enableTLS,
		TLSServerName: tlsServerName,
		CaCertFile:    caCertFile,
	}
}

func (c *Config) getDiscoveryCredentials(taskMeta awsutil.ECSTaskMeta) (discovery.Credentials, error) {
	cfg := discovery.Credentials{
		Type: discovery.CredentialsTypeLogin,
		Login: discovery.LoginCredential{
			Datacenter: c.ConsulLogin.Datacenter,
			Partition:  c.getPartition(),
		},
	}

	authMethod := c.ConsulLogin.Method
	if authMethod == "" {
		authMethod = DefaultAuthMethodName
	}
	cfg.Login.AuthMethod = authMethod

	cfg.Login.Meta = mergeMeta(
		map[string]string{
			"consul.hashicorp.com/task-id": taskMeta.TaskID(),
			"consul.hashicorp.com/cluster": taskMeta.Cluster,
		},
		c.ConsulLogin.Meta,
	)

	bearerToken, err := c.createAWSBearerToken(taskMeta)
	if err != nil {
		return discovery.Credentials{}, err
	}
	cfg.Login.BearerToken = bearerToken

	return cfg, nil
}

func (c *Config) getNamespace() string {
	if c.IsGateway() {
		return c.Gateway.Namespace
	}

	return c.Service.Namespace
}

func (c *Config) getPartition() string {
	if c.IsGateway() {
		return c.Gateway.Partition
	}

	return c.Service.Partition
}

func (c *Config) createAWSBearerToken(taskMeta awsutil.ECSTaskMeta) (string, error) {
	l := c.ConsulLogin

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
		ServerIDHeaderName:     IAMServerIDHeaderName,
		GetEntityMethodHeader:  GetEntityMethodHeader,
		GetEntityURLHeader:     GetEntityURLHeader,
		GetEntityHeadersHeader: GetEntityHeadersHeader,
		GetEntityBodyHeader:    GetEntityBodyHeader,
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

func (c *ConsulServers) getHTTPTLSSettings() *TLSSettings {
	enableTLS := c.Defaults.EnableTLS
	if c.HTTP.EnableTLS != nil {
		enableTLS = *c.HTTP.EnableTLS
	}

	caCertFile := c.Defaults.CaCertFile
	if c.HTTP.CaCertFile != "" {
		caCertFile = c.HTTP.CaCertFile
	}

	tlsServerName := c.Defaults.TLSServerName
	if c.HTTP.TLSServerName != "" {
		tlsServerName = c.HTTP.TLSServerName
	}

	return &TLSSettings{
		Enabled:       enableTLS,
		TLSServerName: tlsServerName,
		CaCertFile:    caCertFile,
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
