// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	iamauth "github.com/hashicorp/consul-awsauth"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-server-connection-manager/discovery"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-rootcerts"
)

const (
	// Cert used for internal RPC communication to the servers
	ConsulGRPCCACertPemEnvVar = "CONSUL_GRPC_CACERT_PEM"

	ConsulDataplaneDNSBindHost = "127.0.0.1"
	ConsulDataplaneDNSBindPort = 8600

	// Login meta fields added to the token
	ConsulTokenTaskIDMeta    = "consul.hashicorp.com/task-id"
	ConsulTokenClusterIDMeta = "consul.hashicorp.com/cluster"

	defaultGRPCPort    = 8503
	defaultHTTPPort    = 8501
	defaultIAMRolePath = "/consul-ecs/"

	// Cert used for securing HTTP traffic towards the server
	consulHTTPSCertPemEnvVar = "CONSUL_HTTPS_CACERT_PEM"

	bootstrapTokenEnvVar = "CONSUL_HTTP_TOKEN"
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

		caCert := os.Getenv(ConsulGRPCCACertPemEnvVar)
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

	// We skip login if CONSUL_HTTP_TOKEN is non empty
	token := GetConsulToken()
	if token != "" {
		cfg.Credentials = discovery.Credentials{
			Type: discovery.CredentialsTypeStatic,
			Static: discovery.StaticTokenCredential{
				Token: token,
			},
		}
	} else if c.ConsulLogin.Enabled {
		credentials, err := c.getLoginDiscoveryCredentials(taskMeta)
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

func GetConsulToken() string {
	return os.Getenv(bootstrapTokenEnvVar)
}

func (c *Config) getLoginDiscoveryCredentials(taskMeta awsutil.ECSTaskMeta) (discovery.Credentials, error) {
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

	clusterARN, err := taskMeta.ClusterARN()
	if err != nil {
		return discovery.Credentials{}, err
	}

	cfg.Login.Meta = mergeMeta(
		map[string]string{
			ConsulTokenTaskIDMeta:    taskMeta.TaskID(),
			ConsulTokenClusterIDMeta: clusterARN,
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

	// v2 uses functional options to build the config
	var opts []func(*config.LoadOptions) error
	opts = append(opts, config.WithRegion(region))

	// In v2, we use WithCredentialsProvider instead of manually setting it on a struct
	if l.AccessKeyID != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(l.AccessKeyID, l.SecretAccessKey, ""),
		))
	}

	// LoadDefaultConfig is the v2 replacement for session.NewSession
	// context.TODO() is used here as this is a configuration load call
	cfg, err := config.LoadDefaultConfig(context.TODO(), opts...)
	if err != nil {
		return "", fmt.Errorf("unable to load SDK config, %v", err)
	}

	// In v2, cfg.Credentials is a Provider (interface), not a concrete struct.
	// Most consumers (like iamauth) will call cfg.Credentials.Retrieve(ctx)
	if cfg.Credentials == nil {
		return "", fmt.Errorf("AWS credentials not found")
	}

	loginData, err := iamauth.GenerateLoginData(&iamauth.LoginInput{
		// iamauth might need an update to accept aws.CredentialsProvider
		// if it was previously expecting v1 credentials.
		Creds:                  cfg.Credentials,
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
