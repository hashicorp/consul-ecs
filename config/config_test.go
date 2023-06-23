package config

import (
	"crypto/tls"
	"os"
	"testing"

	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul-server-connection-manager/discovery"
	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/require"
)

const testCA = `
-----BEGIN CERTIFICATE-----
MIIC7TCCApOgAwIBAgIQbHoocPoQq7qR3MTNUXdLVDAKBggqhkjOPQQDAjCBuTEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2Nv
MRowGAYDVQQJExExMDEgU2Vjb25kIFN0cmVldDEOMAwGA1UEERMFOTQxMDUxFzAV
BgNVBAoTDkhhc2hpQ29ycCBJbmMuMUAwPgYDVQQDEzdDb25zdWwgQWdlbnQgQ0Eg
MTQ0MTkwOTA0MDA4ODQxOTE3MTQzNDM4MjEzMTEzMjA0NjU2OTgwMB4XDTIyMDkx
NjE4NDUwNloXDTI3MDkxNTE4NDUwNlowgbkxCzAJBgNVBAYTAlVTMQswCQYDVQQI
EwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEaMBgGA1UECRMRMTAxIFNlY29u
ZCBTdHJlZXQxDjAMBgNVBBETBTk0MTA1MRcwFQYDVQQKEw5IYXNoaUNvcnAgSW5j
LjFAMD4GA1UEAxM3Q29uc3VsIEFnZW50IENBIDE0NDE5MDkwNDAwODg0MTkxNzE0
MzQzODIxMzExMzIwNDY1Njk4MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABA9w
J9aqbpdoVXQLdYTfUpBM2bgElznRYQP/GcNQUtvopvVywPjC7obFuZP1oM7YX7Wy
hGyeudV4pvF1lz9nVeOjezB5MA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTAD
AQH/MCkGA1UdDgQiBCA9dZuoEX3yrbebyEEzsN4L2rr7FJd6FsjIioR6KbMIhTAr
BgNVHSMEJDAigCA9dZuoEX3yrbebyEEzsN4L2rr7FJd6FsjIioR6KbMIhTAKBggq
hkjOPQQDAgNIADBFAiARhJR88w9EXLsq5A932auHvLFAw+uQ0a2TLSaJF54fyAIh
APQczkCoIFiLlGp0GYeHEfjvrdm2g8Q3BUDjeAUfZPaW
-----END CERTIFICATE-----`

func TestConsulServerConnManagerConfig(t *testing.T) {
	cases := map[string]struct {
		cfg       *Config
		taskMeta  awsutil.ECSTaskMeta
		expConfig func(awsutil.ECSTaskMeta) discovery.Config
	}{
		"basic flags without TLS or ACLs": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts:    "consul.dc1.address",
					GRPCPort: 8502,
				},
			},
			expConfig: func(t awsutil.ECSTaskMeta) discovery.Config {
				return discovery.Config{
					Addresses: "consul.dc1.address",
					GRPCPort:  8502,
				}
			},
		},
		"TLS enabled": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts:     "consul.dc1.address",
					GRPCPort:  8503,
					EnableTLS: true,
				},
			},
			expConfig: func(t awsutil.ECSTaskMeta) discovery.Config {
				return discovery.Config{
					Addresses: "consul.dc1.address",
					GRPCPort:  8503,
					TLS:       &tls.Config{},
				}
			},
		},
		"TLS enabled with TLS Server Name and server watch disabled": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts:           "exec=/usr/local/bin/discover-servers",
					GRPCPort:        8503,
					EnableTLS:       true,
					TLSServerName:   "consul.dc1.address",
					SkipServerWatch: true,
				},
			},
			expConfig: func(t awsutil.ECSTaskMeta) discovery.Config {
				return discovery.Config{
					Addresses: "exec=/usr/local/bin/discover-servers",
					GRPCPort:  8503,
					TLS: &tls.Config{
						ServerName: "consul.dc1.address",
					},
					ServerWatchDisabled: true,
				}
			},
		},
		"ACL Auth method": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
				},
				ConsulLogin: ConsulLogin{
					Enabled:    true,
					Method:     "test-auth-method",
					Datacenter: "test-dc",
					Meta:       map[string]string{"key1": "value1", "key2": "value2"},
				},
				Service: ServiceRegistration{
					Namespace: "test-ns",
					Partition: "test-ns",
				},
			},
			taskMeta: awsutil.ECSTaskMeta{
				Cluster: "test-cluster",
				TaskARN: "arn:aws:ecs:us-east-1:123456789:task/test/abcdef",
				Family:  "family-service",
			},
			expConfig: func(t awsutil.ECSTaskMeta) discovery.Config {
				return discovery.Config{
					Addresses: "consul.dc1.address",
					Credentials: discovery.Credentials{
						Type: discovery.CredentialsTypeLogin,
						Login: discovery.LoginCredential{
							AuthMethod: "test-auth-method",
							Datacenter: "test-dc",
							Meta: map[string]string{
								"key1":                         "value1",
								"key2":                         "value2",
								"consul.hashicorp.com/task-id": t.TaskID(),
								"consul.hashicorp.com/cluster": t.Cluster,
							},
						},
					},
				}
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var srvConfig testutil.ServerConfigCallback
			if c.cfg.ConsulLogin.Enabled {
				// Enable ACLs to test with the auth method
				srvConfig = testutil.ConsulACLConfigFn
				_, apiCfg := testutil.ConsulServer(t, srvConfig)
				consulClient, err := api.NewClient(apiCfg)
				require.NoError(t, err)
				fakeAws := testutil.AuthMethodInit(t, consulClient, c.taskMeta.Family, c.cfg.ConsulLogin.Method)

				// Use the fake local AWS server.
				c.cfg.ConsulLogin.STSEndpoint = fakeAws.URL + "/sts"
			}

			cfg, err := c.cfg.ConsulServerConnMgrConfig(c.taskMeta)
			require.NoError(t, err)

			expectedCfg := c.expConfig(c.taskMeta)
			require.Equal(t, expectedCfg.Addresses, cfg.Addresses)

			if c.cfg.ConsulLogin.Enabled {
				require.Equal(t, expectedCfg.Credentials.Type, cfg.Credentials.Type)
				require.Equal(t, expectedCfg.Credentials.Login.AuthMethod, cfg.Credentials.Login.AuthMethod)
				require.Equal(t, expectedCfg.Credentials.Login.Namespace, cfg.Credentials.Login.Namespace)
				require.Equal(t, expectedCfg.Credentials.Login.Partition, cfg.Credentials.Login.Partition)
				require.Equal(t, expectedCfg.Credentials.Login.Meta, cfg.Credentials.Login.Meta)
				require.Equal(t, expectedCfg.Credentials.Login.Datacenter, cfg.Credentials.Login.Datacenter)
				require.NotEmpty(t, cfg.Credentials.Login.BearerToken)
			}
		})
	}
}

func TestConsulServerConnManagerConfig_TLS(t *testing.T) {
	caFile := writeCAFile(t)

	cases := map[string]struct {
		cfg        *Config
		setupEnv   func(*testing.T)
		cleanupEnv func() error
	}{
		"TLS with CACertFile": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts:      "consul.dc1.address",
					EnableTLS:  true,
					CACertFile: caFile.Name(),
				},
			},
		},
		"TLS with CACertPEM": {
			setupEnv: func(t *testing.T) {
				t.Setenv(consulCACertPemEnvVar, testCA)
			},
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts:     "consul.dc1.address",
					EnableTLS: true,
				},
			},
			cleanupEnv: func() error {
				return os.Unsetenv(consulCACertPemEnvVar)
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.setupEnv != nil {
				c.setupEnv(t)
				t.Cleanup(func() {
					require.NoError(t, c.cleanupEnv())
				})
			}
			cfg, err := c.cfg.ConsulServerConnMgrConfig(awsutil.ECSTaskMeta{})
			require.NoError(t, err)

			require.NotNil(t, cfg.TLS.RootCAs)
		})
	}
}

func TestClientConfig(t *testing.T) {
	caFile := writeCAFile(t)
	cases := map[string]struct {
		cfg        *Config
		expConfig  *api.Config
		setupEnv   func(*testing.T)
		cleanupEnv func() error
	}{
		"basic flags without TLS": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
				},
			},
			expConfig: &api.Config{
				Scheme: "http",
			},
		},
		"basic flags without TLS and custom service namespace and partition": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
				},
				Service: ServiceRegistration{
					Name:      "test-service",
					Namespace: "test-ns",
					Partition: "test-par",
				},
			},
			expConfig: &api.Config{
				Scheme:    "http",
				Namespace: "test-ns",
				Partition: "test-par",
			},
		},
		"basic flags without TLS and custom gateway namespace and partition": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
				},
				Gateway: &GatewayRegistration{
					Name:      "test-service",
					Namespace: "test-ns",
					Partition: "test-par",
					Kind:      api.ServiceKindMeshGateway,
				},
			},
			expConfig: &api.Config{
				Scheme:    "http",
				Namespace: "test-ns",
				Partition: "test-par",
			},
		},
		"TLS with CaCertFile": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts:           "consul.dc1.address",
					EnableHTTPS:     true,
					HTTPSCACertFile: caFile.Name(),
				},
			},
			expConfig: &api.Config{
				Scheme: "https",
				TLSConfig: api.TLSConfig{
					Address: "consul.dc1.address",
					CAFile:  caFile.Name(),
				},
			},
		},
		"TLS with CaCertPEM": {
			setupEnv: func(t *testing.T) {
				t.Setenv(consulHTTPSCertPemEnvVar, testCA)
			},
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts:         "exec=/usr/local/bin/query-servers",
					EnableHTTPS:   true,
					TLSServerName: "consul.dc1.address",
				},
			},
			cleanupEnv: func() error {
				return os.Unsetenv(consulHTTPSCertPemEnvVar)
			},
			expConfig: &api.Config{
				Scheme: "https",
				TLSConfig: api.TLSConfig{
					Address: "consul.dc1.address",
					CAPem:   []byte(testCA),
				},
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.setupEnv != nil {
				c.setupEnv(t)
				t.Cleanup(func() {
					require.NoError(t, c.cleanupEnv())
				})
			}

			cfg := c.cfg.ClientConfig()
			require.Equal(t, c.expConfig, cfg)
		})
	}
}

func writeCAFile(t *testing.T) *os.File {
	caFile, err := os.CreateTemp("", "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(caFile.Name())
	})

	_, err = caFile.WriteString(testCA)
	require.NoError(t, err)
	return caFile
}
