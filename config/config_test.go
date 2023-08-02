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
		cfg                    *Config
		taskMeta               awsutil.ECSTaskMeta
		consulHTTPTokenPresent bool
		expConfig              func(awsutil.ECSTaskMeta) discovery.Config
	}{
		"basic flags without TLS or ACLs": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
					GRPC: GRPCSettings{
						Port: 8502,
					},
				},
			},
			expConfig: func(t awsutil.ECSTaskMeta) discovery.Config {
				return discovery.Config{
					Addresses: "consul.dc1.address",
					GRPCPort:  8502,
				}
			},
		},
		"TLS enabled only in default Settings": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
					GRPC: GRPCSettings{
						Port: 8503,
					},
					Defaults: DefaultSettings{
						EnableTLS: true,
					},
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
		"TLS enabled in GRPC Settings": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
					GRPC: GRPCSettings{
						Port:      8503,
						EnableTLS: testutil.BoolPtr(true),
					},
					Defaults: DefaultSettings{
						EnableTLS: false,
					},
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
		"TLS enabled only in default Settings with TLS ServerName": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
					GRPC: GRPCSettings{
						Port: 8503,
					},
					Defaults: DefaultSettings{
						EnableTLS:     true,
						TLSServerName: "consul.dc1.address",
					},
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
		"test if grpc TLS settings overrides the default TLS configuration": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts:           "exec=/usr/local/bin/discover-servers",
					SkipServerWatch: true,
					GRPC: GRPCSettings{
						Port:          8503,
						EnableTLS:     testutil.BoolPtr(true),
						TLSServerName: "consul.dc1.address",
					},
					Defaults: DefaultSettings{
						EnableTLS:     true,
						TLSServerName: "consul.dc2.address",
					},
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
		"TLS enabled in default settings but disabled in grpc settings": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts:           "exec=/usr/local/bin/discover-servers",
					SkipServerWatch: true,
					GRPC: GRPCSettings{
						Port:      8502,
						EnableTLS: testutil.BoolPtr(false),
					},
					Defaults: DefaultSettings{
						EnableTLS:     true,
						TLSServerName: "consul.dc2.address",
					},
				},
			},
			expConfig: func(t awsutil.ECSTaskMeta) discovery.Config {
				return discovery.Config{
					Addresses:           "exec=/usr/local/bin/discover-servers",
					GRPCPort:            8502,
					TLS:                 &tls.Config{},
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
					Partition: "test-partition",
				},
			},
			taskMeta: awsutil.ECSTaskMeta{
				Cluster: "test-cluster",
				TaskARN: "arn:aws:ecs:us-east-1:123456789:task/test/abcdef",
				Family:  "family-service",
			},
			expConfig: func(t awsutil.ECSTaskMeta) discovery.Config {
				clusterARN, err := t.ClusterARN()
				if err != nil {
					return discovery.Config{}
				}
				return discovery.Config{
					Addresses: "consul.dc1.address",
					Credentials: discovery.Credentials{
						Type: discovery.CredentialsTypeLogin,
						Login: discovery.LoginCredential{
							AuthMethod: "test-auth-method",
							Datacenter: "test-dc",
							Partition:  "test-partition",
							Meta: map[string]string{
								"key1":                         "value1",
								"key2":                         "value2",
								"consul.hashicorp.com/task-id": t.TaskID(),
								"consul.hashicorp.com/cluster": clusterARN,
							},
						},
					},
				}
			},
		},
		"Consul HTTP token is non empty": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
				},
				ConsulLogin: ConsulLogin{
					Enabled: true,
				},
			},
			expConfig: func(t awsutil.ECSTaskMeta) discovery.Config {
				return discovery.Config{
					Addresses: "consul.dc1.address",
					Credentials: discovery.Credentials{
						Type: discovery.CredentialsTypeStatic,
						Static: discovery.StaticTokenCredential{
							Token: "test-token",
						},
					},
				}
			},
			consulHTTPTokenPresent: true,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var srvConfig testutil.ServerConfigCallback
			if c.cfg.ConsulLogin.Enabled && !c.consulHTTPTokenPresent {
				// Enable ACLs to test with the auth method
				srvConfig = testutil.ConsulACLConfigFn
				_, apiCfg := testutil.ConsulServer(t, srvConfig)
				consulClient, err := api.NewClient(apiCfg)
				require.NoError(t, err)
				fakeAws := testutil.AuthMethodInit(t, consulClient, c.taskMeta.Family, c.cfg.ConsulLogin.Method)

				// Use the fake local AWS server.
				c.cfg.ConsulLogin.STSEndpoint = fakeAws.URL + "/sts"
			} else if c.cfg.ConsulLogin.Enabled {
				t.Setenv(bootstrapTokenEnvVar, "test-token")
			}

			cfg, err := c.cfg.ConsulServerConnMgrConfig(c.taskMeta)
			require.NoError(t, err)

			expectedCfg := c.expConfig(c.taskMeta)
			require.Equal(t, expectedCfg.Addresses, cfg.Addresses)

			if testutil.EnterpriseFlag() {
				expectedCfg.Credentials.Login.Partition = "test-partition"
			}

			if c.cfg.ConsulLogin.Enabled && !c.consulHTTPTokenPresent {
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
		cfg      *Config
		setupEnv func(*testing.T)
	}{
		"TLS with CACertFile provided via default settings": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
					GRPC: GRPCSettings{
						Port: 8503,
					},
					Defaults: DefaultSettings{
						EnableTLS:  true,
						CaCertFile: caFile.Name(),
					},
				},
			},
		},
		"test if grpc settings overrides the default tls configuration": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
					GRPC: GRPCSettings{
						Port:       8503,
						EnableTLS:  testutil.BoolPtr(true),
						CaCertFile: caFile.Name(),
					},
					Defaults: DefaultSettings{
						EnableTLS:  true,
						CaCertFile: "test-ca-cert",
					},
				},
			},
		},
		"TLS with CACertPEM": {
			setupEnv: func(t *testing.T) {
				t.Setenv(ConsulGRPCCACertPemEnvVar, testCA)
			},
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
					GRPC: GRPCSettings{
						Port:      8503,
						EnableTLS: testutil.BoolPtr(true),
					},
					Defaults: DefaultSettings{
						EnableTLS: false,
					},
				},
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.setupEnv != nil {
				c.setupEnv(t)
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
		cfg       *Config
		expConfig *api.Config
		setupEnv  func(*testing.T)
	}{
		"basic flags without TLS": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
					Defaults: DefaultSettings{
						EnableTLS: false,
					},
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
					Defaults: DefaultSettings{
						EnableTLS: false,
					},
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
					Defaults: DefaultSettings{
						EnableTLS: false,
					},
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
		"TLS with CaCertFile provided via default settings": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
					HTTP: HTTPSettings{
						Port:        8501,
						EnableHTTPS: true,
					},
					Defaults: DefaultSettings{
						EnableTLS:  true,
						CaCertFile: caFile.Name(),
					},
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
		"test if http tls settings override the default tls configuration": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
					HTTP: HTTPSettings{
						Port:        8501,
						EnableHTTPS: true,
						EnableTLS:   testutil.BoolPtr(true),
						CaCertFile:  caFile.Name(),
					},
					Defaults: DefaultSettings{
						EnableTLS:  true,
						CaCertFile: "test-ca-cert.pem",
					},
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
		"TLS enabled via default settings but disabled in http settings": {
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "consul.dc1.address",
					HTTP: HTTPSettings{
						Port:      8500,
						EnableTLS: testutil.BoolPtr(false),
					},
					Defaults: DefaultSettings{
						EnableTLS:  true,
						CaCertFile: caFile.Name(),
					},
				},
			},
			expConfig: &api.Config{
				Scheme:    "http",
				TLSConfig: api.TLSConfig{},
			},
		},
		"TLS with CaCertPEM": {
			setupEnv: func(t *testing.T) {
				t.Setenv(consulHTTPSCertPemEnvVar, testCA)
			},
			cfg: &Config{
				ConsulServers: ConsulServers{
					Hosts: "exec=/usr/local/bin/query-servers",
					HTTP: HTTPSettings{
						Port:          8501,
						EnableTLS:     testutil.BoolPtr(true),
						EnableHTTPS:   true,
						TLSServerName: "consul.dc1.address",
					},
					Defaults: DefaultSettings{
						EnableTLS: false,
					},
				},
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
