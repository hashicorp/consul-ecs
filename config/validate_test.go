package config

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var config = Config{
	Secret: Secret{
		Provider: "secret-manager",
		Configuration: SecretConfiguration{
			Prefix:                     "asdf",
			ConsulClientTokenSecretARN: "ARN",
		},
	},
	Mesh: Mesh{
		Service: Service{
			Name: "blah",
			Port: 1234,
			Tags: []string{"tag1"},
			Meta: map[string]string{"a": "1"},
		},
		Sidecar: Sidecar{
			Proxy: SidecarProxy{
				Upstreams: []Upstream{
					{
						DestinationName: "asdf",
						LocalBindPort:   543,
					},
				},
			},
		},
		HealthSyncContainers: []string{"container1"},
		BootstrapDir:         "/consul/",
	},
}

func TestParse(t *testing.T) {
	rawConfig := OpenFile(t, "resources/test_config.json")
	parsedConfig, err := Parse(rawConfig)
	require.NoError(t, err)

	require.Equal(t, config, parsedConfig)

}

func TestParseErrrors(t *testing.T) {
	rawConfig := OpenFile(t, "resources/test_config_missing_fields.json")
	// TODO test multiple errors
	_, err := Parse(rawConfig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "aclTokenSecret: provider is required")
}

func TestGet(t *testing.T) {
	rawConfig := OpenFile(t, "resources/test_config.json")
	os.Setenv(configEnvironmentVariable, rawConfig)
	t.Cleanup(func() {
		err := os.Unsetenv(configEnvironmentVariable)
		require.NoError(t, err)
	})

	parsedConfig, err := Get(GetConfigOptions{})
	require.NoError(t, err)
	require.Equal(t, config, parsedConfig)
}

func OpenFile(t *testing.T, path string) string {
	file, err := os.Open(path)

	require.NoError(t, err)

	defer file.Close()

	byteFile, _ := ioutil.ReadAll(file)

	return string(byteFile)
}
