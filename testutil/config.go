package testutil

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/stretchr/testify/require"
)

// TempDir creates a temporary "bootstrap" directory. A test cleanup is configured to removes the
// temp directory and its contents.
func TempDir(t *testing.T) string {
	dir, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	t.Cleanup(func() {
		err := os.RemoveAll(dir)
		if err != nil {
			t.Logf("warning, failed to cleanup temp dir %s - %s", dir, err)
		}
	})

	return dir
}

// SetECSConfigEnvVar the CONSUL_ECS_CONFIG_JSON environment variable
// to the JSON string of the provided config.Config object. A test clean is added
// to unset the environment variable.
func SetECSConfigEnvVar(t *testing.T, conf *config.Config) {
	configBytes, err := json.MarshalIndent(conf, "", "  ")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = os.Unsetenv(config.ConfigEnvironmentVariable)
	})

	err = os.Setenv(config.ConfigEnvironmentVariable, string(configBytes))
	require.NoError(t, err)

	t.Logf("%s=%s", config.ConfigEnvironmentVariable, os.Getenv(config.ConfigEnvironmentVariable))
}
