package testutil

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/stretchr/testify/require"
)

// TempDir creates a temporary directory. A test cleanup removes the directory
// and its contents.
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
// to the JSON string of the provided value, with a test cleanup.
func SetECSConfigEnvVar(t *testing.T, val interface{}) {
	configBytes, err := json.MarshalIndent(val, "", "  ")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = os.Unsetenv(config.ConfigEnvironmentVariable)
	})

	err = os.Setenv(config.ConfigEnvironmentVariable, string(configBytes))
	require.NoError(t, err)

	t.Logf("%s=%s", config.ConfigEnvironmentVariable, os.Getenv(config.ConfigEnvironmentVariable))
}

// EnterpriseFlag indicates whether or not the test was invoked with the -enterprise
// command line argument.
func EnterpriseFlag() bool {
	re := regexp.MustCompile("^-+enterprise$")
	for _, a := range os.Args {
		if re.Match([]byte(strings.ToLower(a))) {
			return true
		}
	}
	return false
}
