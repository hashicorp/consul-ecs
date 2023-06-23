// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	configEnvVar = "CONSUL_ECS_CONFIG_JSON"
)

// TempDir creates a temporary directory. A test cleanup removes the directory
// and its contents.
func TempDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "")
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
		_ = os.Unsetenv(configEnvVar)
	})

	t.Setenv(configEnvVar, string(configBytes))

	t.Logf("%s=%s", configEnvVar, os.Getenv(configEnvVar))
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
