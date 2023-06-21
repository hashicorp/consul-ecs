package meshinit

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateJSONWithoutTLS(t *testing.T) {
	cfg := &dataplaneConfig{
		Addresses: "consul_server.dc1",
		GRPCPort:  8502,
		NodeName:  "test-node-1",
		ServiceID: "frontend-service-sidecar-proxy",
	}

	jsonData, err := cfg.GenerateJSON()
	require.NoError(t, err)

	err = os.WriteFile("sample.json", jsonData, 0444)
	if err != nil {
		require.NoError(t, err)
	}
}

func TestGenerateJSONWithTLS(t *testing.T) {
	cfg := &dataplaneConfig{
		Addresses: "consul_server.dc1",
		GRPCPort:  8502,
		NodeName:  "test-node-1",
		ServiceID: "frontend-service-sidecar-proxy",
		TLS: &dataplaneTLSConfig{
			disabled:    false,
			caCertsPath: "sample.pem",
		},
	}

	_, err := cfg.GenerateJSON()
	require.NoError(t, err)

	// err = os.WriteFile("sample.json", jsonData, 0444)
	// if err != nil {
	// 	require.NoError(t, err)
	// }
}
