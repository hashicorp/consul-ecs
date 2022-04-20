package testutil

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/stretchr/testify/require"
)

// TaskMetaHandler returns an http.Handler that always responds with the given string
// for the 'GET /task' request of the ECS Task Metadata server.
func TaskMetaHandler(t *testing.T, resp string) http.Handler {
	return TaskMetaHandlerFn(t, func() string { return resp })
}

// TaskMetaHandler wraps the respFn in an http.Handler for the ECS Task Metadata server.
// respFn should return a response to the 'GET /task' request.
func TaskMetaHandlerFn(t *testing.T, respFn func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil && r.URL.Path == "/task" && r.Method == "GET" {
			resp := respFn()
			_, err := w.Write([]byte(resp))
			require.NoError(t, err)
		}
	})
}

// TaskMetaServer starts a local HTTP server to mimic the ECS Task Metadata server.
// This sets ECS_CONTAINER_METADATA_URI_V4 and configures a test cleanup.
// Because of the environment variable, this is unsafe for running tests in parallel.
func TaskMetaServer(t *testing.T, handler http.Handler) {
	ecsMetadataServer := httptest.NewServer(handler)
	t.Cleanup(func() {
		_ = os.Unsetenv(awsutil.ECSMetadataURIEnvVar)
		ecsMetadataServer.Close()
	})
	err := os.Setenv(awsutil.ECSMetadataURIEnvVar, ecsMetadataServer.URL)
	require.NoError(t, err)
}
