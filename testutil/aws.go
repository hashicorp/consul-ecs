// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/testutil/iamauthtest"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil/retry"
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
		if r != nil && r.Method == "GET" {
			switch r.URL.Path {
			case "/task":
				resp := respFn()
				_, err := w.Write([]byte(resp))
				require.NoError(t, err)
			case "/ok":
				// A "health" endpoint to make sure the server has started for tests.
				// We don't use /task to avoid affecting state used by respFn.
				_, err := w.Write([]byte("ok"))
				require.NoError(t, err)
			}
		}
	})
}

// TaskMetaServer starts a local HTTP server to mimic the ECS Task Metadata server.
// This sets ECS_CONTAINER_METADATA_URI_V4 and configures a test cleanup.
// Because of the environment variable, this is unsafe for running tests in parallel.
func TaskMetaServer(t *testing.T, handler http.Handler) {
	ecsMetadataServer := httptest.NewServer(handler)

	// Help detect invalid concurrent servers since this relies on an environment variable.
	require.Empty(t, os.Getenv(awsutil.ECSMetadataURIEnvVar),
		"%s already set. TaskMetaServer cannot be used concurrently.", awsutil.ECSMetadataURIEnvVar,
	)

	t.Cleanup(func() {
		_ = os.Unsetenv(awsutil.ECSMetadataURIEnvVar)
		ecsMetadataServer.Close()
	})
	err := os.Setenv(awsutil.ECSMetadataURIEnvVar, ecsMetadataServer.URL)

	require.NoError(t, err)

	// Wait for a successful response before proceeding.
	retry.RunWith(&retry.Timer{Timeout: 3 * time.Second, Wait: 250 * time.Millisecond}, t, func(r *retry.R) {
		resp, err := ecsMetadataServer.Client().Get(ecsMetadataServer.URL + "/ok")
		require.NoError(r, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(r, err)
		require.Equal(r, string(body), "ok")
	})

}

// AuthMethodInit sets up necessary pieces for the IAM auth method:
//   - Start a fake AWS server. This responds with an IAM role tagged with expectedServiceName.
//   - Configures an auth method + binding rule that uses the tagged service name from the IAM
//     role for the service identity.
//   - Sets the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to dummy values.
//
// When using this, you will also need to point the login command at the fake AWS server,
// for example:
//
//	fakeAws := authMethodInit(...)
//	consulLogin.ExtraLoginFlags = []string{"-aws-sts-endpoint", fakeAws.URL + "/sts"}
func AuthMethodInit(t *testing.T, consulClient *api.Client, expectedServiceName string) *httptest.Server {
	arn := "arn:aws:iam::1234567890:role/my-role"
	uniqueId := "AAAsomeuniqueid"

	// Start a fake AWS API server for STS and IAM.
	fakeAws := iamauthtest.NewTestServer(t, &iamauthtest.Server{
		GetCallerIdentityResponse: iamauthtest.MakeGetCallerIdentityResponse(
			arn, uniqueId, "1234567890",
		),
		GetRoleResponse: iamauthtest.MakeGetRoleResponse(
			arn, uniqueId, iamauthtest.Tags{
				Members: []iamauthtest.TagMember{
					{Key: "service-name", Value: expectedServiceName},
				},
			},
		),
	})

	method, _, err := consulClient.ACL().AuthMethodCreate(&api.ACLAuthMethod{
		Name:        config.DefaultAuthMethodName,
		Type:        "aws-iam",
		Description: "aws auth method for unit test",
		Config: map[string]interface{}{
			// Trust the role to login.
			"BoundIAMPrincipalARNs": []string{arn},
			// Enable fetching the IAM role
			"EnableIAMEntityDetails": true,
			// Make this tag available to the binding rule: `entity_tags.service_name`
			"IAMEntityTags": []string{"service-name"},
			// Point the auth method at the local fake AWS server.
			"STSEndpoint": fakeAws.URL + "/sts",
			"IAMEndpoint": fakeAws.URL + "/iam",
		},
	}, nil)
	require.NoError(t, err)

	_, _, err = consulClient.ACL().BindingRuleCreate(&api.ACLBindingRule{
		AuthMethod: method.Name,
		BindType:   api.BindingRuleBindTypeService,
		// Pull the service name from the IAM role `service-name` tag.
		BindName: "${entity_tags.service-name}",
	}, nil)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Unsetenv("AWS_ACCESS_KEY_ID")
		os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	})
	os.Setenv("AWS_ACCESS_KEY_ID", "fake-key-id")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "fake-secret-key")

	return fakeAws
}
