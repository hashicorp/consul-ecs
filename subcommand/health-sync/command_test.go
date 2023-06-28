// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go/aws/credentials"
	iamauth "github.com/hashicorp/consul-awsauth"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestNoCLIFlagsSupported(t *testing.T) {
	ui := cli.NewMockUi()
	cmd := Command{UI: ui}
	code := cmd.Run([]string{"some-arg"})
	require.Equal(t, 1, code)
	require.Equal(t, "unexpected argument: some-arg\n", ui.ErrorWriter.String())
}

func TestLogoutSuccess(t *testing.T) {
	bootstrapDir := testutil.TempDir(t)
	tokenFilename := "test-token"
	tokenPath := filepath.Join(bootstrapDir, tokenFilename)

	// Start Consul server.
	_, cfg := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
	client, err := api.NewClient(cfg)
	require.NoError(t, err)

	// Login to an auth method. We can only log out of tokens created by a login.
	fakeAws := testutil.AuthMethodInit(t, client, "test-service", config.DefaultAuthMethodName)

	loginData, err := iamauth.GenerateLoginData(&iamauth.LoginInput{
		Creds:                  credentials.NewStaticCredentials("fake-key-id", "fake-secret-key", ""),
		IncludeIAMEntity:       true,
		STSEndpoint:            fakeAws.URL + "/sts",
		STSRegion:              "fake-region",
		Logger:                 hclog.New(nil),
		GetEntityMethodHeader:  config.GetEntityMethodHeader,
		GetEntityURLHeader:     config.GetEntityURLHeader,
		GetEntityHeadersHeader: config.GetEntityHeadersHeader,
		GetEntityBodyHeader:    config.GetEntityBodyHeader,
	})
	require.NoError(t, err)
	bearerToken, err := json.Marshal(loginData)
	require.NoError(t, err)

	tok, _, err := client.ACL().Login(&api.ACLLoginParams{
		AuthMethod:  config.DefaultAuthMethodName,
		BearerToken: string(bearerToken),
		Meta:        nil,
	}, nil)
	require.NoError(t, err)

	// Write the token to file. Health-sync reads tokens from files.
	err = os.WriteFile(tokenPath, []byte(tok.SecretID), 0644)
	require.NoError(t, err)

	// Configure a client with the token.
	tokenCfg := api.DefaultConfig()
	tokenCfg.Address = cfg.Address
	tokenCfg.TokenFile = tokenPath
	tokenClient, err := api.NewClient(tokenCfg)
	require.NoError(t, err)
	_, _, err = tokenClient.ACL().TokenReadSelf(nil)
	require.NoError(t, err)

	ui := cli.NewMockUi()
	cmd := &Command{
		UI:  ui,
		log: hclog.NewNullLogger(),
		config: &config.Config{
			BootstrapDir:     bootstrapDir,
			ConsulHTTPAddr:   cfg.Address,
			ConsulCACertFile: cfg.TLSConfig.CAFile,
			ConsulLogin: config.ConsulLogin{
				Enabled: true,
			},
		},
	}

	err = cmd.logout(tokenFilename)
	require.NoError(t, err)

	// Ensure the token was deleted.
	tok, _, err = tokenClient.ACL().TokenReadSelf(nil)
	require.Error(t, err)
	require.Nil(t, tok)
}

func TestLogoutFailure(t *testing.T) {
	bootstrapDir := testutil.TempDir(t)
	tokenFilename := "test-token"
	tokenPath := filepath.Join(bootstrapDir, tokenFilename)

	_, cfg := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
	cmd := &Command{
		UI:  cli.NewMockUi(),
		log: hclog.NewNullLogger(),
		config: &config.Config{
			BootstrapDir:     bootstrapDir,
			ConsulHTTPAddr:   cfg.Address,
			ConsulCACertFile: cfg.TLSConfig.CAFile,
			ConsulLogin: config.ConsulLogin{
				Enabled: true,
			},
		},
	}

	t.Run("token file not found", func(t *testing.T) {
		err := cmd.logout(tokenFilename)
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating client for logout")
	})
	t.Run("invalid token", func(t *testing.T) {
		err := os.WriteFile(tokenPath, []byte("3a336524-e02f-4a7e-85f3-fe8687d20891"), 0600)
		require.NoError(t, err)
		err = cmd.logout(tokenFilename)
		require.Error(t, err)
		require.Contains(t, err.Error(), "logout failed")
	})

}
