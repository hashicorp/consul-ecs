// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mocks

import (
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

type SMClient struct {
	secretsmanageriface.SecretsManagerAPI
	Secret *secretsmanager.GetSecretValueOutput
}

func (m *SMClient) GetSecretValue(*secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	return m.Secret, nil
}

func (m *SMClient) UpdateSecret(input *secretsmanager.UpdateSecretInput) (*secretsmanager.UpdateSecretOutput, error) {
	m.Secret.Name = input.SecretId
	m.Secret.SecretString = input.SecretString
	return nil, nil
}
