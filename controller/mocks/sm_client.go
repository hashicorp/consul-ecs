// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package mocks

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type SMClient struct {
	Secret *secretsmanager.GetSecretValueOutput
}

// SMAPI defines the interface for Secrets Manager v2 used by the controller
type SMAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	UpdateSecret(ctx context.Context, params *secretsmanager.UpdateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error)
}

func (m *SMClient) GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m.Secret, nil
}

func (m *SMClient) UpdateSecret(ctx context.Context, input *secretsmanager.UpdateSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error) {
	if m.Secret != nil {
		m.Secret.Name = input.SecretId
		m.Secret.SecretString = input.SecretString
	}
	return &secretsmanager.UpdateSecretOutput{}, nil
}
