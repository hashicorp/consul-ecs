// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package mocks

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// SMClient implements a mock for the Secrets Manager v2 client.
type SMClient struct {
	Secret *secretsmanager.GetSecretValueOutput
}

// SMAPI defines the interface for Secrets Manager v2 used by the controller.
// This interface allows you to swap the real SDK client with this mock.
type SMAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	UpdateSecret(ctx context.Context, params *secretsmanager.UpdateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error)
}

// GetSecretValue mock implementation
func (m *SMClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m.Secret, nil
}

// UpdateSecret mock implementation
func (m *SMClient) UpdateSecret(ctx context.Context, params *secretsmanager.UpdateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error) {
	if m.Secret != nil {
		// In a real scenario, UpdateSecret might create a new version,
		// but for a mock, updating the current pointer is usually sufficient.
		m.Secret.Name = params.SecretId
		m.Secret.SecretString = params.SecretString
	}
	return &secretsmanager.UpdateSecretOutput{}, nil
}
