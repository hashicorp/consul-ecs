package mocks

import (
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

type SMClient struct {
	secretsmanageriface.SecretsManagerAPI
	Secret        *secretsmanager.GetSecretValueOutput
	UpdateSecretF func(input *secretsmanager.UpdateSecretInput) (*secretsmanager.UpdateSecretOutput, error)
}

func (m *SMClient) GetSecretValue(*secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	return m.Secret, nil
}

func (m *SMClient) UpdateSecret(input *secretsmanager.UpdateSecretInput) (*secretsmanager.UpdateSecretOutput, error) {
	m.Secret.Name = input.SecretId
	m.Secret.SecretString = input.SecretString
	if m.UpdateSecretF != nil {
		return m.UpdateSecretF(input)
	}
	return nil, nil
}
