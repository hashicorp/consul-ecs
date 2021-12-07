package config

import "github.com/hashicorp/consul/api"

type SecretProvider string

type SecretConfiguration struct {
	Prefix                     string `json:"prefix"`
	ConsulClientTokenSecretARN string `json:"consulClientTokenSecretArn"`
}

type Secret struct {
	Provider      SecretProvider      `json:"provider"`
	Configuration SecretConfiguration `json:"configuration"`
}

type Mesh struct {
	BootstrapDir         string                       `json:"bootstrapDir"`
	HealthSyncContainers []string                     `json:"healthSyncContainers,omitempty"`
	Sidecar              api.AgentServiceRegistration `json:"sidecar"`
	Service              api.AgentServiceRegistration `json:"service"`
}

type Config struct {
	Secret Secret `json:"aclTokenSecret"`
	Mesh   Mesh   `json:"mesh"`
}
