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

type SidecarProxy struct {
	// Use api.Upstream here. We can restrict allowed fields in jsonschema.
	Upstreams []api.Upstream `json:"upstreams,omitempty"`
}

type Sidecar struct {
	Proxy SidecarProxy `json:"proxy"`
}

type Service struct {
	Name   string                 `json:"name"`
	Checks api.AgentServiceChecks `json:"checks,omitempty"`
	Port   int                    `json:"port,omitempty"`
	Tags   []string               `json:"tags,omitempty"`
	Meta   map[string]string      `json:"meta,omitempty"`
}

type Mesh struct {
	BootstrapDir         string   `json:"bootstrapDir"`
	HealthSyncContainers []string `json:"healthSyncContainers,omitempty"`
	Sidecar              Sidecar  `json:"sidecar"`
	Service              Service  `json:"service"`
}

type Config struct {
	Secret Secret `json:"aclTokenSecret"`
	Mesh   Mesh   `json:"mesh"`
}
