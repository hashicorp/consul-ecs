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
	Upstreams []api.Upstream `json:"upstreams"`
}

type Sidecar struct {
	Proxy SidecarProxy `json:"proxy"`
}

type Service struct {
	Name   string                  `json:"name"`
	Checks []api.AgentServiceCheck `json:"checks"`
	Port   int                     `json:"port"`
	Tags   []string                `json:"tags"`
	Meta   map[string]string       `json:"meta"`
}

type Mesh struct {
	BootstrapDir         string   `json:"bootstrapDir"`
	HealthSyncContainers []string `json:"healthSyncContainers"`
	Sidecar              Sidecar  `json:"sidecar"`
	Service              Service  `json:"service"`
}

type Config struct {
	Secret Secret `json:"aclTokenSecret"`
	Mesh   Mesh   `json:"mesh"`
}
