package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-multierror"
	"github.com/xeipuuv/gojsonschema"
)

type SecretProvider string

const (
	configEnvironmentVariable = "CONSUL_ECS_CONFIG_JSON"
)

type SecretConfiguration struct {
	Prefix                     string `json:"prefix"`
	ConsulClientTokenSecretARN string `json:"consulClientTokenSecretArn"`
}

type Secret struct {
	Provider      SecretProvider      `json:"provider"`
	Configuration SecretConfiguration `json:"configuration"`
}

// ensure this remains a subset of api.Upstream. Can we test this?
type Upstream struct {
	DestinationName string `json:"destinationName"`
	LocalBindPort   int    `json:"localBindPort"`
}

type SidecarProxy struct {
	Upstreams []Upstream `json:"upstreams"`
}

type Sidecar struct {
	Proxy SidecarProxy `json:"proxy"`
}

type Service struct {
	Name   string                  `json:"name"`
	Checks []api.AgentServiceCheck `json:"check"`
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

func validate(config string) error {
	schemaLoader := gojsonschema.NewStringLoader(schema)
	configLoader := gojsonschema.NewStringLoader(config)

	result, err := gojsonschema.Validate(schemaLoader, configLoader)

	if err != nil {
		return err
	}

	if result.Valid() {
		return nil
	} else {
		for _, e := range result.Errors() {
			err = multierror.Append(err, fmt.Errorf("%s", e.String()))
		}
	}

	return err
}

func Parse(encodedConfig string) (Config, error) {
	var config Config
	err := validate(encodedConfig)

	if err != nil {
		return config, err
	}

	err = json.Unmarshal([]byte(encodedConfig), &config)

	if err != nil {
		return config, err
	}

	return config, err
}

type GetConfigOptions struct {
	ParamName string
}

func Get(options GetConfigOptions) (Config, error) {
	var config Config

	rawConfig := os.Getenv(configEnvironmentVariable)

	if rawConfig == "" {
		return config, fmt.Errorf("%q isn't populated", configEnvironmentVariable)
	}

	return Parse(rawConfig)
}
