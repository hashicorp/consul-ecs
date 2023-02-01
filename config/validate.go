// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashicorp/go-multierror"
	"github.com/xeipuuv/gojsonschema"
)

const (
	ConfigEnvironmentVariable = "CONSUL_ECS_CONFIG_JSON"
)

func validate(config string) error {
	schemaLoader := gojsonschema.NewStringLoader(Schema)
	configLoader := gojsonschema.NewStringLoader(config)

	result, err := gojsonschema.Validate(schemaLoader, configLoader)
	if err != nil {
		return err
	}
	if result.Valid() {
		return nil
	}

	for _, e := range result.Errors() {
		err = multierror.Append(err, fmt.Errorf("%s", e.String()))
	}
	return err
}

func parse(encodedConfig string) (*Config, error) {
	if err := validate(encodedConfig); err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal([]byte(encodedConfig), &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func FromEnv() (*Config, error) {
	rawConfig := os.Getenv(ConfigEnvironmentVariable)
	if rawConfig == "" {
		return nil, fmt.Errorf("%q isn't populated", ConfigEnvironmentVariable)
	}
	return parse(rawConfig)
}
