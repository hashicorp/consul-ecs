// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package dataplane

import (
	"encoding/json"
)

type DataplaneConfig struct {
	Consul    ConsulConfig     `json:"consul"`
	Proxy     ProxyConfig      `json:"proxy"`
	XDSServer XDSServerConfig  `json:"xdsServer"`
	Envoy     EnvoyConfig      `json:"envoy"`
	Logging   LoggingConfig    `json:"logging"`
	DNSServer *DNSServerConfig `json:"dnsServer,omitempty"`
}

type ConsulConfig struct {
	Addresses       string             `json:"addresses"`
	GRPCPort        int                `json:"grpcPort"`
	SkipServerWatch bool               `json:"serverWatchDisabled"`
	TLS             *TLSConfig         `json:"tls,omitempty"`
	Credentials     *CredentialsConfig `json:"credentials,omitempty"`
}

type TLSConfig struct {
	Disabled       bool   `json:"disabled"`
	GRPCCACertPath string `json:"caCertsPath,omitempty"`
	TLSServerName  string `json:"tlsServerName,omitempty"`
}

type CredentialsConfig struct {
	CredentialType string                 `json:"type"`
	Login          LoginCredentialsConfig `json:"login"`
}

type LoginCredentialsConfig struct {
	AuthMethod  string            `json:"authMethod"`
	Namespace   string            `json:"namespace,omitempty"`
	Partition   string            `json:"partition,omitempty"`
	Datacenter  string            `json:"datacenter"`
	BearerToken string            `json:"bearerToken"`
	Meta        map[string]string `json:"meta"`
}

type ProxyConfig struct {
	NodeName  string `json:"nodeName"`
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
	Partition string `json:"partition"`
}

type XDSServerConfig struct {
	Address string `json:"bindAddress"`
}

type EnvoyConfig struct {
	ReadyBindAddr string `json:"readyBindAddress"`
	ReadyBindPort int    `json:"readyBindPort"`
}

type LoggingConfig struct {
	LogLevel string `json:"logLevel"`
}

type DNSServerConfig struct {
	BindAddress string `json:"bindAddress"`
	BindPort    int    `json:"bindPort"`
}

func (d *DataplaneConfig) generateJSON() ([]byte, error) {
	dataplaneJSON, err := json.Marshal(&d)
	if err != nil {
		return nil, err
	}

	return dataplaneJSON, err
}
