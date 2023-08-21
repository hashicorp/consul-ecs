package dataplane

import (
	"encoding/json"
)

type dataplaneConfig struct {
	Consul    ConsulConfig    `json:"consul"`
	Service   ServiceConfig   `json:"service"`
	XDSServer XDSServerConfig `json:"xdsServer"`
	Envoy     EnvoyConfig     `json:"envoy"`
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
	Static         StaticCredentialConfig `json:"static"`
}

type StaticCredentialConfig struct {
	Token string `json:"token"`
}

type ServiceConfig struct {
	NodeName       string `json:"nodeName"`
	ProxyServiceID string `json:"serviceID"`
	Namespace      string `json:"namespace"`
	Partition      string `json:"partition"`
}

type XDSServerConfig struct {
	Address string `json:"bindAddress"`
}

type EnvoyConfig struct {
	ReadyBindAddr string `json:"readyBindAddress"`
	ReadyBindPort int    `json:"readyBindPort"`
}

func (d *dataplaneConfig) generateJSON() ([]byte, error) {
	dataplaneJSON, err := json.Marshal(&d)
	if err != nil {
		return nil, err
	}

	return dataplaneJSON, err
}
