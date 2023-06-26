package dataplane

import (
	"bytes"
	"encoding/json"
	"strconv"
	"text/template"
)

type dataplaneConfig struct {
	consul    consulConfig
	service   serviceConfig
	logging   loggingConfig
	xdsServer xdsServerConfig
	envoy     envoyConfig
	telemetry telemetryConfig
}

type dataplaneConfigTmplArgs struct {
	ConsulJSON    string
	ServiceJSON   string
	LoggingJSON   string
	XDSServerJSON string
	EnvoyJSON     string
	TelemetryJSON string
}

func (d *dataplaneConfig) generateJSON() ([]byte, error) {
	dpCfgTmplArgs := &dataplaneConfigTmplArgs{}
	var err error

	dpCfgTmplArgs.ConsulJSON, err = d.consul.generateJSON()
	if err != nil {
		return nil, err
	}

	dpCfgTmplArgs.ServiceJSON = d.service.generateJSON()
	dpCfgTmplArgs.LoggingJSON = d.logging.generateJSON()
	dpCfgTmplArgs.TelemetryJSON = d.telemetry.generateJSON()
	dpCfgTmplArgs.EnvoyJSON = d.envoy.generateJSON()
	dpCfgTmplArgs.XDSServerJSON = d.xdsServer.generateJSON()

	t, err := template.New("dataplane").Parse(dataplaneConfigTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = t.Execute(&buf, dpCfgTmplArgs)
	if err != nil {
		return nil, err
	}

	// prettify json before returning
	var prettyBuf bytes.Buffer
	if err := json.Indent(&prettyBuf, buf.Bytes(), "", "  "); err != nil {
		return nil, err
	}

	return prettyBuf.Bytes(), nil
}

const dataplaneConfigTemplate = `{
	"consul": {{ .ConsulJSON }},
	"service": {{ .ServiceJSON }},
	"logging": {{ .LoggingJSON }},
	"xdsServer": {{ .XDSServerJSON }},
	"envoy": {{ .EnvoyJSON }},
	"telemetry": {{ .TelemetryJSON }}
}`

type consulConfig struct {
	addresses       string
	grpcPort        int
	skipServerWatch bool
	tls             *tlsConfig
	credentials     *credentialsConfig
}

type consulConfigTmplArgs struct {
	Addresses       string
	GRPCPort        int
	SkipServerWatch bool
	TLSJSON         string
	CredentialsJSON string
}

func (c consulConfig) generateJSON() (string, error) {
	tmplArgs := &consulConfigTmplArgs{
		Addresses:       c.addresses,
		GRPCPort:        c.grpcPort,
		SkipServerWatch: c.skipServerWatch,
	}

	if c.tls != nil {
		tmplArgs.TLSJSON = c.tls.generateJSON()
	}

	if c.credentials != nil {
		tmplArgs.CredentialsJSON = c.credentials.generateJSON()
	}

	t, err := template.New("consulConfig").Parse(consulConfigTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = t.Execute(&buf, tmplArgs)
	if err != nil {
		return "", err
	}

	return buf.String(), err
}

const consulConfigTemplate = `{
	"addresses": "{{ .Addresses }}",
	"grpcPort": {{ .GRPCPort }},
	"serverWatchDisabled": {{ .SkipServerWatch }}
	{{- if .TLSJSON }}
	,
	"tls": {{ .TLSJSON }}
	{{- end }}
	{{- if .CredentialsJSON }}
	,
	"credentials": {{ .CredentialsJSON }}
	{{- end }}
}`

type tlsConfig struct {
	grpcCACertPath string
	tlsServerName  string
}

func (t *tlsConfig) generateJSON() string {
	return `{
		"disabled": false,
		"caCertsPath": "` + t.grpcCACertPath + `",
		"tlsServerName": "` + t.tlsServerName + `"
	}`
}

type credentialsConfig struct {
	credentialType string
	static         staticCredentialConfig
}

func (c *credentialsConfig) generateJSON() string {
	return `{
		"type": "` + c.credentialType + `",
		"static":` + c.static.generateJSON() + `
	}`
}

type staticCredentialConfig struct {
	token string
}

func (s staticCredentialConfig) generateJSON() string {
	return `{
		"token": "` + s.token + `"
	}`
}

type serviceConfig struct {
	nodeName       string
	proxyServiceID string
	namespace      string
	partition      string
}

func (s serviceConfig) generateJSON() string {
	return `{
		"nodeName": "` + s.nodeName + `",
		"serviceID": "` + s.proxyServiceID + `",
		"namespace": "` + s.namespace + `",
		"partition": "` + s.partition + `"
	}`
}

type loggingConfig struct {
	json  bool
	level string
}

func (l loggingConfig) generateJSON() string {
	return `{
		"logLevel": "` + l.level + `",
		"logJSON": ` + strconv.FormatBool(l.json) + `
	}`
}

type xdsServerConfig struct {
	address string
	port    int
}

func (x xdsServerConfig) generateJSON() string {
	return `{
		"bindAddress": "` + x.address + `",
		"bindPort": ` + strconv.FormatInt(int64(x.port), 10) + `
	}`
}

type envoyConfig struct {
	adminBindAddress string
	adminBindPort    int
}

func (e envoyConfig) generateJSON() string {
	return `{
		"adminBindAddress": "` + e.adminBindAddress + `",
		"adminBindPort": ` + strconv.FormatInt(int64(e.adminBindPort), 10) + `
	}`
}

type telemetryConfig struct {
	useCentralConfig bool
}

func (t telemetryConfig) generateJSON() string {
	return `{
		"useCentralConfig": ` + strconv.FormatBool(t.useCentralConfig) + `
	}`
}
