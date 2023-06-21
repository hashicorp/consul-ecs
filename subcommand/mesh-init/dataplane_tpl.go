package meshinit

import (
	"bytes"
	"encoding/json"
	"strconv"
	"text/template"
)

type dataplaneConfig struct {
	Addresses string
	GRPCPort  int64
	NodeName  string
	ServiceID string
	TLS       *dataplaneTLSConfig
}

type dataplaneConfigTmplArgs struct {
	Addresses string
	GRPCPort  int64
	NodeName  string
	ServiceID string
	TLSJSON   string
}

type dataplaneTLSConfig struct {
	disabled    bool
	caCertsPath string
}

func (d *dataplaneConfig) GenerateJSON() ([]byte, error) {
	args := &dataplaneConfigTmplArgs{}
	args.Addresses = d.Addresses
	args.GRPCPort = d.GRPCPort
	args.NodeName = d.NodeName
	args.ServiceID = d.ServiceID
	if d.TLS != nil {
		args.TLSJSON = d.TLS.GenerateTLSConfigJSON()
	}

	t, err := template.New("dataplane").Parse(dataplaneConfigTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = t.Execute(&buf, args)
	if err != nil {
		return nil, err
	}

	var buf2 bytes.Buffer
	if err := json.Indent(&buf2, buf.Bytes(), "", "  "); err != nil {
		return nil, err
	}

	return buf2.Bytes(), nil
}

func (d *dataplaneTLSConfig) GenerateTLSConfigJSON() string {
	return `"tls":{
        "disabled": ` + strconv.FormatBool(d.disabled) + `,
		"caCertsPath": "` + d.caCertsPath + `"` +
		`}`
}

// "xdsServer": {
// 	"bindAddress": "{{ .TaskIP }}",
// 	"bindPort": 20000
// },

const dataplaneConfigTemplate = `{
	"consul": {
		"addresses": "{{ .Addresses }}",
		"grpcPort": {{ .GRPCPort }},
		"serverWatchDisabled": false
		{{- if .TLSJSON -}}
		,
		{{ .TLSJSON }}
        {{- end }}
	},
	"service": {
		"nodeName": "{{ .NodeName }}",
		"serviceId": "{{ .ServiceID }}",
		"namespace": "default",
		"partition": "default"
	},
	"envoy": {
		"adminBindAddress": "127.0.0.1",
		"adminBindPort": 19000
	},
	"logging": {
		"name": "dp_",
		"logLevel": "info",
		"logJSON": false
	}
}
`
