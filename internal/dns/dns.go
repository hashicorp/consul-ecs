// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dns

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/miekg/dns"
)

const (
	// Defaults taken from /etc/resolv.conf man page
	defaultDNSOptionNdots    = 1
	defaultDNSOptionTimeout  = 5
	defaultDNSOptionAttempts = 2

	defaultEtcResolvConfFile = "/etc/resolv.conf"
)

type ConfigureConsulDNSInput struct {
	// Used only for unit tests
	etcResolvConfFile string
}

// ConfigureConsulDNS reconstructs the /etc/resolv.conf file by setting the
// consul-dataplane's DNS server (i.e. localhost) as the first nameserver in the list.
func (i *ConfigureConsulDNSInput) ConfigureConsulDNS() error {
	etcResolvConfFile := defaultEtcResolvConfFile
	if i.etcResolvConfFile != "" {
		etcResolvConfFile = i.etcResolvConfFile
	}

	cfg, err := dns.ClientConfigFromFile(etcResolvConfFile)
	if err != nil {
		return err
	}

	if cfg == nil {
		return fmt.Errorf("failed to fetch DNS config")
	}

	options := constructDNSOpts(cfg)

	nameservers := []string{config.ConsulDataplaneDNSBindHost}
	nameservers = append(nameservers, cfg.Servers...)

	return buildResolveConf(etcResolvConfFile, cfg, nameservers, options)
}

func constructDNSOpts(cfg *dns.ClientConfig) []string {
	var opts []string
	if cfg.Ndots != defaultDNSOptionNdots {
		opts = append(opts, fmt.Sprintf("ndots:%d", cfg.Ndots))
	}

	if cfg.Timeout != defaultDNSOptionTimeout {
		opts = append(opts, fmt.Sprintf("timeout:%d", cfg.Timeout))
	}

	if cfg.Attempts != defaultDNSOptionAttempts {
		opts = append(opts, fmt.Sprintf("attempts:%d", cfg.Attempts))
	}

	return opts
}

func buildResolveConf(etcResolvConfFile string, cfg *dns.ClientConfig, nameservers, options []string) error {
	content := bytes.NewBuffer(nil)
	if len(cfg.Search) > 0 {
		if searchString := strings.Join(cfg.Search, " "); strings.Trim(searchString, " ") != "." {
			if _, err := content.WriteString("search " + searchString + "\n"); err != nil {
				return err
			}
		}
	}

	for _, ns := range nameservers {
		if _, err := content.WriteString("nameserver " + ns + "\n"); err != nil {
			return err
		}
	}

	if len(options) > 0 {
		if optsString := strings.Join(options, " "); strings.Trim(optsString, " ") != "" {
			if _, err := content.WriteString("options " + optsString + "\n"); err != nil {
				return err
			}
		}
	}

	return os.WriteFile(etcResolvConfFile, content.Bytes(), 0644)
}
