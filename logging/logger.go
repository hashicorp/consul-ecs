// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"flag"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/go-hclog"
)

const defaultLogLevel = "INFO"

type LogOpts struct {
	LogLevel string
}

// FromConfig pulls log settings from the consul-ecs config JSON.
func FromConfig(conf *config.Config) *LogOpts {
	level := conf.LogLevel
	if level == "" {
		level = defaultLogLevel
	}
	return &LogOpts{LogLevel: level}
}

// Flags returns a FlagSet which can be used to add logging flags to a command.
func (l *LogOpts) Flags() *flag.FlagSet {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.StringVar(&l.LogLevel, "log-level", defaultLogLevel, "Log level for this command")
	return fs
}

// Logger returns a configured logger.
func (l *LogOpts) Logger() hclog.Logger {
	return hclog.New(
		&hclog.LoggerOptions{
			Level: hclog.LevelFromString(l.LogLevel),
		},
	)
}

// Merge merges flags from the src FlagSet to the dst FlagSet.
//
// https://github.com/hashicorp/consul/blob/64e35777e044a9c6122093067eacc871f440b7db/command/flags/merge.go
func Merge(dst, src *flag.FlagSet) {
	if dst == nil {
		panic("dst cannot be nil")
	}
	if src == nil {
		return
	}
	src.VisitAll(func(f *flag.Flag) {
		dst.Var(f.Value, f.Name, f.Usage)
	})
}
