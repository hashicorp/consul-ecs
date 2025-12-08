// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"testing"

	"github.com/hashicorp/consul-ecs/config"
	"github.com/stretchr/testify/require"
)

func TestFromConfig(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		config   config.Config
		expected LogOpts
	}{
		"log level = empty string": {
			config:   config.Config{},
			expected: LogOpts{LogLevel: defaultLogLevel},
		},
		"log level = DEBUG": {
			config:   config.Config{LogLevel: "DEBUG"},
			expected: LogOpts{LogLevel: "DEBUG"},
		},
		// lower case okay
		"log level = trace": {
			config:   config.Config{LogLevel: "trace"},
			expected: LogOpts{LogLevel: "trace"},
		},
	}
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			opts := FromConfig(&c.config)
			require.Equal(t, &c.expected, opts)
		})
	}
}

func TestLogger(t *testing.T) {
	cases := []struct {
		opts LogOpts
	}{
		{LogOpts{LogLevel: "TRACE"}},
		{LogOpts{LogLevel: "DEBUG"}},
		{LogOpts{LogLevel: "INFO"}},
	}
	for _, c := range cases {
		t.Run(c.opts.LogLevel, func(t *testing.T) {
			logger := c.opts.Logger()
			switch c.opts.LogLevel {
			case "TRACE":
				require.True(t, logger.IsTrace())
			case "DEBUG":
				require.True(t, logger.IsDebug())
			case "INFO":
				require.True(t, logger.IsInfo())
			default:
				require.FailNow(t, "unhandled log level in assertion", "level = %s", c.opts.LogLevel)
			}
		})
	}
}
