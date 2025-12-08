// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package netdial

import (
	"net"
	"testing"

	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestNetDial(t *testing.T) {
	cases := map[string]struct {
		host   string
		code   int
		errStr string
	}{
		"success":              {host: "localhost", code: 0},
		"failure no listener":  {host: "localhost", code: 2},
		"failure invalid args": {code: 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ui := cli.NewMockUi()
			cmd := Command{UI: ui}

			var args []string

			if c.host != "" {
				l, err := net.Listen("tcp", c.host+":")
				require.NoError(t, err)
				args = append(args, l.Addr().String())
				if c.code != 0 {
					l.Close()
				} else {
					t.Cleanup(func() { l.Close() })
				}
			}

			require.Equal(t, c.code, cmd.Run(args))
		})
	}
}
