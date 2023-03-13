// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package netdial

import (
	"net"
	"strings"
	"testing"

	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestNetDial(t *testing.T) {
	cases := map[string]struct {
		code int
	}{
		"success": {code: 0},
		"failure": {code: 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ui := cli.NewMockUi()
			cmd := Command{UI: ui}

			l, err := net.Listen("tcp", "localhost:")
			require.NoError(t, err)
			args := strings.Split(l.Addr().String(), ":")
			if c.code != 0 {
				l.Close()
			} else {
				t.Cleanup(func() { l.Close() })
			}

			require.Equal(t, c.code, cmd.Run(args))
		})
	}
}
