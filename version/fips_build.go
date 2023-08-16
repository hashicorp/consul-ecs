// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build fips

package version

// This validates during compilation that we are being built with a FIPS enabled go toolchain
import (
	_ "crypto/tls/fipsonly"
)

// IsFIPS returns true if consul-ecs is operating in FIPS-140-2 mode.
func IsFIPS() bool {
	return true
}
