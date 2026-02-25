// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build !fips

package version

// IsFIPS returns true if consul-ecs is operating in FIPS-140-2 mode.
func IsFIPS() bool {
	return false
}
