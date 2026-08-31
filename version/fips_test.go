// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

//go:build fips

package version

import (
	"crypto/fips140"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFIPSModuleActive asserts that a fips-tagged binary is actually running the
// in-tree Go Cryptographic Module (FIPS 140-3). This closes the "we don't verify
// the module" gap: it fails if the binary was not built/activated with the native
// module (GOFIPS140 + GODEBUG=fips140=on).
func TestFIPSModuleActive(t *testing.T) {
	require.True(t, fips140.Enabled(), "expected FIPS 140-3 module to be active (build with GOFIPS140 and GODEBUG=fips140=on)")
	require.True(t, IsFIPS(), "expected IsFIPS() to report true for a fips build")
}

// TestFIPSVersionSuffix asserts the human version carries the FIPS 140-3 build
// metadata suffix.
func TestFIPSVersionSuffix(t *testing.T) {
	GitCommit = ""
	VersionPrerelease = ""
	require.True(t, strings.HasSuffix(GetHumanVersion(), "+fips1403"),
		"expected +fips1403 suffix, got %q", GetHumanVersion())
}
