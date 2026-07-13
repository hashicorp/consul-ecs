// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build fips

package version

// consul-ecs FIPS builds link against the in-tree Go Cryptographic Module
// (FIPS 140-3), selected at build time with GOFIPS140 and activated at run time
// with GODEBUG=fips140=on (baked into the binary via //go:debug fips140=on in
// fips140.go). In FIPS Mode the module constrains the security-relevant
// operations (including restricting TLS to FIPS-approved settings) and runs its
// pre-operational and conditional self-tests, aborting the process on failure.
//
// Note: unlike the former FIPS 140-2 boringcrypto build, crypto/tls/fipsonly is
// intentionally not imported here — that package only exists under
// GOEXPERIMENT=boringcrypto. TLS restriction is provided by the native module.

// IsFIPS returns true if consul-ecs is operating in FIPS-140-3 mode.
func IsFIPS() bool {
	return true
}
