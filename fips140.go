// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

//go:build fips

//go:debug fips140=on

package main

// This file only exists for FIPS builds. The //go:debug fips140=on directive
// bakes FIPS Mode activation into the binary so operators do not need to set
// GODEBUG=fips140=on at run time. The Go Cryptographic Module runs its
// pre-operational and conditional self-tests on initialization and aborts the
// process on failure (fail-closed).
