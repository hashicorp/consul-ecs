// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"fmt"
	"strings"
)

var (
	// The git commit that was compiled. These will be filled in by the compiler.
	GitCommit string

	// The main version number that is being run at the moment.
	//
	// Version must conform to the format expected by
	// github.com/hashicorp/go-version for tests to work.
	Version = "0.6.1"

	// A pre-release marker for the version. If this is "" (empty string)
	// then it means that it is a final release. Otherwise, this is a pre-release
	// such as "dev" (in development), "beta", "rc1", etc.
	VersionPrerelease = ""
)

// GetHumanVersion composes the parts of the version in a way that's suitable
// for displaying to humans.
func GetHumanVersion() string {
	version := Version

	if VersionPrerelease != "" {
		version += fmt.Sprintf("-%s", VersionPrerelease)
	}
	if GitCommit != "" {
		version += fmt.Sprintf(" (%s)", GitCommit)
	}

	// Strip off any single quotes added by the git information.
	return "v" + strings.Replace(version, "'", "", -1)
}
