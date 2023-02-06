// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	cases := map[string]struct {
		commit     string
		prerelease string

		expVersion string
	}{
		"no commit and no prerelease": {
			expVersion: "v" + Version,
		},
		"commit but no prerelease": {
			commit:     "asdf",
			expVersion: "v" + Version + " (asdf)",
		},
		"prerelease but no commit": {
			prerelease: "beta1",
			expVersion: "v" + Version + "-beta1",
		},
		"commit and prerelease": {
			commit:     "asdf",
			prerelease: "beta1",
			expVersion: "v" + Version + "-beta1 (asdf)",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			GitCommit = c.commit
			VersionPrerelease = c.prerelease
			require.Equal(t, c.expVersion, GetHumanVersion())
		})
	}
}
