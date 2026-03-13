# Copyright IBM Corp. 2021, 2025
# SPDX-License-Identifier: MPL-2.0

container {
	dependencies = true
	alpine_secdb = true
	secrets      = true
	triage {
		suppress {
			// The security scanner will detect vulnerabilities in Alpine packages
			// that are included in the container image. While these packages have
			// known CVEs, they are patched at the OS level through apk upgrade.
			// This suppression targets the Alpine package database to avoid false
			// positives from the scanner.
			vulnerabilites = [
				"lib/apk/db/*",
			]
		}
	}
}

binary {
	secrets      = true
	go_modules   = true
	osv          = true
	oss_index    = false
	nvd          = false

	triage {
		suppress {
			vulnerabilities = []
		}
	}
}
