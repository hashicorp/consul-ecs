# Copyright IBM Corp. 2021, 2026
# SPDX-License-Identifier: MPL-2.0

container {
	dependencies = true
	alpine_secdb = true
	secrets      = true

	triage {
		suppress {
			vulnerabilities = [
				# False positive: fixed upstream in gnupg 2.4.8; Alpine ships 2.4.9-r1 but its secdb doesn't record the fix.
				"CVE-2025-30258",
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
			vulnerabilities = [
				"GO-2026-5932",
			]
		}
	}
}
