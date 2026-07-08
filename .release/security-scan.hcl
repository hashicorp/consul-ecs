# Copyright IBM Corp. 2021, 2026
# SPDX-License-Identifier: MPL-2.0

container {
	dependencies = true
	alpine_secdb = true
	secrets      = true

	triage {
		suppress {
			vulnerabilities = [
				"CVE-2025-30258", // Alpine Linux's Security Issue Tracker in gnupg@2.4.9-r0:
				// 2.4.x is the stable version of gnupg and the latest is 2.4.9 which is not affected by the vulnerability
				// according to NVD - CVE-2025-30258, but our scanner is still flagging it. Hence suppressing it for now.
				// Impact: gnupg is used only to verify signatures and is not exploitable in this context.
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
