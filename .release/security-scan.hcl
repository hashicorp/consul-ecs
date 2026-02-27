# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

container {
	dependencies = true
	alpine_secdb = true
	secrets      = true
	triage {
		suppress {
			vulnerabilites = [
				"CVE-2025-46394", // busybox@1.37.0-r18
				"CVE-2024-58251", // busybox@1.37.0-r18
				"CVE-2025-30258", // gnupg@2.4.7-r0
				"CVE-2025-47268", // iputils@20240905-r0
				"CVE-2026-22184", // zlib@1.3.1-r2
				"CVE-2025-13151", // libtasn1@4.20.0-r0
				"CVE-2025-14819", // curl@8.17.0-r1
				"CVE-2025-14524", // curl@8.17.0-r1
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
				"GO-2022-0635", // github.com/aws/aws-sdk-go@v1.55.5
			]
		}
	}
}
