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
				"CVE-2025-46394", // busybox@1.37.0-r18
				"CVE-2024-58251", // busybox@1.37.0-r18
				"CVE-2025-30258", // gnupg@2.4.7-r0
				"CVE-2025-47268", // iputils@20240905-r0
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
