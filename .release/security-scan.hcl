# Copyright IBM Corp. 2021, 2025
# SPDX-License-Identifier: MPL-2.0

container {
  dependencies    = true
  alpine_security = true
  osv             = true
  go_modules      = true

  secrets {
    all = true
  }

  triage {
    suppress {
      // The security scanner will detect vulnerabilities in Alpine packages
      // that are included in the container image. While these packages have
      // known CVEs, they are patched at the OS level through apk upgrade.
      // This suppression targets the Alpine package database to avoid false
      // positives from the scanner.
      vulnerabilities = [
        "CVE-2025-30258",
        "CVE-2025-14017",
        "CVE-2026-1965",
        "CVE-2026-3783",
        "CVE-2026-3784",
        "CVE-2026-3805",
        "CVE-2025-14819",
        "CVE-2025-14524",
		"ALPINE-CVE-2026-22184",
		"ALPINE-CVE-2026-27171",
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
