// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controller

// Cross namespace policy constants
const xnsPolicyName = "cross-namespace-read"
const xnsPolicyDesc = "Allow service and node reads across namespaces within the partition"
const xnsPolicyTpl = `partition "%s" {
  namespace_prefix "" {
    service_prefix "" {
      policy = "read"
    }
    node_prefix "" {
      policy = "read"
    }
  }
}`
