package controller

// Service policy constants

const ossServicePolicyTpl = `service "%s" {
  policy = "write"
}
service "%s-sidecar-proxy" {
  policy = "write"
}
service_prefix "" {
  policy = "read"
}
node_prefix "" {
  policy = "read"
}`

const entServicePolicyTpl = `partition "%s" {
  namespace "%s" {
    service "%s" {
      policy = "write"
    }
    service "%s-sidecar-proxy" {
      policy = "write"
    }
    service_prefix "" {
      policy = "read"
    }
    node_prefix "" {
      policy = "read"
    }
  }
}`

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
