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

// Cross partition/namespace policy constants
const xpPolicyName = "cross-ap-ns-read"
const xpPolicyDesc = "Allow service and node reads across all partitions and namespaces"
const xpPolicy = `partition_prefix "" {
  namespace_prefix "" {
    service_prefix "" {
      policy = "read"
    }
    node_prefix "" {
      policy = "read"
    }
  }
}`
