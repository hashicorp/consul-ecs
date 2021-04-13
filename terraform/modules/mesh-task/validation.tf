locals {
  require_retry_join = (!var.dev_server_enabled && var.retry_join == "") ? file("ERROR: retry_join must be set if dev_server_enabled=false so that Consul clients can join the cluster") : null
}
