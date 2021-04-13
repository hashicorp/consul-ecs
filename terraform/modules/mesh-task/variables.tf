variable "family" {}
variable "execution_role_arn" {}
variable "task_role_arn" {}
variable "port" {}
variable "consul_image" {}
variable "consul_ecs_image" {}
variable "log_group_name" {}
variable "region" {}
variable "app_container" {}
variable "upstreams" {
  default = ""
}
variable "consul_server_service_name" {}
variable "envoy_image" {

}

variable "dev_server_enabled" {
  type        = bool
  default     = true
  description = "Whether the Consul dev server running on ECS is enabled."
}

variable "retry_join" {
  type        = string
  default     = ""
  description = "Argument to pass to -retry-join. If dev_server_enabled=true don't set this, otherwise it's required (https://www.consul.io/docs/agent/options#_retry_join)."
}
