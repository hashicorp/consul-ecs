variable "consul_ecs_image" {}
variable "ecs_cluster_name" {}
variable "region" {}
variable "consul_agent_token_secret_arn" {}
variable "consul_bootstrap_token_secret_arn" {}
variable "cloudwatch_log_group_name" {}
variable "subnets" {}
variable "consul_server_service_name" {
  default = ""
}
variable "consul_server_api_hostname" {
  default = ""
}
variable "consul_server_api_scheme" {
  default = "http"
}
variable "consul_server_api_port" {
  default = 8500
}
variable "assign_public_ip" {
  default = false
}
