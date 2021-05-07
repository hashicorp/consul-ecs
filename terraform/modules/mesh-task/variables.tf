variable "family" {}
variable "execution_role_arn" {}
variable "task_role_arn" {}
variable "port" {}
variable "consul_image" {}
variable "consul_ecs_image" {}
variable "log_group_name" {}
variable "region" {}
variable "consul_ca_cert_secret_arn" {}
variable "consul_ca_cert_secret_key" {}
variable "consul_gossip_encryption_secret_arn" {}
variable "consul_gossip_encryption_secret_key" {}
variable "consul_agent_token_secret_arn" {}
variable "consul_agent_token_secret_key" {}
variable "app_container" {}
variable "upstreams" {
  default = ""
}
variable "consul_server_service_name" {
  default = ""
}
variable "envoy_image" {

}
variable "retry_join_url" {
  default = []
  type    = list(string)
}

variable "datacenter" {
  type = string
}
