variable "tags" {}
variable "region" {}
variable "ecs_cluster" {}
variable "subnets" {}
variable "vpc_id" {}
variable "cloudwatch_log_group_name" {}
variable "lb_subnets" {}
variable "lb_ingress_description" {}
variable "lb_ingress_cidr_blocks" {}
variable "consul_image" {
  default = "hashicorp/consul:1.9.4"
}
