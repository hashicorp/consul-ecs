variable "hcp_client_id" {}
variable "hcp_client_secret" {}

locals {
  hcp_hvn_id            = "lkysow-hcp-test"
  hcp_consul_cluster_id = "lkysow-hcp-test"
}

provider "hcp" {
  client_id     = var.hcp_client_id
  client_secret = var.hcp_client_secret
}

// Create a HashiCorp Virtual Network (HVN).
resource "hcp_hvn" "this" {
  hvn_id         = local.hcp_hvn_id
  cloud_provider = "aws"
  region         = var.region
  cidr_block     = "172.25.16.0/20"
}

// Create an HCP Consul cluster within the HVN.
resource "hcp_consul_cluster" "this" {
  hvn_id     = hcp_hvn.this.hvn_id
  cluster_id = local.hcp_consul_cluster_id
  tier       = "development"
}

data "aws_vpc" "vpc" {
  id = var.vpc_id
}

// Create an HCP network peering to peer your HVN with your AWS VPC.
resource "hcp_aws_network_peering" "this" {
  hvn_id              = hcp_hvn.this.hvn_id
  peer_vpc_id         = var.vpc_id
  peer_account_id     = data.aws_vpc.vpc.owner_id
  peer_vpc_region     = var.region
  peer_vpc_cidr_block = data.aws_vpc.vpc.cidr_block
}

// Accept the VPC peering within your AWS account.
resource "aws_vpc_peering_connection_accepter" "peer" {
  vpc_peering_connection_id = hcp_aws_network_peering.this.provider_peering_id
  auto_accept               = true
}
