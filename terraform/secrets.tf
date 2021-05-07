resource "aws_secretsmanager_secret" "consul-server" {
  name                    = "consul-server-hcp-test"
  recovery_window_in_days = 0
  tags                    = var.tags
}

resource "aws_secretsmanager_secret_version" "consul-server" {
  secret_id = aws_secretsmanager_secret.consul-server.id
  secret_string = jsonencode({
    ca_cert               = base64decode(hcp_consul_cluster.this.consul_ca_file)
    gossip_encryption_key = jsondecode(base64decode(hcp_consul_cluster.this.consul_config_file))["encrypt"]
  })
}

resource "aws_secretsmanager_secret" "consul-agent-token" {
  name                    = "consul-agent-token-hcp-test"
  recovery_window_in_days = 0
  tags                    = var.tags
}

// This gets updated by the controller.
resource "aws_secretsmanager_secret_version" "consul-agent-token" {
  secret_id     = aws_secretsmanager_secret.consul-agent-token.id
  secret_string = jsonencode({})
}

resource "aws_secretsmanager_secret" "bootstrap-token" {
  name                    = "bootstrap-token-hcp-test"
  recovery_window_in_days = 0
  tags                    = var.tags
}

resource "aws_secretsmanager_secret_version" "bootstrap-token" {
  secret_id = aws_secretsmanager_secret.bootstrap-token.id
  secret_string = jsonencode({
    token = hcp_consul_cluster.this.consul_root_token_secret_id
  })
}
