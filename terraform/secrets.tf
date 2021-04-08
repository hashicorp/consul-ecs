
resource "aws_secretsmanager_secret" "consul-server" {
  name                    = "consul-server"
  recovery_window_in_days = 0
  tags                    = var.tags
}

resource "aws_secretsmanager_secret_version" "consul-server" {
  secret_id = aws_secretsmanager_secret.consul-server.id
  secret_string = jsonencode({
    ca_cert               = local.ca_cert
    ca_key                = local.ca_key // todo: only needed be ECS servers
    gossip_encryption_key = var.gossip_encryption_key
  })
}

resource "aws_secretsmanager_secret" "consul-agent-token" {
  name                    = "consul-agent-token"
  recovery_window_in_days = 0
  tags                    = var.tags
}

// This gets updated by the controller.
resource "aws_secretsmanager_secret_version" "consul-agent-token" {
  secret_id     = aws_secretsmanager_secret.consul-agent-token.id
  secret_string = jsonencode({})
}

resource "aws_secretsmanager_secret" "bootstrap-token" {
  name                    = "bootstrap-token"
  recovery_window_in_days = 0
  tags                    = var.tags
}

resource "aws_secretsmanager_secret_version" "bootstrap-token" {
  secret_id = aws_secretsmanager_secret.bootstrap-token.id
  secret_string = jsonencode({
    token = var.bootstrap_token
  })
}
