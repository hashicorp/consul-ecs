locals {
  consul_client_command = <<EOT
ECS_IPV4=$(curl -s $ECS_CONTAINER_METADATA_URI | jq -r '.Networks[0].IPv4Addresses[0]')
TASK_ID=$(curl -s $ECS_CONTAINER_METADATA_URI | jq -r '.DockerId')
echo "$CONSUL_CACERT" > /tmp/consul-ca-cert.pem
echo "acl { tokens { agent = \"$AGENT_TOKEN\"} }"  > /tmp/acl-config.hcl

exec consul agent \
  -datacenter "${var.datacenter}" \
  -advertise "$ECS_IPV4" \
  -node "$TASK_ID" \
  -data-dir /consul/data \
  -encrypt "$CONSUL_GOSSIP_ENCRYPTION_KEY" \
  -config-file /tmp/acl-config.hcl \
  -client 0.0.0.0 \
  %{~for url in var.retry_join_url}  -retry-join "${url}" \
  %{~endfor~}
  -hcl 'telemetry { disable_compat_1.9 = true }' \
  -hcl 'leave_on_terminate = true' \
  -hcl 'ports { grpc = 8502 }' \
  -hcl 'advertise_reconnect_timeout = "15m"' \
  -hcl 'enable_central_service_config = true' \
  -hcl 'ca_file = "/tmp/consul-ca-cert.pem"' \
  -hcl 'auto_encrypt = {tls = true}' \
  -hcl "auto_encrypt = {ip_san = [\"$ECS_IPV4\"]}" \
  -hcl 'verify_outgoing = true' \
  -hcl 'ports {https = 8501}' \
  -hcl 'ports {http = -1}' \
  -hcl='acl {enabled = true, default_policy = "deny", down_policy = "extend-cache", enable_token_persistence = true}' \
EOT
}

resource "aws_ecs_task_definition" "mesh-app" {
  family                   = var.family
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn
  volume {
    name = "consul-data"
  }
  tags = {
    "consul.hashicorp.com/mesh"      = "true"
    "consul.hashicorp.com/port"      = var.port
    "consul.hashicorp.com/upstreams" = var.upstreams
  }
  container_definitions = jsonencode([
    {
      name      = "consul-copy"
      image     = var.consul_image
      essential = false
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = var.log_group_name
          awslogs-region        = var.region
          awslogs-stream-prefix = var.family
        }
      }
      command = ["cp", "/bin/consul", "/consul/consul"]
      mountPoints = [
        {
          sourceVolume  = "consul-data"
          containerPath = "/consul"
        }
      ]
    },
    {
      name      = "mesh-init"
      image     = var.consul_ecs_image
      essential = false
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = var.log_group_name
          awslogs-region        = var.region
          awslogs-stream-prefix = var.family
        }
      }
      command = [
        "mesh-init",
        "-envoy-bootstrap-file=/consul/envoy-bootstrap.json",
        "-tls=true",
        "-tokens-json-file=/consul/data/acl-tokens.json",
        "-port=${var.port}",
        "-upstreams=${var.upstreams}"
      ]
      mountPoints = [
        {
          sourceVolume  = "consul-data"
          containerPath = "/consul"
        }
      ]
      dependsOn = [
        {
          containerName = "consul-copy"
          condition     = "SUCCESS"
        },
      ]
    },
    {
      name      = "consul-client"
      image     = var.consul_image
      essential = false
      portMappings = [
        {
          containerPort = 8300
        },
        {
          containerPort = 8500
        },
        {
          containerPort = 8501
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = var.log_group_name
          awslogs-region        = var.region
          awslogs-stream-prefix = var.family
        }
      },
      entryPoint = ["/bin/sh", "-ec"]
      command    = [local.consul_client_command]
      mountPoints = [
        {
          sourceVolume  = "consul-data"
          containerPath = "/consul"
        }
      ]
      linuxParameters = {
        initProcessEnabled = true
      }
      environment = [
        {
          # copied from kube. todo: why?
          name  = "CONSUL_HTTP_SSL_VERIFY"
          value = "false"
        }
      ]
      secrets = [
        {
          name      = "CONSUL_CACERT",
          valueFrom = "${var.consul_ca_cert_secret_arn}:${var.consul_ca_cert_secret_key}::"
        },
        {
          name      = "AGENT_TOKEN",
          valueFrom = "${var.consul_agent_token_secret_arn}:${var.consul_agent_token_secret_key}::"
        },
        {
          name      = "CONSUL_GOSSIP_ENCRYPTION_KEY",
          valueFrom = "${var.consul_gossip_encryption_secret_arn}:${var.consul_gossip_encryption_secret_key}::"
        }
      ]
    },
    var.app_container,
    {
      name      = "sidecar-proxy"
      image     = var.envoy_image
      essential = false
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = var.log_group_name
          awslogs-region        = var.region
          awslogs-stream-prefix = var.family
        }
      }
      command = ["envoy", "--config-path", "/consul/envoy-bootstrap.json", "--log-level", "debug"]
      portMappings = [
        {
          containerPort = 20000
        },
      ]
      mountPoints = [
        {
          sourceVolume  = "consul-data"
          containerPath = "/consul"
        }
      ]
      dependsOn = [
        {
          containerName = "mesh-init"
          condition     = "SUCCESS"
        },
      ]
      healthCheck = {
        command  = ["nc", "-z", "127.0.0.1", "20000"]
        interval = 30
        retries  = 3
        timeout  = 5
      }
    }
  ])
}
