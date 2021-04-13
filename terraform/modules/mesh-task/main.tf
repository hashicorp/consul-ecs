locals {
  discover_server_container = {
    name             = "discover-servers"
    image            = var.consul_ecs_image
    essential        = false
    logConfiguration = local.log_configuration
    command = [
      "discover-servers",
      "-service-name=${var.consul_server_service_name}",
      "-out=/consul/server-ip"
    ]
    mountPoints = [
      local.consul_data_mount
    ]
  }
  discover_servers_containers = var.dev_server_enabled ? [local.discover_server_container] : []
  log_configuration = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = var.log_group_name
      awslogs-region        = var.region
      awslogs-stream-prefix = var.family
    }
  }
  consul_data_volume_name = "consul_data"
  consul_data_mount = {
    sourceVolume  = local.consul_data_volume_name
    containerPath = "/consul"
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.family
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn
  volume {
    name = local.consul_data_volume_name
  }
  tags = {
    "consul.hashicorp.com/mesh"      = "true"
    "consul.hashicorp.com/port"      = var.port
    "consul.hashicorp.com/upstreams" = var.upstreams
  }
  container_definitions = jsonencode(
    flatten(
      concat(
        local.discover_servers_containers,
        [
          var.app_container,
          {
            name             = "consul-copy"
            image            = var.consul_image
            essential        = false
            logConfiguration = local.log_configuration
            command          = ["cp", "/bin/consul", "/consul/consul"]
            mountPoints = [
              local.consul_data_mount
            ]
          },
          {
            name             = "mesh-init"
            image            = var.consul_ecs_image
            essential        = false
            logConfiguration = local.log_configuration
            command = [
              "mesh-init",
              "-envoy-bootstrap-file=/consul/envoy-bootstrap.json",
              "-port=${var.port}",
              "-upstreams=${var.upstreams}"
            ]
            mountPoints = [
              local.consul_data_mount
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
                protocol      = "tcp"
              },
              {
                containerPort = 8300
                protocol      = "udp"
              },
              {
                containerPort = 8500
                protocol      = "tcp"
              },
            ]
            logConfiguration = local.log_configuration
            entryPoint       = ["/bin/sh", "-ec"]
            command = [
              templatefile(
                "${path.module}/templates/consul_client_command.tpl",
                {
                  dev_server_enabled = var.dev_server_enabled
                  retry_join         = var.retry_join
                }
              )
            ]
            mountPoints = [
              local.consul_data_mount
            ]
            linuxParameters = {
              initProcessEnabled = true
            }
            dependsOn = var.dev_server_enabled ? [{
              containerName = "discover-servers"
              condition     = "SUCCESS"
            }] : []
          },
          {
            name             = "sidecar-proxy"
            image            = var.envoy_image
            essential        = false
            logConfiguration = local.log_configuration
            command          = ["envoy", "--config-path", "/consul/envoy-bootstrap.json"]
            portMappings = [
              {
                containerPort = 20000
              },
            ]
            mountPoints = [
              local.consul_data_mount
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
        ]
      )
    )
  )
}
