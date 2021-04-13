resource "aws_ecs_service" "consul-server" {
  name            = "consul-server"
  cluster         = var.ecs_cluster
  task_definition = aws_ecs_task_definition.consul-server.arn
  desired_count   = 1
  network_configuration {
    subnets = var.subnets
  }
  launch_type = "FARGATE"
  load_balancer {
    target_group_arn = aws_lb_target_group.consul-server.arn
    container_name   = "consul-server"
    container_port   = 8500
  }
  enable_execute_command = true
}

resource "aws_ecs_task_definition" "consul-server" {
  family                   = "consul-server"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.consul-server-execution.arn
  task_role_arn            = aws_iam_role.consul_server_task.arn
  volume {
    name = "consul-data"
  }
  container_definitions = jsonencode([
    {
      name      = "consul-server"
      image     = var.consul_image
      essential = true
      portMappings = [
        {
          containerPort = 8301
        },
        {
          containerPort = 8300
        },
        {
          containerPort = 8500
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = var.cloudwatch_log_group_name
          awslogs-region        = var.region
          awslogs-stream-prefix = "consul-server"
        }
      },
      entryPoint = ["/bin/sh", "-ec"]
      command    = [local.consul_server_command]
      mountPoints = [
        {
          sourceVolume  = "consul-data"
          containerPath = "/consul"
        }
      ]
      linuxParameters = {
        initProcessEnabled = true
      }
    }
  ])
}

resource "aws_iam_policy" "consul-server-execution" {
  name        = "consul-server-temp"
  path        = "/ecs/"
  description = "Consul server execution"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role" "consul-server-execution" {
  name = "consul-server-execution-temp"
  path = "/ecs/"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "consul-server-execution" {
  role       = aws_iam_role.consul-server-execution.id
  policy_arn = aws_iam_policy.consul-server-execution.arn
}

resource "aws_iam_role" "consul_server_task" {
  name = "consul-server-temp"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      },
    ]
  })

  inline_policy {
    name = "exec"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "ssmmessages:CreateControlChannel",
            "ssmmessages:CreateDataChannel",
            "ssmmessages:OpenControlChannel",
            "ssmmessages:OpenDataChannel"
          ]
          Resource = "*"
        }
      ]
    })
  }
}


locals {
  consul_server_command = <<EOF
ECS_IPV4=$(curl -s $ECS_CONTAINER_METADATA_URI | jq -r '.Networks[0].IPv4Addresses[0]')

exec consul agent -server \
  -bootstrap \
  -ui \
  -advertise "$ECS_IPV4" \
  -client 0.0.0.0 \
  -data-dir /tmp/consul-data \
  -encrypt "$CONSUL_GOSSIP_ENCRYPTION_KEY" \
  -hcl 'telemetry { disable_compat_1.9 = true }' \
  -hcl 'connect { enabled = true }' \
  -hcl 'enable_central_service_config = true' \
EOF
}

resource "aws_lb_target_group" "consul-server" {
  name                 = "consul-server-alb"
  port                 = 8500
  protocol             = "HTTP"
  vpc_id               = var.vpc_id
  target_type          = "ip"
  deregistration_delay = 10
  health_check {
    path                = "/v1/status/leader"
    healthy_threshold   = 2
    unhealthy_threshold = 10
    timeout             = 30
    interval            = 60
  }
}

resource "aws_lb" "consul-server" {
  name               = "consul-server"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.consul-server-alb-internet.id]
  subnets            = var.lb_subnets
}

resource "aws_lb_listener" "consul-server" {
  load_balancer_arn = aws_lb.consul-server.arn
  port              = "8500"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.consul-server.arn
  }
}

resource "aws_security_group" "consul-server-alb-internet" {
  name   = "consul-server-alb-internet"
  vpc_id = var.vpc_id

  ingress {
    description = var.lb_ingress_description
    from_port   = 8500
    to_port     = 8500
    protocol    = "tcp"
    cidr_blocks = var.lb_ingress_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
