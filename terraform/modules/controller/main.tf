resource "aws_ecs_service" "consul-controller" {
  name            = "consul-controller-hcp-test"
  cluster         = var.ecs_cluster_name
  task_definition = aws_ecs_task_definition.consul-controller.arn
  desired_count   = 1
  network_configuration {
    subnets          = var.subnets
    assign_public_ip = var.assign_public_ip
  }
  launch_type            = "FARGATE"
  enable_execute_command = true
}

resource "aws_ecs_task_definition" "consul-controller" {
  family                   = "consul-controller-hcp-test"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  task_role_arn            = aws_iam_role.consul-controller.arn
  execution_role_arn       = aws_iam_role.consul-controller-execution.arn
  container_definitions = jsonencode([
    {
      name      = "consul-controller"
      image     = var.consul_ecs_image
      essential = true
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = var.cloudwatch_log_group_name
          awslogs-region        = var.region
          awslogs-stream-prefix = "consul-controller"
        }
      },
      command = concat(
        [
          "controller",
          "-tls=true",
          "-agent-secret-arn", var.consul_agent_token_secret_arn,
        ],
        var.consul_server_service_name != "" ? ["-consul-server-service-name", var.consul_server_service_name] : [],
        var.consul_server_api_hostname != "" ? ["-consul-server-api-hostname", var.consul_server_api_hostname] : [],
        ["-consul-server-api-scheme", var.consul_server_api_scheme],
        ["-consul-server-api-port", tostring(var.consul_server_api_port)]
      )
      linuxParameters = {
        initProcessEnabled = true
      }
      secrets = [
        {
          name      = "CONSUL_HTTP_TOKEN",
          valueFrom = "${var.consul_bootstrap_token_secret_arn}:token::"
        }
      ]
    },
  ])
}

resource "aws_iam_role" "consul-controller" {
  name = "consul-controller-hcp-test"
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
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonECS_FullAccess"]

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
        },
        {
          Effect = "Allow"
          Action = [
            "secretsmanager:GetSecretValue",
            "secretsmanager:UpdateSecret"
          ]
          Resource = var.consul_agent_token_secret_arn
        }
      ]
    })
  }
}

resource "aws_iam_policy" "consul-controller-execution" {
  name        = "consul-controller-hcp-test"
  path        = "/ecs/"
  description = "Consul controller execution"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": [
        "${var.consul_bootstrap_token_secret_arn}"
      ]
    },
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

resource "aws_iam_role" "consul-controller-execution" {
  name = "consul-controller-execution-hcp-test"
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

resource "aws_iam_role_policy_attachment" "consul-controller-execution" {
  role       = aws_iam_role.consul-controller-execution.id
  policy_arn = aws_iam_policy.consul-controller-execution.arn
}
