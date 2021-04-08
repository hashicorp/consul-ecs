output "service_name" {
  value = aws_ecs_service.consul-server.name
}

output "lb_dns_name" {
  value = aws_lb.consul-server.dns_name
}
