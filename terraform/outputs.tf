output "mesh_client_lb_address" {
  value = "http://${aws_lb.mesh-client.dns_name}:9090/ui"
}
