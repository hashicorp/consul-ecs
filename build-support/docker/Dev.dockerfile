FROM hashicorp/consul-ecs:latest

COPY pkg/bin/linux_amd64/consul-ecs /bin
