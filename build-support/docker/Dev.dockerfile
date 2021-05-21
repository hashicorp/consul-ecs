FROM hashicorp/consul-ecs:latest

# change the user to root so we can install stuff
USER root
RUN apk update && apk add iptables
USER consul-ecs

COPY pkg/bin/linux_amd64/consul-ecs /bin
