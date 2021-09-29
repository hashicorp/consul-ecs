FROM hashicorp/consul-ecs:latest

COPY pkg/bin/linux_amd64/consul-ecs /bin

ARG USER=consul-ecs
ARG MOUNT="/consul"

RUN mkdir -p ${MOUNT} && chown ${consul-ecs}:${consul-ecs} ${MOUNT}
VOLUME [${MOUNT}]
