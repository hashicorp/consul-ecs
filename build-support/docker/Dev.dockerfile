FROM hashicorp/consul-ecs:latest

COPY pkg/bin/linux_amd64/consul-ecs /bin

# TODO remove this after the next release
# Changing the owner of /consul to NAME allows mesh-init to run as NAME rather
# than root. See
# https://docs.aws.amazon.com/AmazonECS/latest/developerguide/bind-mounts.html
# for more information
ARG NAME=consul-ecs
USER root
RUN chown ${NAME}:${NAME} /consul
VOLUME [ "/consul" ]
USER ${NAME}
