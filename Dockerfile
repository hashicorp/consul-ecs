FROM hashicorp/consul:1.9.5
COPY output/consul-ecs /bin/consul-ecs
ENTRYPOINT ["/bin/consul-ecs"]
