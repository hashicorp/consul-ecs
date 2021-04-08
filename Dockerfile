FROM alpine:3.13.2
COPY output/consul-ecs consul-ecs
ENTRYPOINT ["./consul-ecs"]
