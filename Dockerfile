# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# This Dockerfile contains multiple targets.
# Use 'docker build --target=<name> .' to build one.
#
# Every target has a BIN_NAME argument that must be provided via --build-arg=BIN_NAME=<name>
# when building.

# go-discover builds the discover binary
FROM golang:1.22.4-alpine as go-discover
RUN CGO_ENABLED=0 go install github.com/hashicorp/go-discover/cmd/discover@214571b6a5309addf3db7775f4ee8cf4d264fd5f

FROM docker.mirror.hashicorp.services/alpine:latest AS release-default

ARG BIN_NAME=consul-ecs
ARG PRODUCT_VERSION
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH
# Export BIN_NAME for the CMD below, it can't see ARGs directly.
ENV BIN_NAME=$BIN_NAME
ENV VERSION=$PRODUCT_VERSION
ENV PRODUCT_NAME=$BIN_NAME

LABEL description="consul-ecs provides first-class integration between Consul and AWS ECS." \
      maintainer="Consul Team <consul@hashicorp.com>" \
      name=$BIN_NAME \
      release=$PRODUCT_VERSION \
      summary="consul-ecs provides first-class integration between Consul and AWS ECS." \
      vendor="HashiCorp" \
      version=$PRODUCT_VERSION \
      org.opencontainers.image.authors="Consul Team <consul@hashicorp.com>" \
      org.opencontainers.image.description="consul-ecs provides first-class integration between Consul and AWS ECS." \
      org.opencontainers.image.documentation="https://www.consul.io/docs/ecs" \
      org.opencontainers.image.source="https://github.com/hashicorp/consul-ecs" \
      org.opencontainers.image.title=$BIN_NAME \
      org.opencontainers.image.url="https://www.consul.io/" \
      org.opencontainers.image.vendor="HashiCorp" \
      org.opencontainers.image.licenses="MPL-2.0" \
      org.opencontainers.image.version=$PRODUCT_VERSION

# Create a non-root user to run the software.
RUN addgroup $BIN_NAME && \
    adduser -S -G $BIN_NAME $BIN_NAME && \
    # Changing the owner of /consul to NAME allows mesh-init to run as NAME rather
    # than root. See
    # https://docs.aws.amazon.com/AmazonECS/latest/developerguide/bind-mounts.html
    # for more information
    mkdir /consul && \
    chown $BIN_NAME:$BIN_NAME /consul

# This folder will hold the consul binary that comes from the the Consul client
# container at runtime
ENV PATH="/bin/consul-inject:${PATH}"

VOLUME [ "/consul" ]

# Set up certificates, base tools, and software.
RUN apk add --no-cache ca-certificates curl gnupg libcap openssl su-exec iputils iptables gcompat libc6-compat libstdc++

# for FIPS CGO glibc compatibility in alpine
# see https://github.com/golang/go/issues/59305
RUN ln -s /lib/libc.so.6 /usr/lib/libresolv.so.2

USER $BIN_NAME
ENTRYPOINT ["/bin/consul-ecs"]
COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /bin/
COPY LICENSE /usr/share/doc/$PRODUCT_NAME/LICENSE.txt
COPY --from=go-discover /go/bin/discover /bin/

# Separate FIPS target to accomodate CRT label assumptions
FROM release-default AS release-fips-default

# Set default target
FROM release-default
