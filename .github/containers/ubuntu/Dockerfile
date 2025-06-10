# Dockerfile for FIPS builds compatible with Ubuntu (glibc)
FROM ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive

ARG GO_VERSION
ARG GOARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    crossbuild-essential-arm64 \
    curl \
    libc-bin \
    binutils \
    git \
    xz-utils \
    zip

# Install Go
RUN curl -L https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -C /opt -zxv

ENV PATH="/root/go/bin:/opt/go/bin:$PATH"

RUN git config --global --add safe.directory /build

# Accept FIPS-specific build args
ARG FIPS_MODE=1
ARG GO_TAGS="fips"
ARG LDFLAGS=""
ARG BIN_NAME="consul-ecs"

# Conditionally install cross-compiler for arm64 only
RUN if [ "$GOARCH" = "arm64" ]; then \
      apt-get update && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu; \
    fi

# Set up environment for FIPS build
ENV CGO_ENABLED=1 \
    GOEXPERIMENT=boringcrypto

WORKDIR /build

# Copy source code into container
COPY . /build

# Build the FIPS-enabled binary for the target arch
RUN cd /build && \
    /opt/go/bin/go version && \
    /opt/go/bin/go env && \
    if [ "$GOARCH" = "arm64" ]; then \
      CC=aarch64-linux-gnu-gcc /opt/go/bin/go build -tags="$GO_TAGS" -ldflags="$LDFLAGS" -o /bin/$BIN_NAME .; \
    else \
      /opt/go/bin/go build -tags="$GO_TAGS" -ldflags="$LDFLAGS" -o /bin/$BIN_NAME .; \
    fi
