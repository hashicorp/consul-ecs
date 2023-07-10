SHELL = /usr/bin/env bash -euo pipefail -c

# ---------- CRT ----------
BIN_NAME = consul-ecs

ARCH     = $(shell A=$$(uname -m); [ $$A = x86_64 ] && A=amd64; echo $$A)
OS       = $(shell uname | tr [[:upper:]] [[:lower:]])
PLATFORM = $(OS)/$(ARCH)
DIST     = dist/$(PLATFORM)
BIN      = $(DIST)/$(BIN_NAME)

BIN_NAME ?= consul-ecs
VERSION ?= $(shell ./build-scripts/version.sh version/version.go)

GIT_COMMIT ?= $(shell git rev-parse --short HEAD)
GIT_DIRTY ?= $(shell test -n "`git status --porcelain`" && echo "+CHANGES" || true)
PROJECT = $(shell go list -m)
LD_FLAGS ?= -X "$(PROJECT)/version.GitCommit=$(GIT_COMMIT)$(GIT_DIRTY)"

version:
	@echo $(VERSION)
.PHONY: version

dist:
	mkdir -p $(DIST)

dev: dist
	GOARCH=$(ARCH) GOOS=$(OS) go build -ldflags "$(LD_FLAGS)" -o $(BIN)
.PHONY: dev

dev-fips: dist
	GOARCH=$(ARCH) GOOS=$(OS) CGO_ENABLED=1 GOEXPERIMENT=boringcrypto go build -tags=fips  -ldflags "$(LD_FLAGS)" -o $(BIN)
.PHONY: dev-fips

# Docker Stuff.
# TODO: Docker in CircleCI doesn't support buildkit.
#       So we enable build-kit in the individual targets.
#       We can set this here one time, once we're off CircleCI.
# export DOCKER_BUILDKIT=1
BUILD_ARGS = BIN_NAME=consul-ecs PRODUCT_VERSION=$(VERSION) GIT_COMMIT=$(GIT_COMMIT) GIT_DIRTY=$(GIT_DIRTY)
TAG        = $(BIN_NAME)/$(TARGET):$(VERSION)
BA_FLAGS   = $(addprefix --build-arg=,$(BUILD_ARGS))
FLAGS      = --target $(TARGET) --platform $(PLATFORM) --tag $(TAG) $(BA_FLAGS)

# Set OS to linux for all docker targets.
docker: OS = linux
docker: TARGET = release-default
docker: dev
	export DOCKER_BUILDKIT=1; docker build $(FLAGS) .
.PHONY: docker

docker-fips: OS = linux
docker-fips: TARGET = release-fips-default
docker-fips: dev-fips
	export DOCKER_BUILDKIT=1; docker build $(FLAGS) .
.PHONY: docker-fips

# Generate reference config documentation.
# Usage:
#   make reference-configuration
#   make reference-configuration consul=<path-to-consul-repo>
# The consul repo path is relative to the defaults to ../../../consul.
consul?=../../../consul
reference-configuration:
	cd $(CURDIR)/hack/generate-config-reference; go run . > "$(consul)/website/content/docs/ecs/configuration-reference.mdx"


.PHONY: build-image ci.dev-docker dev-docker build-dev-dockerfile reference-configuration
