SHELL = bash

GIT_COMMIT?=$(shell git rev-parse --short HEAD)

DEV_IMAGE?=consul-ecs-dev
GIT_COMMIT?=$(shell git rev-parse --short HEAD)
GIT_DIRTY?=$(shell test -n "`git status --porcelain`" && echo "+CHANGES" || true)
GIT_DESCRIBE?=$(shell git describe --tags --always)
CONSUL_ECS_VERSION?=$(shell git tag -l --sort -version:refname | head -n 1 | cut -c2-)

################
# CI Variables #
################
CI_DEV_DOCKER_NAMESPACE?=hashicorpdev
CI_DEV_DOCKER_IMAGE_NAME?=consul-ecs
CI_DEV_DOCKER_WORKDIR?=.
################

DEV_PUSH?=0
ifeq ($(DEV_PUSH),1)
DEV_PUSH_ARG=
else
DEV_PUSH_ARG=--no-push
endif

dev-tree:
	@$(SHELL) $(CURDIR)/build-support/scripts/dev.sh $(DEV_PUSH_ARG)

build-dev-dockerfile:
	@cp $(CURDIR)/build-support/docker/Release.dockerfile $(CURDIR)/build-support/docker/Dev.dockerfile
	@cat $(CURDIR)/build-support/docker/dev-patches >> $(CURDIR)/build-support/docker/Dev.dockerfile


# In CircleCI, the linux binary will be attached from a previous step at pkg/bin/linux_amd64/. This make target
# should only run in CI and not locally.
ci.dev-docker: build-dev-dockerfile
	@echo "Building consul-ecs Development container - $(CI_DEV_DOCKER_IMAGE_NAME)"
	@echo $(CI_DEV_DOCKER_WORKDIR)
	@echo $(CURDIR)
	@docker build -t '$(CI_DEV_DOCKER_NAMESPACE)/$(CI_DEV_DOCKER_IMAGE_NAME):$(GIT_COMMIT)' \
	--build-arg VERSION=$(CONSUL_ECS_VERSION) \
	--label COMMIT_SHA=$(CIRCLE_SHA1) \
	--label PULL_REQUEST=$(CIRCLE_PULL_REQUEST) \
	--label CIRCLE_BUILD_URL=$(CIRCLE_BUILD_URL) \
	$(CI_DEV_DOCKER_WORKDIR) -f $(CURDIR)/build-support/docker/Dev.dockerfile
	@echo $(DOCKER_PASS) | docker login -u="$(DOCKER_USER)" --password-stdin
	@echo "Pushing dev image to: https://cloud.docker.com/u/$(CI_DEV_DOCKER_NAMESPACE)/repository/docker/$(CI_DEV_DOCKER_NAMESPACE)/$(CI_DEV_DOCKER_IMAGE_NAME)"
	@docker push $(CI_DEV_DOCKER_NAMESPACE)/$(CI_DEV_DOCKER_IMAGE_NAME):$(GIT_COMMIT)
ifeq ($(CIRCLE_BRANCH), main)
	@docker tag $(CI_DEV_DOCKER_NAMESPACE)/$(CI_DEV_DOCKER_IMAGE_NAME):$(GIT_COMMIT) $(CI_DEV_DOCKER_NAMESPACE)/$(CI_DEV_DOCKER_IMAGE_NAME):latest
	@docker push $(CI_DEV_DOCKER_NAMESPACE)/$(CI_DEV_DOCKER_IMAGE_NAME):latest
endif

dev-docker: build-dev-dockerfile
	@$(SHELL) $(CURDIR)/build-support/scripts/build-local.sh -o linux -a amd64
	@docker build -t '$(DEV_IMAGE)' \
		--build-arg 'GIT_COMMIT=$(GIT_COMMIT)' \
		--build-arg VERSION=$(CONSUL_ECS_VERSION) \
		--build-arg 'GIT_DIRTY=$(GIT_DIRTY)' \
		--build-arg 'GIT_DESCRIBE=$(GIT_DESCRIBE)' \
		-f $(CURDIR)/build-support/docker/Dev.dockerfile $(CURDIR)

# Generate reference config documentation.
# Usage:
#   make reference-configuration
#   make reference-configuration consul=<path-to-consul-repo>
# The consul repo path is relative to the defaults to ../../../consul.
consul?=../../../consul
reference-configuration:
	cd $(CURDIR)/hack/generate-config-reference; go run . > "$(consul)/website/content/docs/ecs/configuration-reference.mdx"


.PHONY: build-image ci.dev-docker dev-docker build-dev-dockerfile reference-configuration
