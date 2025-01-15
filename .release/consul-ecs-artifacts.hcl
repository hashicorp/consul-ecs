# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

schema = 1
artifacts {
  zip = [
    "consul-ecs_${version}+fips1402_linux_amd64.zip",
    "consul-ecs_${version}+fips1402_linux_arm64.zip",
    "consul-ecs_${version}_linux_386.zip",
    "consul-ecs_${version}_linux_amd64.zip",
    "consul-ecs_${version}_linux_arm.zip",
    "consul-ecs_${version}_linux_arm64.zip",
  ]
  container = [
    "consul-ecs_release-default_linux_386_${version}_${commit_sha}.docker.dev.tar",
    "consul-ecs_release-default_linux_386_${version}_${commit_sha}.docker.tar",
    "consul-ecs_release-default_linux_amd64_${version}_${commit_sha}.docker.dev.tar",
    "consul-ecs_release-default_linux_amd64_${version}_${commit_sha}.docker.tar",
    "consul-ecs_release-default_linux_arm64_${version}_${commit_sha}.docker.dev.tar",
    "consul-ecs_release-default_linux_arm64_${version}_${commit_sha}.docker.tar",
    "consul-ecs_release-default_linux_arm_${version}_${commit_sha}.docker.dev.tar",
    "consul-ecs_release-default_linux_arm_${version}_${commit_sha}.docker.tar",
    "consul-ecs_release-fips-default_linux_amd64_${version}+fips1402_${commit_sha}.docker.dev.tar",
    "consul-ecs_release-fips-default_linux_amd64_${version}+fips1402_${commit_sha}.docker.tar",
    "consul-ecs_release-fips-default_linux_arm64_${version}+fips1402_${commit_sha}.docker.dev.tar",
    "consul-ecs_release-fips-default_linux_arm64_${version}+fips1402_${commit_sha}.docker.tar",
  ]
}
