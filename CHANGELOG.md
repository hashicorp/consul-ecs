## UNRELEASED

BREAKING CHANGES
* `consul-ecs` docker images no longer have the `consul` binary. The
  mesh-init subcommand still expects the `consul` binary on the
  `$PATH`. [[GH-40](https://github.com/hashicorp/consul-ecs/pull/40)]
* mesh-init: The `-envoy-bootstrap-file` option is removed, and replaced with `-envoy-bootstrap-dir`.
  The Envoy bootstrap config file is written to `envoy-bootstrap.json` within that directory.
  [[GH-42](https://github.com/hashicorp/consul-ecs/pull/42)]

FEATURES
* Add a `health-sync` subcommand to sync ECS health checks into Consul [[GH-33](https://github.com/hashicorp/consul-ecs/pull/33)]
* Add the `-health-sync-containers` flag to `mesh-init` [[GH-36](https://github.com/hashicorp/consul-ecs/pull/36)]
* Add `-tags`, `-service-name` and `-meta` flags to `mesh-init` [[GH-41](https://github.com/hashicorp/consul-ecs/pull/41)]
* Add the `-service-name` flag to `health-sync`. [[GH-43](https://github.com/hashicorp/consul-ecs/pull/43)]
* The ACL controller now reads the Consul service name from the
  `consul.hashicorp.com/service-name` tag on the ECS task. If the tag
  does not exist, it uses the Task family as the Consul service name.
  [[GH-44](https://github.com/hashicorp/consul-ecs/pull/44)]
* Add a `envoy-entrypoint` subcommand, which can be used as the entrypoint to the Envoy container running in ECS
  to support graceful shutdown. [[GH-42](https://github.com/hashicorp/consul-ecs/pull/42)]

BUG FIXES:
* Fix edge cases in the ACL controller where ACL tokens never get cleaned
  up. [[GH-45](https://github.com/hashicorp/consul-ecs/pull/45)]

## 0.2.0-beta2 (September 30, 2021)
IMPROVEMENTS
* Clean up ACL tokens for services/task families that are deleted. [[GH-30](https://github.com/hashicorp/consul-ecs/pull/30)]
* Change the owner of `/consul` in the Docker image  to `consul-ecs`. This
  allows `mesh-init` to run as `consul-ecs` rather than `root`.
  [[GH-37](https://github.com/hashicorp/consul-ecs/pull/37)]

FEATURES
* mesh-init: Add `-checks` option to register service health checks.
  [[GH-29](https://github.com/hashicorp/consul-ecs/pull/29)]

## 0.2.0-beta1 (September 16, 2021)

BREAKING CHANGES
* Remove `discover-servers` command. Due to the many changes made for beta,
  upgrading is not supported. We recommend doing an uninstall and reinstall
  of the Terraform module. [[GH-21](https://github.com/hashicorp/consul-ecs/pull/21)]

FEATURES
* Add a new command called `acl-controller`. The command will first
  create the token for the Consul client and then will start a controller
  to manage service tokens. [[GH-22](https://github.com/hashicorp/consul-ecs/pull/22)]

IMPROVEMENTS
* AWS client discovers the current region, if unset, from ECS Task Metadata.
  [[GH-20](https://github.com/hashicorp/consul-ecs/pull/20)]

## 0.1.2 (May 25, 2021)

IMPROVEMENTS
* Fix Docker image to build off of `hashicorp/consul:1.9.5`

## 0.1.1 (May 24, 2021)

IMPROVEMENTS
* Docker image contains Consul 1.9.5 binary.

## 0.1.0 (May 24, 2021)

Initial release
