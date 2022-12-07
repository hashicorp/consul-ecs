## Unreleased

FEATURES
* mesh-init: Add `proxy.publicListenerPort` config option to set Envoy's public listener port.

IMPROVEMENTS
* Support Consul 1.13 and 1.14

## 0.5.1 (July 28, 2022)

BUG FIXES:
* Fix the description of the anonymous token policy so that it exactly matches the description
  created by `consul-k8s`. This fixes a connectivity issue that occurs when `consul-k8s` and
  `consul-ecs` deployments are connected to the same Consul datacenter.
  [[GH-114](https://github.com/hashicorp/consul-ecs/pull/114)]

## 0.5.0 (June 21, 2022)

BREAKING CHANGES
* Update `acl-controller` to cleanup ACL tokens created from Consul's AWS IAM auth method. Remove
  `-secret-name-prefix` and `-consul-client-secret-arn` flags. The controller no longer creates ACL
  tokens. [[GH-82](https://github.com/hashicorp/consul-ecs/pull/82)]
* A lower case service name is required by `mesh-init` and `health-sync`. When the `service.name` field
  is specified, it must be a valid name for a Consul service identity. Otherwise, if `service.name` is
  not specified, the lower-cased task family is used for the Consul service name.
  [[GH-97](https://github.com/hashicorp/consul-ecs/pull/97)]

FEATURES
* Add `-log-level` flag to `acl-controller`, `envoy-entrypoint`, and `app-entrypoint`
  commands. Add `logLevel` field to config JSON for `mesh-init` and `health-sync` commands.
  [[GH-67](https://github.com/hashicorp/consul-ecs/pull/67)]
* Support obtaining ACL tokens from Consul's AWS IAM auth method. This requires Consul 1.12.0+.
  `mesh-init` now does a `consul login` to obtain a token if `consulLogin.enabled = true`.
  `health-sync` does a `consul logout` during shutdown to destroy these tokens.
  Add `consulHTTPAddr`, `consulCACertFile`, and `consulLogin` fields to the config JSON.
  [[GH-69](https://github.com/hashicorp/consul-ecs/pull/69)]
  [[GH-76](https://github.com/hashicorp/consul-ecs/pull/76)]
  [[GH-77](https://github.com/hashicorp/consul-ecs/pull/77)]
* Update `acl-controller` to configure Consul's AWS IAM auth method at startup.
  Add `-iam-role-path` flag to specify the path of IAM roles permitted to login.
  [[GH-71](https://github.com/hashicorp/consul-ecs/pull/71)]

IMPROVEMENTS
* `consul-ecs version` now includes the git commit sha.
  [[GH-85](https://github.com/hashicorp/consul-ecs/pull/85)]

DEPRECATIONS
* Only release Linux builds since this binary is only used in Linux containers.
  Windows, Darwin, FreeBSD, and Solaris builds are no longer published to releases.hashicorp.com.
  [[GH-91](https://github.com/hashicorp/consul-ecs/pull/91)]

BUG FIXES:
* Fix issue in the `acl-controller` command where namespaces are not created in the correct
  partition when using Consul 1.12. [[GH-72](https://github.com/hashicorp/consul-ecs/pull/72)]
* Fix note text for synced Consul health checks. [[GH-80](https://github.com/hashicorp/consul-ecs/pull/80)]
* Fix issue where the `acl-controller` did not update the default namespace with the cross-namespace policy.
  [[GH-104](https://github.com/hashicorp/consul-ecs/pull/104)]
* Fix token cleanup in the `acl-controller` when Consul Enterprise admin partitions are enabled.
  [[GH-105](https://github.com/hashicorp/consul-ecs/pull/105)]
* The `acl-controller` configures the anonymous token with `service:read` and `node:read`
  permissions to support cross-dc or cross-partition traffic through mesh gateways.
  [[GH-103](https://github.com/hashicorp/consul-ecs/pull/103)]
  [[GH-106](https://github.com/hashicorp/consul-ecs/pull/106)]

## 0.4.1 (April 08, 2022)

This is a patch release that keeps the consul-ecs project in sync with the
[terraform-aws-consul-ecs](https://github.com/hashicorp/terraform-aws-consul-ecs) project.

## 0.4.0 (April 04, 2022)

FEATURES
* Add support for admin partitions and namespaces (Consul Enterprise).
  [[GH-61](https://github.com/hashicorp/consul-ecs/pull/61)]

## 0.3.0 (January 27, 2022)

BREAKING CHANGES
* mesh-init, health-sync: Switch to file-based config. All CLI flags and options are removed
  from the `mesh-init` and `health-sync` commands. Instead, use the `CONSUL_ECS_CONFIG_JSON`
  environment variable to pass JSON configuration which follows this [schema](config/schema.json).
  [[GH-53](https://github.com/hashicorp/consul-ecs/pull/53)]
  [[GH-54](https://github.com/hashicorp/consul-ecs/pull/54)]

FEATURES
* Add a `app-entrypoint` subcommand which can be used to delay application
  shutdown after receing a TERM signal to support graceful shutdown in ECS.
  [[GH-48](https://github.com/hashicorp/consul-ecs/pull/48)]
* Update `github.com/hashicorp/consul/api` package to `v1.12.0` to support
  passing service registration fields for admin partitions and h2ping checks.
  [[GH-59](https://github.com/hashicorp/consul-ecs/pull/59)]

## 0.2.0 (November 16, 2021)

BREAKING CHANGES
* `consul-ecs` docker images no longer have the `consul` binary. The
  mesh-init subcommand still expects the `consul` binary on the
  `$PATH`. [[GH-40](https://github.com/hashicorp/consul-ecs/pull/40)]
* mesh-init: The `-envoy-bootstrap-file` option is removed, and replaced with `-envoy-bootstrap-dir`.
  The Envoy bootstrap config file is written to `envoy-bootstrap.json` within that directory.
  [[GH-42](https://github.com/hashicorp/consul-ecs/pull/42)]

FEATURES
* Add a `health-sync` subcommand to sync ECS health checks into Consul. [[GH-33](https://github.com/hashicorp/consul-ecs/pull/33)]
* Add the `-health-sync-containers` flag to `mesh-init`. [[GH-36](https://github.com/hashicorp/consul-ecs/pull/36)]
* Add `-tags`, `-service-name` and `-meta` flags to `mesh-init`. [[GH-41](https://github.com/hashicorp/consul-ecs/pull/41)]
* Add the `-service-name` flag to `health-sync`. [[GH-43](https://github.com/hashicorp/consul-ecs/pull/43)]
* The ACL controller now reads the Consul service name from the
  `consul.hashicorp.com/service-name` tag on the ECS task. If the tag
  does not exist, it uses the Task family as the Consul service name.
  [[GH-44](https://github.com/hashicorp/consul-ecs/pull/44)]
* Add a `envoy-entrypoint` subcommand, which can be used as the entrypoint to the Envoy container running in ECS
  to support graceful shutdown. [[GH-42](https://github.com/hashicorp/consul-ecs/pull/42)]

BUG FIXES:
* Fix bugs in which ACL tokens are not created or deleted in certain cases.
  [[GH-45](https://github.com/hashicorp/consul-ecs/pull/45)] [[GH-46](https://github.com/hashicorp/consul-ecs/pull/46)]

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
