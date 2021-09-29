## Unreleased

IMPROVEMENTS
* Clean up ACL tokens for services/task families that are deleted. [[GH-30](https://github.com/hashicorp/consul-ecs/pull/30)]

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
