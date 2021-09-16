## UNRELEASED

## 0.2.0-beta1 (September 16, 2021)

FEATURES
* Add a new command called `acl-controller`. The command will first
  create the token for the Consul client and then will start a controller
  to manage service tokens. [[GH-22](https://github.com/hashicorp/consul-ecs/pull/22)]

IMPROVMENTS
* AWS client discovers the current region, if unset, from ECS Task Metadata. 
  [[GH-20](https://github.com/hashicorp/consul-ecs/pull/20)]

DEPRECATIONS
* Remove `discover-servers` command. [[GH-21](https://github.com/hashicorp/consul-ecs/pull/21)]

## 0.1.2 (May 25, 2021)

IMPROVEMENTS
* Fix Docker image to build off of `hashicorp/consul:1.9.5`

## 0.1.1 (May 24, 2021)

IMPROVEMENTS
* Docker image contains Consul 1.9.5 binary.

## 0.1.0 (May 24, 2021)

Initial release
