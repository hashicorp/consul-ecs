## Unreleased
BUG FIXES
* Fix bug where calls to AWS IAM and STS services error out due to URL with multiple trailing slashes.

SECURITY
* Upgrade go version to `1.23.6` and crypto to `0.35.0` to address [CVE-2025-22869](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-22869)

IMPROVEMENTS
* Remove info logs from health sync checks  

## 0.9.0 (Jan 15, 2025)
BUG FIXES
* Fix the issue where the service was accepting traffic even though it wasn't healthy. This fix updates the health check status for `consul-dataplane` container and takes into account the health of the service container as well.

IMPROVEMENTS
* Bump Go version to `1.22.7`
* Bump Go version to `1.22.5`
* Bump Go version to `1.22.4`
* Bump Go version to `1.22.3`

SECURITY
* Upgrade go version to `1.22.5` to address [CVE-2024-24791](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24791)
* Upgrade go-retryablehttp to address [CVE-2024-6104](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6104)

## 0.8.1 (May 10, 2024)

BUG FIXES
* Update `google.golang.org/protobuf` to v1.33.0 and `github.com/golang/protobuf` to v1.5.4 to address [CVE-2024-24786](https://nvd.nist.gov/vuln/detail/CVE-2024-24786). [[GH-240](https://github.com/hashicorp/consul-ecs/pull/240)]
* Fix `mesh-init` local executable copying in dynamically-linked execution contexts [[GH-242](https://github.com/hashicorp/consul-ecs/pull/242)]

IMPROVEMENTS
* Bump Go version to `1.21.10`
* Bump `x/net` to `0.23.0`

## 0.8.0 (Feb 29, 2024)

BREAKING CHANGES
* Following are the changes made to the `control-plane` container
  - Rename `control-plane` subcommand to `mesh-init`. [[GH-209](https://github.com/hashicorp/consul-ecs/pull/209)]
  - Removes a lot of functionalities from `control-plane` [[GH-207](https://github.com/hashicorp/consul-ecs/pull/207)]
  - `mesh-init` will be a short lived container with the following responsibities
    - Perform Consul login and obtain a ACL token.
    - Register the service and sidecar proxy to Consul catalog.
    - Write ECS binary to shared volume.
    - Prepare and write Consul Dataplane configuration to a shared volume.
  - `mesh-init` unlike `control-plane` no longer writes the login token to a shared volume and passes it on to the `Consul-dataplane` container. It instead generates the login configuration needed to get a Consul ACL token and writes it as part of the Consul dataplane configuration to a shared volume. Dataplane uses the login configuration to mint the token with the required permissions.[[GH-208](https://github.com/hashicorp/consul-ecs/pull/208)]
* Adds a new command `health-sync` with the following responsibilities [[GH-210](https://github.com/hashicorp/consul-ecs/pull/210)]
  - Perform Consul login and obtain an ACL token.
  - Setup the Consul client to talk directly to the server.
  - Accumulate all the health checks associated with the service and the proxy which would have been previously registered as `critical` by `mesh-init`
  - Enters into a long running reconciliation loop where it
    - Periodically syncs back ECS container health status into Consul.
    - Marks all service and proxy checks as critical upon receiving SIGTERM.
    - Listens to changes to the Consul servers and reconfigures the Consul client if at all the server details change.
    - Gracefully shuts down(upon receiving SIGTERM) making sure that the Consul Dataplane has terminated properly and then proceeds with deregistering the service and proxy and performs a Consul logout to invalidate the ACL token.
* The `transparentProxy.enabled` field defaults to `true` if not specified. Transparent proxy is not yet supported for FARGATE based launch types. When performing upgrades from previous versions of Consul ECS, care must be taken to always pass `false` for the `transparentProxy.enabled` field for FARGATE launch types to ensure that `mesh-init` process doesn't fail due to insufficient privileges when applying traffic redirection rules

FEATURES
* Transparent proxy support for ECS EC2 launch type [[GH-212](https://github.com/hashicorp/consul-ecs/pull/212)]
  - Add a `transparentProxy` stanza to the `ECS_CONFIG_JSON` schema to control traffic redirection settings for the ECS task.[[GH-171](https://github.com/hashicorp/consul-ecs/pull/171)]
  - Enable support for Consul DNS within the ECS task via the `transparentProxy.consulDNS` stanza. When enabled, Consul Dataplane starts up a DNS server on port 8600 and proxies DNS queries to the Consul DNS server. The `/etc/resolv.conf` file of the ECS task is also modified to make sure that `127.0.0.1` is the first nameserver in the list.[[GH-170](https://github.com/hashicorp/consul-ecs/pull/170)]
  - Adds a `redirecttraffic` package that invokes the `iptables` SDK of Consul which internally applies the traffic redirection rules needed to properly setup transparent proxy within the ECS task. [[GH-173](https://github.com/hashicorp/consul-ecs/pull/173)]
  - The mesh-init process, in addition to registering service and proxy to Consul, also invokes the required modules to apply traffic redirection rules and set up Consul DNS within the ECS task. [[GH-174](https://github.com/hashicorp/consul-ecs/pull/174)]
* API and terminating gateways
  - Add support for configuring API and terminating gateways as ECS tasks [[GH-192](https://github.com/hashicorp/consul-ecs/pull/192)]
  - Add following changes to the controller to support API gateways in ACL enabled clusters [[GH-198](https://github.com/hashicorp/consul-ecs/pull/198)]
    - Create the `consul-ecs-api-gateway-role` ACL role and `consul-ecs-api-gateway-policy` ACL policy.
    - Add a new IAM entity tag `consul.hashicorp.name.gateway-kind` to the existing service auth method's config.
    - Add a new binding rule specific to API gateway that helps binding the API gateway's ACL token to the preconfigured `consul-ecs-api-gateway-role`
  - Add following changes to the controller to support Terminating gateways in ACL enabled clusters [[GH-199](https://github.com/hashicorp/consul-ecs/pull/199)]
    - Create the `consul-ecs-terminating-gateway-role` ACL role. This role will be assigned to the ACL token obtained by the terminating gateway task after performing a Consul login. Users can assign policies to this role via terraform whenever needed.
    - Add a new binding rule specific to terminating gateways that helps bind the terminating gateway's ACL token to the preconfigured `consul-ecs-terminating-gateway-role`

IMPROVEMENTS
* Bump Go version to `1.21.6`

BUG FIXES
* Fix permissions given to the ACL token generated for a Mesh gateway based ECS task. Following are the changes made to add additional permissions [[GH-215](https://github.com/hashicorp/consul-ecs/pull/215)]
  - Create the `consul-ecs-mesh-gateway-role` ACL role and `consul-ecs-mesh-gateway-policy` ACL policy with the `mesh:write` and `peering:read` permissions.
  - Add a new binding rule specific to Mesh gateway that helps binding the Mesh gateway's ACL token to the preconfigured `consul-ecs-mesh-gateway-role`

## 0.7.3 (Feb 16, 2024)

IMPROVEMENTS
* Bump Go to `1.21.6`

## 0.6.2 (Feb 16, 2023)

IMPROVEMENTS
* Bump Go to `1.21.6`

## 0.7.2 (Jan 25, 2024)

BUG FIXES
* Fix permissions given to the ACL token generated for a Mesh gateway based ECS task. The controller must be upgraded to this version for the fix to kick in. Following are the changes made to add additional permissions [[GH-216](https://github.com/hashicorp/consul-ecs/pull/216)]
  - Create the `consul-ecs-mesh-gateway-role` ACL role and `consul-ecs-mesh-gateway-policy` ACL policy with the `mesh:write` and `peering:read` permissions.
  - Add a new IAM entity tag `consul.hashicorp.name.gateway-kind` to the existing service auth method's config.
  - Add a new binding rule specific to Mesh gateway that helps binding the Mesh gateway's ACL token to the preconfigured `consul-ecs-mesh-gateway-role`

## 0.7.1 (Dec 18, 2023)

BUG FIXES
* Fixes a bug which prevented graceful shutdown of the Consul dataplane container. [[GH-200](https://github.com/hashicorp/consul-ecs/pull/200)]

## 0.7.0 (Nov 7, 2023)

BREAKING CHANGES
* Adopt the architecture described in [Simplified Service Mesh with Consul Dataplane](https://developer.hashicorp.com/consul/docs/connect/dataplane): [[GH-161](https://github.com/hashicorp/consul-ecs/pull/161)]
  - Consul client agents are no longer used.
  - Consul Dataplane must be run in place of Envoy in each ECS task. Consul Dataplane manages the Envoy process and proxies xDS requests from Envoy to Consul servers.
  - The `consul-ecs` binary now communicates with Consul servers using HTTP(S) and GRPC.
  - Services are registered directly with the central catalog on the Consul servers. Services in the same ECS cluster are registered to the same Consul node name.
* Remove the `mesh-init` and `health-sync` commands, and add a unified `control-plane` command to replace them. The `control-plane` command starts a long running process with the following responsibilities:
   - Automatically (re)discover and (re)connect to Consul servers using [connection manager](https://github.com/hashicorp/consul-server-connection-manager). The `consulServer.hosts` config option supports an IP, DNS name, or an `exec=` string specifying a command that returns a list of IP addresses. [[GH-143](https://github.com/hashicorp/consul-ecs/pull/143)]
   - Make an ACL Login request to obtain an ACL token when using the Consul AWS IAM auth method.
   - Register the service and sidecar proxy with the central catalog on the Consul servers.[[GH-144](https://github.com/hashicorp/consul-ecs/pull/144)]
   - Write the configuration for Consul Dataplane to a file on a shared volume. [[GH-145](https://github.com/hashicorp/consul-ecs/pull/145)]
   - Sync ECS health check statuses for the ECS task into the central catalog on the Consul servers on a periodic basis.[[GH-146](https://github.com/hashicorp/consul-ecs/pull/146)]
   - Gracefully shutdown when an ECS task is stopped. Upon receiving a SIGTERM, mark synced health checks critical and wait for Consul Dataplane to stop. Then remove health checks, services, and perform an ACL Logout if necessary.[[GH-147](https://github.com/hashicorp/consul-ecs/pull/147)]
* controller: Add a new `controller` command in place of the `acl-controller` command with the following changes:
   - Remove all CLI flags. Configuration is read from the `ECS_CONFIG_JSON` environment variable.[[GH-150](https://github.com/hashicorp/consul-ecs/pull/150)]
   - Automatically (re)discover and (re)connect to Consul servers, similar to the `control-plane` command.
   - Because Consul client agents are no longer used, the controller no longer configures the "client" auth method, policy, role, and binding rule which previously enabled Consul client agents to login.
   - Register the ECS cluster as a synthetic node in the central catalog on the Consul servers. The synthetic node is used to register services running in the ECS cluster.
   - Ensure leftover tokens and services are removed for ECS tasks that have stopped.[[GH-153](https://github.com/hashicorp/consul-ecs/pull/153)]
* Changes to `ECS_CONFIG_JSON` schema.
   - Remove the `consulHTTPAddr` and `consulCACertFile` fields.
   - Add the `consulLogin.datacenter` field.
   - Add the `controller` field to support configuring the new `controller` command.
   - Add the `consulServers` field to specify the Consul server location and protocol-specific settings.
   - The `consulServers.hosts` field is required. This specifies the Consul server location as an IP address, DNS name, or `exec=` string specifying a command that returns a list of IP addresses. To use [cloud auto-join](https://developer.hashicorp.com/consul/docs/install/cloud-auto-join), use an `exec=` string to run the `discover` CLI. For example, the following string invokes the discover CLI with a cloud auto-join string: `exec=discover -q addrs provider=aws region=us-west-2 tag_key=consul-server tag_value=true`. The `discover` CLI is included in the Consul ECS and Consul Dataplane images by default.
   - Remove the `service.checks` field. Consul agent health checks are no longer supported because Consul client agents are not used. Instead, set the `healthSyncContainers` field to have `consul-ecs` sync ECS health checks into Consul.
   - Add the `proxy.healthCheckPort` field which can be hit to determine Envoy's readiness.
   - Add the `proxy.upstreams.destinationPeer` field to enable the proxy to hit upstreams present in peer Consul clusters.
   - Add the `meshGateway.healthCheckPort` field which can be hit to determine Envoy's readiness.
   - Add the `proxy.localServiceAddress` field to configure Envoy to use a different address for the local service.
* Add the [go-discover](https://github.com/hashicorp/go-discover) binary to the Consul ECS image to better support [cloud auto-join](https://developer.hashicorp.com/consul/docs/install/cloud-auto-join).[[GH-160](https://github.com/hashicorp/consul-ecs/pull/160)]

FEATURES
* Use the `AWS_REGION` container environment variable and `AvailabilityZone` attribute of an ECS task meta JSON to set the locality parameters in Consul service and proxy registrations. These parameters are used to perform locality aware routing for Consul Enterprise installations. [[GH-167](https://github.com/hashicorp/consul-ecs/pull/167)]

IMPROVEMENTS
* Bump Golang to 1.20

## 0.6.1 (Nov 2, 2023)

IMPROVEMENTS
* Bump Go to `1.20`

## 0.6.0 (Mar 15, 2023)

FEATURES
* net-dial: Add new `consul-ecs net-dial` subcommand to support ECS health checks when `nc`
  is not available in the container image.
  [[GH-135]](https://github.com/hashicorp/consul-ecs/pull/135)
* acl-controller: Add support for Consul 1.15.x.
  [[GH-133]](https://github.com/hashicorp/consul-ecs/pull/133)
* mesh-init: Add `proxy.publicListenerPort` config option to set Envoy's public listener port.

BREAKING CHANGES
* Remove `consulLogin.extraLoginFields` config option. The Consul Login API is used directly instead
  of the `consul login` CLI command for logging into the AWS IAM auth method. Add `meta`, `region`,
  `stsEndpoint`, and `serverIdHeaderValue` fields to the `consulLogin` config object.
  [[GH-115](https://github.com/hashicorp/consul-ecs/pull/115)]

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
