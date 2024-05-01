# Contributing to Consul-ECS

Thanks for your interest in Consul on ECS. We value feedback and contributions from the community whether it is a bug report, enhancements, new features or documentation.

Please read through this document before submitting any issues or pull requests to ensure we have all the necessary 
information to effectively respond to your bug report or contribution.


## Reporting Issues, Bugs or Feature Requests

We welcome users to report issues or suggest features.

If you're suggesting a new feature (i.e., functionality that doesn't exist yet), please use our [issue template](https://github.com/hashicorp/consul-ecs/issues).  This will prompt you to answer a few questions that will help us figure out what you're looking for.  The template will also tag incoming issues with "Enhancement".  This gives us a way to filter the community-opened issues quickly so we can review as a team.

Check for duplicates when filing an issue. Please check [existing open](https://github.com/hashicorp/consul-ecs/issues), or [recently closed](https://github.com/hashicorp/consul-ecs/issues?q=is%3Aissue+is%3Aclosed) issues to make sure somebody else hasn't already reported the issue. 


If you're reporting what you think is a bug (i.e., something isn't right with an existing feature), please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps performed
* The version of our code being used for our product(Consul version)
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment

## Running Tests

Tests will run using the locally installed `consul` binary.

Running the Enterprise tests requires a local Consul Enterprise binary, passing the `-enterprise` flag as an argument to `go test`, and a valid Consul Enterprise license (configure by [setting `CONSUL_LICENSE` or `CONSUL_LICENSE_PATH` in your environment](https://developer.hashicorp.com/consul/docs/enterprise/license/overview#applying-a-license)).
```shell
export CONSUL_LICENSE_PATH=...
go test -v ./... -- -enterprise
```

To run the CE tests, omit the `-enterprise` flag and ensure your local binary is Consul CE.
```shell
go test -v ./...
```

Note that the CE tests cannot be run with a Consul Enterprise binary due to defaulting of tenancy fields.

## Licensing

See the [LICENSE](https://github.com/hashicorp/consul-ecs/blob/main/LICENSE.md) file for our project's licensing. We will ask you to confirm the licensing of your contribution.

If you want to contribute to this project, we may ask you to sign a **[Contributor License Agreement (CLA)](https://www.hashicorp.com/cla)**.