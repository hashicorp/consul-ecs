## Consul on ECS Fargate

Deploys Consul on ECS Fargate along with two example applications.

### Pre-requisites
* ECS Cluster

### Resources
* Demo Consul server
* Controller
* mesh-client example app that calls mesh-app
* mesh-app example app
* Exposes mesh-client and Consul server via ALB
* Log group

### Usage
* Create an ECS cluster
* Create a `local.tfvars` file and fill out the required variables:
    ```hcl
    ecs_cluster = "<cluster arn>"
    region      = "<region>"
    tags = {
      key = "value"
    }
    vpc_id           = "<vpc id>"
    subnets          = ["<app subnet>"]
    lb_subnets       = ["<lb subnet 1>", "<lb subnet 2>"]
    log_group_name   = "<log group name>"

    # Configure the ingress rule for the mesh client and server ALB.
    # I set this to only allow my workstation IP.
    lb_ingress_security_group_rule_description = ""
    lb_ingress_security_group_rule_cidr_blocks = ["<ip>/32"]
    ```
* Run `terraform apply`
* Add security group rules that allow ingress into your ECS cluster from the ALBs.
* Run `terraform output` to get URLs
  * Log in to Consul server with the bootstrap ACL token (default is `57c5d69a-5f19-469b-0543-12a487eecc66`)
  * Add an intention `* => *` to allow `mesh-client` to talk to `mesh-app`.
  * The mesh client URL should show `mesh-client` talking to `mesh-app`.
