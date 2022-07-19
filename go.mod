module github.com/hashicorp/consul-ecs

go 1.16

// TODO: Remove these once newer versions are published.
replace github.com/hashicorp/consul/api => ../consul/api

replace github.com/hashicorp/consul/sdk => ../consul/sdk

require (
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/aws/aws-sdk-go v1.38.2
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/deckarep/golang-set v1.7.1
	github.com/google/btree v1.0.0 // indirect
	github.com/google/go-cmp v0.5.7
	github.com/hashicorp/consul/api v1.12.0
	github.com/hashicorp/consul/sdk v0.10.0
	github.com/hashicorp/go-hclog v0.15.0
	github.com/hashicorp/go-multierror v1.1.0
	github.com/hashicorp/go-uuid v1.0.1
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/mitchellh/cli v1.1.2
	github.com/mitchellh/mapstructure v1.1.2
	github.com/stretchr/testify v1.6.1
	github.com/xeipuuv/gojsonschema v1.2.0
	gopkg.in/yaml.v3 v3.0.0 // indirect
)
