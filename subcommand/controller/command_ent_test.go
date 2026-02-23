// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build enterprise

package controller

import (
	"testing"
)

const (
	expEntAnonTokenPolicy = `
partition_prefix "" {
  namespace_prefix "" {
    node_prefix "" {
      policy = "read"
    }
    service_prefix "" {
      policy = "read"
    }
  }
}`
)

func TestUpsertConsulResourcesEnt(t *testing.T) {
	testUpsertConsulResources(t, map[string]iamAuthTestCase{
		"recreate the partition": {
			partitionsEnabled: true,
			deletePartition:   true,
		},
		"recreate all resources ent": {
			deletePolicy:       true,
			deleteRole:         true,
			deleteAuthMethods:  true,
			deleteBindingRules: true,
			deletePartition:    true,
			partitionsEnabled:  true,
		},
	})
}

func TestUpsertAnonymousTokenPolicyEnt(t *testing.T) {
	testUpsertAnonymousTokenPolicy(t, map[string]anonTokenTest{
		"primary datacenter": {
			agentConfig: AgentConfig{
				Config:      Config{Datacenter: "dc1"},
				DebugConfig: Config{PrimaryDatacenter: "dc1"},
			},
			partitionsEnabled: true,
			expPolicy:         expEntAnonTokenPolicy,
		},
	})
}

func TestUpsertAPIGatewayTokenPolicyAndRole(t *testing.T) {
	testUpsertAPIGatewayPolicyAndRole(t, map[string]gatewayTokenTest{
		"test creation": {
			partitionsEnabled: true,
		},
	})
}

func TestUpsertMeshGatewayTokenPolicyAndRole(t *testing.T) {
	testUpsertMeshGatewayPolicyAndRole(t, map[string]gatewayTokenTest{
		"test creation": {
			partitionsEnabled: true,
		},
		"test creation with non default partition": {
			partitionsEnabled:      true,
			useNonDefaultPartition: true,
		},
	})
}
