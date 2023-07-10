// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build enterprise

package aclcontroller

import (
	"testing"
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
