//go:build enterprise

package aclcontroller

import (
	"fmt"
	"testing"
)

var expPartitionedClientPolicy = fmt.Sprintf(`partition "%s" {
  node_prefix "" {
    policy = "write"
  }
  namespace_prefix "" {
    service_prefix "" {
      policy = "read"
    }
  }
}`, testPartitionName)

func TestUpsertConsulResourcesEnt(t *testing.T) {
	testUpsertConsulResources(t, map[string]iamAuthTestCase{
		"recreate the partition": {
			partitionsEnabled: true,
			deletePartition:   true,
			expPolicyRules:    expPartitionedClientPolicy,
		},
		"recreate all resources ent": {
			deletePolicy:       true,
			deleteRole:         true,
			deleteAuthMethods:  true,
			deleteBindingRules: true,
			deletePartition:    true,
			partitionsEnabled:  true,
			expPolicyRules:     expPartitionedClientPolicy,
		},
	})
}

func TestUpsertAnonymousTokenPolicyEnt(t *testing.T) {
	testUpsertAnonymousTokenPolicy(t, map[string]anonTokenTest{
		"mgw WAN fed enabled, primary DC, create policy": {
			agentConfig: AgentConfig{
				Config: Config{Datacenter: "dc1"},
				DebugConfig: Config{
					PrimaryDatacenter:               "dc1",
					MeshGatewayWANFederationEnabled: true,
				},
			},
			partitionsEnabled: true,
			expPolicy:         expEntAnonTokenPolicy,
		},
	})
}
