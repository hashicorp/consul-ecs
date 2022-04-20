//go:build enterprise

package aclcontroller

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
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

func TestUpsertConsulClientTokenEnt(t *testing.T) {
	cases := testCases{
		"when partitions are enabled with no token or policy": {
			existingSecret: &secretsmanager.GetSecretValueOutput{
				ARN:          aws.String("test-consul-client-token-arn"),
				Name:         aws.String("test-consul-client-token"),
				SecretString: aws.String(`{}`),
			},
			partitionsEnabled: true,
			expPolicyRules:    expPartitionedClientPolicy,
		},
	}
	testUpsertConsulClientToken(t, cases)
}
