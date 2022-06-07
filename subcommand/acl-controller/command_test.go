package aclcontroller

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/testutil"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

const testPartitionName = "test-partition"

var (
	testTaskMetadataResponse = awsutil.ECSTaskMeta{
		Cluster: "test",
		TaskARN: "arn:aws:ecs:us-east-1:123456789:task/test/abcdef",
		Family:  "controller",
	}
	expOssClientPolicy = `node_prefix "" { policy = "write" } service_prefix "" { policy = "read" }`
)

type iamAuthTestCase struct {
	deletePolicy       bool
	deleteRole         bool
	deleteAuthMethods  bool
	deleteBindingRules bool
	deletePartition    bool
	partitionsEnabled  bool
	expPolicyRules     string
}

func TestUpsertConsulResources(t *testing.T) {
	testUpsertConsulResources(t, map[string]iamAuthTestCase{
		"recreate no ACL resources": {
			expPolicyRules: expOssClientPolicy,
		},
		"recreate the ACL auth method": {
			deleteAuthMethods: true,
			expPolicyRules:    expOssClientPolicy,
		},
		"recreate the ACL policy": {
			deletePolicy:   true,
			expPolicyRules: expOssClientPolicy,
		},
		"recreate the ACL role": {
			deleteRole:     true,
			expPolicyRules: expOssClientPolicy,
		},
		"recreate the ACL binding rule": {
			deleteBindingRules: true,
			expPolicyRules:     expOssClientPolicy,
		},
		"recreate all resources": {
			deletePolicy:       true,
			deleteRole:         true,
			deleteAuthMethods:  true,
			deleteBindingRules: true,
			expPolicyRules:     expOssClientPolicy,
		},
	})
}

func testUpsertConsulResources(t *testing.T, cases map[string]iamAuthTestCase) {
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
			if c.partitionsEnabled {
				cfg.Partition = testPartitionName
			}
			consulClient, err := api.NewClient(cfg)
			require.NoError(t, err)

			ui := cli.NewMockUi()
			cmd := Command{
				UI:              ui,
				flagIAMRolePath: "/path/to/roles",
				log:             hclog.Default().Named("acl-controller"),
			}
			if c.partitionsEnabled {
				cmd.flagPartitionsEnabled = true
				cmd.flagPartition = testPartitionName
			}

			// Upsert once to create the resources
			err = cmd.upsertConsulResources(consulClient, testTaskMetadataResponse)
			require.NoError(t, err)

			checkConsulResources(t, consulClient, c.expPolicyRules, c.partitionsEnabled)

			// Optionally, delete some of the resources
			if c.deleteAuthMethods {
				methods, _, err := consulClient.ACL().AuthMethodList(nil)
				require.NoError(t, err)
				for _, method := range methods {
					_, err := consulClient.ACL().AuthMethodDelete(method.Name, nil)
					require.NoError(t, err)
				}
				methods, _, err = consulClient.ACL().AuthMethodList(nil)
				require.NoError(t, err)
				require.Len(t, methods, 0)
			}
			if c.deletePolicy {
				policies, _, err := consulClient.ACL().PolicyList(nil)
				require.NoError(t, err)
				for _, policy := range policies {
					if policy.Name != "global-management" {
						_, err := consulClient.ACL().PolicyDelete(policy.ID, nil)
						require.NoError(t, err)
					}
				}
				// Only the global management policy should exist.
				policies, _, err = consulClient.ACL().PolicyList(nil)
				require.NoError(t, err)
				if c.partitionsEnabled {
					require.Len(t, policies, 0)
				} else {
					// The default partition has a global-management policy
					require.Len(t, policies, 1)
					require.Equal(t, policies[0].Name, "global-management")
				}
			}
			if c.deleteRole {
				roles, _, err := consulClient.ACL().RoleList(nil)
				require.NoError(t, err)
				for _, role := range roles {
					_, err := consulClient.ACL().RoleDelete(role.ID, nil)
					require.NoError(t, err)
				}
				roles, _, err = consulClient.ACL().RoleList(nil)
				require.NoError(t, err)
				require.Len(t, roles, 0)
			}
			if c.deleteBindingRules {
				methods, _, err := consulClient.ACL().AuthMethodList(nil)
				require.NoError(t, err)
				for _, method := range methods {
					rules, _, err := consulClient.ACL().BindingRuleList(method.Name, nil)
					require.NoError(t, err)
					for _, rule := range rules {
						_, err := consulClient.ACL().BindingRuleDelete(rule.ID, nil)
						require.NoError(t, err)
					}
					rules, _, err = consulClient.ACL().BindingRuleList(method.Name, nil)
					require.NoError(t, err)
					require.Len(t, rules, 0)
				}
			}
			if c.partitionsEnabled && c.deletePartition {
				ctx := context.Background()
				partitions, _, err := consulClient.Partitions().List(ctx, nil)
				require.NoError(t, err)
				for _, part := range partitions {
					if part.Name != "default" {
						_, err := consulClient.Partitions().Delete(ctx, part.Name, nil)
						require.NoError(t, err)
					}
				}
				// Apparently, takes moment for the partition to actually be deleted.
				retry.RunWith(&retry.Timer{Timeout: 2 * time.Second, Wait: 200 * time.Millisecond}, t, func(r *retry.R) {
					partitions, _, err = consulClient.Partitions().List(ctx, nil)
					require.NoError(r, err)
					require.Len(r, partitions, 1)
				})
			}

			// Upsert again to recreate the deleted resources
			err = cmd.upsertConsulResources(consulClient, testTaskMetadataResponse)
			require.NoError(t, err)
			checkConsulResources(t, consulClient, c.expPolicyRules, c.partitionsEnabled)
		})
	}
}

func checkConsulResources(t *testing.T, consulClient *api.Client, expPolicyRules string, partitionsEnabled bool) {
	t.Helper()

	// Check the partition is created.
	if partitionsEnabled {
		partitions, _, err := consulClient.Partitions().List(context.Background(), nil)
		require.NoError(t, err)
		require.Len(t, partitions, 2)
		sort.Slice(partitions, func(i, j int) bool {
			return partitions[i].Name < partitions[j].Name
		})
		require.Equal(t, partitions[0].Name, "default")
		require.Equal(t, partitions[1].Name, testPartitionName)
	}

	// Check the client policy is created.
	policies, _, err := consulClient.ACL().PolicyList(nil)
	require.NoError(t, err)
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Name < policies[j].Name
	})

	require.Equal(t, policies[0].Name, "consul-ecs-client-policy")
	if partitionsEnabled {
		require.Len(t, policies, 1)
	} else {
		// The default partition also has the global-management policy
		require.Len(t, policies, 2)
		require.Equal(t, policies[1].Name, "global-management")
	}

	policy, _, err := consulClient.ACL().PolicyReadByName("consul-ecs-client-policy", nil)
	require.NoError(t, err)
	require.Equal(t, expPolicyRules, policy.Rules)

	// Check the client role is created with policy attached
	// Note: When the policy is deleted, it is detached from the role
	roles, _, err := consulClient.ACL().RoleList(nil)
	require.NoError(t, err)
	require.Len(t, roles, 1)

	role, _, err := consulClient.ACL().RoleReadByName("consul-ecs-client-role", nil)
	require.NoError(t, err)
	require.Len(t, role.Policies, 1)
	require.Equal(t, role.Policies[0].Name, "consul-ecs-client-policy")

	// Check the auth methods are created
	methods, _, err := consulClient.ACL().AuthMethodList(nil)
	require.NoError(t, err)
	require.Len(t, methods, 2)
	sort.Slice(methods, func(i, j int) bool {
		return methods[i].Name < methods[j].Name
	})
	require.Equal(t, methods[0].Name, "iam-ecs-client-token")
	require.Equal(t, methods[1].Name, "iam-ecs-service-token")

	{
		method, _, err := consulClient.ACL().AuthMethodRead("iam-ecs-client-token", nil)
		require.NoError(t, err)
		require.Equal(t, method.Type, "aws-iam")
		require.Equal(t, method.Name, "iam-ecs-client-token")
		require.Len(t, method.NamespaceRules, 0)
		require.Equal(t, method.Config, map[string]interface{}{
			"BoundIAMPrincipalARNs": []interface{}{
				"arn:aws:iam::123456789:role/path/to/roles/*",
			},
			"EnableIAMEntityDetails": true,
		})

		// Check the binding rule is created.
		rules, _, err := consulClient.ACL().BindingRuleList(method.Name, nil)
		require.NoError(t, err)
		require.Len(t, rules, 1)

		rule, _, err := consulClient.ACL().BindingRuleRead(rules[0].ID, nil)
		require.NoError(t, err)
		require.Equal(t, rule.BindType, api.BindingRuleBindTypeRole)
		require.Equal(t, rule.BindName, "consul-ecs-client-role")
	}

	{
		method, _, err := consulClient.ACL().AuthMethodRead("iam-ecs-service-token", nil)
		require.NoError(t, err)
		require.Equal(t, method.Type, "aws-iam")
		require.Equal(t, method.Name, "iam-ecs-service-token")
		if partitionsEnabled {
			require.Len(t, method.NamespaceRules, 1)
			require.Equal(t, method.NamespaceRules[0], &api.ACLAuthMethodNamespaceRule{
				Selector:      fmt.Sprintf(`entity_tags["%s"] != ""`, authMethodNamespaceTag),
				BindNamespace: fmt.Sprintf(`${entity_tags.%s}`, authMethodNamespaceTag),
			})
		} else {
			require.Len(t, method.NamespaceRules, 0)
		}

		require.Equal(t, method.Config, map[string]interface{}{
			"BoundIAMPrincipalARNs": []interface{}{
				"arn:aws:iam::123456789:role/path/to/roles/*",
			},
			"EnableIAMEntityDetails": true,
			"IAMEntityTags": []interface{}{
				authMethodServiceNameTag,
				authMethodNamespaceTag,
			},
		})

		// Check the binding rule is created.
		rules, _, err := consulClient.ACL().BindingRuleList(method.Name, nil)
		require.NoError(t, err)
		require.Len(t, rules, 1)

		rule, _, err := consulClient.ACL().BindingRuleRead(rules[0].ID, nil)
		require.NoError(t, err)
		require.Equal(t, rule.BindType, api.BindingRuleBindTypeService)
		require.Equal(t, rule.BindName, fmt.Sprintf(`${entity_tags.%s}`, authMethodServiceNameTag))
	}
}

func TestAnonymousTokenRules(t *testing.T) {
	a := []bool{false, true}
	cmd := &Command{}
	for _, e := range a {
		cmd.flagPartitionsEnabled = e
		rules, err := cmd.anonymousPolicyRules()
		require.NoError(t, err)
		fmt.Println(rules)
	}
}

func TestUpsertAuthMethod(t *testing.T) {
	t.Parallel()
	cfg := testutil.ConsulServer(t, testutil.ConsulACLConfigFn)
	consulClient, err := api.NewClient(cfg)
	require.NoError(t, err)

	cmd := Command{
		log: hclog.Default().Named("acl-controller"),
	}

	// Simulate two ACL controllers adding auth method config.
	allPrincipals := []interface{}{
		"arn:aws:iam::123456789:role/path/1/*",
		"arn:aws:iam::123456789:role/path/2/*",
		"arn:aws:iam::123456789:role/path/3/*",
		"arn:aws:iam::123456789:role/path/4/*",
	}

	methodOne := makeAuthMethod(allPrincipals[0:3])
	methodTwo := makeAuthMethod(allPrincipals[1:])

	// Upsert once - one controller starting up.
	{
		err := cmd.upsertAuthMethod(consulClient, methodOne)
		require.NoError(t, err)

		upserted, _, err := consulClient.ACL().AuthMethodRead(methodOne.Name, nil)
		require.NoError(t, err)
		require.Equal(t, methodOne.Config, upserted.Config)
	}

	// Upsert again - another controller starting up.
	{
		err := cmd.upsertAuthMethod(consulClient, methodTwo)
		require.NoError(t, err)

		upserted, _, err := consulClient.ACL().AuthMethodRead(methodTwo.Name, nil)
		require.NoError(t, err)

		// BoundIAMPrincipalARNs should be merged together.
		expected := makeAuthMethod(allPrincipals)
		require.Equal(t, expected.Config, upserted.Config)
	}
}

func TestForceStringSlice(t *testing.T) {
	cases := map[string]struct {
		val    interface{}
		exp    []string
		expErr string
	}{
		"nil": {},
		"string slice": {
			val: []string{"a", "b"},
			exp: []string{"a", "b"},
		},
		"interface slice with strings": {
			val: []interface{}{"a", "b"},
			exp: []string{"a", "b"},
		},
		"interface slice with mixed values": {
			val: []interface{}{"a", "b", 1234},
			// returns the string values if you want them.
			exp: []string{"a", "b"},
			// also returns an error, to detect non-strings.
			expErr: "[]interface{} slice contains non-string values",
		},
		"int slice": {
			val:    []int{123, 456},
			expErr: "value of type []int is not a []string",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			strs, err := forceStringSlice(c.val)
			require.Equal(t, strs, c.exp)
			if c.expErr != "" {
				require.Error(t, err)
				require.Equal(t, c.expErr, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUniqueStrings(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		vals []string
		exp  []string
	}{
		"nil": {},
		"no dupes": {
			vals: []string{"a", "b"},
			exp:  []string{"a", "b"},
		},
		"dupes": {
			vals: []string{"c", "b", "a", "c", "a", "b"},
			exp:  []string{"a", "b", "c"}, // always sorted
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			unique := uniqueStrings(c.vals)
			require.Equal(t, c.exp, unique)
		})
	}
}

func makeAuthMethod(principals interface{}) *api.ACLAuthMethod {
	return &api.ACLAuthMethod{
		Name:        "test-method",
		Type:        "aws-iam",
		Description: "AWS IAM auth method for unit test",
		Config: map[string]interface{}{
			// This is the only field that matters.
			"BoundIAMPrincipalARNs":  principals,
			"EnableIAMEntityDetails": true,
		},
	}
}
