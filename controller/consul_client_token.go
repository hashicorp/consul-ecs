package controller

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
)

// UpsertConsulClientToken creates or updates ACL policy and token for the Consul client in Consul.
// It then saves the created token in AWS Secrets Manager in the secret provided by secretARN.
func UpsertConsulClientToken(consulClient *api.Client, smClient secretsmanageriface.SecretsManagerAPI, secretARN, secretPrefix string, log hclog.Logger) error {
	// Read the secret from AWS.
	currSecretValue, err := smClient.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretARN),
	})
	if err != nil {
		return fmt.Errorf("retrieving Consul client secret: %w", err)
	}

	// Unmarshal the secret value JSON.
	var currSecret tokenSecretJSON
	err = json.Unmarshal([]byte(*currSecretValue.SecretString), &currSecret)
	if err != nil {
		return fmt.Errorf("unmarshalling Consul client secret value JSON: %w", err)
	}

	var currToken *api.ACLToken

	// If the secret is not empty, check if Consul already has a token with this AccessorID.
	if currSecret.AccessorID != "" {
		currToken, _, err = consulClient.ACL().TokenRead(currSecret.AccessorID, nil)
		if err != nil && !isACLNotFoundError(err) {
			return fmt.Errorf("reading token: %w", err)
		}
	}

	// Exit if current token is found in Consul.
	if currToken != nil {
		return nil
	}
	// Otherwise, we need to create one.
	// First, we need to check if the policy for the Consul client already exists.
	// If it does, we will skip policy creation.
	policyName := fmt.Sprintf("%s-consul-client-policy", secretPrefix)
	policy, _, err := consulClient.ACL().PolicyReadByName(policyName, nil)

	// When policy is not found, Consul returns ACL not found error.
	if isACLNotFoundError(err) {
		// Create a policy for the Consul clients.
		log.Info("creating ACL policy", "name", policyName)
		policy, _, err = consulClient.ACL().PolicyCreate(&api.ACLPolicy{
			Name:        policyName,
			Description: "Consul Client Token Policy for ECS",
			// We use this token for all Consul clients, and that's why the node_prefix needs to be "".
			Rules: `node_prefix "" { policy = "write" } service_prefix "" { policy = "read" }`,
		}, nil)
		if err != nil {
			return fmt.Errorf("creating Consul client ACL policy: %w", err)
		}
		log.Info("ACL policy created successfully", "name", policyName)
	} else if err != nil {
		return fmt.Errorf("reading Consul client ACL policy: %w", err)
	} else {
		log.Info("ACL policy already exists; skipping policy creation", "name", policyName)
	}

	log.Info("creating Consul client ACL token")
	token, _, err := consulClient.ACL().TokenCreate(&api.ACLToken{
		Description: "ECS Consul client Token",
		Policies:    []*api.ACLTokenPolicyLink{{Name: policy.Name}},
	}, nil)
	if err != nil {
		return fmt.Errorf("creating Consul client ACL token: %w", err)
	}
	log.Info("Consul client ACL token created successfully")

	clientSecret, err := json.Marshal(tokenSecretJSON{Token: token.SecretID, AccessorID: token.AccessorID})
	if err != nil {
		return fmt.Errorf("marshalling Consul client token: %w", err)
	}

	// Finally, update the AWS Secret with the new values of the token.
	log.Info("updating secret", "arn", secretARN)
	_, err = smClient.UpdateSecret(&secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(secretARN),
		SecretString: aws.String(string(clientSecret)),
	})
	if err != nil {
		return fmt.Errorf("updating secret: %s", err)
	}
	log.Info("secret updated successfully", "arn", secretARN)
	return nil
}
