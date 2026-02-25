// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package awsutil

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"

	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	ECSMetadataURIEnvVar = "ECS_CONTAINER_METADATA_URI_V4"
	AWSRegionEnvVar      = "AWS_REGION"

	containerTypeNormal  = "NORMAL"
	DesiredStatusStopped = "STOPPED"

	metadataTimeout = 2 * time.Second
)

type ECSTaskMeta struct {
	Cluster          string                 `json:"Cluster"`
	TaskARN          string                 `json:"TaskARN"`
	Family           string                 `json:"Family"`
	Containers       []ECSTaskMetaContainer `json:"Containers"`
	AvailabilityZone string                 `json:"AvailabilityZone"`
}

type ECSTaskMetaContainer struct {
	Name          string               `json:"Name"`
	Health        ECSTaskMetaHealth    `json:"Health"`
	DesiredStatus string               `json:"DesiredStatus"`
	KnownStatus   string               `json:"KnownStatus"`
	Networks      []ECSTaskMetaNetwork `json:"Networks"`
	Type          string               `json:"Type"`
}

type ECSTaskMetaHealth struct {
	Status      string `json:"status"`
	StatusSince string `json:"statusSince"`
	ExitCode    int    `json:"exitCode"`
}

type ECSTaskMetaNetwork struct {
	IPv4Addresses  []string `json:"IPv4Addresses"`
	PrivateDNSName string   `json:"PrivateDNSName"`
}

func (e ECSTaskMeta) TaskID() string {
	return ParseTaskID(e.TaskARN)
}

func (e ECSTaskMeta) ClusterARN() (string, error) {
	if strings.HasPrefix(e.Cluster, "arn:") {
		return e.Cluster, nil
	}
	// On EC2, the "Cluster" field is the name, not the ARN.
	clusterArn := strings.Replace(e.TaskARN, ":task/", ":cluster/", 1)
	index := strings.LastIndex(clusterArn, "/")
	if index < 0 {
		return "", fmt.Errorf("unable to determine cluster ARN from task ARN %q", e.TaskARN)
	}
	return clusterArn[:index], nil
}

func ParseTaskID(taskArn string) string {
	split := strings.Split(taskArn, "/")
	if len(split) == 0 {
		return ""
	}
	return split[len(split)-1]
}

func (e ECSTaskMeta) AccountID() (string, error) {
	a, err := arn.Parse(e.TaskARN)
	if err != nil {
		return "", fmt.Errorf("unable to determine AWS account id from Task ARN: %q", e.TaskARN)
	}
	return a.AccountID, nil
}

func (e ECSTaskMeta) Region() (string, error) {
	a, err := arn.Parse(e.TaskARN)
	if err != nil {
		return "", fmt.Errorf("unable to determine AWS region from Task ARN: %q", e.TaskARN)
	}
	return a.Region, nil
}

// NodeIP returns the IP of the node the task is running on.
func (e ECSTaskMeta) NodeIP() string {
	ip := "127.0.0.1" // default to localhost
	if len(e.Containers) > 0 &&
		len(e.Containers[0].Networks) > 0 &&
		len(e.Containers[0].Networks[0].IPv4Addresses) > 0 {
		ip = e.Containers[0].Networks[0].IPv4Addresses[0]
	}
	return ip
}

func (e ECSTaskMeta) HasContainerStopped(name string) bool {
	stopped := true
	for _, c := range e.Containers {
		if c.Name == name && !c.HasStopped() {
			stopped = false
			break
		}
	}
	return stopped
}

func (c ECSTaskMetaContainer) HasStopped() bool {
	return c.DesiredStatus == DesiredStatusStopped &&
		c.KnownStatus == DesiredStatusStopped
}

func (c ECSTaskMetaContainer) IsNormalType() bool {
	return c.Type == containerTypeNormal
}

func ECSTaskMetadata() (ECSTaskMeta, error) {
	var metadataResp ECSTaskMeta

	metadataURI := os.Getenv(ECSMetadataURIEnvVar)
	if metadataURI == "" {
		return metadataResp, fmt.Errorf("%s env var not set", ECSMetadataURIEnvVar)
	}

	client := &http.Client{
		Timeout: metadataTimeout,
	}

	resp, err := client.Get(fmt.Sprintf("%s/task", metadataURI))
	if err != nil {
		return metadataResp, fmt.Errorf("calling metadata uri: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return metadataResp, fmt.Errorf("metadata endpoint returned status %d", resp.StatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return metadataResp, fmt.Errorf("reading metadata uri response body: %w", err)
	}

	if err := json.Unmarshal(respBytes, &metadataResp); err != nil {
		return metadataResp, fmt.Errorf("unmarshalling metadata uri response: %w", err)
	}

	return metadataResp, nil
}

// UserAgentMiddleware adds a custom user-agent string to SDK v2 requests.
func UserAgentMiddleware(caller string) func(*smithymiddleware.Stack) error {
	return func(stack *smithymiddleware.Stack) error {
		return stack.Build.Add(
			smithymiddleware.BuildMiddlewareFunc("CustomUserAgent",
				func(ctx context.Context, in smithymiddleware.BuildInput, next smithymiddleware.BuildHandler) (
					out smithymiddleware.BuildOutput, metadata smithymiddleware.Metadata, err error,
				) {
					req, ok := in.Request.(*smithyhttp.Request)
					if ok {
						req.Header.Set("User-Agent", req.Header.Get("User-Agent")+" "+caller)
					}
					return next.HandleBuild(ctx, in)
				}),
			smithymiddleware.After,
		)
	}
}

// NewAWSConfig loads AWS SDK v2 config with proper region injection.
func NewAWSConfig(meta ECSTaskMeta, userAgentCaller string) (aws.Config, error) {
	ctx := context.Background()

	// 1. Try env var first
	region := os.Getenv(AWSRegionEnvVar)

	// 2. Fallback to ECS metadata
	if region == "" {
		var err error
		region, err = meta.Region()
		if err != nil {
			return aws.Config{}, err
		}
	}

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(region),
	)
	if err != nil {
		return aws.Config{}, err
	}

	if userAgentCaller != "" {
		cfg.APIOptions = append(cfg.APIOptions, UserAgentMiddleware(userAgentCaller))
	}

	return cfg, nil
}

func GetAWSRegion() string {
	return os.Getenv(AWSRegionEnvVar)
}
