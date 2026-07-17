// Copyright IBM Corp. 2021, 2026
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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	ECSMetadataURIEnvVar = "ECS_CONTAINER_METADATA_URI_V4"

	AWSRegionEnvVar = "AWS_REGION"

	// This is the type assigned to the containers that are
	// present in the task definition.
	containerTypeNormal = "NORMAL"
)

// UserAgentMiddleware adds a custom user-agent string to SDK v2 requests.
// Implement it as a named struct for better clarity in the middleware stack.
type userAgentMiddleware struct {
	caller string
}

type ECSTaskMeta struct {
	Cluster          string                 `json:"Cluster"`
	TaskARN          string                 `json:"TaskARN"`
	Family           string                 `json:"Family"`
	Containers       []ECSTaskMetaContainer `json:"Containers"`
	AvailabilityZone string                 `json:"AvailabilityZone"`
}

// ECSTaskAPI is the subset of the ECS API needed by mesh-init.
type ECSTaskAPI interface {
	DescribeTasks(ctx context.Context, params *ecs.DescribeTasksInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
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

// ImageVersion returns a version identifier derived from a container image
// reference. It prefers the image tag (e.g. "1.3.0"). When the image has no tag
// (it is pinned only by digest, or references a bare repository), it returns
// the raw image reference unchanged, so the value is still meaningful and can
// be used to pull the exact image.
// It returns "" only when image is empty.
func ImageVersion(image string) string {
	imageWithTag := image // reference reduced to its final "repo:tag" segment
	tag := ""             // the tag portion, if the image has one

	// Drop any digest ("@sha256:...") so it isn't mistaken for a tag.
	if idx := strings.Index(imageWithTag, "@"); idx != -1 {
		imageWithTag = imageWithTag[:idx]
	}
	// Reduce to the final path segment so a registry "host:port" isn't mistaken for a tag.
	if idx := strings.LastIndex(imageWithTag, "/"); idx != -1 {
		imageWithTag = imageWithTag[idx+1:]
	}
	if idx := strings.Index(imageWithTag, ":"); idx != -1 {
		tag = imageWithTag[idx+1:]
	}

	if tag != "" {
		return tag
	}
	// No tag: return the raw reference (bare repo or digest-pinned) as-is.
	return image
}

// ContainerImage returns the image reference for the named container from
// ECS DescribeTasks runtime state. It returns "" (with no error) when the
// container is not present in the task response.
func ContainerImage(ctx context.Context, client ECSTaskAPI, cluster, taskARN, containerName string) (string, error) {
	out, err := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{
		Cluster: aws.String(cluster),
		Tasks:   []string{taskARN},
	})
	if err != nil {
		return "", fmt.Errorf("describing ECS task %q: %w", taskARN, err)
	}
	if out == nil || len(out.Tasks) == 0 {
		return "", fmt.Errorf("task %q not found", taskARN)
	}
	for _, container := range out.Tasks[0].Containers {
		if aws.ToString(container.Name) == containerName {
			return aws.ToString(container.Image), nil
		}
	}
	return "", nil
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
	// Task ARN: "arn:aws:ecs:us-east-1:000000000000:task/cluster/00000000000000000000000000000000"
	// https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
	// See also: https://github.com/aws/containers-roadmap/issues/337
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
	return c.DesiredStatus == string(types.DesiredStatusStopped) &&
		c.KnownStatus == string(types.DesiredStatusStopped)
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
	resp, err := http.Get(fmt.Sprintf("%s/task", metadataURI))
	if err != nil {
		return metadataResp, fmt.Errorf("calling metadata uri: %s", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return metadataResp, fmt.Errorf("reading metadata uri response body: %s", err)
	}
	if err := json.Unmarshal(respBytes, &metadataResp); err != nil {
		return metadataResp, fmt.Errorf("unmarshalling metadata uri response: %s", err)
	}
	return metadataResp, nil
}

func (m *userAgentMiddleware) ID() string {
	return "ConsulECSUserAgent"
}

// UserAgentMiddleware adds a custom user-agent string to SDK v2 requests.
func (m *userAgentMiddleware) HandleBuild(
	ctx context.Context, in smithymiddleware.BuildInput, next smithymiddleware.BuildHandler,
) (
	out smithymiddleware.BuildOutput, metadata smithymiddleware.Metadata, err error,
) {
	req, ok := in.Request.(*smithyhttp.Request)
	if ok {
		// Append the caller to the existing User-Agent
		ua := req.Header.Get("User-Agent")
		if ua != "" {
			ua = ua + " "
		}
		req.Header.Set("User-Agent", ua+m.caller)
	}
	return next.HandleBuild(ctx, in)
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
		// Register the middleware onto the Build step of the stack
		cfg.APIOptions = append(cfg.APIOptions, func(stack *smithymiddleware.Stack) error {
			return stack.Build.Add(&userAgentMiddleware{caller: userAgentCaller}, smithymiddleware.After)
		})
	}

	return cfg, nil
}

func GetAWSRegion() string {
	return os.Getenv(AWSRegionEnvVar)
}
