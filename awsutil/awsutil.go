// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awsutil

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/consul-ecs/version"
)

const ECSMetadataURIEnvVar = "ECS_CONTAINER_METADATA_URI_V4"

type ECSTaskMeta struct {
	Cluster    string                 `json:"Cluster"`
	TaskARN    string                 `json:"TaskARN"`
	Family     string                 `json:"Family"`
	Containers []ECSTaskMetaContainer `json:"Containers"`
}

type ECSTaskMetaContainer struct {
	Name          string               `json:"Name"`
	Health        ECSTaskMetaHealth    `json:"Health"`
	DesiredStatus string               `json:"DesiredStatus"`
	KnownStatus   string               `json:"KnownStatus"`
	Networks      []ECSTaskMetaNetwork `json:"Networks"`
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
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return metadataResp, fmt.Errorf("reading metadata uri response body: %s", err)
	}
	if err := json.Unmarshal(respBytes, &metadataResp); err != nil {
		return metadataResp, fmt.Errorf("unmarshalling metadata uri response: %s", err)
	}
	return metadataResp, nil
}

func UserAgentHandler(caller string) request.NamedHandler {
	return request.NamedHandler{
		Name: "UserAgentHandler",
		Fn: func(r *request.Request) {
			userAgent := r.HTTPRequest.Header.Get("User-Agent")
			r.HTTPRequest.Header.Set("User-Agent",
				fmt.Sprintf("consul-ecs-%s/%s (%s) %s", caller, version.Version, runtime.GOOS, userAgent))
		},
	}
}

// NewSession prepares a client session.
// The returned session includes a User-Agent handler to enable AWS to track usage.
// If the AWS SDK fails to find the region, the region is parsed from Task metadata
// (on EC2 the region is not typically defined in the environment).
func NewSession(meta ECSTaskMeta, userAgentCaller string) (*session.Session, error) {
	clientSession, err := session.NewSession()
	if err != nil {
		return nil, err
	}

	clientSession.Handlers.Build.PushBackNamed(UserAgentHandler(userAgentCaller))

	cfg := clientSession.Config
	if cfg.Region == nil || *cfg.Region == "" {
		region, err := meta.Region()
		if err != nil {
			return nil, err
		}
		cfg.Region = aws.String(region)
	}
	return clientSession, nil
}
