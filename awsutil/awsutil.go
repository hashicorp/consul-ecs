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
	Name          string            `json:"Name"`
	Health        ECSTaskMetaHealth `json:"Health"`
	DesiredStatus string            `json:"DesiredStatus"`
	KnownStatus   string            `json:"KnownStatus"`
}

type ECSTaskMetaHealth struct {
	Status      string `json:"status"`
	StatusSince string `json:"statusSince"`
	ExitCode    int    `json:"exitCode"`
}

func (e ECSTaskMeta) TaskID() string {
	split := strings.Split(e.TaskARN, "/")
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

func (e ECSTaskMeta) region() (string, error) {
	// Task ARN: "arn:aws:ecs:us-east-1:000000000000:task/cluster/00000000000000000000000000000000"
	// https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
	// See also: https://github.com/aws/containers-roadmap/issues/337
	a, err := arn.Parse(e.TaskARN)
	if err != nil {
		return "", fmt.Errorf("unable to determine AWS region from Task ARN: %q", e.TaskARN)
	}
	return a.Region, nil
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
		region, err := meta.region()
		if err != nil {
			return nil, err
		}
		cfg.Region = aws.String(region)
	}
	return clientSession, nil
}
