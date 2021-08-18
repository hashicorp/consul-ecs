package awsutil

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/consul-ecs/version"
)

const ECSMetadataURIEnvVar = "ECS_CONTAINER_METADATA_URI_V4"

type ECSTaskMeta struct {
	Cluster string `json:"Cluster"`
	TaskARN string `json:"TaskARN"`
	Family  string `json:"Family"`
}

func (e ECSTaskMeta) TaskID() string {
	split := strings.Split(e.TaskARN, "/")
	if len(split) == 0 {
		return ""
	}
	return split[len(split)-1]
}

func (e ECSTaskMeta) Region() string {
	// https://github.com/aws/containers-roadmap/issues/337
	split := strings.Split(e.TaskARN, ":")
	if len(split) < 4 {
		return ""
	}
	return split[3]
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
	respBytes, err := ioutil.ReadAll(resp.Body)
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
		return clientSession, err
	}

	clientSession.Handlers.Build.PushBackNamed(UserAgentHandler(userAgentCaller))

	cfg := clientSession.Config
	if cfg.Region == nil || *cfg.Region == "" {
		cfg.Region = aws.String(meta.Region())
	}
	return clientSession, nil
}
