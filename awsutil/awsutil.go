package awsutil

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/aws/aws-sdk-go/aws/request"
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
	// Use the region from Task metadata if missing from environment (for EC2).
	// https://github.com/aws/containers-roadmap/issues/337
	for _, envKey := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if region := os.Getenv(envKey); region != "" {
			return region
		}
	}

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
