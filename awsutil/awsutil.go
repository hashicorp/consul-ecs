package awsutil

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

const ecsMetadataURIEnvVar = "ECS_CONTAINER_METADATA_URI_V4"

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

func ECSTaskMetadata() (ECSTaskMeta, error) {
	var metadataResp ECSTaskMeta

	metadataURI := os.Getenv(ecsMetadataURIEnvVar)
	if metadataURI == "" {
		return metadataResp, fmt.Errorf("%s env var not set", ecsMetadataURIEnvVar)
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
