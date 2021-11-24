package metrics

import (
	"fmt"
	"time"

	"github.com/armon/go-metrics"
	"github.com/armon/go-metrics/datadog"
)

func Init() error {
	datadogAddress := "127.0.0.1:8125"
	defaultConfig := metrics.DefaultConfig("consul-ecs")

	sink, err := datadog.NewDogStatsdSink(datadogAddress, "")

	if err != nil {
		return fmt.Errorf("coudln't create datadog sync: %w", err)
	}
	_, err = metrics.NewGlobal(defaultConfig, sink)

	if err != nil {
		return fmt.Errorf("error registering datadog sink: %w", err)
	}

	return nil
}

func MeasureSinceWithLabels(key []string, start time.Time, labels []metrics.Label) {
	elapsed := time.Since(start)
	val := float32(elapsed) / float32(time.Millisecond)
	metrics.AddSampleWithLabels(key, val, labels)

}

var (
	MeshInitLatency                       = []string{"mesh-init", "init", "latency"}
	HealthSyncLatency                     = []string{"health-sync", "sync", "latency"}
	HealthSyncShutdownLatency             = []string{"health-sync", "shutdown", "latency"}
	AclControllerListLatency              = []string{"acl-controller", "list", "latency"}
	AclControllerReconcileResources       = []string{"acl-controller", "resources"}
	AclControllerResourceReconcileLatency = []string{"acl-controller", "reconcile", "latency"}
	EnvoyEntrypointShutdownLatency        = []string{"envoy-entrypoint", "shutdown", "latency"}
)
