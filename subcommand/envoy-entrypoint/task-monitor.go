//go:build !windows
// +build !windows

package envoyentrypoint

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/go-hclog"
)

var (
	nonAppContainers = map[string]struct{}{
		// TODO: replace with consul-dataplane
		"consul-client":            {},
		"sidecar-proxy":            {},
		"consul-ecs-control-plane": {},
	}
)

type AppContainerMonitor struct {
	log hclog.Logger
	ctx context.Context

	doneCh chan struct{}
}

func NewAppContainerMonitor(log hclog.Logger, ctx context.Context) *AppContainerMonitor {
	return &AppContainerMonitor{
		log:    log,
		ctx:    ctx,
		doneCh: make(chan struct{}, 1),
	}
}

func (t *AppContainerMonitor) Done() chan struct{} {
	return t.doneCh
}

// Run will wake up when SIGTERM is received. Then, it polls task metadata
// until the application container(s) stop. Use the Done() channel to wait
// until it has finished. It is cancellable through its context.
func (t *AppContainerMonitor) Run() {
	defer close(t.doneCh)

	if !t.waitForSIGTERM() {
		t.doneCh <- struct{}{}
		return
	}

	t.log.Info("waiting for application container(s) to stop")
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(1 * time.Second):
			taskMeta, err := awsutil.ECSTaskMetadata()
			if err != nil {
				t.log.Error("fetching task metadata", "err", err.Error())
				break // escape this case of the select
			}

			if allAppContainersStopped(taskMeta) {
				t.log.Info("application container(s) have stopped, terminating envoy")
				t.doneCh <- struct{}{}
				return
			}
		}
	}
}

func (t *AppContainerMonitor) waitForSIGTERM() bool {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	defer signal.Stop(sigs)

	for {
		select {
		case <-sigs:
			return true
		case <-t.ctx.Done():
			return false
		}
	}
}

func allAppContainersStopped(taskMeta awsutil.ECSTaskMeta) bool {
	allStopped := true
	for _, container := range taskMeta.Containers {
		if isApplication(container) && !isStopped(container) {
			allStopped = false
		}
	}
	return allStopped
}

func isApplication(container awsutil.ECSTaskMetaContainer) bool {
	_, ok := nonAppContainers[container.Name]
	return !ok
}

func isStopped(container awsutil.ECSTaskMetaContainer) bool {
	return container.DesiredStatus == ecs.DesiredStatusStopped &&
		container.KnownStatus == ecs.DesiredStatusStopped
}
