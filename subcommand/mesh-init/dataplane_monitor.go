package meshinit

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

type DataplaneContainerMonitor struct {
	log hclog.Logger
	ctx context.Context

	doneCh chan struct{}
}

func NewDataplaneContainerMonitor(log hclog.Logger, ctx context.Context) *DataplaneContainerMonitor {
	return &DataplaneContainerMonitor{
		log:    log,
		ctx:    ctx,
		doneCh: make(chan struct{}, 1),
	}
}

func (t *DataplaneContainerMonitor) Done() chan struct{} {
	return t.doneCh
}

// Run will wake up when SIGTERM is received. Then, it polls task metadata
// until the dataplane container stops. Use the Done() channel to wait
// until it has finished. It is cancellable through its context.
func (t *DataplaneContainerMonitor) Run() {
	defer close(t.doneCh)

	if !t.waitForSIGTERM() {
		t.doneCh <- struct{}{}
		return
	}

	t.log.Info("waiting for dataplane container to stop")
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

			if dataplaneContainerStopped(taskMeta) {
				t.log.Info("dataplane container(s) has stopped, terminating control plane")
				t.doneCh <- struct{}{}
				return
			}
		}
	}
}

func (t *DataplaneContainerMonitor) waitForSIGTERM() bool {
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

func dataplaneContainerStopped(taskMeta awsutil.ECSTaskMeta) bool {
	stopped := true
	for _, container := range taskMeta.Containers {
		if isDataplaneContainer(container) && !isStopped(container) {
			stopped = false
		}
	}
	return stopped
}

func isDataplaneContainer(container awsutil.ECSTaskMetaContainer) bool {
	return container.Name == "consul-dataplane"
}

func isStopped(container awsutil.ECSTaskMetaContainer) bool {
	return container.DesiredStatus == ecs.DesiredStatusStopped &&
		container.KnownStatus == ecs.DesiredStatusStopped
}
