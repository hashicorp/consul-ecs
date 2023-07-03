package meshinit

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/consul-ecs/config"
	"github.com/hashicorp/go-hclog"
)

type dataplaneMonitor struct {
	ctx context.Context
	log hclog.Logger

	doneCh chan struct{}
}

func newDataplaneMonitor(ctx context.Context, logger hclog.Logger) *dataplaneMonitor {
	return &dataplaneMonitor{
		ctx:    ctx,
		log:    logger,
		doneCh: make(chan struct{}, 1),
	}
}

func (d *dataplaneMonitor) done() chan struct{} {
	return d.doneCh
}

// Run will wake up when SIGTERM is received. Then, it polls task metadata
// until the dataplane container stops. Use the Done() channel to wait
// until it has finished.
func (d *dataplaneMonitor) run() {
	defer close(d.doneCh)

	if !d.waitForSIGTERM() {
		d.doneCh <- struct{}{}
		return
	}

	d.log.Info("waiting for dataplane container to stop")
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-time.After(1 * time.Second):
			taskMeta, err := awsutil.ECSTaskMetadata()
			if err != nil {
				d.log.Error("fetching task metadata", "err", err.Error())
				break
			}

			if hasDataplaneContainerStopped(taskMeta) {
				d.log.Info("dataplane container has stopped, terminating control plane")
				d.doneCh <- struct{}{}
				return
			}
		}
	}
}

func (d *dataplaneMonitor) waitForSIGTERM() bool {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	defer signal.Stop(sigs)

	for {
		select {
		case <-sigs:
			return true
		case <-d.ctx.Done():
			return false
		}
	}
}

func hasDataplaneContainerStopped(taskMeta awsutil.ECSTaskMeta) bool {
	stopped := true
	for _, container := range taskMeta.Containers {
		if isDataplaneContainer(container) && !isStopped(container) {
			stopped = false
		}
	}
	return stopped
}

func isDataplaneContainer(container awsutil.ECSTaskMetaContainer) bool {
	return container.Name == config.ConsulDataplaneContainerName
}

func isStopped(container awsutil.ECSTaskMetaContainer) bool {
	return container.DesiredStatus == ecs.DesiredStatusStopped &&
		container.KnownStatus == ecs.DesiredStatusStopped
}
