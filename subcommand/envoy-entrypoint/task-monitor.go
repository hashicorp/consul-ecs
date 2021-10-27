package envoyentrypoint

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/hashicorp/consul-ecs/awsutil"
	"github.com/hashicorp/go-hclog"
)

var (
	nonAppContainers = map[string]struct{}{
		"consul-client":        {},
		"sidecar-proxy":        {},
		"health-sync":          {},
		"consul-ecs-mesh-init": {},
	}
)

type AppContainerMonitor struct {
	log  hclog.Logger
	once sync.Once
	ctx  context.Context

	doneCh chan bool
}

func NewAppContainerMonitor(log hclog.Logger, ctx context.Context) *AppContainerMonitor {
	return &AppContainerMonitor{
		log:    log,
		ctx:    ctx,
		doneCh: make(chan bool, 1),
	}
}

func (t *AppContainerMonitor) Done() chan bool {
	return t.doneCh
}

func (t *AppContainerMonitor) Run(wg *sync.WaitGroup) {
	t.once.Do(func() {
		t.realRun(wg)
	})
}

func (t *AppContainerMonitor) realRun(wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	defer close(t.doneCh)

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
				t.doneCh <- true
				return
			}
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
