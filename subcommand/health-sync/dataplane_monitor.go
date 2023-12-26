// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package healthsync

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

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
		doneCh: make(chan struct{}),
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

			d.log.Info("Waiting for dataplane container to stop")
			if taskMeta.HasContainerStopped(config.ConsulDataplaneContainerName) {
				d.log.Info("dataplane container has stopped, terminating health-sync")
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
