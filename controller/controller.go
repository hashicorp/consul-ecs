// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/consul-ecs/datadog"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
)

const DefaultPollingInterval = 10 * time.Second

const ReconcileDDTag = "controller.reconcile"

// Controller is a generic controller implementation.
// It periodically polls for Resources and reconciles
// them by calling Resource's Upsert or Delete function accordingly.
type Controller struct {
	// Resources lists resources for Controller to reconcile.
	Resources ResourceLister
	// PollingInterval is an interval that Controller will use to reconcile all Resources.
	PollingInterval time.Duration
	// Log is the logger used by the Controller.
	Log hclog.Logger

	StatsClient datadog.Client
}

// Run starts the Controller loop. The loop will exit when ctx is canceled.
func (c *Controller) Run(ctx context.Context) {
	for {
		select {
		case <-time.After(c.PollingInterval):
			startTime := time.Now()
			err := c.reconcile()
			if err != nil {
				c.Log.Error("error during reconcile", "err", err)
				c.StatsClient.Timing(ReconcileDDTag, time.Since(startTime), []string{"error: true"})
			} else {
				c.StatsClient.Timing(ReconcileDDTag, time.Since(startTime), []string{"error: false"})
			}
		case <-ctx.Done():
			return
		}
	}
}

// reconcile first lists all resources and then reconciles them with Controller's state.
func (c *Controller) reconcile() error {
	c.Log.Debug("starting reconcile")

	startTime := time.Now()
	resources, err := c.Resources.List()
	if err != nil {
		c.StatsClient.Timing("controller.reconcile_list", time.Since(startTime), []string{"error: true"})
		return fmt.Errorf("listing resources: %w", err)
	}
	c.StatsClient.Timing("controller.reconcile_list", time.Since(startTime), []string{"error: false"})

	var merr error
	startTime = time.Now()
	if err = c.Resources.ReconcileNamespaces(resources); err != nil {
		c.StatsClient.Timing("controller.reconcile_namespaces", time.Since(startTime), []string{"error: true"})
		merr = multierror.Append(merr, fmt.Errorf("reconciling namespaces: %w", err))
	}
	c.StatsClient.Timing("controller.reconcile_namespaces", time.Since(startTime), []string{"error: false"})

	startTime = time.Now()
	for _, resource := range resources {
		err = resource.Reconcile()
		if err != nil {
			merr = multierror.Append(err, fmt.Errorf("reconciling resource: %w", err))
		}
	}

	if merr != nil {
		c.StatsClient.Timing("controller.reconcile_resources", time.Since(startTime), []string{"error: true"})
	} else {
		c.StatsClient.Timing("controller.reconcile_resources", time.Since(startTime), []string{"error: false"})
	}

	c.Log.Debug("reconcile finished")
	return merr
}
