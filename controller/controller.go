package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-hclog"
)

const DefaultPollingInterval = 10 * time.Second

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
}

// Run starts the Controller loop. The loop will exit when ctx is canceled.
func (c *Controller) Run(ctx context.Context) {
	for {
		select {
		case <-time.After(c.PollingInterval):
			err := c.reconcile()
			if err != nil {
				c.Log.Error("error during reconcile", "err", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// reconcile first lists all resources and then reconciles them with Controller's state.
func (c *Controller) reconcile() error {
	c.Log.Info("starting reconcile")
	resources, err := c.Resources.List()
	if err != nil {
		return fmt.Errorf("listing resources: %w", err)
	}

	if err = c.Resources.ReconcileNamespaces(resources); err != nil {
		return fmt.Errorf("reconciling namespaces: %w", err)
	}

	for _, resource := range resources {
		err = resource.Reconcile()
		if err != nil {
			c.Log.Error("error reconciling resource", "err", err)
		}
	}

	c.Log.Info("reconcile finished successfully")
	return nil
}
