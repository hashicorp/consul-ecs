package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-hclog"
)

const DefaultUpsertPollingInterval = 10 * time.Second
const DefaultDeletePollingInterval = 2 * time.Minute

// Controller is a generic controller implementation.
// It periodically polls for Resources and reconciles
// them by calling Resource's Upsert or Delete function accordingly.
type Controller struct {
	// Resources lists resources for Controller to reconcile.
	Resources ResourceLister
	// UpsertPollingInterval is an interval that Controller will use to upsert Resources.
	UpsertPollingInterval time.Duration
	// DeletePollingInterval is an interval that Controller will use to delete Resources. This should be larger than and evenly divisible by UpsertPollingInterval.
	DeletePollingInterval time.Duration
	// Log is the logger used by the Controller.
	Log hclog.Logger
}

// Run starts the Controller loop. The loop will exit when ctx is canceled.
// Upserting and deleting are combined into a single call to reconcile to
// reduce calls to Consul and the ECS API.
func (c *Controller) Run(ctx context.Context) {
	iteration := 0

	for {
		select {
		case <-time.After(c.UpsertPollingInterval):
			err := c.reconcile(c.canDelete(iteration))
			if err != nil {
				c.Log.Error("error during reconcile", "err", err)
			}
			iteration++
		case <-ctx.Done():
			return
		}
	}
}

func (c *Controller) canDelete(iteration int) bool {
	return iteration%int(c.DeletePollingInterval/c.UpsertPollingInterval) == 0
}

// reconcile first lists all resources and then reconciles them with Controller's state.
func (c *Controller) reconcile(canDelete bool) error {
	c.Log.Info("starting reconcile")
	resources, err := c.Resources.List()
	if err != nil {
		return fmt.Errorf("listing resources: %w", err)
	}
	for _, resource := range resources {
		err = resource.Reconcile(canDelete)
		if err != nil {
			c.Log.Error("error reconciling resource", "err", err)
		}
	}

	c.Log.Info("reconcile finished successfully")
	return nil
}
