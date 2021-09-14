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

	// resourceState is the internal Controller's state. The Controller
	// will periodically update the state to reflect the state of the Resources.
	resourceState map[string]struct{}
}

// Run starts the Controller loop. The loop will exit when ctx is canceled.
func (c *Controller) Run(ctx context.Context) {
	c.resourceState = make(map[string]struct{})

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

// reconcile first lists all resources and reconciles them with Controller's state.
func (c *Controller) reconcile() error {
	c.Log.Info("starting reconcile")
	resources, err := c.Resources.List()
	if err != nil {
		return fmt.Errorf("listing resources: %w", err)
	}

	for _, resource := range resources {
		resourceID, err := resource.ID()
		if err != nil {
			return fmt.Errorf("getting resource ID: %w", err)
		}
		if _, ok := c.resourceState[resourceID]; !ok {
			err = resource.Upsert()
			if err != nil {
				c.Log.Error("error upserting resource", "err", err)
				continue
			}
			c.resourceState[resourceID] = struct{}{}
		}
	}
	// todo: reconcile deletes
	c.Log.Info("reconcile finished successfully")
	return nil
}
