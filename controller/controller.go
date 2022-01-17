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
func (c *Controller) Run(ctx context.Context, mode string) {
	for {
		select {
		case <-time.After(c.PollingInterval):
			if mode == "acl" {
				err := c.reconcile()
				if err != nil {
					c.Log.Error("error during reconcile", "err", err)
				}
			} else {

				err := c.reap()
				if err != nil {
					c.Log.Error("error during reap", "err", err)
				}
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
	for _, resource := range resources {
		err = resource.Reconcile()
		if err != nil {
			c.Log.Error("error reconciling resource", "err", err)
		}
	}

	c.Log.Info("reconcile finished successfully")
	return nil
}

func (c *Controller) reap() error {
	c.Log.Info("starting reap")
	ecsNodes, err := c.Resources.fetchNodesRunningOnECS()
	if err != nil {
		return fmt.Errorf("listing ecs nodes: %w", err)
	}

	consulNodes, err := c.Resources.fetchConsulNodes()

	if err != nil {
		return fmt.Errorf("listing consul nodes: %w", err)
	}

	for _, consulNode := range consulNodes {
		if _, ok := ecsNodes[consulNode]; !ok {
			err := c.Resources.reap(consulNode)
			if err != nil {
				c.Log.Error("error reaping resource", "err", err)
			}
		}
	}

	c.Log.Info("reap finished")
	return nil
}
