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

	ACLTokens ACLTokenLister
	Deleter   TokenInfoDeleter
	// PollingInterval is an interval that Controller will use to reconcile all Resources.
	PollingInterval time.Duration
	// Log is the logger used by the Controller.
	Log hclog.Logger

	// resourceState is the internal Controller's state. The Controller
	// will periodically update the state to reflect the state of the Resources.
	// The state stores ResourceIDs that have been successfully upserted
	// by the controller. If the resource with that ID no longer exists in the source,
	// the resourceState should not have that resource ID in its internal state either.
	resourceState map[ResourceID]Resource
}

// Run starts the Controller loop. The loop will exit when ctx is canceled.
func (c *Controller) Run(ctx context.Context) {
	if c.resourceState == nil {
		c.resourceState = make(map[ResourceID]Resource)
	}

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

	var familyToResource map[string]Resource

	for _, resource := range resources {
		familyToResource[string(resource.ID())] = resource
	}

	tokenList, err := c.ACLTokens.TokenList()

	if err != nil {
		return fmt.Errorf("listing tokens: %w", err)
	}

	for family, resource := range familyToResource {
		if _, ok := tokenList[family]; !ok {
			err = resource.Upsert()

			if err != nil {
				c.Log.Warn("Error inserting token information",
					"family", family,
					"err", err)
				return err
			}
		}
	}

	for family, tokens := range tokenList {
		if _, ok := familyToResource[family]; !ok {
			err = c.Deleter.DeleteTokenInfo(family, tokens)
			if err != nil {
				c.Log.Warn("Error deleting token information",
					"family", family,
					"err", err)
				return err
			}
		}
	}

	return nil
}
