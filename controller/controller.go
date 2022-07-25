package controller

import (
	"context"
	"fmt"
	"time"

	"consul-server-discovery/discovery"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
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

	WatcherChan chan discovery.ServerIPs
	NewClientFn func(discovery.ServerIPs) (*api.Client, error)
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
		case ips := <-c.WatcherChan:
			// TODO: Recreate the consul client with the new addr.
			// Maybe not quite the right place to do this.
			lister, ok := c.Resources.(TaskStateLister)
			if ok {
				client, err := c.NewClientFn(ips)
				if err != nil {
					lister.ConsulClient = client
				}
			}

		case <-ctx.Done():
			return
		}
	}
}

// reconcile first lists all resources and then reconciles them with Controller's state.
func (c *Controller) reconcile() error {
	c.Log.Debug("starting reconcile")
	resources, err := c.Resources.List()
	if err != nil {
		return fmt.Errorf("listing resources: %w", err)
	}

	var merr error
	if err = c.Resources.ReconcileNamespaces(resources); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("reconciling namespaces: %w", err))
	}

	for _, resource := range resources {
		err = resource.Reconcile()
		if err != nil {
			merr = multierror.Append(err, fmt.Errorf("reconciling resource: %w", err))
		}
	}

	c.Log.Debug("reconcile finished")
	return merr
}
