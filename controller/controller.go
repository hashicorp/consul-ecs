// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controller

import (
	"fmt"
	"time"

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
}

// Reconcile first lists all resources and then reconciles them with Controller's state.
func (c *Controller) Reconcile() error {
	c.Log.Debug("starting reconcile")
	resources, err := c.Resources.List()
	if err != nil {
		return fmt.Errorf("listing resources: %w", err)
	}

	var merr error
	if err = c.Resources.ReconcileNamespaces(resources); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("reconciling namespaces: %w", err))
	}

	if err = c.Resources.ReconcileServices(resources); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("reconciling services: %w", err))
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
