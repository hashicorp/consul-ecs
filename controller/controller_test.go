// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

// global mutex for these tests to pass the race detector
var mutex sync.Mutex

func TestRun(t *testing.T) {
	t.Parallel()
	resource1 := &testResource{
		name: "resource1",
	}

	resource2 := &testResource{
		name: "resource2",
	}

	lister := &testResourceLister{
		resources: []*testResource{resource1, resource2},
	}

	ctrl := Controller{
		Resources:       lister,
		PollingInterval: 1 * time.Second,
		Log:             hclog.NewNullLogger(),
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(cancelFunc)

	go ctrl.Run(ctx)

	retry.Run(t, func(r *retry.R) {
		mutex.Lock()
		defer mutex.Unlock()
		require.True(r, lister.nsReconciled)
		for _, resource := range lister.resources {
			require.True(r, resource.reconciled)
		}
	})
}

type testResourceLister struct {
	resources    []*testResource
	nsReconciled bool
}

type testResource struct {
	name       string
	reconciled bool
}

func (t *testResourceLister) List() ([]Resource, error) {
	mutex.Lock()
	defer mutex.Unlock()

	var resources []Resource
	for _, resource := range t.resources {
		resources = append(resources, resource)
	}
	return resources, nil
}

func (t *testResourceLister) ReconcileNamespaces([]Resource) error {
	mutex.Lock()
	defer mutex.Unlock()

	t.nsReconciled = true
	return nil
}

func (t *testResource) Reconcile() error {
	mutex.Lock()
	defer mutex.Unlock()

	t.reconciled = true
	return nil
}

func (t *testResource) Namespace() string {
	return ""
}

func (t *testResource) ID() TaskID {
	return ""
}

func (t *testResource) IsPresent() bool {
	return true
}
