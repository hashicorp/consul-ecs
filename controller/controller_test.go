// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controller

import (
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

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

	ctrl.Reconcile()

	require.True(t, lister.nsReconciled)
	require.True(t, lister.servicesReconciled)
	for _, resource := range lister.resources {
		require.True(t, resource.reconciled)
	}
}

type testResourceLister struct {
	resources          []*testResource
	nsReconciled       bool
	servicesReconciled bool
}

type testResource struct {
	name       string
	reconciled bool
}

func (t *testResourceLister) List() ([]Resource, error) {
	var resources []Resource
	for _, resource := range t.resources {
		resources = append(resources, resource)
	}
	return resources, nil
}

func (t *testResourceLister) ReconcileNamespaces([]Resource) error {
	t.nsReconciled = true
	return nil
}

func (t *testResourceLister) ReconcileServices([]Resource) error {
	t.servicesReconciled = true
	return nil
}

func (t *testResource) Reconcile() error {
	t.reconciled = true
	return nil
}

func (t *testResource) Namespace() string {
	return ""
}

func (t *testResource) IsPresent() bool {
	return true
}

func (t *testResource) ID() TaskID {
	return ""
}
