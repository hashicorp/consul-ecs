package controller

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
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
		for _, resource := range lister.resources {
			require.True(r, resource.reconciled)
		}
	})
}

type testResourceLister struct {
	resources []*testResource
}

type testResource struct {
	name       string
	reconciled bool
}

func (t testResourceLister) List() ([]Resource, error) {
	var resources []Resource
	for _, resource := range t.resources {
		resources = append(resources, resource)
	}
	return resources, nil
}

func (t *testResource) Reconcile() error {
	t.reconciled = true

	return nil
}
