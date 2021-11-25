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
		Resources:             lister,
		UpsertPollingInterval: 500 * time.Millisecond,
		DeletePollingInterval: 1 * time.Second,
		Log:                   hclog.NewNullLogger(),
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(cancelFunc)

	go ctrl.Run(ctx)

	retry.Run(t, func(r *retry.R) {
		for _, resource := range lister.resources {
			// Since deletes occur for every other upsert, they should always happen
			// in a 2 to 1 ratio. This ensures that r.reconcileCount is called at
			// least three times to make sure this ratio holds over time.
			require.LessOrEqual(r, 3, resource.reconcileCount)
			require.Equal(r, resource.deleteCount*2, resource.reconcileCount)
		}
	})
}

type testResourceLister struct {
	resources []*testResource
}

type testResource struct {
	name           string
	reconcileCount int
	deleteCount    int
}

func (t testResourceLister) List() ([]Resource, error) {
	var resources []Resource
	for _, resource := range t.resources {
		resources = append(resources, resource)
	}
	return resources, nil
}

func (t *testResource) Reconcile(canDelete bool) error {
	t.reconcileCount++

	if canDelete {
		t.deleteCount++
	}

	return nil
}
