package controller

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	cases := map[string]struct {
		source map[ResourceID]struct{}
		sink   map[ResourceID]struct{}
	}{
		"upsert single": {
			source: map[ResourceID]struct{}{"foo": {}},
			sink:   make(map[ResourceID]struct{}),
		},
		"upsert multiple": {
			source: map[ResourceID]struct{}{"foo": {}, "bar": {}},
			sink:   make(map[ResourceID]struct{}),
		},
		"delete": {
			source: map[ResourceID]struct{}{"foo": {}, "bar": {}},
			sink:   map[ResourceID]struct{}{"baz": {}},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			resourceLister := &testResourceLister{
				source: c.source,
				sink:   c.sink,
			}

			ctrl := Controller{
				Resources:       resourceLister,
				PollingInterval: 1 * time.Second,
				Log:             hclog.NewNullLogger(),
			}
			// If sink already has resources, then we need to make sure
			// that the controller's internal state has them too.
			if c.sink != nil {
				ctrl.resourceState = make(map[ResourceID]Resource)
				for id := range c.sink {
					ctrl.resourceState[id] = testResource{name: string(id), sink: &c.sink}
				}
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			t.Cleanup(cancelFunc)

			go ctrl.Run(ctx)

			retry.Run(t, func(r *retry.R) {
				require.True(r, reflect.DeepEqual(resourceLister.sink, c.source))
				resourceStateIDs := make(map[ResourceID]struct{})
				for id := range ctrl.resourceState {
					resourceStateIDs[id] = struct{}{}
				}
				require.True(t, reflect.DeepEqual(resourceStateIDs, c.source))
			})
		})
	}
}

type testResourceLister struct {
	source map[ResourceID]struct{}
	sink   map[ResourceID]struct{}
}

type testResource struct {
	name string
	sink *map[ResourceID]struct{}
}

func (t testResourceLister) List() ([]Resource, error) {
	var resources []Resource
	for k := range t.source {
		resources = append(resources, testResource{name: string(k), sink: &t.sink})
	}
	return resources, nil
}

func (t testResource) ID() (ResourceID, error) {
	return ResourceID(t.name), nil
}

func (t testResource) Upsert() error {
	id, _ := t.ID()
	(*t.sink)[id] = struct{}{}

	return nil
}

func (t testResource) Delete() error {
	id, _ := t.ID()
	delete(*t.sink, id)

	return nil
}
