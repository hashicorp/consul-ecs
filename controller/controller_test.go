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
	}{
		"upsert single": {
			source: map[ResourceID]struct{}{"foo": {}},
		},
		"upsert multiple": {
			source: map[ResourceID]struct{}{"foo": {}, "bar": {}},
		},
		// todo: test deletes
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			resourceLister := &testResourceLister{
				source: c.source,
				sink:   make(map[ResourceID]struct{}),
			}
			ctrl := Controller{
				Resources:       resourceLister,
				PollingInterval: 1 * time.Second,
				Log:             hclog.NewNullLogger(),
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			t.Cleanup(cancelFunc)

			go ctrl.Run(ctx)

			retry.Run(t, func(r *retry.R) {
				require.True(r, reflect.DeepEqual(resourceLister.sink, c.source))
				require.True(t, reflect.DeepEqual(ctrl.resourceState, c.source))
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
