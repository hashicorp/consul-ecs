package datadog

import (
	"fmt"
	"time"

	"github.com/DataDog/datadog-go/statsd"
)

type Client interface {
	Count(string, int64, []string) error
	Timing(string, time.Duration, []string) error
	Close() error
}

type client struct {
	statsdClient *statsd.Client
}

func NewClient() (Client, error) {
	statsdClient, err := statsd.New("localhost:8125")
	if err != nil {
		return nil, err
	}

	return &client{
		statsdClient: statsdClient,
	}, nil
}

func (c *client) Count(metric string, inc int64, tags []string) error {
	return c.statsdClient.Count(processMetric(metric), inc, tags, 1)
}

func (c *client) Timing(metric string, value time.Duration, tags []string) error {
	return c.statsdClient.Timing(processMetric(metric), value, tags, 1)
}

func (c *client) Close() error {
	return c.statsdClient.Close()
}

func processMetric(metric string) string {
	return fmt.Sprintf("consul_ecs.%s", metric)
}
