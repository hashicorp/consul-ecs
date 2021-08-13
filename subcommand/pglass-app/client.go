package pglassapp

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func (c *Command) clientMain() error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	// Don't need to do anything for now. Just catch the SIGTERM so we don't exit.
	// And, print when we receive the SIGTERM
	go func() {
		for sig := range sigs {
			c.log.Info("signal received", "signal", sig)
		}
	}()

	url := fmt.Sprintf("http://%s:%d", c.flagHost, c.flagPort)

	for {
		resp, err := http.Get(url)
		if err != nil {
			c.log.Error(err.Error())
			time.Sleep(5 * time.Second)
			continue
		}

		c.log.Info(fmt.Sprintf("[%v] GET %v", resp.StatusCode, resp.Request.URL))
		time.Sleep(5 * time.Second)
	}
	return nil
}