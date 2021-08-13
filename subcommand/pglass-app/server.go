package pglassapp

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func (c *Command) serverMain() error {
	// Catch SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)

	// make our server
	addr := fmt.Sprintf("%s:%d", c.flagHost, c.flagPort)
	c.log.Info("starting server", "addr", addr)
	server := &http.Server{Addr: addr}

	// After SIGTERM, wait 15 seconds before exiting.
	go func() {
		for sig := range sigs {
			c.log.Info("signal received", "signal", sig)
			// Start a 15 second timer
			timer := time.NewTimer(15 * time.Second)
			<-timer.C
			c.log.Info("shutting down server")
			server.Shutdown(nil)
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status": "ok"}`)
		c.log.Info("GET / -> 200")
	})

	return server.ListenAndServe()
}