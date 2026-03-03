package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"unifiedsecurityscanner/control-plane/risk-engine/internal/httpapi"
)

func main() {
	bindAddress := os.Getenv("USS_RISK_ENGINE_BIND")
	if bindAddress == "" {
		bindAddress = ":18110"
	}

	server := httpapi.New(bindAddress)

	errs := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
			return
		}
		errs <- nil
	}()

	shutdownSignals := make(chan os.Signal, 1)
	signal.Notify(shutdownSignals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errs:
		if err != nil {
			log.Fatalf("risk engine api failed: %v", err)
		}
	case <-shutdownSignals:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("risk engine shutdown failed: %v", err)
		}
	}
}
