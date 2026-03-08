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

	"unifiedsecurityscanner/platform-services/internal/config"
	"unifiedsecurityscanner/platform-services/internal/httpapi"
	"unifiedsecurityscanner/platform-services/internal/store"
)

func main() {
	cfg := config.Load()
	logger := log.New(os.Stdout, "platform-api ", log.LstdFlags|log.LUTC)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dataStore, err := store.New(ctx, cfg)
	if err != nil {
		logger.Fatalf("create store: %v", err)
	}
	defer dataStore.Close()

	server := httpapi.NewWithStore(cfg, dataStore)
	errCh := make(chan error, 1)

	go func() {
		logger.Printf("starting platform services api bind=%s version=%s", cfg.APIBindAddress, cfg.BuildVersion)
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("graceful shutdown failed: %v", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("server stopped unexpectedly: %v", err)
		}
	}
}
