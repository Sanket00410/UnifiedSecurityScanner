package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"unifiedsecurityscanner/platform-services/internal/config"
	"unifiedsecurityscanner/platform-services/internal/store"
	"unifiedsecurityscanner/platform-services/internal/worker"
)

func main() {
	cfg := config.Load()
	logger := log.New(os.Stdout, "platform-worker ", log.LstdFlags|log.LUTC)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dataStore, err := store.New(ctx, cfg)
	if err != nil {
		logger.Fatalf("create store: %v", err)
	}
	defer dataStore.Close()

	runner := worker.New(cfg, dataStore, logger)
	if err := runner.Run(ctx); err != nil {
		logger.Fatalf("platform worker failed: %v", err)
	}
}
