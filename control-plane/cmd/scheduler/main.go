package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
)

func main() {
	cfg := config.Load()
	logger := log.New(os.Stdout, "scheduler ", log.LstdFlags|log.LUTC)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := jobs.NewStore(ctx, cfg)
	if err != nil {
		logger.Fatalf("scheduler store init failed: %v", err)
	}
	defer store.Close()

	scheduler := jobs.NewScheduler(cfg.SchedulerInterval, logger, store, cfg.WebhookDispatchLimitPerTenant)
	if err := scheduler.Run(ctx); err != nil {
		logger.Fatalf("scheduler failed: %v", err)
	}
}
