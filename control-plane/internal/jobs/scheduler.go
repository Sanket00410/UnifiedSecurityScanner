package jobs

import (
	"context"
	"log"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
)

type webhookDispatchSweeper interface {
	DispatchWebhookDeliveriesForAllTenants(ctx context.Context, actor string, limitPerTenant int) (models.DispatchWebhookDeliveriesSweepResult, error)
}

type Scheduler struct {
	logger                        *log.Logger
	interval                      time.Duration
	webhookDispatchSweeper        webhookDispatchSweeper
	webhookDispatchLimitPerTenant int
}

func NewScheduler(interval time.Duration, logger *log.Logger, webhookSweeper webhookDispatchSweeper, webhookDispatchLimitPerTenant int) *Scheduler {
	return &Scheduler{
		logger:                        logger,
		interval:                      interval,
		webhookDispatchSweeper:        webhookSweeper,
		webhookDispatchLimitPerTenant: webhookDispatchLimitPerTenant,
	}
}

func (s *Scheduler) Run(ctx context.Context) error {
	s.logger.Printf("scheduler started interval=%s", s.interval)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Println("scheduler stopped")
			return nil
		case tick := <-ticker.C:
			s.logger.Printf("scheduler tick at %s", tick.UTC().Format(time.RFC3339))
			if s.webhookDispatchSweeper == nil {
				continue
			}

			result, err := s.webhookDispatchSweeper.DispatchWebhookDeliveriesForAllTenants(ctx, "scheduler", s.webhookDispatchLimitPerTenant)
			if err != nil {
				s.logger.Printf("webhook dispatch sweep failed: %v", err)
				continue
			}

			s.logger.Printf(
				"webhook dispatch sweep tenants=%d attempted=%d delivered=%d failed=%d skipped=%d",
				result.TenantsEvaluated,
				result.Attempted,
				result.Delivered,
				result.Failed,
				result.Skipped,
			)
		}
	}
}
