package jobs

import (
	"context"
	"log"
	"time"
)

type Scheduler struct {
	logger   *log.Logger
	interval time.Duration
}

func NewScheduler(interval time.Duration, logger *log.Logger) *Scheduler {
	return &Scheduler{
		logger:   logger,
		interval: interval,
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
		}
	}
}
