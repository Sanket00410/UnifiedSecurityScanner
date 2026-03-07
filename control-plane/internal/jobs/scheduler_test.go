package jobs

import (
	"context"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
)

type schedulerWebhookSweepStub struct {
	mu     sync.Mutex
	calls  int
	limit  int
	actor  string
	result models.DispatchWebhookDeliveriesSweepResult
	err    error
}

func (s *schedulerWebhookSweepStub) DispatchWebhookDeliveriesForAllTenants(_ context.Context, actor string, limitPerTenant int) (models.DispatchWebhookDeliveriesSweepResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.actor = actor
	s.limit = limitPerTenant
	return s.result, s.err
}

func (s *schedulerWebhookSweepStub) snapshot() (calls int, actor string, limit int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.actor, s.limit
}

func TestSchedulerDispatchesWebhookSweepOnTick(t *testing.T) {
	stub := &schedulerWebhookSweepStub{
		result: models.DispatchWebhookDeliveriesSweepResult{
			TenantsEvaluated: 1,
			Attempted:        2,
			Delivered:        1,
			Failed:           1,
			Skipped:          0,
			ByTenant: map[string]models.DispatchTenantSummary{
				"bootstrap-org-local": {Attempted: 2, Delivered: 1, Failed: 1, Skipped: 0},
			},
		},
	}

	logger := log.New(io.Discard, "", 0)
	scheduler := NewScheduler(10*time.Millisecond, logger, stub, 55)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
	defer cancel()

	if err := scheduler.Run(ctx); err != nil {
		t.Fatalf("run scheduler: %v", err)
	}

	calls, actor, limit := stub.snapshot()
	if calls == 0 {
		t.Fatal("expected scheduler to trigger at least one webhook dispatch sweep")
	}
	if actor != "scheduler" {
		t.Fatalf("expected scheduler actor, got %s", actor)
	}
	if limit != 55 {
		t.Fatalf("expected dispatch limit 55, got %d", limit)
	}
}

func TestSchedulerWithNilWebhookSweeperStillRuns(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	scheduler := NewScheduler(5*time.Millisecond, logger, nil, 100)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if err := scheduler.Run(ctx); err != nil {
		t.Fatalf("run scheduler with nil sweeper: %v", err)
	}
}
