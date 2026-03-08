package store

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"unifiedsecurityscanner/platform-services/internal/config"
	"unifiedsecurityscanner/platform-services/internal/database"
)

const (
	maxListLimit           = 500
	defaultListLimit       = 100
	defaultRetryAttempts   = 5
	defaultRetryBaseSecs   = 5
	defaultRetryMaxSecs    = 300
	maxResponseBodyBytes   = 32_768
	defaultExportEventRows = 2_000
)

var idSequence uint64

type Store struct {
	pool            *pgxpool.Pool
	defaultTenantID string
}

func New(ctx context.Context, cfg config.Config) (*Store, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	poolConfig.MaxConns = cfg.DatabaseMaxConns
	poolConfig.MinConns = cfg.DatabaseMinConns
	poolConfig.MaxConnLifetime = cfg.DatabaseConnTTL

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}

	if err := database.Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}

	return &Store{
		pool:            pool,
		defaultTenantID: strings.TrimSpace(cfg.DefaultTenantID),
	}, nil
}

func (s *Store) Close() {
	if s == nil || s.pool == nil {
		return
	}
	s.pool.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *Store) ResolveTenantID(raw string) string {
	if tenantID := strings.TrimSpace(raw); tenantID != "" {
		return tenantID
	}
	if tenantID := strings.TrimSpace(s.defaultTenantID); tenantID != "" {
		return tenantID
	}
	return "bootstrap-org-local"
}

func nextID(prefix string) string {
	sequence := atomic.AddUint64(&idSequence, 1)
	return fmt.Sprintf("%s-%d-%06d", strings.TrimSpace(prefix), time.Now().UTC().Unix(), sequence)
}
