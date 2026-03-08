package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	APIBindAddress    string
	DatabaseURL       string
	DatabaseMaxConns  int32
	DatabaseMinConns  int32
	DatabaseConnTTL   time.Duration
	APIAuthToken      string
	WorkerID          string
	WorkerInterval    time.Duration
	WorkerLeaseTTL    time.Duration
	WorkerBatchSize   int
	HTTPClientTimeout time.Duration
	ExportRoot        string
	DefaultTenantID   string
	BuildVersion      string
}

func Load() Config {
	return Config{
		APIBindAddress:    getEnv("USS_PLATFORM_SERVICES_BIND", ":18090"),
		DatabaseURL:       getEnv("USS_DATABASE_URL", "postgres://postgres:postgres@localhost:5432/unified_security_scanner?sslmode=disable"),
		DatabaseMaxConns:  getInt32("USS_DATABASE_MAX_CONNS", 4),
		DatabaseMinConns:  getInt32("USS_DATABASE_MIN_CONNS", 1),
		DatabaseConnTTL:   getDuration("USS_DATABASE_CONN_TTL", 30*time.Minute),
		APIAuthToken:      getEnv("USS_PLATFORM_SERVICES_API_TOKEN", getEnv("USS_BOOTSTRAP_ADMIN_TOKEN", "uss-local-admin-token")),
		WorkerID:          getEnv("USS_PLATFORM_SERVICES_WORKER_ID", "platform-worker-local"),
		WorkerInterval:    getDuration("USS_PLATFORM_SERVICES_WORKER_INTERVAL", 10*time.Second),
		WorkerLeaseTTL:    getDuration("USS_PLATFORM_SERVICES_WORKER_LEASE_TTL", 45*time.Second),
		WorkerBatchSize:   getInt("USS_PLATFORM_SERVICES_WORKER_BATCH_SIZE", 32),
		HTTPClientTimeout: getDuration("USS_PLATFORM_SERVICES_HTTP_TIMEOUT", 15*time.Second),
		ExportRoot:        getEnv("USS_PLATFORM_SERVICES_EXPORT_ROOT", "./exports"),
		DefaultTenantID:   getEnv("USS_PLATFORM_SERVICES_DEFAULT_TENANT", "bootstrap-org-local"),
		BuildVersion:      getEnv("USS_BUILD_VERSION", "dev"),
	}
}

func getEnv(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func getDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getInt32(key string, fallback int32) int32 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return fallback
	}
	return int32(parsed)
}

func getInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
