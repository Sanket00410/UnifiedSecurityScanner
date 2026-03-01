package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	APIBindAddress     string
	DatabaseURL        string
	DatabaseMaxConns   int32
	DatabaseMinConns   int32
	DatabaseConnTTL    time.Duration
	SchedulerInterval  time.Duration
	WorkerHeartbeatTTL time.Duration
	BuildVersion       string
}

func Load() Config {
	return Config{
		APIBindAddress:     getEnv("USS_API_BIND_ADDRESS", ":8080"),
		DatabaseURL:        getEnv("USS_DATABASE_URL", "postgres://postgres:postgres@localhost:5432/unified_security_scanner?sslmode=disable"),
		DatabaseMaxConns:   getInt32("USS_DATABASE_MAX_CONNS", 4),
		DatabaseMinConns:   getInt32("USS_DATABASE_MIN_CONNS", 1),
		DatabaseConnTTL:    getDuration("USS_DATABASE_CONN_TTL", 30*time.Minute),
		SchedulerInterval:  getDuration("USS_SCHEDULER_INTERVAL", 15*time.Second),
		WorkerHeartbeatTTL: getDuration("USS_WORKER_HEARTBEAT_TTL", 2*time.Minute),
		BuildVersion:       getEnv("USS_BUILD_VERSION", "dev"),
	}
}

func getEnv(key, fallback string) string {
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
