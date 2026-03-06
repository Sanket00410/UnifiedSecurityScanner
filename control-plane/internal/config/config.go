package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	APIBindAddress              string
	GRPCBindAddress             string
	UIDistPath                  string
	GRPCTLSCertFile             string
	GRPCTLSKeyFile              string
	GRPCTLSClientCAFile         string
	GRPCTLSRequireClientCert    bool
	DatabaseURL                 string
	DatabaseMaxConns            int32
	DatabaseMinConns            int32
	DatabaseConnTTL             time.Duration
	SchedulerInterval           time.Duration
	WorkerHeartbeatTTL          time.Duration
	BuildVersion                string
	WorkerSharedSecret          string
	BootstrapOrgSlug            string
	BootstrapOrgName            string
	BootstrapAdminName          string
	BootstrapAdminEmail         string
	BootstrapAdminRole          string
	BootstrapAdminToken         string
	OIDCIssuerURL               string
	OIDCClientID                string
	OIDCClientSecret            string
	OIDCRedirectURL             string
	OIDCDefaultRole             string
	WorkloadIdentitySigningKey  string
	WorkloadIdentityTTL         time.Duration
	WorkloadCertificateTTL      time.Duration
	CertificateAuthorityCertPEM string
	CertificateAuthorityKeyPEM  string
	KMSMasterKey                string
	SecretLeaseMaxTTL           time.Duration
	EvidenceSigningKey          string
	EvidenceSigningKeyID        string
}

func Load() Config {
	workerSecret := getEnv("USS_WORKER_SHARED_SECRET", "")

	return Config{
		APIBindAddress:              getEnv("USS_API_BIND_ADDRESS", ":8080"),
		GRPCBindAddress:             getEnv("USS_GRPC_BIND_ADDRESS", ":9090"),
		UIDistPath:                  getEnv("USS_UI_DIST_PATH", ""),
		GRPCTLSCertFile:             getEnv("USS_GRPC_TLS_CERT_FILE", ""),
		GRPCTLSKeyFile:              getEnv("USS_GRPC_TLS_KEY_FILE", ""),
		GRPCTLSClientCAFile:         getEnv("USS_GRPC_TLS_CLIENT_CA_FILE", ""),
		GRPCTLSRequireClientCert:    getBool("USS_GRPC_TLS_REQUIRE_CLIENT_CERT", false),
		DatabaseURL:                 getEnv("USS_DATABASE_URL", "postgres://postgres:postgres@localhost:5432/unified_security_scanner?sslmode=disable"),
		DatabaseMaxConns:            getInt32("USS_DATABASE_MAX_CONNS", 4),
		DatabaseMinConns:            getInt32("USS_DATABASE_MIN_CONNS", 1),
		DatabaseConnTTL:             getDuration("USS_DATABASE_CONN_TTL", 30*time.Minute),
		SchedulerInterval:           getDuration("USS_SCHEDULER_INTERVAL", 15*time.Second),
		WorkerHeartbeatTTL:          getDuration("USS_WORKER_HEARTBEAT_TTL", 2*time.Minute),
		BuildVersion:                getEnv("USS_BUILD_VERSION", "dev"),
		WorkerSharedSecret:          workerSecret,
		BootstrapOrgSlug:            getEnv("USS_BOOTSTRAP_ORG_SLUG", "local"),
		BootstrapOrgName:            getEnv("USS_BOOTSTRAP_ORG_NAME", "Local Organization"),
		BootstrapAdminName:          getEnv("USS_BOOTSTRAP_ADMIN_NAME", "Local Admin"),
		BootstrapAdminEmail:         getEnv("USS_BOOTSTRAP_ADMIN_EMAIL", "admin@local"),
		BootstrapAdminRole:          getEnv("USS_BOOTSTRAP_ADMIN_ROLE", "platform_admin"),
		BootstrapAdminToken:         getEnv("USS_BOOTSTRAP_ADMIN_TOKEN", "uss-local-admin-token"),
		OIDCIssuerURL:               getEnv("USS_OIDC_ISSUER_URL", ""),
		OIDCClientID:                getEnv("USS_OIDC_CLIENT_ID", ""),
		OIDCClientSecret:            getEnv("USS_OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:             getEnv("USS_OIDC_REDIRECT_URL", ""),
		OIDCDefaultRole:             getEnv("USS_OIDC_DEFAULT_ROLE", "viewer"),
		WorkloadIdentitySigningKey:  getEnv("USS_WORKLOAD_IDENTITY_SIGNING_KEY", workerSecret),
		WorkloadIdentityTTL:         getDuration("USS_WORKLOAD_IDENTITY_TTL", 2*time.Hour),
		WorkloadCertificateTTL:      getDuration("USS_WORKLOAD_CERTIFICATE_TTL", 24*time.Hour),
		CertificateAuthorityCertPEM: getEnv("USS_CA_CERT_PEM", ""),
		CertificateAuthorityKeyPEM:  getEnv("USS_CA_KEY_PEM", ""),
		KMSMasterKey:                getEnv("USS_KMS_MASTER_KEY", workerSecret),
		SecretLeaseMaxTTL:           getDuration("USS_SECRET_LEASE_MAX_TTL", 30*time.Minute),
		EvidenceSigningKey:          getEnv("USS_EVIDENCE_SIGNING_KEY", workerSecret),
		EvidenceSigningKeyID:        getEnv("USS_EVIDENCE_SIGNING_KEY_ID", "local-hmac-sha256"),
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

func getBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	switch value {
	case "1", "true", "TRUE", "True", "yes", "YES", "on", "ON":
		return true
	case "0", "false", "FALSE", "False", "no", "NO", "off", "OFF":
		return false
	default:
		return fallback
	}
}
