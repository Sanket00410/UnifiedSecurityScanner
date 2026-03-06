package models

import "time"

type EvidenceObject struct {
	ID              string         `json:"id"`
	TenantID        string         `json:"tenant_id,omitempty"`
	ScanJobID       string         `json:"scan_job_id"`
	TaskID          string         `json:"task_id"`
	FindingID       string         `json:"finding_id,omitempty"`
	ObjectKey       string         `json:"object_key,omitempty"`
	ObjectRef       string         `json:"object_ref"`
	StorageProvider string         `json:"storage_provider"`
	StorageTier     string         `json:"storage_tier"`
	Archived        bool           `json:"archived"`
	RetentionUntil  time.Time      `json:"retention_until"`
	ArchivedAt      *time.Time     `json:"archived_at,omitempty"`
	SizeBytes       int64          `json:"size_bytes,omitempty"`
	SHA256          string         `json:"sha256,omitempty"`
	ContentType     string         `json:"content_type,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

type EvidenceListQuery struct {
	ScanJobID string `json:"scan_job_id,omitempty"`
	TaskID    string `json:"task_id,omitempty"`
	FindingID string `json:"finding_id,omitempty"`
	Archived  *bool  `json:"archived,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	Offset    int    `json:"offset,omitempty"`
}

type EvidenceListResult struct {
	Items  []EvidenceObject `json:"items"`
	Total  int64            `json:"total"`
	Limit  int              `json:"limit"`
	Offset int              `json:"offset"`
}

type RunEvidenceRetentionRequest struct {
	ArchiveBefore        *time.Time `json:"archive_before,omitempty"`
	DeleteArchivedBefore *time.Time `json:"delete_archived_before,omitempty"`
	DryRun               bool       `json:"dry_run,omitempty"`
}

type EvidenceRetentionRun struct {
	ID                   string     `json:"id"`
	TenantID             string     `json:"tenant_id,omitempty"`
	TriggeredBy          string     `json:"triggered_by,omitempty"`
	Status               string     `json:"status"`
	ScannedCount         int64      `json:"scanned_count"`
	ArchivedCount        int64      `json:"archived_count"`
	DeletedCount         int64      `json:"deleted_count"`
	DryRun               bool       `json:"dry_run"`
	ArchiveBefore        time.Time  `json:"archive_before"`
	DeleteArchivedBefore *time.Time `json:"delete_archived_before,omitempty"`
	StartedAt            time.Time  `json:"started_at"`
	CompletedAt          time.Time  `json:"completed_at"`
}

type EvidenceIntegrityVerification struct {
	EvidenceID       string    `json:"evidence_id"`
	TenantID         string    `json:"tenant_id,omitempty"`
	ObjectRef        string    `json:"object_ref"`
	Verified         bool      `json:"verified"`
	ObjectExists     bool      `json:"object_exists"`
	HashAvailable    bool      `json:"hash_available"`
	HashMatches      bool      `json:"hash_matches"`
	SignaturePresent bool      `json:"signature_present"`
	SignatureValid   bool      `json:"signature_valid"`
	Algorithm        string    `json:"algorithm,omitempty"`
	KeyID            string    `json:"key_id,omitempty"`
	VerifiedAt       time.Time `json:"verified_at"`
	Message          string    `json:"message"`
}
