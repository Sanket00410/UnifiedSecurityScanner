package models

import "time"

type BackupSnapshot struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id,omitempty"`
	Scope          string     `json:"scope"`
	StorageRef     string     `json:"storage_ref"`
	ChecksumSHA256 string     `json:"checksum_sha256,omitempty"`
	SizeBytes      int64      `json:"size_bytes,omitempty"`
	Status         string     `json:"status"`
	CreatedBy      string     `json:"created_by,omitempty"`
	Notes          string     `json:"notes,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

type CreateBackupSnapshotRequest struct {
	Scope          string     `json:"scope"`
	StorageRef     string     `json:"storage_ref"`
	ChecksumSHA256 string     `json:"checksum_sha256,omitempty"`
	SizeBytes      int64      `json:"size_bytes,omitempty"`
	Status         string     `json:"status,omitempty"`
	Notes          string     `json:"notes,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

type RecoveryDrill struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id,omitempty"`
	SnapshotID  string     `json:"snapshot_id,omitempty"`
	Status      string     `json:"status"`
	StartedBy   string     `json:"started_by,omitempty"`
	Notes       string     `json:"notes,omitempty"`
	RTOSeconds  int64      `json:"rto_seconds,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type CreateRecoveryDrillRequest struct {
	SnapshotID  string     `json:"snapshot_id,omitempty"`
	Status      string     `json:"status,omitempty"`
	Notes       string     `json:"notes,omitempty"`
	RTOSeconds  int64      `json:"rto_seconds,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}
