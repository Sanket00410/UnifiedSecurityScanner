package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

const (
	defaultEvidenceRetentionDays int64 = 90
	maxEvidenceHashSizeBytes     int64 = 64 * 1024 * 1024
)

var (
	evidenceObjectSequence       uint64
	evidenceRetentionRunSequence uint64
)

func (s *Store) ListEvidenceObjectsForTenant(ctx context.Context, tenantID string, query models.EvidenceListQuery) (models.EvidenceListResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	normalized := normalizeEvidenceListQuery(query)

	var total int64
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM evidence_objects
		WHERE tenant_id = $1
		  AND ($2 = '' OR scan_job_id = $2)
		  AND ($3 = '' OR task_id = $3)
		  AND ($4 = '' OR finding_id = $4)
		  AND ($5::boolean IS NULL OR archived = $5::boolean)
	`, tenantID, normalized.ScanJobID, normalized.TaskID, normalized.FindingID, normalized.Archived).Scan(&total); err != nil {
		return models.EvidenceListResult{}, fmt.Errorf("count evidence objects: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			id, tenant_id, scan_job_id, task_id, finding_id,
			object_key, object_ref, storage_provider, storage_tier, archived,
			retention_until, archived_at, size_bytes, sha256, content_type,
			metadata_json, created_at, updated_at
		FROM evidence_objects
		WHERE tenant_id = $1
		  AND ($2 = '' OR scan_job_id = $2)
		  AND ($3 = '' OR task_id = $3)
		  AND ($4 = '' OR finding_id = $4)
		  AND ($5::boolean IS NULL OR archived = $5::boolean)
		ORDER BY created_at DESC, id DESC
		LIMIT $6 OFFSET $7
	`, tenantID, normalized.ScanJobID, normalized.TaskID, normalized.FindingID, normalized.Archived, normalized.Limit, normalized.Offset)
	if err != nil {
		return models.EvidenceListResult{}, fmt.Errorf("query evidence objects: %w", err)
	}
	defer rows.Close()

	items := make([]models.EvidenceObject, 0, normalized.Limit)
	for rows.Next() {
		item, err := scanEvidenceObject(rows)
		if err != nil {
			return models.EvidenceListResult{}, fmt.Errorf("scan evidence object: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return models.EvidenceListResult{}, fmt.Errorf("iterate evidence objects: %w", err)
	}

	return models.EvidenceListResult{
		Items:  items,
		Total:  total,
		Limit:  normalized.Limit,
		Offset: normalized.Offset,
	}, nil
}

func (s *Store) GetEvidenceObjectForTenant(ctx context.Context, tenantID string, evidenceID string) (models.EvidenceObject, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	evidenceID = strings.TrimSpace(evidenceID)

	row := s.pool.QueryRow(ctx, `
		SELECT
			id, tenant_id, scan_job_id, task_id, finding_id,
			object_key, object_ref, storage_provider, storage_tier, archived,
			retention_until, archived_at, size_bytes, sha256, content_type,
			metadata_json, created_at, updated_at
		FROM evidence_objects
		WHERE tenant_id = $1
		  AND id = $2
	`, tenantID, evidenceID)

	item, err := scanEvidenceObject(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.EvidenceObject{}, false, nil
		}
		return models.EvidenceObject{}, false, fmt.Errorf("get evidence object: %w", err)
	}

	return item, true, nil
}

func (s *Store) ListEvidenceRetentionRunsForTenant(ctx context.Context, tenantID string, limit int) ([]models.EvidenceRetentionRun, error) {
	tenantID = strings.TrimSpace(tenantID)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			id, tenant_id, triggered_by, status, scanned_count, archived_count, deleted_count,
			dry_run, archive_before, delete_archived_before, started_at, completed_at
		FROM evidence_retention_runs
		WHERE tenant_id = $1
		ORDER BY started_at DESC, id DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list evidence retention runs: %w", err)
	}
	defer rows.Close()

	out := make([]models.EvidenceRetentionRun, 0, limit)
	for rows.Next() {
		run, err := scanEvidenceRetentionRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan evidence retention run: %w", err)
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate evidence retention runs: %w", err)
	}

	return out, nil
}

func (s *Store) RunEvidenceRetentionForTenant(ctx context.Context, tenantID string, actor string, request models.RunEvidenceRetentionRequest) (models.EvidenceRetentionRun, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	now := time.Now().UTC()
	archiveBefore := now
	if request.ArchiveBefore != nil {
		archiveBefore = request.ArchiveBefore.UTC()
	}

	var deleteArchivedBefore *time.Time
	if request.DeleteArchivedBefore != nil {
		deleteAt := request.DeleteArchivedBefore.UTC()
		deleteArchivedBefore = &deleteAt
	}

	run := models.EvidenceRetentionRun{
		ID:                   nextEvidenceRetentionRunID(),
		TenantID:             tenantID,
		TriggeredBy:          actor,
		Status:               "completed",
		DryRun:               request.DryRun,
		ArchiveBefore:        archiveBefore,
		DeleteArchivedBefore: deleteArchivedBefore,
		StartedAt:            now,
		CompletedAt:          now,
	}
	if request.DryRun {
		run.Status = "dry_run"
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.EvidenceRetentionRun{}, fmt.Errorf("begin evidence retention tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM evidence_objects
		WHERE tenant_id = $1
	`, tenantID).Scan(&run.ScannedCount); err != nil {
		return models.EvidenceRetentionRun{}, fmt.Errorf("count evidence for retention run: %w", err)
	}

	if request.DryRun {
		if err := tx.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM evidence_objects
			WHERE tenant_id = $1
			  AND archived = FALSE
			  AND retention_until <= $2
		`, tenantID, archiveBefore).Scan(&run.ArchivedCount); err != nil {
			return models.EvidenceRetentionRun{}, fmt.Errorf("count archive candidates: %w", err)
		}

		if deleteArchivedBefore != nil {
			if err := tx.QueryRow(ctx, `
				SELECT COUNT(*)
				FROM evidence_objects
				WHERE tenant_id = $1
				  AND archived = TRUE
				  AND archived_at IS NOT NULL
				  AND archived_at <= $2
			`, tenantID, *deleteArchivedBefore).Scan(&run.DeletedCount); err != nil {
				return models.EvidenceRetentionRun{}, fmt.Errorf("count delete candidates: %w", err)
			}
		}
	} else {
		archiveResult, err := tx.Exec(ctx, `
			UPDATE evidence_objects
			SET archived = TRUE,
			    storage_tier = 'archive',
			    archived_at = $3,
			    updated_at = $3
			WHERE tenant_id = $1
			  AND archived = FALSE
			  AND retention_until <= $2
		`, tenantID, archiveBefore, now)
		if err != nil {
			return models.EvidenceRetentionRun{}, fmt.Errorf("archive evidence objects: %w", err)
		}
		run.ArchivedCount = archiveResult.RowsAffected()

		if deleteArchivedBefore != nil {
			deleteResult, err := tx.Exec(ctx, `
				DELETE FROM evidence_objects
				WHERE tenant_id = $1
				  AND archived = TRUE
				  AND archived_at IS NOT NULL
				  AND archived_at <= $2
			`, tenantID, *deleteArchivedBefore)
			if err != nil {
				return models.EvidenceRetentionRun{}, fmt.Errorf("delete archived evidence objects: %w", err)
			}
			run.DeletedCount = deleteResult.RowsAffected()
		}
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO evidence_retention_runs (
			id, tenant_id, triggered_by, status, scanned_count, archived_count, deleted_count,
			dry_run, archive_before, delete_archived_before, started_at, completed_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
	`, run.ID, run.TenantID, run.TriggeredBy, run.Status, run.ScannedCount, run.ArchivedCount, run.DeletedCount, run.DryRun, run.ArchiveBefore, run.DeleteArchivedBefore, run.StartedAt, run.CompletedAt)
	if err != nil {
		return models.EvidenceRetentionRun{}, fmt.Errorf("insert evidence retention run: %w", err)
	}

	if err := publishPlatformEventTx(ctx, tx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "evidence_retention.executed",
		SourceService: "control-plane",
		AggregateType: "tenant",
		AggregateID:   tenantID,
		Payload: map[string]any{
			"run_id":                 run.ID,
			"dry_run":                run.DryRun,
			"archive_before":         run.ArchiveBefore,
			"delete_archived_before": run.DeleteArchivedBefore,
			"scanned_count":          run.ScannedCount,
			"archived_count":         run.ArchivedCount,
			"deleted_count":          run.DeletedCount,
			"triggered_by":           run.TriggeredBy,
		},
		CreatedAt: now,
	}); err != nil {
		return models.EvidenceRetentionRun{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.EvidenceRetentionRun{}, fmt.Errorf("commit evidence retention tx: %w", err)
	}

	return run, nil
}

func registerTaskEvidenceTx(ctx context.Context, tx pgx.Tx, task models.TaskContext, evidencePaths []string, now time.Time) (int, error) {
	if len(evidencePaths) == 0 {
		return 0, nil
	}

	seen := make(map[string]struct{}, len(evidencePaths))
	registeredCount := 0
	retentionUntil := now.AddDate(0, 0, int(defaultEvidenceRetentionDays))

	for _, rawRef := range evidencePaths {
		ref := strings.TrimSpace(rawRef)
		if ref == "" {
			continue
		}
		if _, exists := seen[ref]; exists {
			continue
		}
		seen[ref] = struct{}{}

		provider, key := normalizeEvidenceReference(ref)
		sizeBytes, shaDigest, contentType := collectEvidenceMetadata(ref, key)

		metadata := map[string]any{
			"source":     "worker_submission",
			"task_id":    task.TaskID,
			"scan_job":   task.ScanJobID,
			"adapter_id": task.AdapterID,
		}
		if filename := strings.TrimSpace(filepath.Base(key)); filename != "" && filename != "." {
			metadata["filename"] = filename
		}

		payload, err := json.Marshal(metadata)
		if err != nil {
			return registeredCount, fmt.Errorf("marshal evidence metadata: %w", err)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO evidence_objects (
				id, tenant_id, scan_job_id, task_id, finding_id,
				object_key, object_ref, storage_provider, storage_tier, archived,
				retention_until, archived_at, size_bytes, sha256, content_type,
				metadata_json, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, '', $5, $6, $7, 'hot', FALSE,
				$8, NULL, $9, $10, $11, $12, $13, $13
			)
			ON CONFLICT (tenant_id, task_id, object_ref) DO UPDATE SET
				object_key = EXCLUDED.object_key,
				storage_provider = EXCLUDED.storage_provider,
				retention_until = GREATEST(evidence_objects.retention_until, EXCLUDED.retention_until),
				size_bytes = GREATEST(evidence_objects.size_bytes, EXCLUDED.size_bytes),
				sha256 = CASE WHEN EXCLUDED.sha256 <> '' THEN EXCLUDED.sha256 ELSE evidence_objects.sha256 END,
				content_type = CASE WHEN EXCLUDED.content_type <> '' THEN EXCLUDED.content_type ELSE evidence_objects.content_type END,
				metadata_json = evidence_objects.metadata_json || EXCLUDED.metadata_json,
				updated_at = EXCLUDED.updated_at
		`, nextEvidenceObjectID(), task.TenantID, task.ScanJobID, task.TaskID, key, ref, provider, retentionUntil, sizeBytes, shaDigest, contentType, payload, now)
		if err != nil {
			return registeredCount, fmt.Errorf("upsert evidence object: %w", err)
		}

		registeredCount++
	}

	return registeredCount, nil
}

func normalizeEvidenceListQuery(query models.EvidenceListQuery) models.EvidenceListQuery {
	query.ScanJobID = strings.TrimSpace(query.ScanJobID)
	query.TaskID = strings.TrimSpace(query.TaskID)
	query.FindingID = strings.TrimSpace(query.FindingID)

	if query.Limit <= 0 || query.Limit > 1000 {
		query.Limit = 100
	}
	if query.Offset < 0 {
		query.Offset = 0
	}

	return query
}

func scanEvidenceObject(row interface{ Scan(dest ...any) error }) (models.EvidenceObject, error) {
	var (
		item         models.EvidenceObject
		metadataJSON []byte
	)

	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.ScanJobID,
		&item.TaskID,
		&item.FindingID,
		&item.ObjectKey,
		&item.ObjectRef,
		&item.StorageProvider,
		&item.StorageTier,
		&item.Archived,
		&item.RetentionUntil,
		&item.ArchivedAt,
		&item.SizeBytes,
		&item.SHA256,
		&item.ContentType,
		&metadataJSON,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.EvidenceObject{}, err
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &item.Metadata); err != nil {
			return models.EvidenceObject{}, fmt.Errorf("decode evidence metadata: %w", err)
		}
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}

	return item, nil
}

func scanEvidenceRetentionRun(row interface{ Scan(dest ...any) error }) (models.EvidenceRetentionRun, error) {
	var run models.EvidenceRetentionRun
	err := row.Scan(
		&run.ID,
		&run.TenantID,
		&run.TriggeredBy,
		&run.Status,
		&run.ScannedCount,
		&run.ArchivedCount,
		&run.DeletedCount,
		&run.DryRun,
		&run.ArchiveBefore,
		&run.DeleteArchivedBefore,
		&run.StartedAt,
		&run.CompletedAt,
	)
	if err != nil {
		return models.EvidenceRetentionRun{}, err
	}

	return run, nil
}

func normalizeEvidenceReference(ref string) (provider string, key string) {
	value := strings.TrimSpace(ref)
	if value == "" {
		return "local", ""
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err == nil && strings.TrimSpace(parsed.Scheme) != "" {
			provider = strings.ToLower(strings.TrimSpace(parsed.Scheme))
			key = strings.TrimPrefix(parsed.Host+parsed.Path, "/")
			if parsed.RawQuery != "" {
				key += "?" + parsed.RawQuery
			}
			return provider, key
		}
	}

	return "filesystem", filepath.ToSlash(value)
}

func collectEvidenceMetadata(ref string, key string) (int64, string, string) {
	contentType := strings.TrimSpace(mime.TypeByExtension(strings.ToLower(filepath.Ext(key))))
	localPath := localPathForEvidenceRef(ref)
	if localPath == "" {
		return 0, "", contentType
	}

	fileInfo, err := os.Stat(localPath)
	if err != nil || fileInfo.IsDir() {
		return 0, "", contentType
	}

	sizeBytes := fileInfo.Size()
	if contentType == "" {
		contentType = strings.TrimSpace(mime.TypeByExtension(strings.ToLower(filepath.Ext(localPath))))
	}

	if sizeBytes <= 0 || sizeBytes > maxEvidenceHashSizeBytes {
		return sizeBytes, "", contentType
	}

	file, err := os.Open(localPath)
	if err != nil {
		return sizeBytes, "", contentType
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return sizeBytes, "", contentType
	}

	return sizeBytes, hex.EncodeToString(hash.Sum(nil)), contentType
}

func localPathForEvidenceRef(ref string) string {
	value := strings.TrimSpace(ref)
	if value == "" {
		return ""
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return ""
		}

		if strings.EqualFold(parsed.Scheme, "file") {
			path := strings.TrimSpace(parsed.Path)
			if path == "" {
				path = strings.TrimSpace(parsed.Opaque)
			}
			if path == "" {
				return ""
			}
			return filepath.FromSlash(path)
		}

		return ""
	}

	return value
}

func nextEvidenceObjectID() string {
	sequence := atomic.AddUint64(&evidenceObjectSequence, 1)
	return fmt.Sprintf("evidence-object-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextEvidenceRetentionRunID() string {
	sequence := atomic.AddUint64(&evidenceRetentionRunSequence, 1)
	return fmt.Sprintf("evidence-retention-%d-%06d", time.Now().UTC().Unix(), sequence)
}
