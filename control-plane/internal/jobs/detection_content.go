package jobs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListDetectionRulepacksForTenant(ctx context.Context, tenantID string, engine string, status string, limit int) ([]models.DetectionRulepack, error) {
	tenantID = strings.TrimSpace(tenantID)
	engine = normalizeDetectionEngine(engine)
	status = normalizeDetectionRulepackStatus(status)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, engine, status, description, current_version,
		       created_by, updated_by, created_at, updated_at
		FROM detection_rulepacks
		WHERE tenant_id = $1
		  AND ($2 = '' OR engine = $2)
		  AND ($3 = '' OR status = $3)
		ORDER BY updated_at DESC, id DESC
		LIMIT $4
	`, tenantID, engine, status, limit)
	if err != nil {
		return nil, fmt.Errorf("list detection rulepacks: %w", err)
	}
	defer rows.Close()

	items := make([]models.DetectionRulepack, 0, limit)
	for rows.Next() {
		item, err := scanDetectionRulepack(rows)
		if err != nil {
			return nil, fmt.Errorf("scan detection rulepack row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate detection rulepack rows: %w", err)
	}
	return items, nil
}

func (s *Store) GetDetectionRulepackForTenant(ctx context.Context, tenantID string, rulepackID string) (models.DetectionRulepack, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	rulepackID = strings.TrimSpace(rulepackID)
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, engine, status, description, current_version,
		       created_by, updated_by, created_at, updated_at
		FROM detection_rulepacks
		WHERE tenant_id = $1
		  AND id = $2
	`, tenantID, rulepackID)
	item, err := scanDetectionRulepack(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DetectionRulepack{}, false, nil
		}
		return models.DetectionRulepack{}, false, fmt.Errorf("get detection rulepack: %w", err)
	}
	return item, true, nil
}

func (s *Store) CreateDetectionRulepackForTenant(ctx context.Context, tenantID string, actor string, request models.CreateDetectionRulepackRequest) (models.DetectionRulepack, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	name := strings.TrimSpace(request.Name)
	engine := normalizeDetectionEngine(request.Engine)
	if name == "" || engine == "" {
		return models.DetectionRulepack{}, fmt.Errorf("name and engine are required")
	}
	status := normalizeDetectionRulepackStatus(request.Status)
	if status == "" {
		status = "draft"
	}

	now := time.Now().UTC()
	item := models.DetectionRulepack{
		ID:             nextDetectionRulepackID(),
		TenantID:       tenantID,
		Name:           name,
		Engine:         engine,
		Status:         status,
		Description:    strings.TrimSpace(request.Description),
		CurrentVersion: "",
		CreatedBy:      actor,
		UpdatedBy:      actor,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO detection_rulepacks (
			id, tenant_id, name, engine, status, description, current_version,
			created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, '',
			$7, $7, $8, $8
		)
		RETURNING id, tenant_id, name, engine, status, description, current_version,
		          created_by, updated_by, created_at, updated_at
	`, item.ID, item.TenantID, item.Name, item.Engine, item.Status, item.Description, item.CreatedBy, item.CreatedAt)

	created, err := scanDetectionRulepack(row)
	if err != nil {
		return models.DetectionRulepack{}, fmt.Errorf("create detection rulepack: %w", err)
	}
	return created, nil
}

func (s *Store) UpdateDetectionRulepackForTenant(ctx context.Context, tenantID string, rulepackID string, actor string, request models.UpdateDetectionRulepackRequest) (models.DetectionRulepack, bool, error) {
	current, found, err := s.GetDetectionRulepackForTenant(ctx, tenantID, rulepackID)
	if err != nil || !found {
		return models.DetectionRulepack{}, found, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	if value := strings.TrimSpace(request.Name); value != "" {
		current.Name = value
	}
	if value := normalizeDetectionEngine(request.Engine); value != "" {
		current.Engine = value
	}
	if value := normalizeDetectionRulepackStatus(request.Status); value != "" {
		current.Status = value
	}
	if value := strings.TrimSpace(request.Description); value != "" {
		current.Description = value
	}
	current.UpdatedBy = actor
	current.UpdatedAt = time.Now().UTC()

	row := s.pool.QueryRow(ctx, `
		UPDATE detection_rulepacks
		SET name = $3,
		    engine = $4,
		    status = $5,
		    description = $6,
		    updated_by = $7,
		    updated_at = $8
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, name, engine, status, description, current_version,
		          created_by, updated_by, created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(rulepackID), current.Name, current.Engine, current.Status,
		current.Description, current.UpdatedBy, current.UpdatedAt)

	updated, err := scanDetectionRulepack(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DetectionRulepack{}, false, nil
		}
		return models.DetectionRulepack{}, true, fmt.Errorf("update detection rulepack: %w", err)
	}
	return updated, true, nil
}

func (s *Store) ListDetectionRulepackVersionsForTenant(ctx context.Context, tenantID string, rulepackID string, limit int) ([]models.DetectionRulepackVersion, error) {
	tenantID = strings.TrimSpace(tenantID)
	rulepackID = strings.TrimSpace(rulepackID)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, rulepack_id, version_tag, content_ref, checksum,
		       status, quality_score, published_by, published_at, created_at
		FROM detection_rulepack_versions
		WHERE tenant_id = $1
		  AND rulepack_id = $2
		ORDER BY created_at DESC, id DESC
		LIMIT $3
	`, tenantID, rulepackID, limit)
	if err != nil {
		return nil, fmt.Errorf("list detection rulepack versions: %w", err)
	}
	defer rows.Close()

	items := make([]models.DetectionRulepackVersion, 0, limit)
	for rows.Next() {
		item, err := scanDetectionRulepackVersion(rows)
		if err != nil {
			return nil, fmt.Errorf("scan detection rulepack version row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate detection rulepack version rows: %w", err)
	}
	return items, nil
}

func (s *Store) CreateDetectionRulepackVersionForTenant(ctx context.Context, tenantID string, rulepackID string, actor string, request models.CreateDetectionRulepackVersionRequest) (models.DetectionRulepackVersion, error) {
	tenantID = strings.TrimSpace(tenantID)
	rulepackID = strings.TrimSpace(rulepackID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	versionTag := strings.TrimSpace(request.VersionTag)
	if versionTag == "" {
		return models.DetectionRulepackVersion{}, fmt.Errorf("version_tag is required")
	}

	status := normalizeDetectionVersionStatus(request.Status)
	if status == "" {
		status = "draft"
	}
	now := time.Now().UTC()
	item := models.DetectionRulepackVersion{
		ID:           nextDetectionRulepackVersionID(),
		TenantID:     tenantID,
		RulepackID:   rulepackID,
		VersionTag:   versionTag,
		ContentRef:   strings.TrimSpace(request.ContentRef),
		Checksum:     strings.TrimSpace(request.Checksum),
		Status:       status,
		QualityScore: request.QualityScore,
		CreatedAt:    now,
	}
	if status == "canary" || status == "active" {
		item.PublishedBy = actor
		item.PublishedAt = &now
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.DetectionRulepackVersion{}, fmt.Errorf("begin detection rulepack version create tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, found, err := s.GetDetectionRulepackForTenant(ctx, tenantID, rulepackID)
	if err != nil {
		return models.DetectionRulepackVersion{}, err
	}
	if !found {
		return models.DetectionRulepackVersion{}, ErrDetectionRulepackNotFound
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO detection_rulepack_versions (
			id, tenant_id, rulepack_id, version_tag, content_ref, checksum,
			status, quality_score, published_by, published_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11
		)
		RETURNING id, tenant_id, rulepack_id, version_tag, content_ref, checksum,
		          status, quality_score, published_by, published_at, created_at
	`, item.ID, item.TenantID, item.RulepackID, item.VersionTag, item.ContentRef, item.Checksum,
		item.Status, item.QualityScore, item.PublishedBy, item.PublishedAt, item.CreatedAt)

	created, err := scanDetectionRulepackVersion(row)
	if err != nil {
		return models.DetectionRulepackVersion{}, fmt.Errorf("create detection rulepack version: %w", err)
	}

	if created.Status == "active" {
		_, err = tx.Exec(ctx, `
			UPDATE detection_rulepacks
			SET current_version = $3,
			    status = 'active',
			    updated_by = $4,
			    updated_at = $5
			WHERE tenant_id = $1
			  AND id = $2
		`, tenantID, rulepackID, created.VersionTag, actor, now)
		if err != nil {
			return models.DetectionRulepackVersion{}, fmt.Errorf("update detection rulepack active version: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return models.DetectionRulepackVersion{}, fmt.Errorf("commit detection rulepack version create tx: %w", err)
	}
	return created, nil
}

func (s *Store) PromoteDetectionRulepackVersionForTenant(ctx context.Context, tenantID string, rulepackID string, versionID string, actor string, request models.PromoteDetectionRulepackVersionRequest) (models.DetectionRulepackRollout, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	rulepackID = strings.TrimSpace(rulepackID)
	versionID = strings.TrimSpace(versionID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	phase := normalizeDetectionRolloutPhase(request.Phase)
	if phase == "" {
		phase = "canary"
	}
	requireQualityGate := true
	if request.RequireQualityGate != nil {
		requireQualityGate = *request.RequireQualityGate
	}
	minQualityScore := request.MinQualityScore
	if minQualityScore <= 0 {
		minQualityScore = 0.75
	}
	if minQualityScore > 1 {
		minQualityScore = 1
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.DetectionRulepackRollout{}, false, fmt.Errorf("begin detection promotion tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rulepack, found, err := getDetectionRulepackTx(ctx, tx, tenantID, rulepackID)
	if err != nil {
		return models.DetectionRulepackRollout{}, false, err
	}
	if !found {
		return models.DetectionRulepackRollout{}, false, nil
	}

	version, found, err := getDetectionRulepackVersionTx(ctx, tx, tenantID, rulepackID, versionID)
	if err != nil {
		return models.DetectionRulepackRollout{}, false, err
	}
	if !found {
		return models.DetectionRulepackRollout{}, false, nil
	}

	if requireQualityGate && (phase == "active" || phase == "rollback") {
		if err := enforceDetectionQualityGateTx(ctx, tx, tenantID, rulepackID, versionID, minQualityScore); err != nil {
			return models.DetectionRulepackRollout{}, false, err
		}
	}

	now := time.Now().UTC()
	versionStatus := "canary"
	if phase == "active" || phase == "rollback" {
		versionStatus = "active"
	}
	_, err = tx.Exec(ctx, `
		UPDATE detection_rulepack_versions
		SET status = $4,
		    published_by = $5,
		    published_at = $6
		WHERE tenant_id = $1
		  AND rulepack_id = $2
		  AND id = $3
	`, tenantID, rulepackID, versionID, versionStatus, actor, now)
	if err != nil {
		return models.DetectionRulepackRollout{}, false, fmt.Errorf("promote detection rulepack version: %w", err)
	}

	if versionStatus == "active" {
		_, err = tx.Exec(ctx, `
			UPDATE detection_rulepacks
			SET current_version = $3,
			    status = 'active',
			    updated_by = $4,
			    updated_at = $5
			WHERE tenant_id = $1
			  AND id = $2
		`, tenantID, rulepackID, version.VersionTag, actor, now)
		if err != nil {
			return models.DetectionRulepackRollout{}, false, fmt.Errorf("update detection rulepack current version: %w", err)
		}
	} else if rulepack.Status == "draft" {
		_, err = tx.Exec(ctx, `
			UPDATE detection_rulepacks
			SET status = 'active',
			    updated_by = $3,
			    updated_at = $4
			WHERE tenant_id = $1
			  AND id = $2
		`, tenantID, rulepackID, actor, now)
		if err != nil {
			return models.DetectionRulepackRollout{}, false, fmt.Errorf("activate detection rulepack during canary: %w", err)
		}
	}

	rollout := models.DetectionRulepackRollout{
		ID:          nextDetectionRulepackRolloutID(),
		TenantID:    tenantID,
		RulepackID:  rulepackID,
		VersionID:   versionID,
		Phase:       phase,
		Status:      "completed",
		TargetScope: strings.TrimSpace(request.TargetScope),
		Notes:       strings.TrimSpace(request.Notes),
		StartedBy:   actor,
		StartedAt:   now,
		CompletedAt: &now,
		CreatedAt:   now,
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO detection_rulepack_rollouts (
			id, tenant_id, rulepack_id, version_id, phase, status, target_scope,
			notes, started_by, started_at, completed_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12
		)
		RETURNING id, tenant_id, rulepack_id, version_id, phase, status, target_scope,
		          notes, started_by, started_at, completed_at, created_at
	`, rollout.ID, rollout.TenantID, rollout.RulepackID, rollout.VersionID, rollout.Phase, rollout.Status,
		rollout.TargetScope, rollout.Notes, rollout.StartedBy, rollout.StartedAt, rollout.CompletedAt, rollout.CreatedAt)

	created, err := scanDetectionRulepackRollout(row)
	if err != nil {
		return models.DetectionRulepackRollout{}, false, fmt.Errorf("create detection rulepack rollout: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.DetectionRulepackRollout{}, false, fmt.Errorf("commit detection promotion tx: %w", err)
	}
	return created, true, nil
}

func (s *Store) ListDetectionRulepackRolloutsForTenant(ctx context.Context, tenantID string, rulepackID string, limit int) ([]models.DetectionRulepackRollout, error) {
	tenantID = strings.TrimSpace(tenantID)
	rulepackID = strings.TrimSpace(rulepackID)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, rulepack_id, version_id, phase, status, target_scope,
		       notes, started_by, started_at, completed_at, created_at
		FROM detection_rulepack_rollouts
		WHERE tenant_id = $1
		  AND rulepack_id = $2
		ORDER BY started_at DESC, id DESC
		LIMIT $3
	`, tenantID, rulepackID, limit)
	if err != nil {
		return nil, fmt.Errorf("list detection rulepack rollouts: %w", err)
	}
	defer rows.Close()

	items := make([]models.DetectionRulepackRollout, 0, limit)
	for rows.Next() {
		item, err := scanDetectionRulepackRollout(rows)
		if err != nil {
			return nil, fmt.Errorf("scan detection rulepack rollout row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate detection rulepack rollout rows: %w", err)
	}
	return items, nil
}

func (s *Store) ListDetectionRulepackQualityRunsForTenant(ctx context.Context, tenantID string, rulepackID string, versionID string, limit int) ([]models.DetectionRulepackQualityRun, error) {
	tenantID = strings.TrimSpace(tenantID)
	rulepackID = strings.TrimSpace(rulepackID)
	versionID = strings.TrimSpace(versionID)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, rulepack_id, version_id, benchmark_name, dataset_ref,
		       run_status, quality_score, total_tests, passed_tests, failed_tests,
		       false_positive_count, false_negative_count, regression_count, suppression_delta,
		       notes, executed_by, executed_at, created_at
		FROM detection_rulepack_quality_runs
		WHERE tenant_id = $1
		  AND rulepack_id = $2
		  AND ($3 = '' OR version_id = $3)
		ORDER BY executed_at DESC, id DESC
		LIMIT $4
	`, tenantID, rulepackID, versionID, limit)
	if err != nil {
		return nil, fmt.Errorf("list detection quality runs: %w", err)
	}
	defer rows.Close()

	items := make([]models.DetectionRulepackQualityRun, 0, limit)
	for rows.Next() {
		item, err := scanDetectionRulepackQualityRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan detection quality run row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate detection quality run rows: %w", err)
	}
	return items, nil
}

func (s *Store) RecordDetectionRulepackQualityRunForTenant(ctx context.Context, tenantID string, rulepackID string, actor string, request models.RecordDetectionRulepackQualityRunRequest) (models.DetectionRulepackQualityRun, error) {
	tenantID = strings.TrimSpace(tenantID)
	rulepackID = strings.TrimSpace(rulepackID)
	versionID := strings.TrimSpace(request.VersionID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	if versionID == "" {
		return models.DetectionRulepackQualityRun{}, fmt.Errorf("version_id is required")
	}

	runStatus := normalizeDetectionQualityRunStatus(request.RunStatus)
	totalTests := clampInt64(request.TotalTests)
	passedTests := clampInt64(request.PassedTests)
	failedTests := clampInt64(request.FailedTests)
	falsePositiveCount := clampInt64(request.FalsePositiveCount)
	falseNegativeCount := clampInt64(request.FalseNegativeCount)
	regressionCount := clampInt64(request.RegressionCount)
	suppressionDelta := request.SuppressionDelta

	if totalTests == 0 && passedTests+failedTests > 0 {
		totalTests = passedTests + failedTests
	}
	if totalTests > 0 && passedTests > totalTests {
		passedTests = totalTests
	}
	if totalTests > 0 && failedTests > totalTests {
		failedTests = totalTests
	}
	if totalTests > 0 && passedTests+failedTests > totalTests {
		failedTests = totalTests - passedTests
		if failedTests < 0 {
			failedTests = 0
		}
	}

	if runStatus == "" {
		if failedTests == 0 && regressionCount == 0 {
			runStatus = "passed"
		} else {
			runStatus = "failed"
		}
	}

	qualityScore := request.QualityScore
	if qualityScore <= 0 {
		qualityScore = computeDetectionQualityScore(totalTests, passedTests, falsePositiveCount, falseNegativeCount, regressionCount)
	}
	if qualityScore < 0 {
		qualityScore = 0
	}
	if qualityScore > 1 {
		qualityScore = 1
	}

	executedAt := time.Now().UTC()
	if request.ExecutedAt != nil {
		executedAt = request.ExecutedAt.UTC()
	}
	now := time.Now().UTC()

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.DetectionRulepackQualityRun{}, fmt.Errorf("begin detection quality run tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, foundRulepack, err := getDetectionRulepackTx(ctx, tx, tenantID, rulepackID)
	if err != nil {
		return models.DetectionRulepackQualityRun{}, err
	}
	if !foundRulepack {
		return models.DetectionRulepackQualityRun{}, ErrDetectionRulepackNotFound
	}

	_, foundVersion, err := getDetectionRulepackVersionTx(ctx, tx, tenantID, rulepackID, versionID)
	if err != nil {
		return models.DetectionRulepackQualityRun{}, err
	}
	if !foundVersion {
		return models.DetectionRulepackQualityRun{}, ErrDetectionVersionNotFound
	}

	item := models.DetectionRulepackQualityRun{
		ID:                 nextDetectionQualityRunID(),
		TenantID:           tenantID,
		RulepackID:         rulepackID,
		VersionID:          versionID,
		BenchmarkName:      strings.TrimSpace(request.BenchmarkName),
		DatasetRef:         strings.TrimSpace(request.DatasetRef),
		RunStatus:          runStatus,
		QualityScore:       qualityScore,
		TotalTests:         totalTests,
		PassedTests:        passedTests,
		FailedTests:        failedTests,
		FalsePositiveCount: falsePositiveCount,
		FalseNegativeCount: falseNegativeCount,
		RegressionCount:    regressionCount,
		SuppressionDelta:   suppressionDelta,
		Notes:              strings.TrimSpace(request.Notes),
		ExecutedBy:         actor,
		ExecutedAt:         executedAt,
		CreatedAt:          now,
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO detection_rulepack_quality_runs (
			id, tenant_id, rulepack_id, version_id, benchmark_name, dataset_ref,
			run_status, quality_score, total_tests, passed_tests, failed_tests,
			false_positive_count, false_negative_count, regression_count, suppression_delta,
			notes, executed_by, executed_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14, $15,
			$16, $17, $18, $19
		)
		RETURNING id, tenant_id, rulepack_id, version_id, benchmark_name, dataset_ref,
		          run_status, quality_score, total_tests, passed_tests, failed_tests,
		          false_positive_count, false_negative_count, regression_count, suppression_delta,
		          notes, executed_by, executed_at, created_at
	`, item.ID, item.TenantID, item.RulepackID, item.VersionID, item.BenchmarkName, item.DatasetRef,
		item.RunStatus, item.QualityScore, item.TotalTests, item.PassedTests, item.FailedTests,
		item.FalsePositiveCount, item.FalseNegativeCount, item.RegressionCount, item.SuppressionDelta,
		item.Notes, item.ExecutedBy, item.ExecutedAt, item.CreatedAt)

	created, err := scanDetectionRulepackQualityRun(row)
	if err != nil {
		return models.DetectionRulepackQualityRun{}, fmt.Errorf("create detection quality run: %w", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE detection_rulepack_versions
		SET quality_score = $4
		WHERE tenant_id = $1
		  AND rulepack_id = $2
		  AND id = $3
	`, tenantID, rulepackID, versionID, created.QualityScore)
	if err != nil {
		return models.DetectionRulepackQualityRun{}, fmt.Errorf("update detection version quality score: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.DetectionRulepackQualityRun{}, fmt.Errorf("commit detection quality run tx: %w", err)
	}
	return created, nil
}

type detectionReader interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func getDetectionRulepackTx(ctx context.Context, reader detectionReader, tenantID string, rulepackID string) (models.DetectionRulepack, bool, error) {
	row := reader.QueryRow(ctx, `
		SELECT id, tenant_id, name, engine, status, description, current_version,
		       created_by, updated_by, created_at, updated_at
		FROM detection_rulepacks
		WHERE tenant_id = $1
		  AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(rulepackID))
	item, err := scanDetectionRulepack(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DetectionRulepack{}, false, nil
		}
		return models.DetectionRulepack{}, false, fmt.Errorf("get detection rulepack: %w", err)
	}
	return item, true, nil
}

func getDetectionRulepackVersionTx(ctx context.Context, reader detectionReader, tenantID string, rulepackID string, versionID string) (models.DetectionRulepackVersion, bool, error) {
	row := reader.QueryRow(ctx, `
		SELECT id, tenant_id, rulepack_id, version_tag, content_ref, checksum,
		       status, quality_score, published_by, published_at, created_at
		FROM detection_rulepack_versions
		WHERE tenant_id = $1
		  AND rulepack_id = $2
		  AND id = $3
	`, strings.TrimSpace(tenantID), strings.TrimSpace(rulepackID), strings.TrimSpace(versionID))
	item, err := scanDetectionRulepackVersion(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DetectionRulepackVersion{}, false, nil
		}
		return models.DetectionRulepackVersion{}, false, fmt.Errorf("get detection rulepack version: %w", err)
	}
	return item, true, nil
}

func scanDetectionRulepack(row interface{ Scan(dest ...any) error }) (models.DetectionRulepack, error) {
	var item models.DetectionRulepack
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.Name,
		&item.Engine,
		&item.Status,
		&item.Description,
		&item.CurrentVersion,
		&item.CreatedBy,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.DetectionRulepack{}, err
	}
	item.Engine = normalizeDetectionEngine(item.Engine)
	item.Status = normalizeDetectionRulepackStatus(item.Status)
	return item, nil
}

func scanDetectionRulepackVersion(row interface{ Scan(dest ...any) error }) (models.DetectionRulepackVersion, error) {
	var item models.DetectionRulepackVersion
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.RulepackID,
		&item.VersionTag,
		&item.ContentRef,
		&item.Checksum,
		&item.Status,
		&item.QualityScore,
		&item.PublishedBy,
		&item.PublishedAt,
		&item.CreatedAt,
	)
	if err != nil {
		return models.DetectionRulepackVersion{}, err
	}
	item.Status = normalizeDetectionVersionStatus(item.Status)
	return item, nil
}

func scanDetectionRulepackRollout(row interface{ Scan(dest ...any) error }) (models.DetectionRulepackRollout, error) {
	var item models.DetectionRulepackRollout
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.RulepackID,
		&item.VersionID,
		&item.Phase,
		&item.Status,
		&item.TargetScope,
		&item.Notes,
		&item.StartedBy,
		&item.StartedAt,
		&item.CompletedAt,
		&item.CreatedAt,
	)
	if err != nil {
		return models.DetectionRulepackRollout{}, err
	}
	item.Phase = normalizeDetectionRolloutPhase(item.Phase)
	item.Status = normalizeDetectionRolloutStatus(item.Status)
	return item, nil
}

func scanDetectionRulepackQualityRun(row interface{ Scan(dest ...any) error }) (models.DetectionRulepackQualityRun, error) {
	var item models.DetectionRulepackQualityRun
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.RulepackID,
		&item.VersionID,
		&item.BenchmarkName,
		&item.DatasetRef,
		&item.RunStatus,
		&item.QualityScore,
		&item.TotalTests,
		&item.PassedTests,
		&item.FailedTests,
		&item.FalsePositiveCount,
		&item.FalseNegativeCount,
		&item.RegressionCount,
		&item.SuppressionDelta,
		&item.Notes,
		&item.ExecutedBy,
		&item.ExecutedAt,
		&item.CreatedAt,
	)
	if err != nil {
		return models.DetectionRulepackQualityRun{}, err
	}
	item.RunStatus = normalizeDetectionQualityRunStatus(item.RunStatus)
	return item, nil
}

func normalizeDetectionEngine(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "semgrep", "trivy", "gitleaks", "checkov", "zap", "nmap", "metasploit", "custom":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeDetectionRulepackStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "draft", "active", "deprecated":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeDetectionVersionStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "draft", "canary", "active", "deprecated":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeDetectionRolloutPhase(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "canary", "active", "rollback":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeDetectionRolloutStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "started", "completed", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeDetectionQualityRunStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "passed", "failed", "error":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func clampInt64(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func computeDetectionQualityScore(totalTests int64, passedTests int64, falsePositiveCount int64, falseNegativeCount int64, regressionCount int64) float64 {
	if totalTests <= 0 {
		return 0
	}

	passRate := float64(passedTests) / float64(totalTests)
	penaltyUnits := float64(falsePositiveCount+falseNegativeCount+regressionCount) / float64(totalTests)
	score := passRate - (penaltyUnits * 0.5)
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

func enforceDetectionQualityGateTx(ctx context.Context, tx pgx.Tx, tenantID string, rulepackID string, versionID string, minQualityScore float64) error {
	row := tx.QueryRow(ctx, `
		SELECT run_status, quality_score
		FROM detection_rulepack_quality_runs
		WHERE tenant_id = $1
		  AND rulepack_id = $2
		  AND version_id = $3
		ORDER BY executed_at DESC, id DESC
		LIMIT 1
	`, tenantID, rulepackID, versionID)

	var (
		runStatus    string
		qualityScore float64
	)
	if err := row.Scan(&runStatus, &qualityScore); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: no quality run found for version", ErrDetectionQualityGateFailed)
		}
		return fmt.Errorf("load detection quality gate run: %w", err)
	}
	runStatus = normalizeDetectionQualityRunStatus(runStatus)
	if runStatus != "passed" {
		return fmt.Errorf("%w: latest quality run status is %s", ErrDetectionQualityGateFailed, runStatus)
	}
	if qualityScore < minQualityScore {
		return fmt.Errorf("%w: quality score %.3f is below minimum %.3f", ErrDetectionQualityGateFailed, qualityScore, minQualityScore)
	}
	return nil
}

func nextDetectionRulepackID() string {
	value := atomic.AddUint64(&detectionRulepackSequence, 1)
	return fmt.Sprintf("rulepack-%d-%06d", time.Now().UTC().Unix(), value)
}

func nextDetectionRulepackVersionID() string {
	value := atomic.AddUint64(&detectionRulepackVersionSequence, 1)
	return fmt.Sprintf("rulepack-version-%d-%06d", time.Now().UTC().Unix(), value)
}

func nextDetectionRulepackRolloutID() string {
	value := atomic.AddUint64(&detectionRulepackRolloutSequence, 1)
	return fmt.Sprintf("rulepack-rollout-%d-%06d", time.Now().UTC().Unix(), value)
}

func nextDetectionQualityRunID() string {
	value := atomic.AddUint64(&detectionQualityRunSequence, 1)
	return fmt.Sprintf("rulepack-quality-%d-%06d", time.Now().UTC().Unix(), value)
}
