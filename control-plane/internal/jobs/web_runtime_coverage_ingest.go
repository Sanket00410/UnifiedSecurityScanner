package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func ingestWebRuntimeCoverageRunTx(
	ctx context.Context,
	tx pgx.Tx,
	task models.TaskContext,
	taskLabels map[string]string,
	submission models.TaskResultSubmission,
	now time.Time,
) (bool, error) {
	adapterID := normalizeRuntimeCoverageAdapterID(task.AdapterID)
	if adapterID == "" {
		return false, nil
	}

	webTargetID := strings.TrimSpace(taskLabels["web_target_id"])
	if webTargetID == "" {
		return false, nil
	}

	coverage, evidenceRef, found, err := extractRuntimeCoverageFromEvidence(adapterID, submission.EvidencePaths)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}

	createdBy := strings.TrimSpace(submission.WorkerID)
	if createdBy == "" {
		createdBy = "system"
	}

	item := models.WebRuntimeCoverageRun{
		ID:                          nextWebRuntimeCoverageRunID(),
		TenantID:                    strings.TrimSpace(task.TenantID),
		WebTargetID:                 webTargetID,
		ScanJobID:                   strings.TrimSpace(task.ScanJobID),
		RouteCoverage:               clampCoverage(coverage.RouteCoverage),
		APICoverage:                 clampCoverage(coverage.APICoverage),
		AuthCoverage:                clampCoverage(coverage.AuthCoverage),
		DiscoveredRouteCount:        coverage.DiscoveredRouteCount,
		DiscoveredAPIOperationCount: coverage.DiscoveredAPIOperationCount,
		DiscoveredAuthStateCount:    coverage.DiscoveredAuthStateCount,
		EvidenceRef:                 strings.TrimSpace(evidenceRef),
		CreatedBy:                   createdBy,
		CreatedAt:                   now,
	}
	if item.DiscoveredRouteCount < 0 || item.DiscoveredAPIOperationCount < 0 || item.DiscoveredAuthStateCount < 0 {
		return false, fmt.Errorf("ingest web runtime coverage run: discovered counts must be greater than or equal to zero")
	}

	if _, err := createWebRuntimeCoverageRunTx(ctx, tx, item); err != nil {
		return false, err
	}

	if err := publishPlatformEventTx(ctx, tx, models.PlatformEvent{
		TenantID:      item.TenantID,
		EventType:     "web_runtime_coverage_run.ingested",
		SourceService: "control-plane",
		AggregateType: "web_target",
		AggregateID:   item.WebTargetID,
		Payload: map[string]any{
			"scan_job_id":        item.ScanJobID,
			"route_coverage":     item.RouteCoverage,
			"api_coverage":       item.APICoverage,
			"auth_coverage":      item.AuthCoverage,
			"discovered_routes":  item.DiscoveredRouteCount,
			"discovered_api_ops": item.DiscoveredAPIOperationCount,
			"discovered_auth":    item.DiscoveredAuthStateCount,
			"evidence_ref":       item.EvidenceRef,
			"ingested_by_worker": createdBy,
			"coverage_run_id":    item.ID,
			"source_adapter_id":  adapterID,
			"source_task_id":     strings.TrimSpace(task.TaskID),
		},
		CreatedAt: now,
	}); err != nil {
		return false, err
	}

	return true, nil
}

func createWebRuntimeCoverageRunTx(
	ctx context.Context,
	queryer interface {
		QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	},
	item models.WebRuntimeCoverageRun,
) (models.WebRuntimeCoverageRun, error) {
	row := queryer.QueryRow(ctx, `
		INSERT INTO web_runtime_coverage_runs (
			id, tenant_id, web_target_id, scan_job_id, route_coverage, api_coverage, auth_coverage,
			discovered_route_count, discovered_api_operation_count, discovered_auth_state_count,
			evidence_ref, created_by, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10,
			$11, $12, $13
		)
		RETURNING id, tenant_id, web_target_id, scan_job_id, route_coverage, api_coverage, auth_coverage,
		          discovered_route_count, discovered_api_operation_count, discovered_auth_state_count,
		          evidence_ref, created_by, created_at
	`, item.ID, item.TenantID, item.WebTargetID, item.ScanJobID, item.RouteCoverage, item.APICoverage, item.AuthCoverage,
		item.DiscoveredRouteCount, item.DiscoveredAPIOperationCount, item.DiscoveredAuthStateCount,
		item.EvidenceRef, item.CreatedBy, item.CreatedAt)

	created, err := scanWebRuntimeCoverageRun(row)
	if err != nil {
		return models.WebRuntimeCoverageRun{}, fmt.Errorf("create web runtime coverage run: %w", err)
	}
	return created, nil
}

func normalizeRuntimeCoverageAdapterID(adapterID string) string {
	switch strings.ToLower(strings.TrimSpace(adapterID)) {
	case "browser-probe":
		return "browser-probe"
	case "zap-api":
		return "zap-api"
	default:
		return ""
	}
}

func extractRuntimeCoverageFromEvidence(adapterID string, evidencePaths []string) (models.CreateWebRuntimeCoverageRunRequest, string, bool, error) {
	for _, path := range evidencePaths {
		normalizedPath := strings.TrimSpace(path)
		if normalizedPath == "" {
			continue
		}

		payloadBytes, err := os.ReadFile(normalizedPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return models.CreateWebRuntimeCoverageRunRequest{}, "", false, fmt.Errorf("read runtime coverage evidence %s: %w", normalizedPath, err)
		}

		coverage, found, err := parseBrowserProbeCoveragePayload(payloadBytes)
		if err != nil {
			return models.CreateWebRuntimeCoverageRunRequest{}, "", false, fmt.Errorf("parse %s coverage evidence %s: %w", adapterID, normalizedPath, err)
		}
		if found {
			coverage.EvidenceRef = normalizedPath
			return coverage, normalizedPath, true, nil
		}
	}

	return models.CreateWebRuntimeCoverageRunRequest{}, "", false, nil
}

type browserProbeCoveragePayload struct {
	RouteCoverage                    *float64 `json:"route_coverage"`
	RouteCoverageCamel               *float64 `json:"routeCoverage"`
	APICoverage                      *float64 `json:"api_coverage"`
	APICoverageCamel                 *float64 `json:"apiCoverage"`
	AuthCoverage                     *float64 `json:"auth_coverage"`
	AuthCoverageCamel                *float64 `json:"authCoverage"`
	DiscoveredRouteCount             *int64   `json:"discovered_route_count"`
	DiscoveredRouteCountCamel        *int64   `json:"discoveredRouteCount"`
	DiscoveredAPIOperationCount      *int64   `json:"discovered_api_operation_count"`
	DiscoveredAPIOperationCountCamel *int64   `json:"discoveredApiOperationCount"`
	DiscoveredAuthStateCount         *int64   `json:"discovered_auth_state_count"`
	DiscoveredAuthStateCountCamel    *int64   `json:"discoveredAuthStateCount"`
}

func (p browserProbeCoveragePayload) present() bool {
	return p.RouteCoverage != nil ||
		p.RouteCoverageCamel != nil ||
		p.APICoverage != nil ||
		p.APICoverageCamel != nil ||
		p.AuthCoverage != nil ||
		p.AuthCoverageCamel != nil ||
		p.DiscoveredRouteCount != nil ||
		p.DiscoveredRouteCountCamel != nil ||
		p.DiscoveredAPIOperationCount != nil ||
		p.DiscoveredAPIOperationCountCamel != nil ||
		p.DiscoveredAuthStateCount != nil ||
		p.DiscoveredAuthStateCountCamel != nil
}

func (p browserProbeCoveragePayload) toRequest() models.CreateWebRuntimeCoverageRunRequest {
	return models.CreateWebRuntimeCoverageRunRequest{
		RouteCoverage:               firstFloat(p.RouteCoverage, p.RouteCoverageCamel),
		APICoverage:                 firstFloat(p.APICoverage, p.APICoverageCamel),
		AuthCoverage:                firstFloat(p.AuthCoverage, p.AuthCoverageCamel),
		DiscoveredRouteCount:        firstInt64(p.DiscoveredRouteCount, p.DiscoveredRouteCountCamel),
		DiscoveredAPIOperationCount: firstInt64(p.DiscoveredAPIOperationCount, p.DiscoveredAPIOperationCountCamel),
		DiscoveredAuthStateCount:    firstInt64(p.DiscoveredAuthStateCount, p.DiscoveredAuthStateCountCamel),
	}
}

func parseBrowserProbeCoveragePayload(payload []byte) (models.CreateWebRuntimeCoverageRunRequest, bool, error) {
	trimmed := strings.TrimSpace(string(payload))
	if trimmed == "" {
		return models.CreateWebRuntimeCoverageRunRequest{}, false, nil
	}

	var envelope struct {
		Coverage        *browserProbeCoveragePayload `json:"coverage"`
		CoverageSummary *browserProbeCoveragePayload `json:"coverage_summary"`
		Metrics         *browserProbeCoveragePayload `json:"metrics"`
		Summary         struct {
			Coverage *browserProbeCoveragePayload `json:"coverage"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return models.CreateWebRuntimeCoverageRunRequest{}, false, nil
	}

	for _, candidate := range []*browserProbeCoveragePayload{
		envelope.Coverage,
		envelope.CoverageSummary,
		envelope.Metrics,
		envelope.Summary.Coverage,
	} {
		if candidate != nil && candidate.present() {
			return candidate.toRequest(), true, nil
		}
	}

	var topLevel browserProbeCoveragePayload
	if err := json.Unmarshal(payload, &topLevel); err != nil {
		return models.CreateWebRuntimeCoverageRunRequest{}, false, nil
	}
	if topLevel.present() {
		return topLevel.toRequest(), true, nil
	}

	return models.CreateWebRuntimeCoverageRunRequest{}, false, nil
}

func firstFloat(values ...*float64) float64 {
	for _, value := range values {
		if value != nil {
			return *value
		}
	}
	return 0
}

func firstInt64(values ...*int64) int64 {
	for _, value := range values {
		if value != nil {
			return *value
		}
	}
	return 0
}
