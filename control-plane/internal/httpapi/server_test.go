package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

type stubAPIStore struct {
	authPrincipal            models.AuthPrincipal
	authenticated            bool
	authErr                  error
	createScanJobErr         error
	createKMSKeyErr          error
	kmsEncryptErr            error
	kmsDecryptErr            error
	kmsSignErr               error
	kmsVerifyErr             error
	createSecretReferenceErr error
	issueSecretLeaseErr      error
	issueWorkerCertErr       error
	caBundleErr              error
	scanPresets              []models.ScanPreset
	scanTargets              []models.ScanTarget
	kmsKeys                  []models.KMSKey
	ingestionSources         []models.IngestionSource
	ingestionEvents          []models.IngestionEvent
	ingestionWebhookResponse models.IngestionWebhookResponse
	ingestionWebhookErr      error
	platformEvents           []models.PlatformEvent
	tenantOpsSnapshot        models.TenantOperationsSnapshot
	tenantExecutionControls  models.TenantExecutionControls
	tenantExecutionErr       error
	operationalMetrics       models.OperationalMetrics
	findingSearchResult      models.FindingSearchResult
	findingSearchErr         error
	evidenceListResult       models.EvidenceListResult
	evidenceListErr          error
	evidenceObject           models.EvidenceObject
	evidenceObjectFound      bool
	evidenceIntegrity        models.EvidenceIntegrityVerification
	evidenceIntegrityFound   bool
	evidenceRetentionRuns    []models.EvidenceRetentionRun
	evidenceRetentionRun     models.EvidenceRetentionRun
	evidenceRetentionErr     error
	backupSnapshots          []models.BackupSnapshot
	recoveryDrills           []models.RecoveryDrill
	backupDRErr              error
	secretReferences         []models.SecretReference
	secretLeases             []models.SecretLease
	kmsEncryptResponse       models.KMSEncryptResponse
	kmsDecryptResponse       models.KMSDecryptResponse
	kmsSignResponse          models.KMSSignResponse
	kmsVerifyResponse        models.KMSVerifyResponse
	issuedSecretLease        models.IssuedSecretLease
	workloadCertificates     []models.WorkloadCertificate
	issuedWorkerCertificate  models.IssuedWorkerCertificate
	caBundle                 models.CertificateAuthorityBundle
	tenantConfigEntries      []models.TenantConfigEntry
	tenantConfigErr          error
	findings                 []models.CanonicalFinding
	auditEvents              []models.AuditEvent
	apiTokens                []models.APIToken
	assetProfile             models.AssetProfile
	assetSummaries           []models.AssetSummary
	apiAssets                []models.APIAsset
	apiEndpointsByAsset      map[string][]models.APIEndpoint
	importOpenAPIErr         error
	assetControls            []models.CompensatingControl
	syncedAssets             models.SyncAssetProfilesResult
	findingWaivers           []models.FindingWaiver
	riskSummary              models.RiskSummary
	remediation              models.RemediationAction
	remediationActivities    []models.RemediationActivity
	remediationEvidence      []models.RemediationEvidence
	remediationAssignments   []models.RemediationAssignmentRequest
	remediationVerifications []models.RemediationVerification
	remediationExceptions    []models.RemediationException
	remediationTickets       []models.RemediationTicketLink
	notifications            []models.NotificationEvent
	notificationSweep        models.NotificationSweepResult
	policy                   models.Policy
	policies                 []models.Policy
	policyVersions           []models.PolicyVersion
	policyApprovals          []models.PolicyApproval
	scanJob                  models.ScanJob
	createdOIDC              models.CreatedAPIToken
	oidcProvider             string
	oidcSubject              string
	oidcEmail                string
	oidcDisplayName          string
	registerResponse         models.WorkerRegistrationResponse
}

func (s *stubAPIStore) Ping(context.Context) error {
	return nil
}

func (s *stubAPIStore) AuthenticateToken(context.Context, string) (models.AuthPrincipal, bool, error) {
	return s.authPrincipal, s.authenticated, s.authErr
}

func (s *stubAPIStore) CreateOIDCSession(_ context.Context, provider string, subject string, email string, displayName string) (models.CreatedAPIToken, error) {
	s.oidcProvider = provider
	s.oidcSubject = subject
	s.oidcEmail = email
	s.oidcDisplayName = displayName
	return s.createdOIDC, nil
}

func (s *stubAPIStore) RecordAuditEvent(_ context.Context, event models.AuditEvent) error {
	s.auditEvents = append(s.auditEvents, event)
	return nil
}

func (s *stubAPIStore) ListAuditEvents(context.Context, string, int) ([]models.AuditEvent, error) {
	return s.auditEvents, nil
}

func (s *stubAPIStore) ListAPITokens(context.Context, string, int) ([]models.APIToken, error) {
	return s.apiTokens, nil
}

func (s *stubAPIStore) CreateAPIToken(context.Context, models.AuthPrincipal, models.CreateAPITokenRequest) (models.CreatedAPIToken, error) {
	return models.CreatedAPIToken{}, nil
}

func (s *stubAPIStore) DisableAPIToken(context.Context, string, string) (models.APIToken, bool, error) {
	return models.APIToken{}, false, nil
}

func (s *stubAPIStore) ListForTenant(context.Context, string, int) ([]models.ScanJob, error) {
	return nil, nil
}

func (s *stubAPIStore) CreateForTenant(context.Context, string, models.CreateScanJobRequest) (models.ScanJob, error) {
	if s.createScanJobErr != nil {
		return models.ScanJob{}, s.createScanJobErr
	}
	return s.scanJob, nil
}

func (s *stubAPIStore) GetForTenant(context.Context, string, string) (models.ScanJob, bool, error) {
	return models.ScanJob{}, false, nil
}

func (s *stubAPIStore) ListScanPresetsForTenant(context.Context, string) ([]models.ScanPreset, error) {
	return s.scanPresets, nil
}

func (s *stubAPIStore) ListScanTargetsForTenant(context.Context, string, int) ([]models.ScanTarget, error) {
	return s.scanTargets, nil
}

func (s *stubAPIStore) GetScanTargetForTenant(_ context.Context, _ string, targetID string) (models.ScanTarget, bool, error) {
	for _, item := range s.scanTargets {
		if item.ID == targetID {
			return item, true, nil
		}
	}
	return models.ScanTarget{}, false, nil
}

func (s *stubAPIStore) CreateScanTargetForTenant(_ context.Context, tenantID string, actor string, request models.CreateScanTargetRequest) (models.ScanTarget, error) {
	item := models.ScanTarget{
		ID:         "scan-target-created",
		TenantID:   tenantID,
		Name:       request.Name,
		TargetKind: request.TargetKind,
		Target:     request.Target,
		Profile:    request.Profile,
		Tools:      request.Tools,
		Labels:     request.Labels,
		CreatedBy:  actor,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	if strings.TrimSpace(item.Name) == "" {
		item.Name = "Unnamed Scan Target"
	}
	if strings.TrimSpace(item.Profile) == "" {
		item.Profile = "balanced"
	}
	s.scanTargets = append(s.scanTargets, item)
	return item, nil
}

func (s *stubAPIStore) UpdateScanTargetForTenant(_ context.Context, _ string, targetID string, request models.UpdateScanTargetRequest) (models.ScanTarget, bool, error) {
	for idx := range s.scanTargets {
		if s.scanTargets[idx].ID != targetID {
			continue
		}
		if strings.TrimSpace(request.Name) != "" {
			s.scanTargets[idx].Name = strings.TrimSpace(request.Name)
		}
		if strings.TrimSpace(request.TargetKind) != "" {
			s.scanTargets[idx].TargetKind = strings.TrimSpace(request.TargetKind)
		}
		if strings.TrimSpace(request.Target) != "" {
			s.scanTargets[idx].Target = strings.TrimSpace(request.Target)
		}
		if strings.TrimSpace(request.Profile) != "" {
			s.scanTargets[idx].Profile = strings.TrimSpace(request.Profile)
		}
		if len(request.Tools) > 0 {
			s.scanTargets[idx].Tools = request.Tools
		}
		if request.Labels != nil {
			s.scanTargets[idx].Labels = request.Labels
		}
		s.scanTargets[idx].UpdatedAt = time.Now().UTC()
		return s.scanTargets[idx], true, nil
	}

	return models.ScanTarget{}, false, nil
}

func (s *stubAPIStore) DeleteScanTargetForTenant(_ context.Context, _ string, targetID string) (bool, error) {
	next := make([]models.ScanTarget, 0, len(s.scanTargets))
	deleted := false
	for _, item := range s.scanTargets {
		if item.ID == targetID {
			deleted = true
			continue
		}
		next = append(next, item)
	}
	s.scanTargets = next
	return deleted, nil
}

func (s *stubAPIStore) RunScanTargetForTenant(_ context.Context, _ string, targetID string, _ string, request models.RunScanTargetRequest) (models.ScanTarget, models.ScanJob, bool, error) {
	for idx := range s.scanTargets {
		if s.scanTargets[idx].ID != targetID {
			continue
		}

		now := time.Now().UTC()
		profile := strings.TrimSpace(request.Profile)
		if profile == "" {
			profile = s.scanTargets[idx].Profile
		}
		if profile == "" {
			profile = "balanced"
		}
		tools := request.Tools
		if len(tools) == 0 {
			tools = s.scanTargets[idx].Tools
		}

		s.scanTargets[idx].LastRunAt = &now
		s.scanTargets[idx].UpdatedAt = now

		job := s.scanJob
		if strings.TrimSpace(job.ID) == "" {
			job = models.ScanJob{ID: "job-from-target", Status: models.ScanJobStatusQueued}
		}
		job.TargetKind = s.scanTargets[idx].TargetKind
		job.Target = s.scanTargets[idx].Target
		job.Profile = profile
		job.Tools = tools
		if job.Status == "" {
			job.Status = models.ScanJobStatusQueued
		}
		return s.scanTargets[idx], job, true, nil
	}

	return models.ScanTarget{}, models.ScanJob{}, false, nil
}

func (s *stubAPIStore) ListIngestionSourcesForTenant(context.Context, string, int) ([]models.IngestionSource, error) {
	return s.ingestionSources, nil
}

func (s *stubAPIStore) GetIngestionSourceForTenant(_ context.Context, _ string, sourceID string) (models.IngestionSource, bool, error) {
	for _, item := range s.ingestionSources {
		if item.ID == sourceID {
			return item, true, nil
		}
	}
	return models.IngestionSource{}, false, nil
}

func (s *stubAPIStore) CreateIngestionSourceForTenant(_ context.Context, tenantID string, actor string, request models.CreateIngestionSourceRequest) (models.CreatedIngestionSource, error) {
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}

	item := models.IngestionSource{
		ID:          "ingestion-source-created",
		TenantID:    tenantID,
		Name:        strings.TrimSpace(request.Name),
		Provider:    strings.TrimSpace(request.Provider),
		Enabled:     enabled,
		TargetKind:  strings.TrimSpace(request.TargetKind),
		Target:      strings.TrimSpace(request.Target),
		Profile:     strings.TrimSpace(request.Profile),
		Tools:       request.Tools,
		Labels:      request.Labels,
		CreatedBy:   actor,
		UpdatedBy:   actor,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		LastEventAt: nil,
	}
	if item.Name == "" {
		item.Name = "Unnamed Ingestion Source"
	}
	if item.Provider == "" {
		item.Provider = "generic"
	}
	if item.Profile == "" {
		item.Profile = "balanced"
	}
	if item.Labels == nil {
		item.Labels = map[string]any{}
	}
	s.ingestionSources = append(s.ingestionSources, item)

	return models.CreatedIngestionSource{
		Source:      item,
		IngestToken: "stub-ingest-token",
	}, nil
}

func (s *stubAPIStore) UpdateIngestionSourceForTenant(_ context.Context, _ string, sourceID string, actor string, request models.UpdateIngestionSourceRequest) (models.IngestionSource, bool, error) {
	for idx := range s.ingestionSources {
		if s.ingestionSources[idx].ID != sourceID {
			continue
		}

		if value := strings.TrimSpace(request.Name); value != "" {
			s.ingestionSources[idx].Name = value
		}
		if value := strings.TrimSpace(request.Provider); value != "" {
			s.ingestionSources[idx].Provider = value
		}
		if request.Enabled != nil {
			s.ingestionSources[idx].Enabled = *request.Enabled
		}
		if value := strings.TrimSpace(request.TargetKind); value != "" {
			s.ingestionSources[idx].TargetKind = value
		}
		if value := strings.TrimSpace(request.Target); value != "" {
			s.ingestionSources[idx].Target = value
		}
		if value := strings.TrimSpace(request.Profile); value != "" {
			s.ingestionSources[idx].Profile = value
		}
		if len(request.Tools) > 0 {
			s.ingestionSources[idx].Tools = request.Tools
		}
		if request.Labels != nil {
			s.ingestionSources[idx].Labels = request.Labels
		}
		s.ingestionSources[idx].UpdatedBy = actor
		s.ingestionSources[idx].UpdatedAt = time.Now().UTC()
		return s.ingestionSources[idx], true, nil
	}

	return models.IngestionSource{}, false, nil
}

func (s *stubAPIStore) DeleteIngestionSourceForTenant(_ context.Context, _ string, sourceID string) (bool, error) {
	next := make([]models.IngestionSource, 0, len(s.ingestionSources))
	deleted := false
	for _, item := range s.ingestionSources {
		if item.ID == sourceID {
			deleted = true
			continue
		}
		next = append(next, item)
	}
	s.ingestionSources = next
	return deleted, nil
}

func (s *stubAPIStore) RotateIngestionSourceTokenForTenant(_ context.Context, _ string, sourceID string, _ string) (models.RotateIngestionSourceTokenResponse, bool, error) {
	for _, item := range s.ingestionSources {
		if item.ID == sourceID {
			return models.RotateIngestionSourceTokenResponse{
				Source:      item,
				IngestToken: "rotated-stub-ingest-token",
			}, true, nil
		}
	}
	return models.RotateIngestionSourceTokenResponse{}, false, nil
}

func (s *stubAPIStore) ListIngestionEventsForTenant(context.Context, string, string, int) ([]models.IngestionEvent, error) {
	return s.ingestionEvents, nil
}

func (s *stubAPIStore) HandleIngestionWebhook(_ context.Context, _ string, _ string, _ models.IngestionWebhookRequest) (models.IngestionWebhookResponse, error) {
	if s.ingestionWebhookErr != nil {
		return models.IngestionWebhookResponse{}, s.ingestionWebhookErr
	}
	if s.ingestionWebhookResponse.Event.ID != "" {
		return s.ingestionWebhookResponse, nil
	}
	return models.IngestionWebhookResponse{
		Event: models.IngestionEvent{
			ID:       "ingestion-event-1",
			Status:   "queued",
			SourceID: "ingestion-source-created",
		},
		Job: &models.ScanJob{
			ID:     "job-ingestion-1",
			Status: models.ScanJobStatusQueued,
		},
	}, nil
}

func (s *stubAPIStore) ListPlatformEventsForTenant(context.Context, string, string, int) ([]models.PlatformEvent, error) {
	return s.platformEvents, nil
}

func (s *stubAPIStore) GetTenantOperationsSnapshot(_ context.Context, tenantID string) (models.TenantOperationsSnapshot, error) {
	if strings.TrimSpace(s.tenantOpsSnapshot.TenantID) == "" {
		s.tenantOpsSnapshot.TenantID = strings.TrimSpace(tenantID)
	}
	return s.tenantOpsSnapshot, nil
}

func (s *stubAPIStore) UpdateTenantLimitsForTenant(_ context.Context, tenantID string, actor string, request models.UpdateTenantLimitsRequest) (models.TenantOperationsSnapshot, error) {
	snapshot := s.tenantOpsSnapshot
	snapshot.TenantID = strings.TrimSpace(tenantID)
	snapshot.Limits.TenantID = strings.TrimSpace(tenantID)
	snapshot.Limits.UpdatedBy = strings.TrimSpace(actor)
	snapshot.Limits.UpdatedAt = time.Now().UTC()

	if request.MaxTotalScanJobs != nil {
		snapshot.Limits.MaxTotalScanJobs = *request.MaxTotalScanJobs
	}
	if request.MaxActiveScanJobs != nil {
		snapshot.Limits.MaxActiveScanJobs = *request.MaxActiveScanJobs
	}
	if request.MaxScanTargets != nil {
		snapshot.Limits.MaxScanTargets = *request.MaxScanTargets
	}
	if request.MaxIngestionSources != nil {
		snapshot.Limits.MaxIngestionSources = *request.MaxIngestionSources
	}
	s.tenantOpsSnapshot = snapshot
	return snapshot, nil
}

func (s *stubAPIStore) GetTenantExecutionControlsForTenant(_ context.Context, tenantID string) (models.TenantExecutionControls, error) {
	if s.tenantExecutionErr != nil {
		return models.TenantExecutionControls{}, s.tenantExecutionErr
	}
	if strings.TrimSpace(s.tenantExecutionControls.TenantID) == "" {
		return models.TenantExecutionControls{
			TenantID:           strings.TrimSpace(tenantID),
			MaintenanceWindows: []models.MaintenanceWindow{},
		}, nil
	}
	return s.tenantExecutionControls, nil
}

func (s *stubAPIStore) UpdateTenantExecutionControlsForTenant(_ context.Context, tenantID string, actor string, request models.UpdateTenantExecutionControlsRequest) (models.TenantExecutionControls, error) {
	if s.tenantExecutionErr != nil {
		return models.TenantExecutionControls{}, s.tenantExecutionErr
	}

	current := s.tenantExecutionControls
	if strings.TrimSpace(current.TenantID) == "" {
		current.TenantID = strings.TrimSpace(tenantID)
	}

	if request.EmergencyStopEnabled != nil {
		current.EmergencyStopEnabled = *request.EmergencyStopEnabled
	}
	if request.EmergencyStopReason != nil {
		current.EmergencyStopReason = strings.TrimSpace(*request.EmergencyStopReason)
	}
	if request.MaintenanceWindows != nil {
		current.MaintenanceWindows = *request.MaintenanceWindows
	}
	current.UpdatedBy = strings.TrimSpace(actor)
	current.UpdatedAt = time.Now().UTC()
	s.tenantExecutionControls = current
	return current, nil
}

func (s *stubAPIStore) GetOperationalMetrics(context.Context) (models.OperationalMetrics, error) {
	return s.operationalMetrics, nil
}

func (s *stubAPIStore) ListTenantConfigForTenant(_ context.Context, _ string, prefix string, _ int) ([]models.TenantConfigEntry, error) {
	if s.tenantConfigErr != nil {
		return nil, s.tenantConfigErr
	}
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if prefix == "" {
		return s.tenantConfigEntries, nil
	}
	out := make([]models.TenantConfigEntry, 0, len(s.tenantConfigEntries))
	for _, entry := range s.tenantConfigEntries {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(entry.Key)), prefix) {
			out = append(out, entry)
		}
	}
	return out, nil
}

func (s *stubAPIStore) GetTenantConfigEntryForTenant(_ context.Context, _ string, key string) (models.TenantConfigEntry, bool, error) {
	if s.tenantConfigErr != nil {
		return models.TenantConfigEntry{}, false, s.tenantConfigErr
	}
	key = strings.ToLower(strings.TrimSpace(key))
	for _, entry := range s.tenantConfigEntries {
		if strings.ToLower(strings.TrimSpace(entry.Key)) == key {
			return entry, true, nil
		}
	}
	return models.TenantConfigEntry{}, false, nil
}

func (s *stubAPIStore) UpsertTenantConfigEntryForTenant(_ context.Context, tenantID string, key string, actor string, request models.UpsertTenantConfigRequest) (models.TenantConfigEntry, error) {
	if s.tenantConfigErr != nil {
		return models.TenantConfigEntry{}, s.tenantConfigErr
	}
	item := models.TenantConfigEntry{
		TenantID:  strings.TrimSpace(tenantID),
		Key:       strings.ToLower(strings.TrimSpace(key)),
		Value:     request.Value,
		UpdatedBy: strings.TrimSpace(actor),
		UpdatedAt: time.Now().UTC(),
	}
	if item.Value == nil {
		item.Value = map[string]any{}
	}
	for idx := range s.tenantConfigEntries {
		if strings.EqualFold(s.tenantConfigEntries[idx].Key, item.Key) {
			s.tenantConfigEntries[idx] = item
			return item, nil
		}
	}
	s.tenantConfigEntries = append(s.tenantConfigEntries, item)
	return item, nil
}

func (s *stubAPIStore) DeleteTenantConfigEntryForTenant(_ context.Context, _ string, key string, _ string) (bool, error) {
	if s.tenantConfigErr != nil {
		return false, s.tenantConfigErr
	}
	key = strings.ToLower(strings.TrimSpace(key))
	filtered := make([]models.TenantConfigEntry, 0, len(s.tenantConfigEntries))
	deleted := false
	for _, entry := range s.tenantConfigEntries {
		if strings.EqualFold(strings.TrimSpace(entry.Key), key) {
			deleted = true
			continue
		}
		filtered = append(filtered, entry)
	}
	s.tenantConfigEntries = filtered
	return deleted, nil
}

func (s *stubAPIStore) RegisterWorker(context.Context, models.WorkerRegistrationRequest) (models.WorkerRegistrationResponse, error) {
	return s.registerResponse, nil
}

func (s *stubAPIStore) RecordHeartbeat(context.Context, models.HeartbeatRequest) (models.HeartbeatResponse, error) {
	return models.HeartbeatResponse{}, nil
}

func (s *stubAPIStore) ListFindingsForTenant(context.Context, string, int) ([]models.CanonicalFinding, error) {
	return s.findings, nil
}

func (s *stubAPIStore) SearchFindingsForTenant(_ context.Context, _ string, _ models.FindingSearchQuery) (models.FindingSearchResult, error) {
	if s.findingSearchErr != nil {
		return models.FindingSearchResult{}, s.findingSearchErr
	}
	if len(s.findingSearchResult.Items) == 0 {
		return models.FindingSearchResult{
			Items:  s.findings,
			Total:  int64(len(s.findings)),
			Limit:  100,
			Offset: 0,
		}, nil
	}
	return s.findingSearchResult, nil
}

func (s *stubAPIStore) ListEvidenceObjectsForTenant(_ context.Context, _ string, _ models.EvidenceListQuery) (models.EvidenceListResult, error) {
	if s.evidenceListErr != nil {
		return models.EvidenceListResult{}, s.evidenceListErr
	}
	if len(s.evidenceListResult.Items) == 0 {
		return models.EvidenceListResult{
			Items:  nil,
			Total:  0,
			Limit:  100,
			Offset: 0,
		}, nil
	}
	return s.evidenceListResult, nil
}

func (s *stubAPIStore) GetEvidenceObjectForTenant(_ context.Context, _ string, _ string) (models.EvidenceObject, bool, error) {
	if !s.evidenceObjectFound {
		return models.EvidenceObject{}, false, nil
	}
	return s.evidenceObject, true, nil
}

func (s *stubAPIStore) VerifyEvidenceObjectIntegrityForTenant(_ context.Context, _ string, _ string) (models.EvidenceIntegrityVerification, bool, error) {
	if !s.evidenceIntegrityFound {
		return models.EvidenceIntegrityVerification{}, false, nil
	}
	return s.evidenceIntegrity, true, nil
}

func (s *stubAPIStore) ListEvidenceRetentionRunsForTenant(_ context.Context, _ string, _ int) ([]models.EvidenceRetentionRun, error) {
	if s.evidenceRetentionErr != nil {
		return nil, s.evidenceRetentionErr
	}
	return s.evidenceRetentionRuns, nil
}

func (s *stubAPIStore) RunEvidenceRetentionForTenant(_ context.Context, _ string, _ string, _ models.RunEvidenceRetentionRequest) (models.EvidenceRetentionRun, error) {
	if s.evidenceRetentionErr != nil {
		return models.EvidenceRetentionRun{}, s.evidenceRetentionErr
	}
	return s.evidenceRetentionRun, nil
}

func (s *stubAPIStore) ListBackupSnapshotsForTenant(_ context.Context, _ string, _ int) ([]models.BackupSnapshot, error) {
	if s.backupDRErr != nil {
		return nil, s.backupDRErr
	}
	return s.backupSnapshots, nil
}

func (s *stubAPIStore) CreateBackupSnapshotForTenant(_ context.Context, tenantID string, actor string, request models.CreateBackupSnapshotRequest) (models.BackupSnapshot, error) {
	if s.backupDRErr != nil {
		return models.BackupSnapshot{}, s.backupDRErr
	}
	item := models.BackupSnapshot{
		ID:             "backup-snapshot-created",
		TenantID:       strings.TrimSpace(tenantID),
		Scope:          strings.TrimSpace(request.Scope),
		StorageRef:     strings.TrimSpace(request.StorageRef),
		ChecksumSHA256: strings.TrimSpace(request.ChecksumSHA256),
		SizeBytes:      request.SizeBytes,
		Status:         "completed",
		CreatedBy:      strings.TrimSpace(actor),
		Notes:          strings.TrimSpace(request.Notes),
		CreatedAt:      time.Now().UTC(),
	}
	s.backupSnapshots = append(s.backupSnapshots, item)
	return item, nil
}

func (s *stubAPIStore) ListRecoveryDrillsForTenant(_ context.Context, _ string, _ int) ([]models.RecoveryDrill, error) {
	if s.backupDRErr != nil {
		return nil, s.backupDRErr
	}
	return s.recoveryDrills, nil
}

func (s *stubAPIStore) CreateRecoveryDrillForTenant(_ context.Context, tenantID string, actor string, request models.CreateRecoveryDrillRequest) (models.RecoveryDrill, error) {
	if s.backupDRErr != nil {
		return models.RecoveryDrill{}, s.backupDRErr
	}
	item := models.RecoveryDrill{
		ID:         "recovery-drill-created",
		TenantID:   strings.TrimSpace(tenantID),
		SnapshotID: strings.TrimSpace(request.SnapshotID),
		Status:     "completed",
		StartedBy:  strings.TrimSpace(actor),
		Notes:      strings.TrimSpace(request.Notes),
		RTOSeconds: request.RTOSeconds,
		StartedAt:  time.Now().UTC(),
	}
	s.recoveryDrills = append(s.recoveryDrills, item)
	return item, nil
}

func (s *stubAPIStore) ListKMSKeysForTenant(context.Context, string, int) ([]models.KMSKey, error) {
	return s.kmsKeys, nil
}

func (s *stubAPIStore) CreateKMSKeyForTenant(_ context.Context, tenantID string, actor string, request models.CreateKMSKeyRequest) (models.KMSKey, error) {
	if s.createKMSKeyErr != nil {
		return models.KMSKey{}, s.createKMSKeyErr
	}
	now := time.Now().UTC()
	item := models.KMSKey{
		ID:        "kms-key-created",
		TenantID:  strings.TrimSpace(tenantID),
		KeyRef:    strings.TrimSpace(request.KeyRef),
		Provider:  strings.TrimSpace(request.Provider),
		Algorithm: strings.TrimSpace(request.Algorithm),
		Purpose:   strings.TrimSpace(request.Purpose),
		Status:    "active",
		CreatedBy: strings.TrimSpace(actor),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if item.Provider == "" {
		item.Provider = "local"
	}
	if item.Algorithm == "" {
		item.Algorithm = "aes-256-gcm"
	}
	if item.Purpose == "" {
		item.Purpose = "encrypt_decrypt"
	}
	s.kmsKeys = append(s.kmsKeys, item)
	return item, nil
}

func (s *stubAPIStore) EncryptWithKMSForTenant(context.Context, string, models.KMSEncryptRequest) (models.KMSEncryptResponse, error) {
	if s.kmsEncryptErr != nil {
		return models.KMSEncryptResponse{}, s.kmsEncryptErr
	}
	if strings.TrimSpace(s.kmsEncryptResponse.KeyRef) != "" {
		return s.kmsEncryptResponse, nil
	}
	return models.KMSEncryptResponse{
		KeyRef:        "stub-key",
		Algorithm:     "aes-256-gcm",
		NonceB64:      "bm9uY2U=",
		CiphertextB64: "Y2lwaGVydGV4dA==",
	}, nil
}

func (s *stubAPIStore) DecryptWithKMSForTenant(context.Context, string, models.KMSDecryptRequest) (models.KMSDecryptResponse, error) {
	if s.kmsDecryptErr != nil {
		return models.KMSDecryptResponse{}, s.kmsDecryptErr
	}
	if strings.TrimSpace(s.kmsDecryptResponse.KeyRef) != "" || strings.TrimSpace(s.kmsDecryptResponse.PlaintextB64) != "" {
		return s.kmsDecryptResponse, nil
	}
	return models.KMSDecryptResponse{
		KeyRef:       "stub-key",
		PlaintextB64: "cGxhaW50ZXh0",
	}, nil
}

func (s *stubAPIStore) SignWithKMSForTenant(context.Context, string, models.KMSSignRequest) (models.KMSSignResponse, error) {
	if s.kmsSignErr != nil {
		return models.KMSSignResponse{}, s.kmsSignErr
	}
	if strings.TrimSpace(s.kmsSignResponse.KeyRef) != "" || strings.TrimSpace(s.kmsSignResponse.SignatureB64) != "" {
		return s.kmsSignResponse, nil
	}
	return models.KMSSignResponse{
		KeyRef:       "stub-key",
		Algorithm:    "hmac-sha256",
		SignatureB64: "c2ln",
	}, nil
}

func (s *stubAPIStore) VerifyWithKMSForTenant(context.Context, string, models.KMSVerifyRequest) (models.KMSVerifyResponse, error) {
	if s.kmsVerifyErr != nil {
		return models.KMSVerifyResponse{}, s.kmsVerifyErr
	}
	if strings.TrimSpace(s.kmsVerifyResponse.KeyRef) != "" {
		return s.kmsVerifyResponse, nil
	}
	return models.KMSVerifyResponse{
		KeyRef: "stub-key",
		Valid:  true,
	}, nil
}

func (s *stubAPIStore) ListSecretReferencesForTenant(context.Context, string, int) ([]models.SecretReference, error) {
	return s.secretReferences, nil
}

func (s *stubAPIStore) GetSecretReferenceForTenant(_ context.Context, _ string, referenceID string) (models.SecretReference, bool, error) {
	for _, item := range s.secretReferences {
		if item.ID == referenceID {
			return item, true, nil
		}
	}
	return models.SecretReference{}, false, nil
}

func (s *stubAPIStore) CreateSecretReferenceForTenant(_ context.Context, tenantID string, actor string, request models.CreateSecretReferenceRequest) (models.SecretReference, error) {
	if s.createSecretReferenceErr != nil {
		return models.SecretReference{}, s.createSecretReferenceErr
	}
	now := time.Now().UTC()
	item := models.SecretReference{
		ID:            "secret-ref-created",
		TenantID:      strings.TrimSpace(tenantID),
		Name:          strings.TrimSpace(request.Name),
		Provider:      strings.TrimSpace(request.Provider),
		SecretPath:    strings.TrimSpace(request.SecretPath),
		SecretVersion: strings.TrimSpace(request.SecretVersion),
		Metadata:      request.Metadata,
		CreatedBy:     strings.TrimSpace(actor),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if item.Provider == "" {
		item.Provider = "vault"
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	s.secretReferences = append(s.secretReferences, item)
	return item, nil
}

func (s *stubAPIStore) UpdateSecretReferenceForTenant(_ context.Context, _ string, referenceID string, _ string, request models.UpdateSecretReferenceRequest) (models.SecretReference, bool, error) {
	for idx := range s.secretReferences {
		if s.secretReferences[idx].ID != referenceID {
			continue
		}
		if value := strings.TrimSpace(request.Name); value != "" {
			s.secretReferences[idx].Name = value
		}
		if value := strings.TrimSpace(request.Provider); value != "" {
			s.secretReferences[idx].Provider = value
		}
		if value := strings.TrimSpace(request.SecretPath); value != "" {
			s.secretReferences[idx].SecretPath = value
		}
		if request.SecretVersion != "" {
			s.secretReferences[idx].SecretVersion = strings.TrimSpace(request.SecretVersion)
		}
		if request.Metadata != nil {
			s.secretReferences[idx].Metadata = request.Metadata
		}
		s.secretReferences[idx].UpdatedAt = time.Now().UTC()
		return s.secretReferences[idx], true, nil
	}
	return models.SecretReference{}, false, nil
}

func (s *stubAPIStore) DeleteSecretReferenceForTenant(_ context.Context, _ string, referenceID string) (bool, error) {
	next := make([]models.SecretReference, 0, len(s.secretReferences))
	deleted := false
	for _, item := range s.secretReferences {
		if item.ID == referenceID {
			deleted = true
			continue
		}
		next = append(next, item)
	}
	s.secretReferences = next
	return deleted, nil
}

func (s *stubAPIStore) ListSecretLeasesForTenant(_ context.Context, _ string, referenceID string, _ int) ([]models.SecretLease, error) {
	if strings.TrimSpace(referenceID) == "" {
		return s.secretLeases, nil
	}
	filtered := make([]models.SecretLease, 0, len(s.secretLeases))
	for _, item := range s.secretLeases {
		if item.SecretReferenceID == referenceID {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}

func (s *stubAPIStore) IssueSecretLeaseForTenant(_ context.Context, tenantID string, actor string, request models.IssueSecretLeaseRequest) (models.IssuedSecretLease, error) {
	if s.issueSecretLeaseErr != nil {
		return models.IssuedSecretLease{}, s.issueSecretLeaseErr
	}
	if strings.TrimSpace(s.issuedSecretLease.Lease.ID) != "" {
		return s.issuedSecretLease, nil
	}
	now := time.Now().UTC()
	lease := models.SecretLease{
		ID:                "secret-lease-created",
		TenantID:          strings.TrimSpace(tenantID),
		SecretReferenceID: strings.TrimSpace(request.SecretReferenceID),
		WorkerID:          strings.TrimSpace(request.WorkerID),
		Status:            "active",
		ExpiresAt:         now.Add(10 * time.Minute),
		CreatedBy:         strings.TrimSpace(actor),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	s.secretLeases = append(s.secretLeases, lease)
	return models.IssuedSecretLease{
		Lease:      lease,
		LeaseToken: "stub-lease-token",
	}, nil
}

func (s *stubAPIStore) RevokeSecretLeaseForTenant(_ context.Context, _ string, leaseID string, _ string) (models.SecretLease, bool, error) {
	now := time.Now().UTC()
	for idx := range s.secretLeases {
		if s.secretLeases[idx].ID != leaseID {
			continue
		}
		s.secretLeases[idx].Status = "revoked"
		s.secretLeases[idx].UpdatedAt = now
		s.secretLeases[idx].RevokedAt = &now
		return s.secretLeases[idx], true, nil
	}
	return models.SecretLease{}, false, nil
}

func (s *stubAPIStore) ListWorkloadCertificatesForTenant(_ context.Context, _ string, subjectID string, _ int) ([]models.WorkloadCertificate, error) {
	if strings.TrimSpace(subjectID) == "" {
		return s.workloadCertificates, nil
	}
	filtered := make([]models.WorkloadCertificate, 0, len(s.workloadCertificates))
	for _, item := range s.workloadCertificates {
		if item.SubjectID == subjectID {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}

func (s *stubAPIStore) IssueWorkerCertificateForTenant(_ context.Context, tenantID string, actor string, request models.IssueWorkerCertificateRequest) (models.IssuedWorkerCertificate, error) {
	if s.issueWorkerCertErr != nil {
		return models.IssuedWorkerCertificate{}, s.issueWorkerCertErr
	}
	if strings.TrimSpace(s.issuedWorkerCertificate.Certificate.ID) != "" {
		return s.issuedWorkerCertificate, nil
	}

	now := time.Now().UTC()
	item := models.WorkloadCertificate{
		ID:                "workload-cert-created",
		TenantID:          strings.TrimSpace(tenantID),
		SubjectType:       "worker",
		SubjectID:         strings.TrimSpace(request.WorkerID),
		SerialNumber:      "stub-serial",
		FingerprintSHA256: "stub-fingerprint",
		CertificatePEM:    "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Status:            "active",
		IssuedBy:          strings.TrimSpace(actor),
		IssuedAt:          now,
		ExpiresAt:         now.Add(24 * time.Hour),
		Metadata:          map[string]any{},
	}
	s.workloadCertificates = append(s.workloadCertificates, item)

	return models.IssuedWorkerCertificate{
		Certificate:   item,
		PrivateKeyPEM: "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----",
		CABundlePEM:   "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
	}, nil
}

func (s *stubAPIStore) RevokeWorkloadCertificateForTenant(_ context.Context, _ string, certificateID string, _ string, reason string) (models.WorkloadCertificate, bool, error) {
	now := time.Now().UTC()
	for idx := range s.workloadCertificates {
		if s.workloadCertificates[idx].ID != certificateID {
			continue
		}
		s.workloadCertificates[idx].Status = "revoked"
		s.workloadCertificates[idx].RevokedAt = &now
		s.workloadCertificates[idx].RevokedReason = strings.TrimSpace(reason)
		return s.workloadCertificates[idx], true, nil
	}
	return models.WorkloadCertificate{}, false, nil
}

func (s *stubAPIStore) GetCertificateAuthorityBundle() (models.CertificateAuthorityBundle, error) {
	if s.caBundleErr != nil {
		return models.CertificateAuthorityBundle{}, s.caBundleErr
	}
	if strings.TrimSpace(s.caBundle.CertificatePEM) != "" {
		return s.caBundle, nil
	}
	return models.CertificateAuthorityBundle{
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
	}, nil
}

func (s *stubAPIStore) ListFindingWaiversForTenant(context.Context, string, string, int) ([]models.FindingWaiver, error) {
	return s.findingWaivers, nil
}

func (s *stubAPIStore) CreateFindingWaiverForTenant(context.Context, string, string, models.CreateFindingWaiverRequest) (models.FindingWaiver, error) {
	if len(s.findingWaivers) == 0 {
		return models.FindingWaiver{}, nil
	}
	return s.findingWaivers[0], nil
}

func (s *stubAPIStore) ListRiskSummaryForTenant(context.Context, string) (models.RiskSummary, error) {
	return s.riskSummary, nil
}

func (s *stubAPIStore) ListAssetsForTenant(context.Context, string, int) ([]models.AssetSummary, error) {
	return s.assetSummaries, nil
}

func (s *stubAPIStore) ListAPIAssetsForTenant(context.Context, string, int) ([]models.APIAsset, error) {
	return s.apiAssets, nil
}

func (s *stubAPIStore) ListAPIEndpointsForTenant(_ context.Context, _ string, apiAssetID string, _ int) ([]models.APIEndpoint, error) {
	if len(s.apiEndpointsByAsset) == 0 {
		return nil, nil
	}
	return s.apiEndpointsByAsset[apiAssetID], nil
}

func (s *stubAPIStore) ImportOpenAPIForTenant(_ context.Context, tenantID string, actor string, request models.ImportOpenAPIRequest) (models.ImportedAPIAsset, error) {
	if s.importOpenAPIErr != nil {
		return models.ImportedAPIAsset{}, s.importOpenAPIErr
	}

	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = "Imported API"
	}
	source := strings.TrimSpace(request.Source)
	if source == "" {
		source = "manual"
	}

	asset := models.APIAsset{
		ID:          fmt.Sprintf("api-asset-%d", len(s.apiAssets)+1),
		TenantID:    strings.TrimSpace(tenantID),
		Name:        name,
		BaseURL:     strings.TrimSpace(request.BaseURL),
		Source:      source,
		SpecVersion: "3.0.0",
		CreatedBy:   strings.TrimSpace(actor),
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	s.apiAssets = append(s.apiAssets, asset)
	return models.ImportedAPIAsset{
		Asset:         asset,
		EndpointCount: 0,
	}, nil
}

func (s *stubAPIStore) GetAssetProfileForTenant(context.Context, string, string) (models.AssetProfile, bool, error) {
	if s.assetProfile.AssetID == "" {
		return models.AssetProfile{}, false, nil
	}
	return s.assetProfile, true, nil
}

func (s *stubAPIStore) UpsertAssetProfileForTenant(context.Context, string, string, models.UpsertAssetProfileRequest) (models.AssetProfile, error) {
	return s.assetProfile, nil
}

func (s *stubAPIStore) SyncAssetProfilesForTenant(context.Context, string, models.SyncAssetProfilesRequest) (models.SyncAssetProfilesResult, error) {
	return s.syncedAssets, nil
}

func (s *stubAPIStore) ListCompensatingControlsForTenant(context.Context, string, string, int) ([]models.CompensatingControl, error) {
	return s.assetControls, nil
}

func (s *stubAPIStore) CreateCompensatingControlForTenant(context.Context, string, string, models.CreateCompensatingControlRequest) (models.CompensatingControl, error) {
	if len(s.assetControls) == 0 {
		return models.CompensatingControl{}, nil
	}
	return s.assetControls[0], nil
}

func (s *stubAPIStore) ListPoliciesForTenant(context.Context, string, int) ([]models.Policy, error) {
	return s.policies, nil
}

func (s *stubAPIStore) GetPolicyForTenant(context.Context, string, string) (models.Policy, bool, error) {
	if s.policy.ID == "" {
		return models.Policy{}, false, nil
	}
	return s.policy, true, nil
}

func (s *stubAPIStore) CreatePolicyForTenant(context.Context, string, models.CreatePolicyRequest) (models.Policy, error) {
	return s.policy, nil
}

func (s *stubAPIStore) UpdatePolicyForTenant(context.Context, string, string, models.UpdatePolicyRequest) (models.Policy, bool, error) {
	if s.policy.ID == "" {
		return models.Policy{}, false, nil
	}
	return s.policy, true, nil
}

func (s *stubAPIStore) ListPolicyVersionsForTenant(context.Context, string, string, int) ([]models.PolicyVersion, error) {
	return s.policyVersions, nil
}

func (s *stubAPIStore) RollbackPolicyForTenant(context.Context, string, string, int64, string) (models.Policy, bool, error) {
	if s.policy.ID == "" {
		return models.Policy{}, false, nil
	}
	return s.policy, true, nil
}

func (s *stubAPIStore) ListPolicyApprovalsForTenant(context.Context, string, int) ([]models.PolicyApproval, error) {
	return s.policyApprovals, nil
}

func (s *stubAPIStore) DecidePolicyApproval(context.Context, string, string, bool, string, string) (models.PolicyApproval, bool, error) {
	if len(s.policyApprovals) == 0 {
		return models.PolicyApproval{}, false, nil
	}
	return s.policyApprovals[0], true, nil
}

func (s *stubAPIStore) ListRemediationsForTenant(context.Context, string, int) ([]models.RemediationAction, error) {
	if s.remediation.ID == "" {
		return nil, nil
	}
	return []models.RemediationAction{s.remediation}, nil
}

func (s *stubAPIStore) GetRemediationForTenant(context.Context, string, string) (models.RemediationAction, bool, error) {
	if s.remediation.ID == "" {
		return models.RemediationAction{}, false, nil
	}
	return s.remediation, true, nil
}

func (s *stubAPIStore) CreateRemediationForTenant(context.Context, string, models.CreateRemediationRequest) (models.RemediationAction, error) {
	return s.remediation, nil
}

func (s *stubAPIStore) TransitionRemediationForTenant(context.Context, string, string, models.TransitionRemediationRequest) (models.RemediationAction, bool, error) {
	if s.remediation.ID == "" {
		return models.RemediationAction{}, false, nil
	}
	return s.remediation, true, nil
}

func (s *stubAPIStore) ListRemediationActivityForTenant(context.Context, string, string, int) ([]models.RemediationActivity, error) {
	return s.remediationActivities, nil
}

func (s *stubAPIStore) CreateRemediationCommentForTenant(context.Context, string, string, string, models.CreateRemediationCommentRequest) (models.RemediationActivity, error) {
	if len(s.remediationActivities) == 0 {
		return models.RemediationActivity{}, nil
	}
	return s.remediationActivities[0], nil
}

func (s *stubAPIStore) ListRemediationEvidenceForTenant(context.Context, string, string, int) ([]models.RemediationEvidence, error) {
	return s.remediationEvidence, nil
}

func (s *stubAPIStore) CreateRemediationEvidenceForTenant(context.Context, string, string, string, models.CreateRemediationEvidenceRequest) (models.RemediationEvidence, error) {
	if len(s.remediationEvidence) == 0 {
		return models.RemediationEvidence{}, nil
	}
	return s.remediationEvidence[0], nil
}

func (s *stubAPIStore) ListRemediationVerificationsForTenant(context.Context, string, string, int) ([]models.RemediationVerification, error) {
	return s.remediationVerifications, nil
}

func (s *stubAPIStore) RequestRemediationRetestForTenant(context.Context, string, string, string, models.CreateRetestRequest) (models.RemediationVerification, models.ScanJob, error) {
	var verification models.RemediationVerification
	if len(s.remediationVerifications) > 0 {
		verification = s.remediationVerifications[0]
	}
	return verification, s.scanJob, nil
}

func (s *stubAPIStore) RecordRemediationVerificationForTenant(context.Context, string, string, string, models.RecordRemediationVerificationRequest) (models.RemediationVerification, bool, error) {
	if len(s.remediationVerifications) == 0 {
		return models.RemediationVerification{}, false, nil
	}
	return s.remediationVerifications[0], true, nil
}

func (s *stubAPIStore) ListRemediationExceptionsForTenant(context.Context, string, string, int) ([]models.RemediationException, error) {
	return s.remediationExceptions, nil
}

func (s *stubAPIStore) CreateRemediationExceptionForTenant(context.Context, string, string, string, models.CreateRemediationExceptionRequest) (models.RemediationException, error) {
	if len(s.remediationExceptions) == 0 {
		return models.RemediationException{}, nil
	}
	return s.remediationExceptions[0], nil
}

func (s *stubAPIStore) DecideRemediationExceptionForTenant(context.Context, string, string, bool, string, string) (models.RemediationException, bool, error) {
	if len(s.remediationExceptions) == 0 {
		return models.RemediationException{}, false, nil
	}
	return s.remediationExceptions[0], true, nil
}

func (s *stubAPIStore) ListRemediationTicketLinksForTenant(context.Context, string, string, int) ([]models.RemediationTicketLink, error) {
	return s.remediationTickets, nil
}

func (s *stubAPIStore) CreateRemediationTicketLinkForTenant(context.Context, string, string, models.CreateRemediationTicketLinkRequest) (models.RemediationTicketLink, error) {
	if len(s.remediationTickets) == 0 {
		return models.RemediationTicketLink{}, nil
	}
	return s.remediationTickets[0], nil
}

func (s *stubAPIStore) SyncRemediationTicketLinkForTenant(context.Context, string, string, string, models.SyncRemediationTicketLinkRequest) (models.RemediationTicketLink, bool, error) {
	if len(s.remediationTickets) == 0 {
		return models.RemediationTicketLink{}, false, nil
	}
	return s.remediationTickets[0], true, nil
}

func (s *stubAPIStore) ListRemediationAssignmentRequestsForTenant(context.Context, string, string, int) ([]models.RemediationAssignmentRequest, error) {
	return s.remediationAssignments, nil
}

func (s *stubAPIStore) CreateRemediationAssignmentRequestForTenant(context.Context, string, string, string, models.CreateRemediationAssignmentRequest) (models.RemediationAssignmentRequest, error) {
	if len(s.remediationAssignments) == 0 {
		return models.RemediationAssignmentRequest{}, nil
	}
	return s.remediationAssignments[0], nil
}

func (s *stubAPIStore) DecideRemediationAssignmentRequestForTenant(context.Context, string, string, bool, string, string) (models.RemediationAssignmentRequest, bool, error) {
	if len(s.remediationAssignments) == 0 {
		return models.RemediationAssignmentRequest{}, false, nil
	}
	return s.remediationAssignments[0], true, nil
}

func (s *stubAPIStore) ListNotificationEventsForTenant(context.Context, string, int) ([]models.NotificationEvent, error) {
	return s.notifications, nil
}

func (s *stubAPIStore) AcknowledgeNotificationEventForTenant(context.Context, string, string, string) (models.NotificationEvent, bool, error) {
	if len(s.notifications) == 0 {
		return models.NotificationEvent{}, false, nil
	}
	return s.notifications[0], true, nil
}

func (s *stubAPIStore) SweepRemediationEscalationsForTenant(context.Context, string, string) (models.NotificationSweepResult, error) {
	return s.notificationSweep, nil
}

func TestAuthSessionRequiresBearerToken(t *testing.T) {
	t.Parallel()

	server := New(config.Load(), &stubAPIStore{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}

	var response models.APIError
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode api error: %v", err)
	}
	if response.Code != "authentication_required" {
		t.Fatalf("unexpected error code: %s", response.Code)
	}
}

func TestAuthSessionReturnsPrincipal(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "bootstrap-user-admin-local",
			OrganizationID:   "bootstrap-org-local",
			OrganizationSlug: "local",
			OrganizationName: "Local Organization",
			Email:            "admin@local",
			DisplayName:      "Local Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
	}

	cfg := config.Load()
	cfg.OIDCIssuerURL = "https://issuer.example.com"
	cfg.OIDCClientID = "uss-control-plane"
	cfg.OIDCClientSecret = "test-secret"
	cfg.OIDCRedirectURL = "http://127.0.0.1:18083/auth/oidc/callback"

	server := New(cfg, store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	request.Header.Set("Authorization", "Bearer uss-local-admin-token")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var session models.AuthSession
	if err := json.NewDecoder(recorder.Body).Decode(&session); err != nil {
		t.Fatalf("decode auth session: %v", err)
	}
	if session.Principal.Email != "admin@local" {
		t.Fatalf("unexpected principal email: %s", session.Principal.Email)
	}
	if !session.BootstrapToken {
		t.Fatal("expected bootstrap token session to be identified")
	}
	if !session.SSOEnabled {
		t.Fatal("expected oidc-ready config to be surfaced")
	}
	if len(store.auditEvents) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(store.auditEvents))
	}
}

func TestAuthTokenScopesEnforced(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "appsec@example.com",
			DisplayName:      "AppSec",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"scan_jobs:read"},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/auth/tokens", nil)
	request.Header.Set("Authorization", "Bearer dev-token")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
	if len(store.auditEvents) != 1 {
		t.Fatalf("expected denied request to be audited, got %d events", len(store.auditEvents))
	}
	if store.auditEvents[0].Status != "denied" {
		t.Fatalf("unexpected audit status: %s", store.auditEvents[0].Status)
	}
	if reason, ok := store.auditEvents[0].Details["reason"].(string); !ok || reason != "scope" {
		t.Fatalf("unexpected audit denial reason: %#v", store.auditEvents[0].Details["reason"])
	}
}

func TestWorkerSecretRequiredForRestRegistration(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		registerResponse: models.WorkerRegistrationResponse{
			Accepted:                 true,
			LeaseID:                  "lease-1",
			HeartbeatIntervalSeconds: 30,
		},
	}

	cfg := config.Load()
	cfg.WorkerSharedSecret = "phase1-worker-secret"

	server := New(cfg, store)
	body := `{"worker_id":"worker-1","worker_version":"1.0.0","operating_system":"windows","hostname":"host-1","capabilities":[]}`

	unauthorizedRecorder := httptest.NewRecorder()
	unauthorizedRequest := httptest.NewRequest(http.MethodPost, "/v1/workers/register", strings.NewReader(body))
	server.httpServer.Handler.ServeHTTP(unauthorizedRecorder, unauthorizedRequest)
	if unauthorizedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without worker secret, got %d", unauthorizedRecorder.Code)
	}

	authorizedRecorder := httptest.NewRecorder()
	authorizedRequest := httptest.NewRequest(http.MethodPost, "/v1/workers/register", strings.NewReader(body))
	authorizedRequest.Header.Set("Content-Type", "application/json")
	authorizedRequest.Header.Set("X-USS-Worker-Secret", "phase1-worker-secret")

	server.httpServer.Handler.ServeHTTP(authorizedRecorder, authorizedRequest)
	if authorizedRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 with worker secret, got %d", authorizedRecorder.Code)
	}

	var response models.WorkerRegistrationResponse
	if err := json.NewDecoder(authorizedRecorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode worker registration response: %v", err)
	}
	if !response.Accepted {
		t.Fatal("expected worker registration to be accepted")
	}
}

func TestIssueWorkerIdentityAndUseForRestRegistration(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "admin@example.com",
			DisplayName:      "Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		registerResponse: models.WorkerRegistrationResponse{
			Accepted:                 true,
			LeaseID:                  "lease-1",
			HeartbeatIntervalSeconds: 30,
		},
	}

	cfg := config.Load()
	cfg.WorkerSharedSecret = ""
	cfg.WorkloadIdentitySigningKey = "phase1-workload-signing-key"
	cfg.WorkloadIdentityTTL = 2 * time.Hour

	server := New(cfg, store)

	issueRecorder := httptest.NewRecorder()
	issueRequest := httptest.NewRequest(http.MethodPost, "/v1/workload-identities/workers/issue", strings.NewReader(`{
		"worker_id":"worker-identity-1",
		"ttl_seconds":3600
	}`))
	issueRequest.Header.Set("Authorization", "Bearer admin-token")
	issueRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(issueRecorder, issueRequest)
	if issueRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 when issuing worker identity token, got %d", issueRecorder.Code)
	}

	var issued models.IssuedWorkerIdentityToken
	if err := json.NewDecoder(issueRecorder.Body).Decode(&issued); err != nil {
		t.Fatalf("decode issued worker identity token: %v", err)
	}
	if issued.Token == "" || issued.WorkerID != "worker-identity-1" {
		t.Fatalf("unexpected issued token payload: %+v", issued)
	}

	registerRecorder := httptest.NewRecorder()
	registerRequest := httptest.NewRequest(http.MethodPost, "/v1/workers/register", strings.NewReader(`{
		"worker_id":"worker-identity-1",
		"worker_version":"1.0.0",
		"operating_system":"linux",
		"hostname":"worker-host",
		"capabilities":[]
	}`))
	registerRequest.Header.Set("Authorization", "Bearer "+issued.Token)
	registerRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(registerRecorder, registerRequest)
	if registerRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 with worker identity token, got %d", registerRecorder.Code)
	}
}

func TestWorkerIdentityRejectsMismatchedWorkerID(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		registerResponse: models.WorkerRegistrationResponse{
			Accepted:                 true,
			LeaseID:                  "lease-1",
			HeartbeatIntervalSeconds: 30,
		},
	}

	cfg := config.Load()
	cfg.WorkerSharedSecret = ""
	cfg.WorkloadIdentitySigningKey = "phase1-workload-signing-key"

	token, _, err := auth.IssueWorkerIdentityToken(cfg.WorkloadIdentitySigningKey, "worker-expected", "org-1", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatalf("issue worker identity token: %v", err)
	}

	server := New(cfg, store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/workers/register", strings.NewReader(`{
		"worker_id":"worker-different",
		"worker_version":"1.0.0",
		"operating_system":"linux",
		"hostname":"worker-host",
		"capabilities":[]
	}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for worker identity mismatch, got %d", recorder.Code)
	}
}

func TestKMSKeyEndpoints(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "admin@example.com",
			DisplayName:      "Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
	}

	server := New(config.Load(), store)

	createRecorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest(http.MethodPost, "/v1/kms/keys", strings.NewReader(`{
		"key_ref":"tenant-master",
		"provider":"local",
		"algorithm":"aes-256-gcm",
		"purpose":"all"
	}`))
	createRequest.Header.Set("Authorization", "Bearer admin-token")
	createRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(createRecorder, createRequest)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 for create kms key, got %d", createRecorder.Code)
	}

	var created models.KMSKey
	if err := json.NewDecoder(createRecorder.Body).Decode(&created); err != nil {
		t.Fatalf("decode create kms key response: %v", err)
	}
	if created.KeyRef != "tenant-master" {
		t.Fatalf("expected key_ref tenant-master, got %s", created.KeyRef)
	}

	listRecorder := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/kms/keys?limit=10", nil)
	listRequest.Header.Set("Authorization", "Bearer admin-token")
	server.httpServer.Handler.ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for list kms keys, got %d", listRecorder.Code)
	}

	var payload struct {
		Items []models.KMSKey `json:"items"`
	}
	if err := json.NewDecoder(listRecorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode list kms keys response: %v", err)
	}
	if len(payload.Items) != 1 {
		t.Fatalf("expected 1 kms key, got %d", len(payload.Items))
	}
}

func TestKMSEncryptSignAndVerifyEndpoints(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "admin@example.com",
			DisplayName:      "Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		kmsEncryptResponse: models.KMSEncryptResponse{
			KeyRef:        "tenant-master",
			Algorithm:     "aes-256-gcm",
			NonceB64:      "bm9uY2U=",
			CiphertextB64: "Y2lwaGVydGV4dA==",
		},
		kmsDecryptResponse: models.KMSDecryptResponse{
			KeyRef:       "tenant-master",
			PlaintextB64: "cGxhaW50ZXh0",
		},
		kmsSignResponse: models.KMSSignResponse{
			KeyRef:       "tenant-master",
			Algorithm:    "hmac-sha256",
			SignatureB64: "c2lnbmF0dXJl",
		},
		kmsVerifyResponse: models.KMSVerifyResponse{
			KeyRef: "tenant-master",
			Valid:  true,
		},
	}

	server := New(config.Load(), store)
	requests := []struct {
		path     string
		payload  string
		decodeAs any
	}{
		{
			path:     "/v1/kms/encrypt",
			payload:  `{"key_ref":"tenant-master","plaintext_b64":"cGxhaW50ZXh0"}`,
			decodeAs: &models.KMSEncryptResponse{},
		},
		{
			path:     "/v1/kms/decrypt",
			payload:  `{"key_ref":"tenant-master","nonce_b64":"bm9uY2U=","ciphertext_b64":"Y2lwaGVydGV4dA=="}`,
			decodeAs: &models.KMSDecryptResponse{},
		},
		{
			path:     "/v1/kms/sign",
			payload:  `{"key_ref":"tenant-master","message_b64":"c2lnbi1tZQ=="}`,
			decodeAs: &models.KMSSignResponse{},
		},
		{
			path:     "/v1/kms/verify",
			payload:  `{"key_ref":"tenant-master","message_b64":"c2lnbi1tZQ==","signature_b64":"c2lnbmF0dXJl"}`,
			decodeAs: &models.KMSVerifyResponse{},
		},
	}

	for _, item := range requests {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, item.path, strings.NewReader(item.payload))
		request.Header.Set("Authorization", "Bearer admin-token")
		request.Header.Set("Content-Type", "application/json")

		server.httpServer.Handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d", item.path, recorder.Code)
		}
		if err := json.NewDecoder(recorder.Body).Decode(item.decodeAs); err != nil {
			t.Fatalf("decode response for %s: %v", item.path, err)
		}
	}
}

func TestSecretReferenceAndLeaseEndpoints(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "admin@example.com",
			DisplayName:      "Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
	}

	server := New(config.Load(), store)

	createSecretRecorder := httptest.NewRecorder()
	createSecretRequest := httptest.NewRequest(http.MethodPost, "/v1/secrets/references", strings.NewReader(`{
		"name":"db-password",
		"provider":"vault",
		"secret_path":"kv/apps/payments/db",
		"metadata":{"env":"prod"}
	}`))
	createSecretRequest.Header.Set("Authorization", "Bearer admin-token")
	createSecretRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(createSecretRecorder, createSecretRequest)
	if createSecretRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 create secret reference, got %d", createSecretRecorder.Code)
	}

	var createdSecret models.SecretReference
	if err := json.NewDecoder(createSecretRecorder.Body).Decode(&createdSecret); err != nil {
		t.Fatalf("decode create secret reference response: %v", err)
	}
	if createdSecret.ID == "" {
		t.Fatal("expected secret reference id")
	}

	issueLeaseRecorder := httptest.NewRecorder()
	issueLeaseRequest := httptest.NewRequest(http.MethodPost, "/v1/secrets/leases/issue", strings.NewReader(fmt.Sprintf(`{
		"secret_reference_id":"%s",
		"worker_id":"worker-1",
		"ttl_seconds":300
	}`, createdSecret.ID)))
	issueLeaseRequest.Header.Set("Authorization", "Bearer admin-token")
	issueLeaseRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(issueLeaseRecorder, issueLeaseRequest)
	if issueLeaseRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 issue secret lease, got %d", issueLeaseRecorder.Code)
	}

	var issuedLease models.IssuedSecretLease
	if err := json.NewDecoder(issueLeaseRecorder.Body).Decode(&issuedLease); err != nil {
		t.Fatalf("decode issued secret lease response: %v", err)
	}
	if issuedLease.Lease.ID == "" || issuedLease.LeaseToken == "" {
		t.Fatalf("expected lease id and token, got %+v", issuedLease)
	}

	revokeRecorder := httptest.NewRecorder()
	revokeRequest := httptest.NewRequest(http.MethodPost, "/v1/secrets/leases/"+issuedLease.Lease.ID+"/revoke", nil)
	revokeRequest.Header.Set("Authorization", "Bearer admin-token")
	server.httpServer.Handler.ServeHTTP(revokeRecorder, revokeRequest)
	if revokeRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 revoke secret lease, got %d", revokeRecorder.Code)
	}

	var revoked models.SecretLease
	if err := json.NewDecoder(revokeRecorder.Body).Decode(&revoked); err != nil {
		t.Fatalf("decode revoke secret lease response: %v", err)
	}
	if revoked.Status != "revoked" {
		t.Fatalf("expected revoked status, got %s", revoked.Status)
	}
}

func TestWorkerCertificateEndpoints(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "admin@example.com",
			DisplayName:      "Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
	}

	server := New(config.Load(), store)

	issueRecorder := httptest.NewRecorder()
	issueRequest := httptest.NewRequest(http.MethodPost, "/v1/workload-identities/workers/certificates", strings.NewReader(`{
		"worker_id":"worker-1",
		"ttl_seconds":3600,
		"dns_names":["worker-1.local"],
		"uri_sans":["spiffe://uss/tenant/org-1/worker/worker-1"]
	}`))
	issueRequest.Header.Set("Authorization", "Bearer admin-token")
	issueRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(issueRecorder, issueRequest)
	if issueRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 issue worker certificate, got %d", issueRecorder.Code)
	}

	var issued models.IssuedWorkerCertificate
	if err := json.NewDecoder(issueRecorder.Body).Decode(&issued); err != nil {
		t.Fatalf("decode issued worker certificate response: %v", err)
	}
	if issued.Certificate.ID == "" || issued.PrivateKeyPEM == "" {
		t.Fatalf("expected issued certificate payload, got %+v", issued)
	}

	listRecorder := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/workload-identities/workers/certificates?subject_id=worker-1&limit=10", nil)
	listRequest.Header.Set("Authorization", "Bearer admin-token")
	server.httpServer.Handler.ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 list worker certificates, got %d", listRecorder.Code)
	}

	var listPayload struct {
		Items []models.WorkloadCertificate `json:"items"`
	}
	if err := json.NewDecoder(listRecorder.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode list worker certificates response: %v", err)
	}
	if len(listPayload.Items) != 1 {
		t.Fatalf("expected 1 worker certificate, got %d", len(listPayload.Items))
	}

	revokeRecorder := httptest.NewRecorder()
	revokeRequest := httptest.NewRequest(http.MethodPost, "/v1/workload-identities/workers/certificates/"+issued.Certificate.ID+"/revoke", strings.NewReader(`{"reason":"rotated"}`))
	revokeRequest.Header.Set("Authorization", "Bearer admin-token")
	revokeRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(revokeRecorder, revokeRequest)
	if revokeRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 revoke worker certificate, got %d", revokeRecorder.Code)
	}

	var revoked models.WorkloadCertificate
	if err := json.NewDecoder(revokeRecorder.Body).Decode(&revoked); err != nil {
		t.Fatalf("decode revoked worker certificate response: %v", err)
	}
	if revoked.Status != "revoked" {
		t.Fatalf("expected revoked certificate status, got %s", revoked.Status)
	}
}

func TestCABundleEndpoint(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "admin@example.com",
			DisplayName:      "Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		caBundle: models.CertificateAuthorityBundle{
			CertificatePEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/trust/ca-bundle", nil)
	request.Header.Set("Authorization", "Bearer admin-token")
	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 ca bundle, got %d", recorder.Code)
	}

	var bundle models.CertificateAuthorityBundle
	if err := json.NewDecoder(recorder.Body).Decode(&bundle); err != nil {
		t.Fatalf("decode ca bundle response: %v", err)
	}
	if !strings.Contains(bundle.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatalf("expected cert pem payload, got %s", bundle.CertificatePEM)
	}
}

func TestAuthTokenCreateRejectsExpiredTimestamp(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "admin@example.com",
			DisplayName:      "Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/tokens", strings.NewReader(`{
		"token_name": "expired",
		"expires_at": "`+time.Now().UTC().Add(-1*time.Minute).Format(time.RFC3339)+`"
	}`))
	request.Header.Set("Authorization", "Bearer admin-token")
	request.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
}

func TestScanJobPolicyDeniedReturnsForbidden(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "appsec@example.com",
			DisplayName:      "AppSec",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		createScanJobErr: &jobs.PolicyDeniedError{
			PolicyID: "policy-1",
			Reason:   "requested tool is blocked by enforced policy",
			RuleHits: []string{"block_tool:metasploit"},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/scan-jobs", strings.NewReader(`{
		"target_kind": "domain",
		"target": "example.com",
		"profile": "default",
		"tools": ["metasploit"]
	}`))
	request.Header.Set("Authorization", "Bearer appsec-token")
	request.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
}

func TestScanPresetsEndpointReturnsItems(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "operator@example.com",
			DisplayName:      "Operator",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		scanPresets: []models.ScanPreset{
			{
				ID:         "repo-balanced",
				Name:       "Repository Balanced",
				TargetKind: "repo",
				Profile:    "balanced",
				Tools:      []string{"semgrep", "trivy"},
			},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/scan-presets", nil)
	request.Header.Set("Authorization", "Bearer operator-token")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload struct {
		Items []models.ScanPreset `json:"items"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode scan preset list: %v", err)
	}
	if len(payload.Items) != 1 || payload.Items[0].ID != "repo-balanced" {
		t.Fatalf("unexpected scan presets payload: %#v", payload.Items)
	}
}

func TestScanTargetRoutesSupportCrudAndRun(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "operator@example.com",
			DisplayName:      "Operator",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		scanJob: models.ScanJob{
			ID:     "job-1",
			Status: models.ScanJobStatusQueued,
		},
	}

	server := New(config.Load(), store)

	createRecorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest(http.MethodPost, "/v1/scan-targets", strings.NewReader(`{
		"name": "Repo Main",
		"target_kind": "repo",
		"target": "c:/repo/main",
		"profile": "balanced",
		"tools": ["semgrep","trivy","gitleaks"]
	}`))
	createRequest.Header.Set("Authorization", "Bearer operator-token")
	createRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(createRecorder, createRequest)

	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 for scan target create, got %d", createRecorder.Code)
	}

	var created models.ScanTarget
	if err := json.NewDecoder(createRecorder.Body).Decode(&created); err != nil {
		t.Fatalf("decode created scan target: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected created scan target id")
	}

	listRecorder := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/scan-targets", nil)
	listRequest.Header.Set("Authorization", "Bearer operator-token")
	server.httpServer.Handler.ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for scan target list, got %d", listRecorder.Code)
	}

	updateRecorder := httptest.NewRecorder()
	updateRequest := httptest.NewRequest(http.MethodPut, "/v1/scan-targets/"+created.ID, strings.NewReader(`{
		"name":"Repo Main Updated",
		"profile":"fast"
	}`))
	updateRequest.Header.Set("Authorization", "Bearer operator-token")
	updateRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(updateRecorder, updateRequest)
	if updateRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for scan target update, got %d", updateRecorder.Code)
	}

	runRecorder := httptest.NewRecorder()
	runRequest := httptest.NewRequest(http.MethodPost, "/v1/scan-targets/"+created.ID+"/run", strings.NewReader(`{"profile":"runtime"}`))
	runRequest.Header.Set("Authorization", "Bearer operator-token")
	runRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(runRecorder, runRequest)
	if runRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 for scan target run, got %d", runRecorder.Code)
	}

	var runPayload struct {
		Target models.ScanTarget `json:"target"`
		Job    models.ScanJob    `json:"job"`
	}
	if err := json.NewDecoder(runRecorder.Body).Decode(&runPayload); err != nil {
		t.Fatalf("decode run payload: %v", err)
	}
	if runPayload.Job.ID == "" || runPayload.Target.ID != created.ID {
		t.Fatalf("unexpected run payload: %#v", runPayload)
	}

	deleteRecorder := httptest.NewRecorder()
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/scan-targets/"+created.ID, nil)
	deleteRequest.Header.Set("Authorization", "Bearer operator-token")
	server.httpServer.Handler.ServeHTTP(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for scan target delete, got %d", deleteRecorder.Code)
	}
}

func TestIngestionSourceRoutesSupportCrudRotateAndListEvents(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "operator@example.com",
			DisplayName:      "Operator",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		ingestionEvents: []models.IngestionEvent{
			{
				ID:       "event-1",
				TenantID: "org-1",
				SourceID: "ingestion-source-created",
				Status:   "queued",
			},
		},
	}

	server := New(config.Load(), store)

	createRecorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest(http.MethodPost, "/v1/ingestion/sources", strings.NewReader(`{
		"name":"GitHub Core Repo",
		"provider":"github",
		"target_kind":"repo",
		"target":"https://github.com/acme/core",
		"profile":"balanced",
		"tools":["semgrep","trivy","gitleaks"]
	}`))
	createRequest.Header.Set("Authorization", "Bearer operator-token")
	createRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(createRecorder, createRequest)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 for ingestion source create, got %d", createRecorder.Code)
	}

	var created models.CreatedIngestionSource
	if err := json.NewDecoder(createRecorder.Body).Decode(&created); err != nil {
		t.Fatalf("decode ingestion source create payload: %v", err)
	}
	if created.Source.ID == "" || created.IngestToken == "" {
		t.Fatalf("expected source id and ingest token, got %#v", created)
	}

	listRecorder := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/ingestion/sources", nil)
	listRequest.Header.Set("Authorization", "Bearer operator-token")
	server.httpServer.Handler.ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for ingestion source list, got %d", listRecorder.Code)
	}

	updateRecorder := httptest.NewRecorder()
	updateRequest := httptest.NewRequest(http.MethodPut, "/v1/ingestion/sources/"+created.Source.ID, strings.NewReader(`{
		"profile":"fast"
	}`))
	updateRequest.Header.Set("Authorization", "Bearer operator-token")
	updateRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(updateRecorder, updateRequest)
	if updateRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for ingestion source update, got %d", updateRecorder.Code)
	}

	rotateRecorder := httptest.NewRecorder()
	rotateRequest := httptest.NewRequest(http.MethodPost, "/v1/ingestion/sources/"+created.Source.ID+"/rotate-token", nil)
	rotateRequest.Header.Set("Authorization", "Bearer operator-token")
	server.httpServer.Handler.ServeHTTP(rotateRecorder, rotateRequest)
	if rotateRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for ingestion source token rotation, got %d", rotateRecorder.Code)
	}

	eventsRecorder := httptest.NewRecorder()
	eventsRequest := httptest.NewRequest(http.MethodGet, "/v1/ingestion/events", nil)
	eventsRequest.Header.Set("Authorization", "Bearer operator-token")
	server.httpServer.Handler.ServeHTTP(eventsRecorder, eventsRequest)
	if eventsRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for ingestion events list, got %d", eventsRecorder.Code)
	}

	deleteRecorder := httptest.NewRecorder()
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/ingestion/sources/"+created.Source.ID, nil)
	deleteRequest.Header.Set("Authorization", "Bearer operator-token")
	server.httpServer.Handler.ServeHTTP(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for ingestion source delete, got %d", deleteRecorder.Code)
	}
}

func TestIngestionWebhookEndpointHandlesAcceptedAndDuplicate(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		ingestionWebhookResponse: models.IngestionWebhookResponse{
			Event: models.IngestionEvent{
				ID:       "ingestion-event-1",
				SourceID: "ingestion-source-1",
				Status:   "queued",
			},
			Job: &models.ScanJob{
				ID:     "job-1",
				Status: models.ScanJobStatusQueued,
			},
		},
	}

	server := New(config.Load(), store)

	acceptedRecorder := httptest.NewRecorder()
	acceptedRequest := httptest.NewRequest(http.MethodPost, "/ingest/webhooks/ingestion-source-1", strings.NewReader(`{
		"event_type":"github.push",
		"external_id":"evt-1"
	}`))
	acceptedRequest.Header.Set(ingestionTokenHeader, "stub-token")
	acceptedRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(acceptedRecorder, acceptedRequest)
	if acceptedRecorder.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for webhook accepted, got %d", acceptedRecorder.Code)
	}

	store.ingestionWebhookResponse.Duplicate = true
	duplicateRecorder := httptest.NewRecorder()
	duplicateRequest := httptest.NewRequest(http.MethodPost, "/ingest/webhooks/ingestion-source-1", strings.NewReader(`{
		"event_type":"github.push",
		"external_id":"evt-1"
	}`))
	duplicateRequest.Header.Set(ingestionTokenHeader, "stub-token")
	duplicateRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(duplicateRecorder, duplicateRequest)
	if duplicateRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for duplicate webhook, got %d", duplicateRecorder.Code)
	}
}

func TestIngestionWebhookEndpointRejectsMissingOrInvalidToken(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{}
	server := New(config.Load(), store)

	missingTokenRecorder := httptest.NewRecorder()
	missingTokenRequest := httptest.NewRequest(http.MethodPost, "/ingest/webhooks/source-1", strings.NewReader(`{}`))
	missingTokenRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(missingTokenRecorder, missingTokenRequest)
	if missingTokenRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing ingestion token, got %d", missingTokenRecorder.Code)
	}

	store.ingestionWebhookErr = jobs.ErrInvalidIngestionToken
	invalidTokenRecorder := httptest.NewRecorder()
	invalidTokenRequest := httptest.NewRequest(http.MethodPost, "/ingest/webhooks/source-1", strings.NewReader(`{}`))
	invalidTokenRequest.Header.Set(ingestionTokenHeader, "invalid-token")
	invalidTokenRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(invalidTokenRecorder, invalidTokenRequest)
	if invalidTokenRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid ingestion token, got %d", invalidTokenRecorder.Code)
	}
}

func TestMetricsEndpointReturnsPrometheusPayload(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		operationalMetrics: models.OperationalMetrics{
			WorkersTotal:        2,
			WorkersHealthy:      1,
			ScanJobsTotal:       8,
			ScanJobsQueued:      2,
			ScanJobsRunning:     1,
			ScanJobsCompleted:   4,
			ScanJobsFailed:      1,
			ScanTargetsTotal:    3,
			IngestionSources:    2,
			IngestionEvents:     5,
			PlatformEventsTotal: 9,
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for /metrics, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "uss_scan_jobs_total 8") {
		t.Fatalf("expected scan job metric in payload, got %s", body)
	}
	if !strings.Contains(body, "uss_platform_events_total 9") {
		t.Fatalf("expected platform events metric in payload, got %s", body)
	}
}

func TestPlatformEventsAndTenantOperationsRoutes(t *testing.T) {
	t.Parallel()

	maxTotal := int64(25)
	maxActive := int64(10)
	maxTargets := int64(100)
	maxIngestion := int64(20)

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "operator@example.com",
			DisplayName:      "Operator",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		platformEvents: []models.PlatformEvent{
			{
				ID:        "event-1",
				TenantID:  "org-1",
				EventType: "scan_job.created",
				CreatedAt: time.Now().UTC(),
			},
		},
		tenantOpsSnapshot: models.TenantOperationsSnapshot{
			TenantID: "org-1",
			Limits: models.TenantLimits{
				TenantID:            "org-1",
				MaxTotalScanJobs:    10,
				MaxActiveScanJobs:   5,
				MaxScanTargets:      50,
				MaxIngestionSources: 10,
				UpdatedBy:           "seed",
				UpdatedAt:           time.Now().UTC(),
			},
			Usage: models.TenantUsage{
				TotalScanJobs:    3,
				ActiveScanJobs:   2,
				ScanTargets:      4,
				IngestionSources: 1,
			},
		},
	}

	server := New(config.Load(), store)

	eventsRecorder := httptest.NewRecorder()
	eventsRequest := httptest.NewRequest(http.MethodGet, "/v1/events?type=scan_job.created", nil)
	eventsRequest.Header.Set("Authorization", "Bearer operator-token")
	server.httpServer.Handler.ServeHTTP(eventsRecorder, eventsRequest)
	if eventsRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for platform events, got %d", eventsRecorder.Code)
	}

	opsGetRecorder := httptest.NewRecorder()
	opsGetRequest := httptest.NewRequest(http.MethodGet, "/v1/tenant/operations", nil)
	opsGetRequest.Header.Set("Authorization", "Bearer operator-token")
	server.httpServer.Handler.ServeHTTP(opsGetRecorder, opsGetRequest)
	if opsGetRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for tenant operations get, got %d", opsGetRecorder.Code)
	}

	opsPutRecorder := httptest.NewRecorder()
	opsPutRequest := httptest.NewRequest(http.MethodPut, "/v1/tenant/operations", strings.NewReader(fmt.Sprintf(`{
		"max_total_scan_jobs": %d,
		"max_active_scan_jobs": %d,
		"max_scan_targets": %d,
		"max_ingestion_sources": %d
	}`, maxTotal, maxActive, maxTargets, maxIngestion)))
	opsPutRequest.Header.Set("Authorization", "Bearer operator-token")
	opsPutRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(opsPutRecorder, opsPutRequest)
	if opsPutRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for tenant operations update, got %d", opsPutRecorder.Code)
	}

	var updated models.TenantOperationsSnapshot
	if err := json.NewDecoder(opsPutRecorder.Body).Decode(&updated); err != nil {
		t.Fatalf("decode tenant operations snapshot: %v", err)
	}
	if updated.Limits.MaxTotalScanJobs != maxTotal || updated.Limits.MaxActiveScanJobs != maxActive {
		t.Fatalf("unexpected updated tenant limits: %#v", updated.Limits)
	}
}

func TestScanJobTenantLimitExceededReturnsTooManyRequests(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "operator@example.com",
			DisplayName:      "Operator",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		createScanJobErr: &jobs.TenantLimitExceededError{
			TenantID: "org-1",
			Metric:   "max_total_scan_jobs",
			Limit:    1,
			Current:  1,
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/scan-jobs", strings.NewReader(`{
		"target_kind":"repo",
		"target":"c:/repo",
		"profile":"balanced"
	}`))
	request.Header.Set("Authorization", "Bearer operator-token")
	request.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for tenant limit exceeded, got %d", recorder.Code)
	}
}

func TestScanJobExecutionControlViolationReturnsConflict(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "operator@example.com",
			DisplayName:      "Operator",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		createScanJobErr: &jobs.ExecutionControlViolationError{
			Code:    jobs.ExecutionControlEmergencyStop,
			Message: "tenant emergency stop is active: incident response",
			Reason:  "incident response",
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/scan-jobs", strings.NewReader(`{
		"target_kind":"repo",
		"target":"c:/repo",
		"profile":"balanced"
	}`))
	request.Header.Set("Authorization", "Bearer operator-token")
	request.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409 for execution controls violation, got %d", recorder.Code)
	}

	var payload map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode conflict payload: %v", err)
	}
	if payload["code"] != jobs.ExecutionControlEmergencyStop {
		t.Fatalf("unexpected conflict code payload: %#v", payload["code"])
	}
}

func TestTenantExecutionControlsEndpointFlow(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "operator@example.com",
			DisplayName:      "Operator",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		tenantExecutionControls: models.TenantExecutionControls{
			TenantID: "org-1",
			MaintenanceWindows: []models.MaintenanceWindow{
				{
					ID:        "nightly-window",
					Timezone:  "UTC",
					Days:      []string{"sat"},
					StartHour: 1,
					EndHour:   3,
				},
			},
			UpdatedBy: "seed",
			UpdatedAt: time.Now().UTC(),
		},
	}

	server := New(config.Load(), store)

	getRecorder := httptest.NewRecorder()
	getRequest := httptest.NewRequest(http.MethodGet, "/v1/tenant/execution-controls", nil)
	getRequest.Header.Set("Authorization", "Bearer operator-token")
	server.httpServer.Handler.ServeHTTP(getRecorder, getRequest)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for tenant execution controls get, got %d", getRecorder.Code)
	}

	putRecorder := httptest.NewRecorder()
	putRequest := httptest.NewRequest(http.MethodPut, "/v1/tenant/execution-controls", strings.NewReader(`{
		"emergency_stop_enabled": true,
		"emergency_stop_reason": "incident response",
		"maintenance_windows": [
			{
				"id": "weekend",
				"name": "Weekend Freeze",
				"timezone": "UTC",
				"days": ["sat","sun"],
				"start_hour": 0,
				"start_minute": 0,
				"end_hour": 6,
				"end_minute": 0,
				"target_kinds": ["domain"],
				"reason": "change freeze"
			}
		]
	}`))
	putRequest.Header.Set("Authorization", "Bearer operator-token")
	putRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(putRecorder, putRequest)
	if putRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for tenant execution controls put, got %d", putRecorder.Code)
	}

	var updated models.TenantExecutionControls
	if err := json.NewDecoder(putRecorder.Body).Decode(&updated); err != nil {
		t.Fatalf("decode execution controls payload: %v", err)
	}
	if !updated.EmergencyStopEnabled {
		t.Fatal("expected emergency stop to be enabled")
	}
	if len(updated.MaintenanceWindows) != 1 {
		t.Fatalf("expected 1 maintenance window, got %d", len(updated.MaintenanceWindows))
	}
}

func TestFindingSearchEndpointReturnsItemsAndPagination(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "viewer@example.com",
			DisplayName:      "Viewer",
			Role:             "viewer",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		findingSearchResult: models.FindingSearchResult{
			Items: []models.CanonicalFinding{
				{
					SchemaVersion: "1.0.0",
					FindingID:     "finding-search-1",
					TenantID:      "org-1",
					Category:      "sast_rule_match",
					Title:         "SQL injection pattern",
					Severity:      "high",
					Confidence:    "high",
					Status:        "open",
					FirstSeenAt:   now,
					LastSeenAt:    now,
					Source: models.CanonicalSourceInfo{
						Layer: "code",
						Tool:  "semgrep",
					},
					Asset: models.CanonicalAssetInfo{
						AssetID:     "repo://core",
						AssetType:   "repo",
						AssetName:   "core",
						Environment: "production",
						Exposure:    "internal",
					},
					Risk: models.CanonicalRisk{
						Priority:     "p1",
						OverallScore: 89.2,
						SLAClass:     "72h",
					},
				},
			},
			Total:  1,
			Limit:  50,
			Offset: 5,
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/search/findings?q=sql&severity=high&limit=50&offset=5", nil)
	request.Header.Set("Authorization", "Bearer viewer-token")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for finding search, got %d", recorder.Code)
	}

	var payload models.FindingSearchResult
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode finding search response: %v", err)
	}
	if payload.Total != 1 || payload.Limit != 50 || payload.Offset != 5 {
		t.Fatalf("unexpected search metadata: %+v", payload)
	}
	if len(payload.Items) != 1 || payload.Items[0].FindingID != "finding-search-1" {
		t.Fatalf("unexpected search items: %+v", payload.Items)
	}
}

func TestFindingSearchEndpointValidatesOverdueParameter(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "viewer@example.com",
			DisplayName:      "Viewer",
			Role:             "viewer",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/search/findings?overdue=maybe", nil)
	request.Header.Set("Authorization", "Bearer viewer-token")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid overdue filter, got %d", recorder.Code)
	}
}

func TestEvidenceEndpointsListGetAndRetentionRun(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "admin@example.com",
			DisplayName:      "Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		evidenceListResult: models.EvidenceListResult{
			Items: []models.EvidenceObject{
				{
					ID:              "evidence-1",
					TenantID:        "org-1",
					ScanJobID:       "job-1",
					TaskID:          "task-1",
					ObjectRef:       "C:/evidence/scan-1.log",
					StorageProvider: "filesystem",
					StorageTier:     "hot",
					Archived:        false,
					RetentionUntil:  now.AddDate(0, 0, 30),
					CreatedAt:       now,
					UpdatedAt:       now,
				},
			},
			Total:  1,
			Limit:  25,
			Offset: 0,
		},
		evidenceObjectFound: true,
		evidenceObject: models.EvidenceObject{
			ID:              "evidence-1",
			TenantID:        "org-1",
			ScanJobID:       "job-1",
			TaskID:          "task-1",
			ObjectRef:       "C:/evidence/scan-1.log",
			StorageProvider: "filesystem",
			StorageTier:     "hot",
			Archived:        false,
			RetentionUntil:  now.AddDate(0, 0, 30),
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		evidenceRetentionRun: models.EvidenceRetentionRun{
			ID:            "evidence-retention-1",
			TenantID:      "org-1",
			TriggeredBy:   "admin@example.com",
			Status:        "dry_run",
			ScannedCount:  5,
			ArchivedCount: 2,
			DeletedCount:  0,
			DryRun:        true,
			ArchiveBefore: now,
			StartedAt:     now,
			CompletedAt:   now,
		},
	}

	server := New(config.Load(), store)

	listRecorder := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/evidence?task_id=task-1&limit=25", nil)
	listRequest.Header.Set("Authorization", "Bearer admin-token")
	server.httpServer.Handler.ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for evidence list, got %d", listRecorder.Code)
	}

	getRecorder := httptest.NewRecorder()
	getRequest := httptest.NewRequest(http.MethodGet, "/v1/evidence/evidence-1", nil)
	getRequest.Header.Set("Authorization", "Bearer admin-token")
	server.httpServer.Handler.ServeHTTP(getRecorder, getRequest)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for evidence object, got %d", getRecorder.Code)
	}

	retentionRecorder := httptest.NewRecorder()
	retentionRequest := httptest.NewRequest(http.MethodPost, "/v1/evidence/retention/run", strings.NewReader(`{"dry_run":true}`))
	retentionRequest.Header.Set("Authorization", "Bearer admin-token")
	retentionRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(retentionRecorder, retentionRequest)
	if retentionRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for evidence retention run, got %d", retentionRecorder.Code)
	}

	var retentionPayload models.EvidenceRetentionRun
	if err := json.NewDecoder(retentionRecorder.Body).Decode(&retentionPayload); err != nil {
		t.Fatalf("decode retention run response: %v", err)
	}
	if !retentionPayload.DryRun || retentionPayload.ArchivedCount != 2 {
		t.Fatalf("unexpected retention payload: %+v", retentionPayload)
	}
}

func TestEvidenceIntegrityVerificationEndpoint(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "viewer@example.com",
			DisplayName:      "Viewer",
			Role:             "viewer",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		evidenceIntegrityFound: true,
		evidenceIntegrity: models.EvidenceIntegrityVerification{
			EvidenceID:       "evidence-1",
			TenantID:         "org-1",
			ObjectRef:        "C:/evidence/scan-1.log",
			Verified:         true,
			ObjectExists:     true,
			HashAvailable:    true,
			HashMatches:      true,
			SignaturePresent: true,
			SignatureValid:   true,
			Algorithm:        "hmac-sha256",
			KeyID:            "local-hmac-sha256",
			VerifiedAt:       now,
			Message:          "evidence hash and signature verified",
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/evidence/evidence-1/verify-integrity", nil)
	request.Header.Set("Authorization", "Bearer viewer-token")
	server.httpServer.Handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for evidence integrity verification, got %d", recorder.Code)
	}

	var payload models.EvidenceIntegrityVerification
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode evidence integrity verification response: %v", err)
	}
	if !payload.Verified || !payload.SignatureValid {
		t.Fatalf("unexpected evidence integrity payload: %+v", payload)
	}
}

func TestEvidenceEndpointValidatesArchivedParameter(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "viewer@example.com",
			DisplayName:      "Viewer",
			Role:             "viewer",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/evidence?archived=maybe", nil)
	request.Header.Set("Authorization", "Bearer viewer-token")

	server.httpServer.Handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid archived filter, got %d", recorder.Code)
	}
}

func TestBackupAndRecoveryDrillEndpoints(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "admin@example.com",
			DisplayName:      "Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		backupSnapshots: []models.BackupSnapshot{
			{
				ID:         "backup-1",
				TenantID:   "org-1",
				Scope:      "full_platform",
				StorageRef: "s3://uss-backups/org-1/backup-1.tar.zst",
				Status:     "completed",
				CreatedBy:  "admin@example.com",
				CreatedAt:  now,
			},
		},
		recoveryDrills: []models.RecoveryDrill{
			{
				ID:         "drill-1",
				TenantID:   "org-1",
				SnapshotID: "backup-1",
				Status:     "completed",
				StartedBy:  "admin@example.com",
				StartedAt:  now,
			},
		},
	}

	server := New(config.Load(), store)

	listSnapshotRecorder := httptest.NewRecorder()
	listSnapshotRequest := httptest.NewRequest(http.MethodGet, "/v1/backups/snapshots?limit=10", nil)
	listSnapshotRequest.Header.Set("Authorization", "Bearer admin-token")
	server.httpServer.Handler.ServeHTTP(listSnapshotRecorder, listSnapshotRequest)
	if listSnapshotRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for backup snapshot list, got %d", listSnapshotRecorder.Code)
	}

	createSnapshotRecorder := httptest.NewRecorder()
	createSnapshotRequest := httptest.NewRequest(http.MethodPost, "/v1/backups/snapshots", strings.NewReader(`{
		"scope":"full_platform",
		"storage_ref":"s3://uss-backups/org-1/backup-2.tar.zst",
		"size_bytes":12345
	}`))
	createSnapshotRequest.Header.Set("Authorization", "Bearer admin-token")
	createSnapshotRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(createSnapshotRecorder, createSnapshotRequest)
	if createSnapshotRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 for backup snapshot create, got %d", createSnapshotRecorder.Code)
	}

	listDrillRecorder := httptest.NewRecorder()
	listDrillRequest := httptest.NewRequest(http.MethodGet, "/v1/backups/recovery-drills?limit=10", nil)
	listDrillRequest.Header.Set("Authorization", "Bearer admin-token")
	server.httpServer.Handler.ServeHTTP(listDrillRecorder, listDrillRequest)
	if listDrillRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for recovery drill list, got %d", listDrillRecorder.Code)
	}

	createDrillRecorder := httptest.NewRecorder()
	createDrillRequest := httptest.NewRequest(http.MethodPost, "/v1/backups/recovery-drills", strings.NewReader(`{
		"snapshot_id":"backup-1",
		"status":"completed",
		"rto_seconds":480
	}`))
	createDrillRequest.Header.Set("Authorization", "Bearer admin-token")
	createDrillRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(createDrillRecorder, createDrillRequest)
	if createDrillRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 for recovery drill create, got %d", createDrillRecorder.Code)
	}
}

func TestTenantConfigEndpointsCRUDFlow(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "admin@example.com",
			DisplayName:      "Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		tenantConfigEntries: []models.TenantConfigEntry{
			{
				TenantID:  "org-1",
				Key:       "retention.evidence",
				Value:     map[string]any{"days": float64(90)},
				UpdatedBy: "admin@example.com",
				UpdatedAt: now,
			},
		},
	}

	server := New(config.Load(), store)

	listRecorder := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/config?prefix=retention", nil)
	listRequest.Header.Set("Authorization", "Bearer admin-token")
	server.httpServer.Handler.ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for config list, got %d", listRecorder.Code)
	}

	getRecorder := httptest.NewRecorder()
	getRequest := httptest.NewRequest(http.MethodGet, "/v1/config/retention.evidence", nil)
	getRequest.Header.Set("Authorization", "Bearer admin-token")
	server.httpServer.Handler.ServeHTTP(getRecorder, getRequest)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for config get, got %d", getRecorder.Code)
	}

	upsertRecorder := httptest.NewRecorder()
	upsertRequest := httptest.NewRequest(http.MethodPut, "/v1/config/retention.evidence", strings.NewReader(`{
		"value":{"days":120}
	}`))
	upsertRequest.Header.Set("Authorization", "Bearer admin-token")
	upsertRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(upsertRecorder, upsertRequest)
	if upsertRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for config upsert, got %d", upsertRecorder.Code)
	}

	deleteRecorder := httptest.NewRecorder()
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/config/retention.evidence", nil)
	deleteRequest.Header.Set("Authorization", "Bearer admin-token")
	server.httpServer.Handler.ServeHTTP(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for config delete, got %d", deleteRecorder.Code)
	}
}

func TestGlobalPolicyCreateRequiresPlatformAdmin(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "appsec@example.com",
			DisplayName:      "AppSec",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/policies", strings.NewReader(`{
		"name": "Global Runtime Guardrail",
		"global": true,
		"mode": "enforce",
		"rules": ["require_approval:metasploit"]
	}`))
	request.Header.Set("Authorization", "Bearer appsec-token")
	request.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
}

func TestAssetRouteSupportsProfilesAndControls(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "appsec@example.com",
			DisplayName:      "AppSec",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		assetProfile: models.AssetProfile{
			TenantID:    "org-1",
			AssetID:     "public.example.com",
			AssetType:   "domain",
			AssetName:   "public.example.com",
			Environment: "production",
			Exposure:    "internet",
			Criticality: 9,
			OwnerTeam:   "edge",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		assetControls: []models.CompensatingControl{
			{
				ID:            "control-1",
				AssetID:       "public.example.com",
				Name:          "WAF",
				ControlType:   "waf",
				ScopeLayer:    "dast",
				Effectiveness: 8,
				Enabled:       true,
				CreatedAt:     now,
				UpdatedAt:     now,
			},
		},
	}

	server := New(config.Load(), store)

	profileRecorder := httptest.NewRecorder()
	profileRequest := httptest.NewRequest(http.MethodPut, "/v1/assets/public.example.com", strings.NewReader(`{
		"asset_type": "domain",
		"asset_name": "public.example.com",
		"environment": "production",
		"exposure": "internet",
		"criticality": 9,
		"owner_team": "edge"
	}`))
	profileRequest.Header.Set("Authorization", "Bearer appsec-token")
	profileRequest.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(profileRecorder, profileRequest)
	if profileRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for asset profile upsert, got %d", profileRecorder.Code)
	}

	controlsRecorder := httptest.NewRecorder()
	controlsRequest := httptest.NewRequest(http.MethodGet, "/v1/assets/public.example.com/controls", nil)
	controlsRequest.Header.Set("Authorization", "Bearer appsec-token")

	server.httpServer.Handler.ServeHTTP(controlsRecorder, controlsRequest)
	if controlsRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for control list, got %d", controlsRecorder.Code)
	}
}

func TestAPIAssetDiscoveryEndpoints(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "appsec@example.com",
			DisplayName:      "AppSec",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		apiAssets: []models.APIAsset{
			{
				ID:            "api-asset-1",
				TenantID:      "org-1",
				Name:          "Public API",
				BaseURL:       "https://api.example.com",
				Source:        "manual",
				SpecVersion:   "3.0.3",
				EndpointCount: 2,
				CreatedAt:     now,
				UpdatedAt:     now,
			},
		},
		apiEndpointsByAsset: map[string][]models.APIEndpoint{
			"api-asset-1": {
				{
					ID:           "api-endpoint-1",
					APIAssetID:   "api-asset-1",
					TenantID:     "org-1",
					Path:         "/v1/users",
					Method:       "GET",
					OperationID:  "listUsers",
					AuthRequired: true,
					CreatedAt:    now,
				},
			},
		},
	}

	server := New(config.Load(), store)

	listRecorder := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/assets/apis?limit=10", nil)
	listRequest.Header.Set("Authorization", "Bearer appsec-token")
	server.httpServer.Handler.ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for api assets list, got %d", listRecorder.Code)
	}

	importRecorder := httptest.NewRecorder()
	importRequest := httptest.NewRequest(http.MethodPost, "/v1/assets/apis", strings.NewReader(`{
		"name": "Billing API",
		"base_url": "https://billing.example.com",
		"source": "git",
		"spec": {
			"openapi": "3.0.3",
			"paths": {
				"/v1/invoices": {
					"get": {
						"operationId": "listInvoices",
						"tags": ["billing"]
					}
				}
			}
		}
	}`))
	importRequest.Header.Set("Authorization", "Bearer appsec-token")
	importRequest.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(importRecorder, importRequest)
	if importRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 for openapi import, got %d", importRecorder.Code)
	}

	endpointsRecorder := httptest.NewRecorder()
	endpointsRequest := httptest.NewRequest(http.MethodGet, "/v1/assets/apis/api-asset-1/endpoints?limit=100", nil)
	endpointsRequest.Header.Set("Authorization", "Bearer appsec-token")
	server.httpServer.Handler.ServeHTTP(endpointsRecorder, endpointsRequest)
	if endpointsRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for api endpoint list, got %d", endpointsRecorder.Code)
	}
}

func TestRemediationRouteSupportsEvidence(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "appsec@example.com",
			DisplayName:      "AppSec",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
		remediation: models.RemediationAction{
			ID:        "remediation-1",
			TenantID:  "org-1",
			FindingID: "finding-1",
			Title:     "Fix auth issue",
			Status:    "open",
			Owner:     "edge",
			CreatedAt: now,
			UpdatedAt: now,
		},
		remediationEvidence: []models.RemediationEvidence{
			{
				ID:            "evidence-1",
				RemediationID: "remediation-1",
				Kind:          "ticket",
				Ref:           "local://evidence/1",
				CreatedAt:     now,
				UpdatedAt:     now,
			},
		},
	}

	server := New(config.Load(), store)

	createRecorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest(http.MethodPost, "/v1/remediations/remediation-1/evidence", strings.NewReader(`{
		"kind": "ticket",
		"ref": "local://evidence/1"
	}`))
	createRequest.Header.Set("Authorization", "Bearer appsec-token")
	createRequest.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(createRecorder, createRequest)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 for remediation evidence create, got %d", createRecorder.Code)
	}

	listRecorder := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/remediations/remediation-1/evidence", nil)
	listRequest.Header.Set("Authorization", "Bearer appsec-token")

	server.httpServer.Handler.ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for remediation evidence list, got %d", listRecorder.Code)
	}
}

func TestOIDCStartRedirectsToProvider(t *testing.T) {
	t.Parallel()

	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": provider.URL + "/authorize",
				"token_endpoint":         provider.URL + "/token",
				"userinfo_endpoint":      provider.URL + "/userinfo",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	cfg := config.Load()
	cfg.OIDCIssuerURL = provider.URL
	cfg.OIDCClientID = "uss-client"
	cfg.OIDCClientSecret = "secret"
	cfg.OIDCRedirectURL = "http://127.0.0.1:18083/auth/oidc/callback"

	server := New(cfg, &stubAPIStore{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/oidc/start", nil)

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", recorder.Code)
	}

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if location.Path != "/authorize" {
		t.Fatalf("unexpected redirect path: %s", location.Path)
	}
	if location.Query().Get("client_id") != "uss-client" {
		t.Fatalf("unexpected client_id: %s", location.Query().Get("client_id"))
	}
	if location.Query().Get("code_challenge") == "" {
		t.Fatal("expected pkce challenge in redirect url")
	}

	cookies := recorder.Result().Cookies()
	if len(cookies) < 2 {
		t.Fatalf("expected oidc cookies to be set, got %d", len(cookies))
	}
}

func TestOIDCCallbackCreatesSessionCookie(t *testing.T) {
	t.Parallel()

	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": provider.URL + "/authorize",
				"token_endpoint":         provider.URL + "/token",
				"userinfo_endpoint":      provider.URL + "/userinfo",
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if r.Form.Get("code_verifier") != "verifier-value" {
				t.Fatalf("unexpected code verifier: %s", r.Form.Get("code_verifier"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "provider-access-token",
				"token_type":   "Bearer",
			})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer provider-access-token" {
				t.Fatalf("unexpected authorization header: %s", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"sub":   "provider-user-1",
				"email": "oidc-user@example.com",
				"name":  "OIDC User",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	store := &stubAPIStore{
		createdOIDC: models.CreatedAPIToken{
			Token: models.APIToken{
				ID:        "token-oidc-1",
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			},
			PlaintextToken: "uss_oidc_session_token",
		},
	}

	cfg := config.Load()
	cfg.OIDCIssuerURL = provider.URL
	cfg.OIDCClientID = "uss-client"
	cfg.OIDCClientSecret = "secret"
	cfg.OIDCRedirectURL = "http://127.0.0.1:18083/auth/oidc/callback"

	server := New(cfg, store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=test-code&state=test-state", nil)
	request.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "test-state"})
	request.AddCookie(&http.Cookie{Name: oidcVerifierCookieName, Value: "verifier-value"})

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", recorder.Code)
	}
	if recorder.Header().Get("Location") != "/app/" {
		t.Fatalf("unexpected redirect location: %s", recorder.Header().Get("Location"))
	}
	if store.oidcEmail != "oidc-user@example.com" {
		t.Fatalf("unexpected oidc email: %s", store.oidcEmail)
	}
	if store.oidcSubject != "provider-user-1" {
		t.Fatalf("unexpected oidc subject: %s", store.oidcSubject)
	}

	foundSessionCookie := false
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value == "uss_oidc_session_token" {
			foundSessionCookie = true
			break
		}
	}
	if !foundSessionCookie {
		t.Fatal("expected session cookie to be set")
	}
}

func TestReportSummaryAppliesFilters(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "viewer@example.com",
			DisplayName:      "Viewer",
			Role:             "viewer",
			AuthProvider:     "local",
			Scopes:           []string{"findings:read"},
		},
		findings: []models.CanonicalFinding{
			{
				FindingID: "finding-high",
				Title:     "SQL Injection",
				Category:  "injection",
				Severity:  "high",
				Status:    "open",
				Source: models.CanonicalSourceInfo{
					Layer: "dast",
					Tool:  "zap",
				},
				Asset: models.CanonicalAssetInfo{
					AssetID:   "asset-1",
					AssetName: "api.example.com",
				},
				Risk: models.CanonicalRisk{
					Priority: "p1",
					Overdue:  true,
				},
				FirstSeenAt: now.Add(-72 * time.Hour),
				LastSeenAt:  now,
			},
			{
				FindingID: "finding-low",
				Title:     "Verbose Error",
				Category:  "info_leak",
				Severity:  "low",
				Status:    "open",
				Source: models.CanonicalSourceInfo{
					Layer: "dast",
					Tool:  "zap",
				},
				Asset: models.CanonicalAssetInfo{
					AssetID:   "asset-2",
					AssetName: "app.example.com",
				},
				Risk: models.CanonicalRisk{
					Priority: "p4",
					Overdue:  false,
				},
				FirstSeenAt: now.Add(-24 * time.Hour),
				LastSeenAt:  now,
			},
		},
		riskSummary: models.RiskSummary{
			GeneratedAt:     now,
			TotalFindings:   2,
			OverdueFindings: 1,
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/reports/summary?severity=high&overdue=true", nil)
	request.Header.Set("Authorization", "Bearer viewer-token")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload struct {
		Filtered struct {
			TotalFindings int64 `json:"total_findings"`
			Overdue       int64 `json:"overdue"`
		} `json:"filtered"`
		SampleSize int64 `json:"sample_size"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode report summary: %v", err)
	}

	if payload.SampleSize != 2 {
		t.Fatalf("expected sample_size=2, got %d", payload.SampleSize)
	}
	if payload.Filtered.TotalFindings != 1 {
		t.Fatalf("expected filtered total=1, got %d", payload.Filtered.TotalFindings)
	}
	if payload.Filtered.Overdue != 1 {
		t.Fatalf("expected filtered overdue=1, got %d", payload.Filtered.Overdue)
	}
}

func TestFindingsExportCSV(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "viewer@example.com",
			DisplayName:      "Viewer",
			Role:             "viewer",
			AuthProvider:     "local",
			Scopes:           []string{"findings:read"},
		},
		findings: []models.CanonicalFinding{
			{
				FindingID: "finding-export",
				Title:     "Hardcoded Secret",
				Category:  "secrets",
				Severity:  "critical",
				Status:    "open",
				Source: models.CanonicalSourceInfo{
					Layer: "secrets",
					Tool:  "gitleaks",
				},
				Asset: models.CanonicalAssetInfo{
					AssetID:   "repo-1",
					AssetName: "service-repo",
				},
				Risk: models.CanonicalRisk{
					Priority:     "p0",
					OverallScore: 9.8,
					SLAClass:     "24h",
					Overdue:      true,
				},
				Tags:        []string{"credential"},
				FirstSeenAt: now.Add(-48 * time.Hour),
				LastSeenAt:  now,
			},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/reports/findings/export?format=csv&priority=p0", nil)
	request.Header.Set("Authorization", "Bearer viewer-token")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.Contains(contentType, "text/csv") {
		t.Fatalf("expected csv content type, got %s", contentType)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "finding_id,title,category,severity,status,priority") {
		t.Fatalf("expected csv header, got %s", body)
	}
	if !strings.Contains(body, "finding-export,Hardcoded Secret,secrets,critical,open,p0") {
		t.Fatalf("expected exported finding row, got %s", body)
	}
}

func TestRootRedirectsToUIDistWhenConfigured(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "index.html"), []byte("<html>ui</html>"), 0o600); err != nil {
		t.Fatalf("write index html: %v", err)
	}

	cfg := config.Load()
	cfg.UIDistPath = tempDir

	server := New(cfg, &stubAPIStore{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", recorder.Code)
	}
	if recorder.Header().Get("Location") != "/ui/" {
		t.Fatalf("expected redirect to /ui/, got %s", recorder.Header().Get("Location"))
	}
}

func TestUIDistServesAssetsAndIndexFallback(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "index.html"), []byte("<html>ui</html>"), 0o600); err != nil {
		t.Fatalf("write index html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "app.js"), []byte("console.log('ui');"), 0o600); err != nil {
		t.Fatalf("write app js: %v", err)
	}

	cfg := config.Load()
	cfg.UIDistPath = tempDir

	server := New(cfg, &stubAPIStore{})

	for _, path := range []string{"/ui/", "/ui/app.js", "/ui/findings"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		server.httpServer.Handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d", path, recorder.Code)
		}
	}
}
