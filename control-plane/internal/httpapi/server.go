package httpapi

import (
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
	"unifiedsecurityscanner/control-plane/internal/rbac"
	"unifiedsecurityscanner/control-plane/internal/tenant"
)

//go:embed static/*
var staticAssets embed.FS

const ingestionTokenHeader = "X-USS-Ingest-Token"

type Server struct {
	cfg           config.Config
	httpServer    *http.Server
	store         apiStore
	uiDistPath    string
	uiDistEnabled bool
}

type apiStore interface {
	Ping(ctx context.Context) error
	AuthenticateToken(ctx context.Context, rawToken string) (models.AuthPrincipal, bool, error)
	CreateOIDCSession(ctx context.Context, provider string, subject string, email string, displayName string) (models.CreatedAPIToken, error)
	RecordAuditEvent(ctx context.Context, event models.AuditEvent) error
	ListAuditEvents(ctx context.Context, organizationID string, limit int) ([]models.AuditEvent, error)
	ListAPITokens(ctx context.Context, organizationID string, limit int) ([]models.APIToken, error)
	CreateAPIToken(ctx context.Context, principal models.AuthPrincipal, request models.CreateAPITokenRequest) (models.CreatedAPIToken, error)
	DisableAPIToken(ctx context.Context, organizationID string, tokenID string) (models.APIToken, bool, error)
	ListForTenant(ctx context.Context, tenantID string, limit int) ([]models.ScanJob, error)
	CreateForTenant(ctx context.Context, tenantID string, request models.CreateScanJobRequest) (models.ScanJob, error)
	GetForTenant(ctx context.Context, tenantID string, id string) (models.ScanJob, bool, error)
	ListScanPresetsForTenant(ctx context.Context, tenantID string) ([]models.ScanPreset, error)
	ListScanEngineControlsForTenant(ctx context.Context, tenantID string, targetKind string, limit int) ([]models.ScanEngineControl, error)
	UpsertScanEngineControlForTenant(ctx context.Context, tenantID string, adapterID string, actor string, request models.UpsertScanEngineControlRequest) (models.ScanEngineControl, error)
	ListWebTargetsForTenant(ctx context.Context, tenantID string, targetType string, limit int) ([]models.WebTarget, error)
	GetWebTargetForTenant(ctx context.Context, tenantID string, targetID string) (models.WebTarget, bool, error)
	CreateWebTargetForTenant(ctx context.Context, tenantID string, actor string, request models.CreateWebTargetRequest) (models.WebTarget, error)
	UpdateWebTargetForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.UpdateWebTargetRequest) (models.WebTarget, bool, error)
	DeleteWebTargetForTenant(ctx context.Context, tenantID string, targetID string) (bool, error)
	GetWebCrawlPolicyForTenant(ctx context.Context, tenantID string, targetID string) (models.WebCrawlPolicy, bool, error)
	UpsertWebCrawlPolicyForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.UpsertWebCrawlPolicyRequest) (models.WebCrawlPolicy, error)
	GetWebCoverageBaselineForTenant(ctx context.Context, tenantID string, targetID string) (models.WebCoverageBaseline, bool, error)
	UpsertWebCoverageBaselineForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.UpsertWebCoverageBaselineRequest) (models.WebCoverageBaseline, error)
	ListWebRuntimeCoverageRunsForTenant(ctx context.Context, tenantID string, targetID string, limit int) ([]models.WebRuntimeCoverageRun, error)
	CreateWebRuntimeCoverageRunForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.CreateWebRuntimeCoverageRunRequest) (models.WebRuntimeCoverageRun, error)
	GetWebCoverageStatusForTenant(ctx context.Context, tenantID string, targetID string) (models.WebCoverageStatus, error)
	EvaluateWebTargetScopeForTenant(ctx context.Context, tenantID string, targetID string, rawURL string) (models.WebTargetScopeEvaluation, error)
	RunWebTargetForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.RunWebTargetRequest) (models.WebTarget, models.ScanJob, bool, error)
	ListWebAuthProfilesForTenant(ctx context.Context, tenantID string, limit int) ([]models.WebAuthProfile, error)
	GetWebAuthProfileForTenant(ctx context.Context, tenantID string, profileID string) (models.WebAuthProfile, bool, error)
	CreateWebAuthProfileForTenant(ctx context.Context, tenantID string, actor string, request models.CreateWebAuthProfileRequest) (models.WebAuthProfile, error)
	UpdateWebAuthProfileForTenant(ctx context.Context, tenantID string, profileID string, actor string, request models.UpdateWebAuthProfileRequest) (models.WebAuthProfile, bool, error)
	DeleteWebAuthProfileForTenant(ctx context.Context, tenantID string, profileID string) (bool, error)
	ListScanTargetsForTenant(ctx context.Context, tenantID string, limit int) ([]models.ScanTarget, error)
	GetScanTargetForTenant(ctx context.Context, tenantID string, targetID string) (models.ScanTarget, bool, error)
	CreateScanTargetForTenant(ctx context.Context, tenantID string, actor string, request models.CreateScanTargetRequest) (models.ScanTarget, error)
	UpdateScanTargetForTenant(ctx context.Context, tenantID string, targetID string, request models.UpdateScanTargetRequest) (models.ScanTarget, bool, error)
	DeleteScanTargetForTenant(ctx context.Context, tenantID string, targetID string) (bool, error)
	RunScanTargetForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.RunScanTargetRequest) (models.ScanTarget, models.ScanJob, bool, error)
	SearchFindingsForTenant(ctx context.Context, tenantID string, query models.FindingSearchQuery) (models.FindingSearchResult, error)
	ListEvidenceObjectsForTenant(ctx context.Context, tenantID string, query models.EvidenceListQuery) (models.EvidenceListResult, error)
	GetEvidenceObjectForTenant(ctx context.Context, tenantID string, evidenceID string) (models.EvidenceObject, bool, error)
	VerifyEvidenceObjectIntegrityForTenant(ctx context.Context, tenantID string, evidenceID string) (models.EvidenceIntegrityVerification, bool, error)
	ListEvidenceRetentionRunsForTenant(ctx context.Context, tenantID string, limit int) ([]models.EvidenceRetentionRun, error)
	RunEvidenceRetentionForTenant(ctx context.Context, tenantID string, actor string, request models.RunEvidenceRetentionRequest) (models.EvidenceRetentionRun, error)
	ListBackupSnapshotsForTenant(ctx context.Context, tenantID string, limit int) ([]models.BackupSnapshot, error)
	CreateBackupSnapshotForTenant(ctx context.Context, tenantID string, actor string, request models.CreateBackupSnapshotRequest) (models.BackupSnapshot, error)
	ListRecoveryDrillsForTenant(ctx context.Context, tenantID string, limit int) ([]models.RecoveryDrill, error)
	CreateRecoveryDrillForTenant(ctx context.Context, tenantID string, actor string, request models.CreateRecoveryDrillRequest) (models.RecoveryDrill, error)
	ListKMSKeysForTenant(ctx context.Context, tenantID string, limit int) ([]models.KMSKey, error)
	CreateKMSKeyForTenant(ctx context.Context, tenantID string, actor string, request models.CreateKMSKeyRequest) (models.KMSKey, error)
	EncryptWithKMSForTenant(ctx context.Context, tenantID string, request models.KMSEncryptRequest) (models.KMSEncryptResponse, error)
	DecryptWithKMSForTenant(ctx context.Context, tenantID string, request models.KMSDecryptRequest) (models.KMSDecryptResponse, error)
	SignWithKMSForTenant(ctx context.Context, tenantID string, request models.KMSSignRequest) (models.KMSSignResponse, error)
	VerifyWithKMSForTenant(ctx context.Context, tenantID string, request models.KMSVerifyRequest) (models.KMSVerifyResponse, error)
	ListSecretReferencesForTenant(ctx context.Context, tenantID string, limit int) ([]models.SecretReference, error)
	GetSecretReferenceForTenant(ctx context.Context, tenantID string, referenceID string) (models.SecretReference, bool, error)
	CreateSecretReferenceForTenant(ctx context.Context, tenantID string, actor string, request models.CreateSecretReferenceRequest) (models.SecretReference, error)
	UpdateSecretReferenceForTenant(ctx context.Context, tenantID string, referenceID string, actor string, request models.UpdateSecretReferenceRequest) (models.SecretReference, bool, error)
	DeleteSecretReferenceForTenant(ctx context.Context, tenantID string, referenceID string) (bool, error)
	ListSecretLeasesForTenant(ctx context.Context, tenantID string, referenceID string, limit int) ([]models.SecretLease, error)
	IssueSecretLeaseForTenant(ctx context.Context, tenantID string, actor string, request models.IssueSecretLeaseRequest) (models.IssuedSecretLease, error)
	RevokeSecretLeaseForTenant(ctx context.Context, tenantID string, leaseID string, actor string) (models.SecretLease, bool, error)
	ListWorkloadCertificatesForTenant(ctx context.Context, tenantID string, subjectID string, limit int) ([]models.WorkloadCertificate, error)
	IssueWorkerCertificateForTenant(ctx context.Context, tenantID string, actor string, request models.IssueWorkerCertificateRequest) (models.IssuedWorkerCertificate, error)
	RevokeWorkloadCertificateForTenant(ctx context.Context, tenantID string, certificateID string, actor string, reason string) (models.WorkloadCertificate, bool, error)
	GetCertificateAuthorityBundle() (models.CertificateAuthorityBundle, error)
	ListIngestionSourcesForTenant(ctx context.Context, tenantID string, limit int) ([]models.IngestionSource, error)
	GetIngestionSourceForTenant(ctx context.Context, tenantID string, sourceID string) (models.IngestionSource, bool, error)
	CreateIngestionSourceForTenant(ctx context.Context, tenantID string, actor string, request models.CreateIngestionSourceRequest) (models.CreatedIngestionSource, error)
	UpdateIngestionSourceForTenant(ctx context.Context, tenantID string, sourceID string, actor string, request models.UpdateIngestionSourceRequest) (models.IngestionSource, bool, error)
	DeleteIngestionSourceForTenant(ctx context.Context, tenantID string, sourceID string) (bool, error)
	RotateIngestionSourceTokenForTenant(ctx context.Context, tenantID string, sourceID string, actor string) (models.RotateIngestionSourceTokenResponse, bool, error)
	RotateIngestionSourceWebhookSecretForTenant(ctx context.Context, tenantID string, sourceID string, actor string) (models.RotateIngestionSourceWebhookSecretResponse, bool, error)
	ListIngestionEventsForTenant(ctx context.Context, tenantID string, sourceID string, limit int) ([]models.IngestionEvent, error)
	HandleIngestionWebhook(ctx context.Context, sourceID string, rawToken string, request models.IngestionWebhookRequest, rawBody []byte) (models.IngestionWebhookResponse, error)
	ListPlatformEventsForTenant(ctx context.Context, tenantID string, eventType string, limit int) ([]models.PlatformEvent, error)
	ListWebhookIntegrationsForTenant(ctx context.Context, tenantID string, status string, eventType string, limit int) ([]models.WebhookIntegration, error)
	GetWebhookIntegrationForTenant(ctx context.Context, tenantID string, webhookID string) (models.WebhookIntegration, bool, error)
	CreateWebhookIntegrationForTenant(ctx context.Context, tenantID string, actor string, request models.CreateWebhookIntegrationRequest) (models.WebhookIntegration, error)
	UpdateWebhookIntegrationForTenant(ctx context.Context, tenantID string, webhookID string, actor string, request models.UpdateWebhookIntegrationRequest) (models.WebhookIntegration, bool, error)
	ListWebhookDeliveriesForTenant(ctx context.Context, tenantID string, webhookID string, status string, limit int) ([]models.WebhookDelivery, error)
	DispatchWebhookDeliveriesForTenant(ctx context.Context, tenantID string, actor string, request models.DispatchWebhookDeliveriesRequest) (models.DispatchWebhookDeliveriesResult, error)
	GetTenantOperationsSnapshot(ctx context.Context, tenantID string) (models.TenantOperationsSnapshot, error)
	UpdateTenantLimitsForTenant(ctx context.Context, tenantID string, actor string, request models.UpdateTenantLimitsRequest) (models.TenantOperationsSnapshot, error)
	GetTenantExecutionControlsForTenant(ctx context.Context, tenantID string) (models.TenantExecutionControls, error)
	UpdateTenantExecutionControlsForTenant(ctx context.Context, tenantID string, actor string, request models.UpdateTenantExecutionControlsRequest) (models.TenantExecutionControls, error)
	GetOperationalMetrics(ctx context.Context) (models.OperationalMetrics, error)
	ListTenantConfigForTenant(ctx context.Context, tenantID string, prefix string, limit int) ([]models.TenantConfigEntry, error)
	GetTenantConfigEntryForTenant(ctx context.Context, tenantID string, key string) (models.TenantConfigEntry, bool, error)
	UpsertTenantConfigEntryForTenant(ctx context.Context, tenantID string, key string, actor string, request models.UpsertTenantConfigRequest) (models.TenantConfigEntry, error)
	DeleteTenantConfigEntryForTenant(ctx context.Context, tenantID string, key string, actor string) (bool, error)
	RegisterWorker(ctx context.Context, request models.WorkerRegistrationRequest) (models.WorkerRegistrationResponse, error)
	RecordHeartbeat(ctx context.Context, request models.HeartbeatRequest) (models.HeartbeatResponse, error)
	ListFindingsForTenant(ctx context.Context, tenantID string, limit int) ([]models.CanonicalFinding, error)
	ListFindingWaiversForTenant(ctx context.Context, tenantID string, findingID string, limit int) ([]models.FindingWaiver, error)
	CreateFindingWaiverForTenant(ctx context.Context, tenantID string, findingID string, request models.CreateFindingWaiverRequest) (models.FindingWaiver, error)
	ListRiskSummaryForTenant(ctx context.Context, tenantID string) (models.RiskSummary, error)
	ListAssetsForTenant(ctx context.Context, tenantID string, limit int) ([]models.AssetSummary, error)
	ListAssetContextEventsForTenant(ctx context.Context, tenantID string, assetID string, eventKind string, limit int) ([]models.AssetContextEvent, error)
	CreateAssetContextEventForTenant(ctx context.Context, tenantID string, actor string, request models.CreateAssetContextEventRequest) (models.AssetContextEvent, error)
	ListAPIAssetsForTenant(ctx context.Context, tenantID string, limit int) ([]models.APIAsset, error)
	ListAPIEndpointsForTenant(ctx context.Context, tenantID string, apiAssetID string, limit int) ([]models.APIEndpoint, error)
	ImportOpenAPIForTenant(ctx context.Context, tenantID string, actor string, request models.ImportOpenAPIRequest) (models.ImportedAPIAsset, error)
	ImportGraphQLSchemaForTenant(ctx context.Context, tenantID string, actor string, request models.ImportGraphQLSchemaRequest) (models.ImportedAPIAsset, error)
	ListExternalAssetsForTenant(ctx context.Context, tenantID string, assetType string, limit int) ([]models.ExternalAsset, error)
	UpsertExternalAssetForTenant(ctx context.Context, tenantID string, actor string, request models.UpsertExternalAssetRequest) (models.ExternalAsset, error)
	SyncExternalAssetsForTenant(ctx context.Context, tenantID string, actor string, request models.SyncExternalAssetsRequest) (models.SyncExternalAssetsResult, error)
	GetAssetProfileForTenant(ctx context.Context, tenantID string, assetID string) (models.AssetProfile, bool, error)
	UpsertAssetProfileForTenant(ctx context.Context, tenantID string, assetID string, request models.UpsertAssetProfileRequest) (models.AssetProfile, error)
	SyncAssetProfilesForTenant(ctx context.Context, tenantID string, request models.SyncAssetProfilesRequest) (models.SyncAssetProfilesResult, error)
	ListCompensatingControlsForTenant(ctx context.Context, tenantID string, assetID string, limit int) ([]models.CompensatingControl, error)
	CreateCompensatingControlForTenant(ctx context.Context, tenantID string, assetID string, request models.CreateCompensatingControlRequest) (models.CompensatingControl, error)
	ListValidationEngagementsForTenant(ctx context.Context, tenantID string, status string, limit int) ([]models.ValidationEngagement, error)
	GetValidationEngagementForTenant(ctx context.Context, tenantID string, engagementID string) (models.ValidationEngagement, bool, error)
	CreateValidationEngagementForTenant(ctx context.Context, tenantID string, actor string, request models.CreateValidationEngagementRequest) (models.ValidationEngagement, error)
	UpdateValidationEngagementForTenant(ctx context.Context, tenantID string, engagementID string, actor string, request models.UpdateValidationEngagementRequest) (models.ValidationEngagement, bool, error)
	ApproveValidationEngagementForTenant(ctx context.Context, tenantID string, engagementID string, actor string, reason string) (models.ValidationEngagement, bool, error)
	ActivateValidationEngagementForTenant(ctx context.Context, tenantID string, engagementID string, actor string) (models.ValidationEngagement, bool, error)
	CloseValidationEngagementForTenant(ctx context.Context, tenantID string, engagementID string, actor string, reason string) (models.ValidationEngagement, bool, error)
	GetValidationExecutionEnvelopeForTenant(ctx context.Context, tenantID string, engagementID string) (models.ValidationExecutionEnvelope, bool, error)
	UpsertValidationExecutionEnvelopeForTenant(ctx context.Context, tenantID string, engagementID string, actor string, request models.UpsertValidationExecutionEnvelopeRequest) (models.ValidationExecutionEnvelope, error)
	ApproveValidationExecutionEnvelopeForTenant(ctx context.Context, tenantID string, engagementID string, actor string, reason string) (models.ValidationExecutionEnvelope, bool, error)
	ActivateValidationExecutionEnvelopeForTenant(ctx context.Context, tenantID string, engagementID string, actor string) (models.ValidationExecutionEnvelope, bool, error)
	CloseValidationExecutionEnvelopeForTenant(ctx context.Context, tenantID string, engagementID string, actor string, reason string) (models.ValidationExecutionEnvelope, bool, error)
	ListValidationPlanStepsForTenant(ctx context.Context, tenantID string, engagementID string, status string, limit int) ([]models.ValidationPlanStep, error)
	CreateValidationPlanStepForTenant(ctx context.Context, tenantID string, actor string, request models.CreateValidationPlanStepRequest) (models.ValidationPlanStep, error)
	DecideValidationPlanStepForTenant(ctx context.Context, tenantID string, stepID string, approved bool, actor string, reason string) (models.ValidationPlanStep, bool, error)
	ListValidationAttackTracesForTenant(ctx context.Context, tenantID string, engagementID string, limit int) ([]models.ValidationAttackTrace, error)
	CreateValidationAttackTraceForTenant(ctx context.Context, tenantID string, actor string, request models.CreateValidationAttackTraceRequest) (models.ValidationAttackTrace, error)
	ListValidationManualTestsForTenant(ctx context.Context, tenantID string, engagementID string, status string, limit int) ([]models.ValidationManualTestCase, error)
	CreateValidationManualTestForTenant(ctx context.Context, tenantID string, actor string, request models.CreateValidationManualTestCaseRequest) (models.ValidationManualTestCase, error)
	UpdateValidationManualTestForTenant(ctx context.Context, tenantID string, testCaseID string, actor string, request models.UpdateValidationManualTestCaseRequest) (models.ValidationManualTestCase, bool, error)
	ListDesignReviewsForTenant(ctx context.Context, tenantID string, status string, limit int) ([]models.DesignReview, error)
	GetDesignReviewForTenant(ctx context.Context, tenantID string, reviewID string) (models.DesignReview, bool, error)
	CreateDesignReviewForTenant(ctx context.Context, tenantID string, actor string, request models.CreateDesignReviewRequest) (models.DesignReview, error)
	UpdateDesignReviewForTenant(ctx context.Context, tenantID string, reviewID string, actor string, request models.UpdateDesignReviewRequest) (models.DesignReview, bool, error)
	SubmitDesignReviewForTenant(ctx context.Context, tenantID string, reviewID string, actor string, reason string) (models.DesignReview, bool, error)
	ApproveDesignReviewForTenant(ctx context.Context, tenantID string, reviewID string, actor string, reason string) (models.DesignReview, bool, error)
	CloseDesignReviewForTenant(ctx context.Context, tenantID string, reviewID string, actor string, reason string) (models.DesignReview, bool, error)
	ListDesignThreatsForTenant(ctx context.Context, tenantID string, reviewID string, status string, limit int) ([]models.DesignThreat, error)
	CreateDesignThreatForTenant(ctx context.Context, tenantID string, reviewID string, actor string, request models.CreateDesignThreatRequest) (models.DesignThreat, error)
	UpdateDesignThreatForTenant(ctx context.Context, tenantID string, reviewID string, threatID string, actor string, request models.UpdateDesignThreatRequest) (models.DesignThreat, bool, error)
	GetDesignDataFlowForTenant(ctx context.Context, tenantID string, reviewID string) (models.DesignDataFlowModel, bool, error)
	UpsertDesignDataFlowForTenant(ctx context.Context, tenantID string, reviewID string, actor string, request models.UpsertDesignDataFlowRequest) (models.DesignDataFlowModel, error)
	ListDesignControlMappingsForTenant(ctx context.Context, tenantID string, reviewID string, framework string, limit int) ([]models.DesignControlMapping, error)
	CreateDesignControlMappingForTenant(ctx context.Context, tenantID string, reviewID string, actor string, request models.CreateDesignControlMappingRequest) (models.DesignControlMapping, error)
	UpdateDesignControlMappingForTenant(ctx context.Context, tenantID string, reviewID string, mappingID string, actor string, request models.UpdateDesignControlMappingRequest) (models.DesignControlMapping, bool, error)
	ListRuntimeTelemetryConnectorsForTenant(ctx context.Context, tenantID string, connectorType string, limit int) ([]models.RuntimeTelemetryConnector, error)
	GetRuntimeTelemetryConnectorForTenant(ctx context.Context, tenantID string, connectorID string) (models.RuntimeTelemetryConnector, bool, error)
	CreateRuntimeTelemetryConnectorForTenant(ctx context.Context, tenantID string, actor string, request models.CreateRuntimeTelemetryConnectorRequest) (models.RuntimeTelemetryConnector, error)
	UpdateRuntimeTelemetryConnectorForTenant(ctx context.Context, tenantID string, connectorID string, actor string, request models.UpdateRuntimeTelemetryConnectorRequest) (models.RuntimeTelemetryConnector, bool, error)
	ListRuntimeTelemetryEventsForTenant(ctx context.Context, tenantID string, query models.RuntimeTelemetryEventQuery) ([]models.RuntimeTelemetryEvent, error)
	IngestRuntimeTelemetryEventForTenant(ctx context.Context, tenantID string, request models.IngestRuntimeTelemetryEventRequest) (models.RuntimeTelemetryEvent, error)
	ListRuntimeFindingEnrichmentsForTenant(ctx context.Context, tenantID string, findingID string, limit int) ([]models.RuntimeFindingEnrichment, error)
	BackfillRuntimeFindingEnrichmentForTenant(ctx context.Context, tenantID string, limit int) (models.RuntimeEnrichmentBackfillResult, error)
	ListComplianceControlMappingsForTenant(ctx context.Context, tenantID string, framework string, sourceID string, limit int) ([]models.ComplianceControlMapping, error)
	CreateComplianceControlMappingForTenant(ctx context.Context, tenantID string, actor string, request models.CreateComplianceControlMappingRequest) (models.ComplianceControlMapping, error)
	UpdateComplianceControlMappingForTenant(ctx context.Context, tenantID string, mappingID string, actor string, request models.UpdateComplianceControlMappingRequest) (models.ComplianceControlMapping, bool, error)
	GetComplianceSummaryForTenant(ctx context.Context, tenantID string) (models.ComplianceSummary, error)
	SyncOWASPMappingsForTenant(ctx context.Context, tenantID string, actor string, request models.SyncOWASPMappingRequest) (models.OWASPMappingSyncResult, error)
	GetSAMMMetricsForTenant(ctx context.Context, tenantID string) (models.SAMMMetrics, error)
	ListDetectionRulepacksForTenant(ctx context.Context, tenantID string, engine string, status string, limit int) ([]models.DetectionRulepack, error)
	GetDetectionRulepackForTenant(ctx context.Context, tenantID string, rulepackID string) (models.DetectionRulepack, bool, error)
	CreateDetectionRulepackForTenant(ctx context.Context, tenantID string, actor string, request models.CreateDetectionRulepackRequest) (models.DetectionRulepack, error)
	UpdateDetectionRulepackForTenant(ctx context.Context, tenantID string, rulepackID string, actor string, request models.UpdateDetectionRulepackRequest) (models.DetectionRulepack, bool, error)
	ListDetectionRulepackVersionsForTenant(ctx context.Context, tenantID string, rulepackID string, limit int) ([]models.DetectionRulepackVersion, error)
	CreateDetectionRulepackVersionForTenant(ctx context.Context, tenantID string, rulepackID string, actor string, request models.CreateDetectionRulepackVersionRequest) (models.DetectionRulepackVersion, error)
	PromoteDetectionRulepackVersionForTenant(ctx context.Context, tenantID string, rulepackID string, versionID string, actor string, request models.PromoteDetectionRulepackVersionRequest) (models.DetectionRulepackRollout, bool, error)
	ListDetectionRulepackRolloutsForTenant(ctx context.Context, tenantID string, rulepackID string, limit int) ([]models.DetectionRulepackRollout, error)
	ListDetectionRulepackQualityRunsForTenant(ctx context.Context, tenantID string, rulepackID string, versionID string, limit int) ([]models.DetectionRulepackQualityRun, error)
	RecordDetectionRulepackQualityRunForTenant(ctx context.Context, tenantID string, rulepackID string, actor string, request models.RecordDetectionRulepackQualityRunRequest) (models.DetectionRulepackQualityRun, error)
	ListDetectionContentDistributionsForTenant(ctx context.Context, tenantID string, rulepackID string, versionID string, status string, limit int) ([]models.DetectionContentDistribution, error)
	GetDetectionContentDistributionForTenant(ctx context.Context, tenantID string, distributionID string) (models.DetectionContentDistribution, bool, error)
	CreateDetectionContentDistributionForTenant(ctx context.Context, tenantID string, actor string, request models.CreateDetectionContentDistributionRequest) (models.DetectionContentDistribution, error)
	UpdateDetectionContentDistributionForTenant(ctx context.Context, tenantID string, distributionID string, actor string, request models.UpdateDetectionContentDistributionRequest) (models.DetectionContentDistribution, bool, error)
	GetAIGatewayPolicyForTenant(ctx context.Context, tenantID string) (models.AIGatewayPolicy, bool, error)
	UpsertAIGatewayPolicyForTenant(ctx context.Context, tenantID string, actor string, request models.UpsertAIGatewayPolicyRequest) (models.AIGatewayPolicy, error)
	ListAITriageRequestsForTenant(ctx context.Context, tenantID string, requestKind string, limit int) ([]models.AITriageRequest, error)
	CreateAITriageSummaryForTenant(ctx context.Context, tenantID string, actor string, request models.CreateAITriageSummaryRequest) (models.AITriageRequest, error)
	ListAITriageEvaluationsForTenant(ctx context.Context, tenantID string, verdict string, triageRequestID string, limit int) ([]models.AITriageEvaluation, error)
	RecordAITriageEvaluationForTenant(ctx context.Context, tenantID string, actor string, request models.RecordAITriageEvaluationRequest) (models.AITriageEvaluation, error)
	ListPoliciesForTenant(ctx context.Context, tenantID string, limit int) ([]models.Policy, error)
	GetPolicyForTenant(ctx context.Context, tenantID string, policyID string) (models.Policy, bool, error)
	CreatePolicyForTenant(ctx context.Context, tenantID string, request models.CreatePolicyRequest) (models.Policy, error)
	UpdatePolicyForTenant(ctx context.Context, tenantID string, policyID string, request models.UpdatePolicyRequest) (models.Policy, bool, error)
	ListPolicyVersionsForTenant(ctx context.Context, tenantID string, policyID string, limit int) ([]models.PolicyVersion, error)
	RollbackPolicyForTenant(ctx context.Context, tenantID string, policyID string, versionNumber int64, updatedBy string) (models.Policy, bool, error)
	ListPolicyApprovalsForTenant(ctx context.Context, tenantID string, limit int) ([]models.PolicyApproval, error)
	DecidePolicyApproval(ctx context.Context, tenantID string, approvalID string, approved bool, decidedBy string, reason string) (models.PolicyApproval, bool, error)
	ListRemediationsForTenant(ctx context.Context, tenantID string, limit int) ([]models.RemediationAction, error)
	GetRemediationForTenant(ctx context.Context, tenantID string, remediationID string) (models.RemediationAction, bool, error)
	CreateRemediationForTenant(ctx context.Context, tenantID string, request models.CreateRemediationRequest) (models.RemediationAction, error)
	TransitionRemediationForTenant(ctx context.Context, tenantID string, remediationID string, request models.TransitionRemediationRequest) (models.RemediationAction, bool, error)
	ListRemediationActivityForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationActivity, error)
	CreateRemediationCommentForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.CreateRemediationCommentRequest) (models.RemediationActivity, error)
	ListRemediationEvidenceForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationEvidence, error)
	CreateRemediationEvidenceForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.CreateRemediationEvidenceRequest) (models.RemediationEvidence, error)
	ListRemediationVerificationsForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationVerification, error)
	RequestRemediationRetestForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.CreateRetestRequest) (models.RemediationVerification, models.ScanJob, error)
	RecordRemediationVerificationForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.RecordRemediationVerificationRequest) (models.RemediationVerification, bool, error)
	ListRemediationExceptionsForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationException, error)
	CreateRemediationExceptionForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.CreateRemediationExceptionRequest) (models.RemediationException, error)
	DecideRemediationExceptionForTenant(ctx context.Context, tenantID string, exceptionID string, approved bool, actor string, reason string) (models.RemediationException, bool, error)
	ListRemediationTicketLinksForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationTicketLink, error)
	CreateRemediationTicketLinkForTenant(ctx context.Context, tenantID string, remediationID string, request models.CreateRemediationTicketLinkRequest) (models.RemediationTicketLink, error)
	SyncRemediationTicketLinkForTenant(ctx context.Context, tenantID string, remediationID string, ticketID string, request models.SyncRemediationTicketLinkRequest) (models.RemediationTicketLink, bool, error)
	ListRemediationAssignmentRequestsForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationAssignmentRequest, error)
	CreateRemediationAssignmentRequestForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.CreateRemediationAssignmentRequest) (models.RemediationAssignmentRequest, error)
	DecideRemediationAssignmentRequestForTenant(ctx context.Context, tenantID string, requestID string, approved bool, actor string, reason string) (models.RemediationAssignmentRequest, bool, error)
	ListNotificationEventsForTenant(ctx context.Context, tenantID string, limit int) ([]models.NotificationEvent, error)
	AcknowledgeNotificationEventForTenant(ctx context.Context, tenantID string, notificationID string, actor string) (models.NotificationEvent, bool, error)
	SweepRemediationEscalationsForTenant(ctx context.Context, tenantID string, actor string) (models.NotificationSweepResult, error)
}

func New(cfg config.Config, store apiStore) *Server {
	uiDistPath := strings.TrimSpace(cfg.UIDistPath)
	uiDistEnabled := hasUIDist(uiDistPath)

	server := &Server{
		cfg:           cfg,
		store:         store,
		uiDistPath:    uiDistPath,
		uiDistEnabled: uiDistEnabled,
	}

	webFS, err := fs.Sub(staticAssets, "static")
	if err != nil {
		panic("embedded web ui assets are missing")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.handleHealth)
	mux.HandleFunc("/readyz", server.handleReady)
	mux.HandleFunc("/metrics", server.handleMetrics)
	mux.HandleFunc("/auth/oidc/start", server.handleOIDCStart)
	mux.HandleFunc("/auth/oidc/callback", server.handleOIDCCallback)
	mux.HandleFunc("/auth/logout", server.handleLogout)
	mux.HandleFunc("/v1/meta", server.withUserAuth(auth.PermissionMetaRead, "meta.read", "service", server.handleMeta))
	mux.HandleFunc("/v1/auth/me", server.withUserAuth(auth.PermissionSessionRead, "session.read", "session", server.handleSession))
	mux.HandleFunc("/v1/auth/tokens", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionTokensRead,
		http.MethodPost: auth.PermissionTokensWrite,
	}, "auth_tokens", "api_token", server.handleAuthTokens))
	mux.HandleFunc("/v1/auth/tokens/", server.withUserAuth(auth.PermissionTokensWrite, "auth_token.disable", "api_token", server.handleAuthTokenByID))
	mux.HandleFunc("/v1/audit-events", server.withUserAuth(auth.PermissionAuditRead, "audit.list", "audit_event", server.handleAuditEvents))
	mux.HandleFunc("/v1/scan-jobs", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionScanJobsRead,
		http.MethodPost: auth.PermissionScanJobsWrite,
	}, "scan_jobs", "scan_job", server.handleScanJobs))
	mux.HandleFunc("/v1/scan-jobs/", server.withUserAuth(auth.PermissionScanJobsRead, "scan_job.read", "scan_job", server.handleScanJobByID))
	mux.HandleFunc("/v1/scan-presets", server.withUserAuth(auth.PermissionScanJobsRead, "scan_presets.list", "scan_preset", server.handleScanPresets))
	mux.HandleFunc("/v1/scan-engine-controls", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet: auth.PermissionPoliciesRead,
	}, "scan_engine_controls", "scan_engine_control", server.handleScanEngineControls))
	mux.HandleFunc("/v1/scan-engine-controls/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodPut: auth.PermissionPoliciesWrite,
	}, "scan_engine_control", "scan_engine_control", server.handleScanEngineControlRoute))
	mux.HandleFunc("/v1/web-targets", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionScanJobsRead,
		http.MethodPost: auth.PermissionScanJobsWrite,
	}, "web_targets", "web_target", server.handleWebTargets))
	mux.HandleFunc("/v1/web-targets/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:    auth.PermissionScanJobsRead,
		http.MethodPut:    auth.PermissionScanJobsWrite,
		http.MethodDelete: auth.PermissionScanJobsWrite,
		http.MethodPost:   auth.PermissionScanJobsWrite,
	}, "web_target", "web_target", server.handleWebTargetRoute))
	mux.HandleFunc("/v1/web-auth-profiles", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionScanJobsRead,
		http.MethodPost: auth.PermissionScanJobsWrite,
	}, "web_auth_profiles", "web_auth_profile", server.handleWebAuthProfiles))
	mux.HandleFunc("/v1/web-auth-profiles/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:    auth.PermissionScanJobsRead,
		http.MethodPut:    auth.PermissionScanJobsWrite,
		http.MethodDelete: auth.PermissionScanJobsWrite,
	}, "web_auth_profile", "web_auth_profile", server.handleWebAuthProfileRoute))
	mux.HandleFunc("/v1/scan-targets", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionScanJobsRead,
		http.MethodPost: auth.PermissionScanJobsWrite,
	}, "scan_targets", "scan_target", server.handleScanTargets))
	mux.HandleFunc("/v1/scan-targets/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:    auth.PermissionScanJobsRead,
		http.MethodPut:    auth.PermissionScanJobsWrite,
		http.MethodDelete: auth.PermissionScanJobsWrite,
		http.MethodPost:   auth.PermissionScanJobsWrite,
	}, "scan_target", "scan_target", server.handleScanTargetRoute))
	mux.HandleFunc("/v1/ingestion/sources", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionScanJobsRead,
		http.MethodPost: auth.PermissionScanJobsWrite,
	}, "ingestion_sources", "ingestion_source", server.handleIngestionSources))
	mux.HandleFunc("/v1/ingestion/sources/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:    auth.PermissionScanJobsRead,
		http.MethodPut:    auth.PermissionScanJobsWrite,
		http.MethodDelete: auth.PermissionScanJobsWrite,
		http.MethodPost:   auth.PermissionScanJobsWrite,
	}, "ingestion_source", "ingestion_source", server.handleIngestionSourceRoute))
	mux.HandleFunc("/v1/ingestion/events", server.withUserAuth(auth.PermissionScanJobsRead, "ingestion_events.list", "ingestion_event", server.handleIngestionEvents))
	mux.HandleFunc("/v1/events", server.withUserAuth(auth.PermissionScanJobsRead, "events.list", "platform_event", server.handlePlatformEvents))
	mux.HandleFunc("/v1/integrations/webhooks", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "webhook_integrations", "webhook_integration", server.handleWebhookIntegrations))
	mux.HandleFunc("/v1/integrations/webhooks/dispatch", server.withUserAuth(auth.PermissionPoliciesWrite, "webhook_delivery.dispatch", "webhook_dispatch", server.handleWebhookDispatch))
	mux.HandleFunc("/v1/integrations/webhooks/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPut:  auth.PermissionPoliciesWrite,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "webhook_integration", "webhook_integration", server.handleWebhookIntegrationRoute))
	mux.HandleFunc("/v1/tenant/operations", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet: auth.PermissionScanJobsRead,
		http.MethodPut: auth.PermissionPoliciesWrite,
	}, "tenant_operations", "tenant", server.handleTenantOperations))
	mux.HandleFunc("/v1/tenant/execution-controls", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet: auth.PermissionPoliciesRead,
		http.MethodPut: auth.PermissionPoliciesWrite,
	}, "tenant_execution_controls", "tenant", server.handleTenantExecutionControls))
	mux.HandleFunc("/v1/config", server.withUserAuth(auth.PermissionPoliciesRead, "tenant_config.list", "tenant_config", server.handleTenantConfig))
	mux.HandleFunc("/v1/config/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:    auth.PermissionPoliciesRead,
		http.MethodPut:    auth.PermissionPoliciesWrite,
		http.MethodDelete: auth.PermissionPoliciesWrite,
	}, "tenant_config", "tenant_config", server.handleTenantConfigRoute))
	mux.HandleFunc("/v1/workload-identities/workers/issue", server.withUserAuth(auth.PermissionPoliciesWrite, "workload_identity.issue", "workload_identity", server.handleIssueWorkerIdentity))
	mux.HandleFunc("/v1/workload-identities/workers/certificates", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "workload_certificates", "workload_certificate", server.handleWorkerCertificates))
	mux.HandleFunc("/v1/workload-identities/workers/certificates/", server.withUserAuth(auth.PermissionPoliciesWrite, "workload_certificate.revoke", "workload_certificate", server.handleWorkerCertificateRoute))
	mux.HandleFunc("/v1/trust/ca-bundle", server.withUserAuth(auth.PermissionPoliciesRead, "trust.ca_bundle", "trust", server.handleCABundle))
	mux.HandleFunc("/v1/kms/keys", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "kms_keys", "kms_key", server.handleKMSKeys))
	mux.HandleFunc("/v1/kms/encrypt", server.withUserAuth(auth.PermissionPoliciesWrite, "kms.encrypt", "kms_operation", server.handleKMSEncrypt))
	mux.HandleFunc("/v1/kms/decrypt", server.withUserAuth(auth.PermissionPoliciesWrite, "kms.decrypt", "kms_operation", server.handleKMSDecrypt))
	mux.HandleFunc("/v1/kms/sign", server.withUserAuth(auth.PermissionPoliciesWrite, "kms.sign", "kms_operation", server.handleKMSSign))
	mux.HandleFunc("/v1/kms/verify", server.withUserAuth(auth.PermissionPoliciesWrite, "kms.verify", "kms_operation", server.handleKMSVerify))
	mux.HandleFunc("/v1/secrets/references", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "secret_references", "secret_reference", server.handleSecretReferences))
	mux.HandleFunc("/v1/secrets/references/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:    auth.PermissionPoliciesRead,
		http.MethodPut:    auth.PermissionPoliciesWrite,
		http.MethodDelete: auth.PermissionPoliciesWrite,
	}, "secret_reference", "secret_reference", server.handleSecretReferenceRoute))
	mux.HandleFunc("/v1/secrets/leases", server.withUserAuth(auth.PermissionPoliciesRead, "secret_leases.list", "secret_lease", server.handleSecretLeases))
	mux.HandleFunc("/v1/secrets/leases/issue", server.withUserAuth(auth.PermissionPoliciesWrite, "secret_lease.issue", "secret_lease", server.handleSecretLeaseIssue))
	mux.HandleFunc("/v1/secrets/leases/", server.withUserAuth(auth.PermissionPoliciesWrite, "secret_lease.revoke", "secret_lease", server.handleSecretLeaseRoute))
	mux.HandleFunc("/ingest/webhooks/", server.handleIngestionWebhook)
	mux.HandleFunc("/v1/findings", server.withUserAuth(auth.PermissionFindingsRead, "findings.list", "finding", server.handleFindings))
	mux.HandleFunc("/v1/search/findings", server.withUserAuth(auth.PermissionFindingsRead, "findings.search", "finding", server.handleFindingSearch))
	mux.HandleFunc("/v1/evidence", server.withUserAuth(auth.PermissionFindingsRead, "evidence.list", "evidence", server.handleEvidence))
	mux.HandleFunc("/v1/evidence/retention/runs", server.withUserAuth(auth.PermissionPoliciesRead, "evidence_retention_runs.list", "evidence_retention_run", server.handleEvidenceRetentionRuns))
	mux.HandleFunc("/v1/evidence/retention/run", server.withUserAuth(auth.PermissionPoliciesWrite, "evidence_retention.run", "evidence_retention_run", server.handleEvidenceRetentionRun))
	mux.HandleFunc("/v1/evidence/", server.withUserAuth(auth.PermissionFindingsRead, "evidence.read", "evidence", server.handleEvidenceRoute))
	mux.HandleFunc("/v1/backups/snapshots", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "backup_snapshots", "backup_snapshot", server.handleBackupSnapshots))
	mux.HandleFunc("/v1/backups/recovery-drills", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "recovery_drills", "recovery_drill", server.handleRecoveryDrills))
	mux.HandleFunc("/v1/findings/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionFindingsRead,
		http.MethodPost: auth.PermissionRemediationsWrite,
	}, "finding", "finding", server.handleFindingRoute))
	mux.HandleFunc("/v1/risk/summary", server.withUserAuth(auth.PermissionFindingsRead, "risk.summary", "risk_summary", server.handleRiskSummary))
	mux.HandleFunc("/v1/reports/summary", server.withUserAuth(auth.PermissionFindingsRead, "reports.summary", "report", server.handleReportSummary))
	mux.HandleFunc("/v1/reports/findings/export", server.withUserAuth(auth.PermissionFindingsRead, "reports.findings_export", "report", server.handleFindingsExport))
	mux.HandleFunc("/v1/assets", server.withUserAuth(auth.PermissionAssetsRead, "assets.list", "asset", server.handleAssets))
	mux.HandleFunc("/v1/assets/context-events", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionAssetsRead,
		http.MethodPost: auth.PermissionAssetsWrite,
	}, "asset_context_events", "asset", server.handleAssetContextEvents))
	mux.HandleFunc("/v1/assets/apis", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionAssetsRead,
		http.MethodPost: auth.PermissionAssetsWrite,
	}, "api_assets", "api_asset", server.handleAPIAssets))
	mux.HandleFunc("/v1/assets/graphql", server.withUserAuth(auth.PermissionAssetsWrite, "graphql_assets.import", "api_asset", server.handleGraphQLAssets))
	mux.HandleFunc("/v1/assets/apis/", server.withUserAuth(auth.PermissionAssetsRead, "api_asset.endpoints", "api_asset", server.handleAPIAssetRoute))
	mux.HandleFunc("/v1/assets/external", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionAssetsRead,
		http.MethodPost: auth.PermissionAssetsWrite,
	}, "external_assets", "external_asset", server.handleExternalAssets))
	mux.HandleFunc("/v1/assets/external/sync", server.withUserAuth(auth.PermissionAssetsWrite, "external_assets.sync", "external_asset", server.handleExternalAssetSync))
	mux.HandleFunc("/v1/assets/sync", server.withUserAuth(auth.PermissionAssetsWrite, "assets.sync", "asset", server.handleAssetSync))
	mux.HandleFunc("/v1/assets/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionAssetsRead,
		http.MethodPut:  auth.PermissionAssetsWrite,
		http.MethodPost: auth.PermissionAssetsWrite,
	}, "asset", "asset", server.handleAssetRoute))
	mux.HandleFunc("/v1/validation-engagements", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "validation_engagements", "validation_engagement", server.handleValidationEngagements))
	mux.HandleFunc("/v1/validation-engagements/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPut:  auth.PermissionPoliciesWrite,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "validation_engagement", "validation_engagement", server.handleValidationEngagementRoute))
	mux.HandleFunc("/v1/validation/envelopes/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPut:  auth.PermissionPoliciesWrite,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "validation_execution_envelope", "validation_execution_envelope", server.handleValidationEnvelopeRoute))
	mux.HandleFunc("/v1/validation/plan-steps", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "validation_plan_steps", "validation_plan_step", server.handleValidationPlanSteps))
	mux.HandleFunc("/v1/validation/plan-steps/", server.withUserAuth(auth.PermissionPoliciesWrite, "validation_plan_step.decide", "validation_plan_step", server.handleValidationPlanStepRoute))
	mux.HandleFunc("/v1/validation/attack-traces", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "validation_attack_traces", "validation_attack_trace", server.handleValidationAttackTraces))
	mux.HandleFunc("/v1/validation/manual-tests", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "validation_manual_tests", "validation_manual_test", server.handleValidationManualTests))
	mux.HandleFunc("/v1/validation/manual-tests/", server.withUserAuth(auth.PermissionPoliciesWrite, "validation_manual_test.update", "validation_manual_test", server.handleValidationManualTestRoute))
	mux.HandleFunc("/v1/design-reviews", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionAssetsRead,
		http.MethodPost: auth.PermissionAssetsWrite,
	}, "design_reviews", "design_review", server.handleDesignReviews))
	mux.HandleFunc("/v1/design-reviews/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionAssetsRead,
		http.MethodPut:  auth.PermissionAssetsWrite,
		http.MethodPost: auth.PermissionAssetsWrite,
	}, "design_review", "design_review", server.handleDesignReviewRoute))
	mux.HandleFunc("/v1/runtime/telemetry/connectors", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionAssetsRead,
		http.MethodPost: auth.PermissionAssetsWrite,
	}, "runtime_telemetry_connectors", "runtime_telemetry_connector", server.handleRuntimeTelemetryConnectors))
	mux.HandleFunc("/v1/runtime/telemetry/connectors/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet: auth.PermissionAssetsRead,
		http.MethodPut: auth.PermissionAssetsWrite,
	}, "runtime_telemetry_connector", "runtime_telemetry_connector", server.handleRuntimeTelemetryConnectorRoute))
	mux.HandleFunc("/v1/runtime/telemetry/events", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionFindingsRead,
		http.MethodPost: auth.PermissionAssetsWrite,
	}, "runtime_telemetry_events", "runtime_telemetry_event", server.handleRuntimeTelemetryEvents))
	mux.HandleFunc("/v1/runtime/telemetry/enrichments", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionFindingsRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "runtime_telemetry_enrichments", "runtime_finding_enrichment", server.handleRuntimeTelemetryEnrichments))
	mux.HandleFunc("/v1/compliance/mappings", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionFindingsRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "compliance_mappings", "compliance_mapping", server.handleComplianceMappings))
	mux.HandleFunc("/v1/compliance/mappings/", server.withUserAuth(auth.PermissionPoliciesWrite, "compliance_mapping.update", "compliance_mapping", server.handleComplianceMappingRoute))
	mux.HandleFunc("/v1/compliance/summary", server.withUserAuth(auth.PermissionFindingsRead, "compliance.summary", "compliance_summary", server.handleComplianceSummary))
	mux.HandleFunc("/v1/compliance/owasp/sync", server.withUserAuth(auth.PermissionPoliciesWrite, "compliance.owasp_sync", "compliance_owasp_mapping", server.handleComplianceOWASPSync))
	mux.HandleFunc("/v1/compliance/samm/metrics", server.withUserAuth(auth.PermissionFindingsRead, "compliance.samm_metrics", "compliance_samm_metrics", server.handleComplianceSAMMMetrics))
	mux.HandleFunc("/v1/detection/rulepacks", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "detection_rulepacks", "detection_rulepack", server.handleDetectionRulepacks))
	mux.HandleFunc("/v1/detection/rulepacks/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPut:  auth.PermissionPoliciesWrite,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "detection_rulepack", "detection_rulepack", server.handleDetectionRulepackRoute))
	mux.HandleFunc("/v1/detection/distributions", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "detection_distributions", "detection_distribution", server.handleDetectionDistributions))
	mux.HandleFunc("/v1/detection/distributions/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet: auth.PermissionPoliciesRead,
		http.MethodPut: auth.PermissionPoliciesWrite,
	}, "detection_distribution", "detection_distribution", server.handleDetectionDistributionRoute))
	mux.HandleFunc("/v1/ai/policy", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet: auth.PermissionPoliciesRead,
		http.MethodPut: auth.PermissionPoliciesWrite,
	}, "ai_policy", "ai_policy", server.handleAIPolicy))
	mux.HandleFunc("/v1/ai/triage/requests", server.withUserAuth(auth.PermissionFindingsRead, "ai_triage_requests.list", "ai_triage_request", server.handleAITriageRequests))
	mux.HandleFunc("/v1/ai/triage/summaries", server.withUserAuth(auth.PermissionPoliciesWrite, "ai_triage_summary.create", "ai_triage_request", server.handleAITriageSummaries))
	mux.HandleFunc("/v1/ai/triage/evaluations", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionFindingsRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "ai_triage_evaluations", "ai_triage_evaluation", server.handleAITriageEvaluations))
	mux.HandleFunc("/v1/policies", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "policies", "policy", server.handlePolicies))
	mux.HandleFunc("/v1/policies/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPut:  auth.PermissionPoliciesWrite,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "policy", "policy", server.handlePolicyRoute))
	mux.HandleFunc("/v1/policy-approvals", server.withUserAuth(auth.PermissionPoliciesRead, "policy_approvals.list", "policy_approval", server.handlePolicyApprovals))
	mux.HandleFunc("/v1/policy-approvals/", server.withUserAuth(auth.PermissionPoliciesWrite, "policy_approval.decide", "policy_approval", server.handlePolicyApprovalDecision))
	mux.HandleFunc("/v1/remediations", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionRemediationsRead,
		http.MethodPost: auth.PermissionRemediationsWrite,
	}, "remediations", "remediation", server.handleRemediations))
	mux.HandleFunc("/v1/remediations/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionRemediationsRead,
		http.MethodPost: auth.PermissionRemediationsWrite,
	}, "remediation", "remediation", server.handleRemediationRoute))
	mux.HandleFunc("/v1/remediation-exceptions/", server.withUserAuth(auth.PermissionRemediationsWrite, "remediation_exception.decide", "remediation_exception", server.handleRemediationExceptionDecision))
	mux.HandleFunc("/v1/remediation-assignments/", server.withUserAuth(auth.PermissionRemediationsWrite, "remediation_assignment.decide", "remediation_assignment", server.handleRemediationAssignmentDecision))
	mux.HandleFunc("/v1/notifications", server.withUserAuth(auth.PermissionRemediationsRead, "notifications.list", "notification", server.handleNotifications))
	mux.HandleFunc("/v1/notifications/", server.withUserAuth(auth.PermissionRemediationsWrite, "notification.ack", "notification", server.handleNotificationRoute))
	mux.HandleFunc("/v1/remediation-escalations/sweep", server.withUserAuth(auth.PermissionRemediationsWrite, "remediation_escalations.sweep", "notification", server.handleRemediationEscalationSweep))
	mux.HandleFunc("/v1/workers/register", server.withWorkerAuth(server.handleWorkerRegister))
	mux.HandleFunc("/v1/workers/heartbeat", server.withWorkerAuth(server.handleWorkerHeartbeat))
	if server.uiDistEnabled {
		mux.HandleFunc("/ui", server.handleUIDistRoot)
		mux.HandleFunc("/ui/", server.handleUIDist)
	}
	mux.HandleFunc("/app", server.handleAppRoot)
	mux.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.FS(webFS))))
	mux.HandleFunc("/", server.handleRoot)

	server.httpServer = &http.Server{
		Addr:              cfg.APIBindAddress,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return server
}

func (s *Server) ListenAndServe() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "control-plane-api",
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	if err := s.store.Ping(r.Context()); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "database_unavailable", "database is not reachable")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ready",
		"service": "control-plane-api",
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	metrics, err := s.store.GetOperationalMetrics(r.Context())
	if err != nil {
		http.Error(w, "metrics_unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w,
		"# HELP uss_workers_total total registered workers\n"+
			"# TYPE uss_workers_total gauge\n"+
			"uss_workers_total %d\n"+
			"# HELP uss_workers_healthy workers with a valid heartbeat\n"+
			"# TYPE uss_workers_healthy gauge\n"+
			"uss_workers_healthy %d\n"+
			"# HELP uss_scan_jobs_total total scan jobs\n"+
			"# TYPE uss_scan_jobs_total gauge\n"+
			"uss_scan_jobs_total %d\n"+
			"# HELP uss_scan_jobs_queued queued scan jobs\n"+
			"# TYPE uss_scan_jobs_queued gauge\n"+
			"uss_scan_jobs_queued %d\n"+
			"# HELP uss_scan_jobs_running running scan jobs\n"+
			"# TYPE uss_scan_jobs_running gauge\n"+
			"uss_scan_jobs_running %d\n"+
			"# HELP uss_scan_jobs_completed completed scan jobs\n"+
			"# TYPE uss_scan_jobs_completed gauge\n"+
			"uss_scan_jobs_completed %d\n"+
			"# HELP uss_scan_jobs_failed failed scan jobs\n"+
			"# TYPE uss_scan_jobs_failed gauge\n"+
			"uss_scan_jobs_failed %d\n"+
			"# HELP uss_scan_targets_total total saved scan targets\n"+
			"# TYPE uss_scan_targets_total gauge\n"+
			"uss_scan_targets_total %d\n"+
			"# HELP uss_ingestion_sources_total total ingestion sources\n"+
			"# TYPE uss_ingestion_sources_total gauge\n"+
			"uss_ingestion_sources_total %d\n"+
			"# HELP uss_ingestion_events_total total ingestion events\n"+
			"# TYPE uss_ingestion_events_total gauge\n"+
			"uss_ingestion_events_total %d\n"+
			"# HELP uss_platform_events_total total platform events\n"+
			"# TYPE uss_platform_events_total gauge\n"+
			"uss_platform_events_total %d\n",
		metrics.WorkersTotal,
		metrics.WorkersHealthy,
		metrics.ScanJobsTotal,
		metrics.ScanJobsQueued,
		metrics.ScanJobsRunning,
		metrics.ScanJobsCompleted,
		metrics.ScanJobsFailed,
		metrics.ScanTargetsTotal,
		metrics.IngestionSources,
		metrics.IngestionEvents,
		metrics.PlatformEventsTotal,
	)
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	s.writeJSON(w, http.StatusOK, models.ServiceMetadata{
		Name:                      "unified-security-scanner-control-plane",
		Version:                   s.cfg.BuildVersion,
		SchedulerIntervalSeconds:  int64(s.cfg.SchedulerInterval.Seconds()),
		WorkerHeartbeatTTLSeconds: int64(s.cfg.WorkerHeartbeatTTL.Seconds()),
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	s.writeJSON(w, http.StatusOK, models.AuthSession{
		Principal:      principal,
		SSOEnabled:     s.oidcConfigured(),
		OIDCIssuerURL:  s.cfg.OIDCIssuerURL,
		OIDCClientID:   s.cfg.OIDCClientID,
		BootstrapToken: auth.IsBootstrapToken(principal),
	})
}

func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	events, err := s.store.ListAuditEvents(r.Context(), principal.OrganizationID, 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_audit_events_failed", "audit events could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": events,
	})
}

func (s *Server) handleAuthTokens(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		tokens, err := s.store.ListAPITokens(r.Context(), principal.OrganizationID, 200)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_api_tokens_failed", "api tokens could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": tokens,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateAPITokenRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		if strings.TrimSpace(request.TokenName) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "token_name is required")
			return
		}
		if request.ExpiresAt != nil && !request.ExpiresAt.After(time.Now().UTC()) {
			s.writeError(w, http.StatusBadRequest, "validation_error", "expires_at must be in the future")
			return
		}

		createdToken, err := s.store.CreateAPIToken(r.Context(), principal, request)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidScope) {
				s.writeError(w, http.StatusBadRequest, "invalid_scope", "the requested token scopes are not allowed for the current role")
				return
			}

			s.writeError(w, http.StatusInternalServerError, "create_api_token_failed", "api token could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, createdToken)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleAuthTokenByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/auth/tokens/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "disable" {
		s.writeError(w, http.StatusNotFound, "auth_token_route_not_found", "the requested api token route was not found")
		return
	}

	token, found, err := s.store.DisableAPIToken(r.Context(), principal.OrganizationID, parts[0])
	if err != nil {
		if errors.Is(err, jobs.ErrProtectedToken) {
			s.writeError(w, http.StatusConflict, "protected_api_token", "the bootstrap token cannot be disabled while it is the only guaranteed access path")
			return
		}

		s.writeError(w, http.StatusInternalServerError, "disable_api_token_failed", "api token could not be disabled")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "api_token_not_found", "api token was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, token)
}

func (s *Server) handleScanJobs(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		jobsList, err := s.store.ListForTenant(r.Context(), principal.OrganizationID, 100)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_scan_jobs_failed", "scan jobs could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": jobsList,
		})
	case http.MethodPost:
		s.createScanJob(w, r, principal)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleScanJobByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	jobID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/scan-jobs/"))
	if jobID == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_job_id", "scan job id is required")
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	job, found, err := s.store.GetForTenant(r.Context(), principal.OrganizationID, jobID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "get_scan_job_failed", "scan job could not be loaded")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "scan_job_not_found", "scan job was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleScanPresets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	items, err := s.store.ListScanPresetsForTenant(r.Context(), principal.OrganizationID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_scan_presets_failed", "scan presets could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

func (s *Server) handleScanEngineControls(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
			return
		}
		limit = parsed
	}

	targetKind := strings.TrimSpace(r.URL.Query().Get("target_kind"))
	items, err := s.store.ListScanEngineControlsForTenant(r.Context(), principal.OrganizationID, targetKind, limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_scan_engine_controls_failed", "scan engine controls could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

func (s *Server) handleScanEngineControlRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	adapterID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/scan-engine-controls/"))
	if adapterID == "" || strings.Contains(adapterID, "/") {
		s.writeError(w, http.StatusNotFound, "scan_engine_control_not_found", "the requested scan engine control route was not found")
		return
	}

	defer r.Body.Close()

	var request models.UpsertScanEngineControlRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	item, err := s.store.UpsertScanEngineControlForTenant(r.Context(), principal.OrganizationID, adapterID, principal.Email, request)
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "required") || strings.Contains(lower, "must be greater than or equal to zero") {
			s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
			return
		}
		s.writeError(w, http.StatusInternalServerError, "upsert_scan_engine_control_failed", "scan engine control could not be saved")
		return
	}

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleWebTargets(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}

		targetType := strings.TrimSpace(r.URL.Query().Get("target_type"))
		items, err := s.store.ListWebTargetsForTenant(r.Context(), principal.OrganizationID, targetType, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_web_targets_failed", "web targets could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateWebTargetRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.BaseURL) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "base_url is required")
			return
		}

		item, err := s.store.CreateWebTargetForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "required") {
				s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_web_target_failed", "web target could not be created")
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleWebTargetRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/web-targets/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "web_target_route_not_found", "the requested web target route was not found")
		return
	}

	targetID := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			item, found, err := s.store.GetWebTargetForTenant(r.Context(), principal.OrganizationID, targetID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_web_target_failed", "web target could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "web_target_not_found", "web target was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpdateWebTargetRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			item, found, err := s.store.UpdateWebTargetForTenant(r.Context(), principal.OrganizationID, targetID, principal.Email, request)
			if err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "required") {
					s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
					return
				}
				s.writeError(w, http.StatusInternalServerError, "update_web_target_failed", "web target could not be updated")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "web_target_not_found", "web target was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		case http.MethodDelete:
			deleted, err := s.store.DeleteWebTargetForTenant(r.Context(), principal.OrganizationID, targetID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "delete_web_target_failed", "web target could not be deleted")
				return
			}
			if !deleted {
				s.writeError(w, http.StatusNotFound, "web_target_not_found", "web target was not found")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	if len(parts) == 2 && parts[1] == "crawl-policy" {
		switch r.Method {
		case http.MethodGet:
			item, found, err := s.store.GetWebCrawlPolicyForTenant(r.Context(), principal.OrganizationID, targetID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_web_crawl_policy_failed", "web crawl policy could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "web_crawl_policy_not_found", "web crawl policy was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpsertWebCrawlPolicyRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			item, err := s.store.UpsertWebCrawlPolicyForTenant(r.Context(), principal.OrganizationID, targetID, principal.Email, request)
			if err != nil {
				switch {
				case errors.Is(err, jobs.ErrWebTargetNotFound):
					s.writeError(w, http.StatusNotFound, "web_target_not_found", "web target was not found")
					return
				case errors.Is(err, jobs.ErrWebAuthProfileNotFound):
					s.writeError(w, http.StatusBadRequest, "validation_error", "auth_profile_id is invalid")
					return
				case strings.Contains(strings.ToLower(err.Error()), "must be greater than or equal to zero"):
					s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
					return
				default:
					s.writeError(w, http.StatusInternalServerError, "upsert_web_crawl_policy_failed", "web crawl policy could not be saved")
					return
				}
			}
			s.writeJSON(w, http.StatusOK, item)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	if len(parts) == 2 && parts[1] == "run" {
		if r.Method != http.MethodPost {
			s.writeMethodNotAllowed(w)
			return
		}

		defer r.Body.Close()

		var request models.RunWebTargetRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		target, job, found, err := s.store.RunWebTargetForTenant(r.Context(), principal.OrganizationID, targetID, principal.Email, request)
		if err != nil {
			switch {
			case errors.Is(err, jobs.ErrWebAuthProfileNotFound):
				s.writeError(w, http.StatusBadRequest, "web_auth_profile_not_found", "configured web auth profile was not found")
				return
			case errors.Is(err, jobs.ErrWebAuthProfileDisabled):
				s.writeError(w, http.StatusConflict, "web_auth_profile_disabled", "configured web auth profile is disabled")
				return
			case errors.Is(err, jobs.ErrWebRuntimeToolNotAllowed):
				s.writeError(w, http.StatusBadRequest, "web_runtime_tool_not_allowed", err.Error())
				return
			}
			if s.writeValidationEngagementExecutionError(w, err) {
				return
			}
			var denied *jobs.PolicyDeniedError
			if errors.As(err, &denied) {
				s.writeJSON(w, http.StatusForbidden, map[string]any{
					"code":      "policy_denied",
					"message":   denied.Error(),
					"policy_id": denied.PolicyID,
					"rule_hits": denied.RuleHits,
				})
				return
			}
			var engineDenied *jobs.EngineControlDeniedError
			if errors.As(err, &engineDenied) {
				s.writeJSON(w, http.StatusForbidden, map[string]any{
					"code":        "engine_control_denied",
					"message":     engineDenied.Error(),
					"adapter_id":  strings.TrimSpace(engineDenied.AdapterID),
					"target_kind": strings.TrimSpace(engineDenied.TargetKind),
				})
				return
			}
			var limitExceeded *jobs.TenantLimitExceededError
			if errors.As(err, &limitExceeded) {
				s.writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"code":    "tenant_limit_exceeded",
					"message": limitExceeded.Error(),
					"metric":  limitExceeded.Metric,
					"limit":   limitExceeded.Limit,
					"current": limitExceeded.Current,
				})
				return
			}
			var controlViolation *jobs.ExecutionControlViolationError
			if errors.As(err, &controlViolation) {
				s.writeJSON(w, http.StatusConflict, map[string]any{
					"code":        strings.TrimSpace(controlViolation.Code),
					"message":     controlViolation.Error(),
					"reason":      strings.TrimSpace(controlViolation.Reason),
					"window_id":   strings.TrimSpace(controlViolation.WindowID),
					"window_name": strings.TrimSpace(controlViolation.WindowName),
				})
				return
			}
			s.writeError(w, http.StatusInternalServerError, "run_web_target_failed", "web target could not be executed")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "web_target_not_found", "web target was not found")
			return
		}

		s.writeJSON(w, http.StatusCreated, map[string]any{
			"target": target,
			"job":    job,
		})
		return
	}

	if len(parts) == 2 && parts[1] == "coverage-runs" {
		switch r.Method {
		case http.MethodGet:
			limit := 200
			if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
				parsed, err := strconv.Atoi(raw)
				if err != nil || parsed <= 0 {
					s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
					return
				}
				limit = parsed
			}
			items, err := s.store.ListWebRuntimeCoverageRunsForTenant(r.Context(), principal.OrganizationID, targetID, limit)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "list_web_runtime_coverage_runs_failed", "web runtime coverage runs could not be loaded")
				return
			}
			s.writeJSON(w, http.StatusOK, map[string]any{
				"items": items,
			})
		case http.MethodPost:
			defer r.Body.Close()

			var request models.CreateWebRuntimeCoverageRunRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			item, err := s.store.CreateWebRuntimeCoverageRunForTenant(r.Context(), principal.OrganizationID, targetID, principal.Email, request)
			if err != nil {
				switch {
				case errors.Is(err, jobs.ErrWebTargetNotFound):
					s.writeError(w, http.StatusNotFound, "web_target_not_found", "web target was not found")
					return
				case strings.Contains(strings.ToLower(err.Error()), "must be greater than or equal to zero"):
					s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
					return
				default:
					s.writeError(w, http.StatusInternalServerError, "create_web_runtime_coverage_run_failed", "web runtime coverage run could not be created")
					return
				}
			}
			s.writeJSON(w, http.StatusCreated, item)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	if len(parts) == 2 && parts[1] == "coverage-status" {
		if r.Method != http.MethodGet {
			s.writeMethodNotAllowed(w)
			return
		}

		item, err := s.store.GetWebCoverageStatusForTenant(r.Context(), principal.OrganizationID, targetID)
		if err != nil {
			if errors.Is(err, jobs.ErrWebTargetNotFound) {
				s.writeError(w, http.StatusNotFound, "web_target_not_found", "web target was not found")
				return
			}
			s.writeError(w, http.StatusInternalServerError, "get_web_coverage_status_failed", "web coverage status could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
		return
	}

	if len(parts) == 2 && parts[1] == "coverage-baseline" {
		switch r.Method {
		case http.MethodGet:
			item, found, err := s.store.GetWebCoverageBaselineForTenant(r.Context(), principal.OrganizationID, targetID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_web_coverage_baseline_failed", "web coverage baseline could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "web_coverage_baseline_not_found", "web coverage baseline was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpsertWebCoverageBaselineRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			item, err := s.store.UpsertWebCoverageBaselineForTenant(r.Context(), principal.OrganizationID, targetID, principal.Email, request)
			if err != nil {
				switch {
				case errors.Is(err, jobs.ErrWebTargetNotFound):
					s.writeError(w, http.StatusNotFound, "web_target_not_found", "web target was not found")
					return
				case strings.Contains(strings.ToLower(err.Error()), "must be greater than or equal to zero"):
					s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
					return
				case strings.Contains(strings.ToLower(err.Error()), "must be between 0 and 100"):
					s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
					return
				default:
					s.writeError(w, http.StatusInternalServerError, "upsert_web_coverage_baseline_failed", "web coverage baseline could not be saved")
					return
				}
			}
			s.writeJSON(w, http.StatusOK, item)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	if len(parts) == 3 && parts[1] == "scope" && parts[2] == "evaluate" {
		if r.Method != http.MethodGet {
			s.writeMethodNotAllowed(w)
			return
		}
		evaluateURL := strings.TrimSpace(r.URL.Query().Get("url"))
		if evaluateURL == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "url is required")
			return
		}
		result, err := s.store.EvaluateWebTargetScopeForTenant(r.Context(), principal.OrganizationID, targetID, evaluateURL)
		if err != nil {
			if errors.Is(err, jobs.ErrWebTargetNotFound) {
				s.writeError(w, http.StatusNotFound, "web_target_not_found", "web target was not found")
				return
			}
			s.writeError(w, http.StatusInternalServerError, "evaluate_web_target_scope_failed", "web target scope could not be evaluated")
			return
		}
		s.writeJSON(w, http.StatusOK, result)
		return
	}

	s.writeError(w, http.StatusNotFound, "web_target_route_not_found", "the requested web target route was not found")
}

func (s *Server) handleWebAuthProfiles(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}

		items, err := s.store.ListWebAuthProfilesForTenant(r.Context(), principal.OrganizationID, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_web_auth_profiles_failed", "web auth profiles could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateWebAuthProfileRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.Name) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "name is required")
			return
		}

		item, err := s.store.CreateWebAuthProfileForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "required") {
				s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_web_auth_profile_failed", "web auth profile could not be created")
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleWebAuthProfileRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/web-auth-profiles/"))
	if path == "" || strings.Contains(path, "/") {
		s.writeError(w, http.StatusNotFound, "web_auth_profile_route_not_found", "the requested web auth profile route was not found")
		return
	}
	profileID := strings.TrimSpace(path)

	switch r.Method {
	case http.MethodGet:
		item, found, err := s.store.GetWebAuthProfileForTenant(r.Context(), principal.OrganizationID, profileID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "get_web_auth_profile_failed", "web auth profile could not be loaded")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "web_auth_profile_not_found", "web auth profile was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case http.MethodPut:
		defer r.Body.Close()

		var request models.UpdateWebAuthProfileRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		item, found, err := s.store.UpdateWebAuthProfileForTenant(r.Context(), principal.OrganizationID, profileID, principal.Email, request)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "required") {
				s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
				return
			}
			s.writeError(w, http.StatusInternalServerError, "update_web_auth_profile_failed", "web auth profile could not be updated")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "web_auth_profile_not_found", "web auth profile was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case http.MethodDelete:
		deleted, err := s.store.DeleteWebAuthProfileForTenant(r.Context(), principal.OrganizationID, profileID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "delete_web_auth_profile_failed", "web auth profile could not be deleted")
			return
		}
		if !deleted {
			s.writeError(w, http.StatusNotFound, "web_auth_profile_not_found", "web auth profile was not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleScanTargets(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}

		items, err := s.store.ListScanTargetsForTenant(r.Context(), principal.OrganizationID, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_scan_targets_failed", "scan targets could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateScanTargetRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		if strings.TrimSpace(request.TargetKind) == "" || strings.TrimSpace(request.Target) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "target_kind and target are required")
			return
		}

		item, err := s.store.CreateScanTargetForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			var limitExceeded *jobs.TenantLimitExceededError
			if errors.As(err, &limitExceeded) {
				s.writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"code":    "tenant_limit_exceeded",
					"message": limitExceeded.Error(),
					"metric":  limitExceeded.Metric,
					"limit":   limitExceeded.Limit,
					"current": limitExceeded.Current,
				})
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_scan_target_failed", "scan target could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleScanTargetRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/scan-targets/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "scan_target_route_not_found", "the requested scan target route was not found")
		return
	}

	targetID := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			item, found, err := s.store.GetScanTargetForTenant(r.Context(), principal.OrganizationID, targetID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_scan_target_failed", "scan target could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "scan_target_not_found", "scan target was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpdateScanTargetRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			item, found, err := s.store.UpdateScanTargetForTenant(r.Context(), principal.OrganizationID, targetID, request)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "update_scan_target_failed", "scan target could not be updated")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "scan_target_not_found", "scan target was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		case http.MethodDelete:
			deleted, err := s.store.DeleteScanTargetForTenant(r.Context(), principal.OrganizationID, targetID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "delete_scan_target_failed", "scan target could not be deleted")
				return
			}
			if !deleted {
				s.writeError(w, http.StatusNotFound, "scan_target_not_found", "scan target was not found")
				return
			}

			w.WriteHeader(http.StatusNoContent)
		default:
			s.writeMethodNotAllowed(w)
		}

		return
	}

	if len(parts) == 2 && parts[1] == "run" {
		if r.Method != http.MethodPost {
			s.writeMethodNotAllowed(w)
			return
		}

		defer r.Body.Close()

		var request models.RunScanTargetRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		target, job, found, err := s.store.RunScanTargetForTenant(r.Context(), principal.OrganizationID, targetID, principal.Email, request)
		if err != nil {
			if s.writeValidationEngagementExecutionError(w, err) {
				return
			}
			var denied *jobs.PolicyDeniedError
			if errors.As(err, &denied) {
				s.writeJSON(w, http.StatusForbidden, map[string]any{
					"code":      "policy_denied",
					"message":   denied.Error(),
					"policy_id": denied.PolicyID,
					"rule_hits": denied.RuleHits,
				})
				return
			}
			var engineDenied *jobs.EngineControlDeniedError
			if errors.As(err, &engineDenied) {
				s.writeJSON(w, http.StatusForbidden, map[string]any{
					"code":        "engine_control_denied",
					"message":     engineDenied.Error(),
					"adapter_id":  strings.TrimSpace(engineDenied.AdapterID),
					"target_kind": strings.TrimSpace(engineDenied.TargetKind),
				})
				return
			}
			var limitExceeded *jobs.TenantLimitExceededError
			if errors.As(err, &limitExceeded) {
				s.writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"code":    "tenant_limit_exceeded",
					"message": limitExceeded.Error(),
					"metric":  limitExceeded.Metric,
					"limit":   limitExceeded.Limit,
					"current": limitExceeded.Current,
				})
				return
			}
			var controlViolation *jobs.ExecutionControlViolationError
			if errors.As(err, &controlViolation) {
				s.writeJSON(w, http.StatusConflict, map[string]any{
					"code":        strings.TrimSpace(controlViolation.Code),
					"message":     controlViolation.Error(),
					"reason":      strings.TrimSpace(controlViolation.Reason),
					"window_id":   strings.TrimSpace(controlViolation.WindowID),
					"window_name": strings.TrimSpace(controlViolation.WindowName),
				})
				return
			}
			s.writeError(w, http.StatusInternalServerError, "run_scan_target_failed", "scan target could not be executed")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "scan_target_not_found", "scan target was not found")
			return
		}

		s.writeJSON(w, http.StatusCreated, map[string]any{
			"target": target,
			"job":    job,
		})
		return
	}

	s.writeError(w, http.StatusNotFound, "scan_target_route_not_found", "the requested scan target route was not found")
}

func (s *Server) handleIngestionSources(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}

		items, err := s.store.ListIngestionSourcesForTenant(r.Context(), principal.OrganizationID, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_ingestion_sources_failed", "ingestion sources could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateIngestionSourceRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		if strings.TrimSpace(request.TargetKind) == "" || strings.TrimSpace(request.Target) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "target_kind and target are required")
			return
		}

		item, err := s.store.CreateIngestionSourceForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			var limitExceeded *jobs.TenantLimitExceededError
			if errors.As(err, &limitExceeded) {
				s.writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"code":    "tenant_limit_exceeded",
					"message": limitExceeded.Error(),
					"metric":  limitExceeded.Metric,
					"limit":   limitExceeded.Limit,
					"current": limitExceeded.Current,
				})
				return
			}
			if errors.Is(err, jobs.ErrInvalidIngestionSourceConfig) {
				s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_ingestion_source_failed", "ingestion source could not be created")
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleIngestionSourceRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/ingestion/sources/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "ingestion_source_route_not_found", "the requested ingestion source route was not found")
		return
	}

	sourceID := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			item, found, err := s.store.GetIngestionSourceForTenant(r.Context(), principal.OrganizationID, sourceID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_ingestion_source_failed", "ingestion source could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "ingestion_source_not_found", "ingestion source was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpdateIngestionSourceRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			item, found, err := s.store.UpdateIngestionSourceForTenant(r.Context(), principal.OrganizationID, sourceID, principal.Email, request)
			if err != nil {
				if errors.Is(err, jobs.ErrInvalidIngestionSourceConfig) {
					s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
					return
				}
				s.writeError(w, http.StatusInternalServerError, "update_ingestion_source_failed", "ingestion source could not be updated")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "ingestion_source_not_found", "ingestion source was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		case http.MethodDelete:
			deleted, err := s.store.DeleteIngestionSourceForTenant(r.Context(), principal.OrganizationID, sourceID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "delete_ingestion_source_failed", "ingestion source could not be deleted")
				return
			}
			if !deleted {
				s.writeError(w, http.StatusNotFound, "ingestion_source_not_found", "ingestion source was not found")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	if len(parts) == 2 && parts[1] == "rotate-token" {
		if r.Method != http.MethodPost {
			s.writeMethodNotAllowed(w)
			return
		}

		rotated, found, err := s.store.RotateIngestionSourceTokenForTenant(r.Context(), principal.OrganizationID, sourceID, principal.Email)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "rotate_ingestion_source_token_failed", "ingestion source token could not be rotated")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "ingestion_source_not_found", "ingestion source was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, rotated)
		return
	}

	if len(parts) == 2 && parts[1] == "rotate-webhook-secret" {
		if r.Method != http.MethodPost {
			s.writeMethodNotAllowed(w)
			return
		}

		rotated, found, err := s.store.RotateIngestionSourceWebhookSecretForTenant(r.Context(), principal.OrganizationID, sourceID, principal.Email)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "rotate_ingestion_source_webhook_secret_failed", "ingestion source webhook secret could not be rotated")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "ingestion_source_not_found", "ingestion source was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, rotated)
		return
	}

	s.writeError(w, http.StatusNotFound, "ingestion_source_route_not_found", "the requested ingestion source route was not found")
}

func (s *Server) handleIngestionEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
			return
		}
		limit = parsed
	}

	sourceID := strings.TrimSpace(r.URL.Query().Get("source_id"))
	items, err := s.store.ListIngestionEventsForTenant(r.Context(), principal.OrganizationID, sourceID, limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_ingestion_events_failed", "ingestion events could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

func (s *Server) handleIngestionWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	sourceID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/ingest/webhooks/"))
	if idx := strings.Index(sourceID, "/"); idx >= 0 {
		sourceID = strings.TrimSpace(sourceID[:idx])
	}
	if sourceID == "" {
		s.writeError(w, http.StatusNotFound, "ingestion_webhook_not_found", "the requested webhook endpoint was not found")
		return
	}

	token := strings.TrimSpace(r.Header.Get(ingestionTokenHeader))
	if token == "" {
		token = auth.ParseBearerToken(r.Header.Get("Authorization"))
	}
	if token == "" {
		s.writeError(w, http.StatusUnauthorized, "invalid_ingestion_token", "a webhook ingestion token is required")
		return
	}

	defer r.Body.Close()

	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_body", "request body could not be read")
		return
	}

	var request models.IngestionWebhookRequest
	if len(rawBody) > 0 {
		if err := json.Unmarshal(rawBody, &request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
	}
	if request.Headers == nil {
		request.Headers = map[string]string{}
	}
	for key, value := range collectIngestionHeaders(r.Header) {
		request.Headers[key] = value
	}

	response, err := s.store.HandleIngestionWebhook(r.Context(), sourceID, token, request, rawBody)
	if err != nil {
		var limitExceeded *jobs.TenantLimitExceededError
		switch {
		case errors.Is(err, jobs.ErrIngestionSourceNotFound):
			s.writeError(w, http.StatusNotFound, "ingestion_source_not_found", "ingestion source was not found")
		case errors.Is(err, jobs.ErrInvalidIngestionToken):
			s.writeError(w, http.StatusUnauthorized, "invalid_ingestion_token", "the webhook ingestion token is invalid")
		case errors.Is(err, jobs.ErrInvalidIngestionSignature):
			s.writeError(w, http.StatusUnauthorized, "invalid_ingestion_signature", "the webhook signature is invalid")
		case errors.Is(err, jobs.ErrIngestionSourceDisabled):
			s.writeError(w, http.StatusConflict, "ingestion_source_disabled", "ingestion source is disabled")
		case errors.As(err, &limitExceeded):
			s.writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"code":    "tenant_limit_exceeded",
				"message": limitExceeded.Error(),
				"metric":  limitExceeded.Metric,
				"limit":   limitExceeded.Limit,
				"current": limitExceeded.Current,
			})
		case strings.Contains(strings.ToLower(err.Error()), "requires target_kind and target"):
			s.writeError(w, http.StatusBadRequest, "validation_error", "ingestion event requires target_kind and target")
		default:
			s.writeError(w, http.StatusInternalServerError, "ingestion_webhook_failed", "webhook ingestion could not be processed")
		}
		return
	}

	status := http.StatusAccepted
	if response.Duplicate {
		status = http.StatusOK
	}
	s.writeJSON(w, status, response)
}

func collectIngestionHeaders(headers http.Header) map[string]string {
	out := map[string]string{}
	for _, key := range []string{
		"X-GitHub-Event",
		"X-GitHub-Delivery",
		"X-Hub-Signature-256",
		"X-Hub-Signature",
		"X-GitLab-Event",
		"X-GitLab-Event-UUID",
		"X-GitLab-Delivery",
		"X-GitLab-Token",
		"X-Event-Key",
		"X-Jenkins-Event",
		"X-Jenkins-Build-Number",
		"X-Jenkins-Job",
		"X-Jenkins-Token",
		"X-Jenkins-Signature",
		"X-USS-Webhook-Signature",
	} {
		value := strings.TrimSpace(headers.Get(key))
		if value == "" {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(key))] = value
	}
	return out
}

func (s *Server) handlePlatformEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
			return
		}
		limit = parsed
	}

	eventType := strings.TrimSpace(r.URL.Query().Get("type"))
	if eventType == "" {
		eventType = strings.TrimSpace(r.URL.Query().Get("event_type"))
	}
	items, err := s.store.ListPlatformEventsForTenant(r.Context(), principal.OrganizationID, eventType, limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_platform_events_failed", "platform events could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

func (s *Server) handleTenantOperations(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		snapshot, err := s.store.GetTenantOperationsSnapshot(r.Context(), principal.OrganizationID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "tenant_operations_failed", "tenant operations snapshot could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, snapshot)
	case http.MethodPut:
		defer r.Body.Close()

		var request models.UpdateTenantLimitsRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		snapshot, err := s.store.UpdateTenantLimitsForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "must be greater than or equal to zero") {
				s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
				return
			}
			s.writeError(w, http.StatusInternalServerError, "update_tenant_limits_failed", "tenant limits could not be updated")
			return
		}

		s.writeJSON(w, http.StatusOK, snapshot)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleTenantExecutionControls(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		controls, err := s.store.GetTenantExecutionControlsForTenant(r.Context(), principal.OrganizationID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "tenant_execution_controls_failed", "tenant execution controls could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, controls)
	case http.MethodPut:
		defer r.Body.Close()

		var request models.UpdateTenantExecutionControlsRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		controls, err := s.store.UpdateTenantExecutionControlsForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "maintenance window") {
				s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
				return
			}
			s.writeError(w, http.StatusInternalServerError, "update_tenant_execution_controls_failed", "tenant execution controls could not be updated")
			return
		}

		s.writeJSON(w, http.StatusOK, controls)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleTenantConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
			return
		}
		limit = parsed
	}

	items, err := s.store.ListTenantConfigForTenant(r.Context(), principal.OrganizationID, r.URL.Query().Get("prefix"), limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_tenant_config_failed", "tenant configuration entries could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

func (s *Server) handleTenantConfigRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	configKey := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/config/"))
	if configKey == "" || strings.Contains(configKey, "/") {
		s.writeError(w, http.StatusNotFound, "not_found", "requested tenant configuration entry was not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		item, found, err := s.store.GetTenantConfigEntryForTenant(r.Context(), principal.OrganizationID, configKey)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "get_tenant_config_failed", "tenant configuration entry could not be loaded")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "not_found", "requested tenant configuration entry was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case http.MethodPut:
		var request models.UpsertTenantConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		actor := strings.TrimSpace(principal.Email)
		if actor == "" {
			actor = strings.TrimSpace(principal.UserID)
		}

		item, err := s.store.UpsertTenantConfigEntryForTenant(r.Context(), principal.OrganizationID, configKey, actor, request)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "upsert_tenant_config_failed", err.Error())
			return
		}

		s.writeJSON(w, http.StatusOK, item)
	case http.MethodDelete:
		actor := strings.TrimSpace(principal.Email)
		if actor == "" {
			actor = strings.TrimSpace(principal.UserID)
		}

		deleted, err := s.store.DeleteTenantConfigEntryForTenant(r.Context(), principal.OrganizationID, configKey, actor)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "delete_tenant_config_failed", "tenant configuration entry could not be deleted")
			return
		}
		if !deleted {
			s.writeError(w, http.StatusNotFound, "not_found", "requested tenant configuration entry was not found")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleIssueWorkerIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	if strings.TrimSpace(s.cfg.WorkloadIdentitySigningKey) == "" {
		s.writeError(w, http.StatusServiceUnavailable, "workload_identity_disabled", "workload identity signing key is not configured")
		return
	}

	defer r.Body.Close()

	var request models.IssueWorkerIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	request.WorkerID = strings.TrimSpace(request.WorkerID)
	if request.WorkerID == "" {
		s.writeError(w, http.StatusBadRequest, "validation_error", "worker_id is required")
		return
	}

	ttl := s.cfg.WorkloadIdentityTTL
	if request.TTLSeconds > 0 {
		ttl = time.Duration(request.TTLSeconds) * time.Second
	}

	now := time.Now().UTC()
	token, claims, err := auth.IssueWorkerIdentityToken(
		s.cfg.WorkloadIdentitySigningKey,
		request.WorkerID,
		principal.OrganizationID,
		ttl,
		now,
	)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "issue_workload_identity_failed", err.Error())
		return
	}

	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	s.writeJSON(w, http.StatusCreated, models.IssuedWorkerIdentityToken{
		Token:      token,
		TokenType:  "Bearer",
		TokenID:    claims.TokenID,
		WorkerID:   claims.WorkerID,
		TenantID:   claims.TenantID,
		IssuedAt:   issuedAt,
		ExpiresAt:  expiresAt,
		TTLSeconds: int64(expiresAt.Sub(issuedAt).Seconds()),
		Audience:   claims.Audience,
	})
}

func (s *Server) handleWorkerCertificates(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 100
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}
		subjectID := strings.TrimSpace(r.URL.Query().Get("subject_id"))
		items, err := s.store.ListWorkloadCertificatesForTenant(r.Context(), principal.OrganizationID, subjectID, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_workload_certificates_failed", "workload certificates could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.IssueWorkerCertificateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		actor := strings.TrimSpace(principal.Email)
		if actor == "" {
			actor = strings.TrimSpace(principal.UserID)
		}
		issued, err := s.store.IssueWorkerCertificateForTenant(r.Context(), principal.OrganizationID, actor, request)
		if err != nil {
			if errors.Is(err, jobs.ErrCertificateAuthorityDisabled) {
				s.writeError(w, http.StatusServiceUnavailable, "certificate_authority_unavailable", "certificate authority is not configured")
				return
			}
			s.writeError(w, http.StatusBadRequest, "issue_workload_certificate_failed", err.Error())
			return
		}
		s.writeJSON(w, http.StatusCreated, issued)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleWorkerCertificateRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	route := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/workload-identities/workers/certificates/"))
	parts := strings.Split(route, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "revoke" {
		s.writeError(w, http.StatusNotFound, "workload_certificate_not_found", "workload certificate was not found")
		return
	}

	var request models.RevokeWorkloadCertificateRequest
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
	}

	actor := strings.TrimSpace(principal.Email)
	if actor == "" {
		actor = strings.TrimSpace(principal.UserID)
	}
	item, found, err := s.store.RevokeWorkloadCertificateForTenant(r.Context(), principal.OrganizationID, parts[0], actor, request.Reason)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "revoke_workload_certificate_failed", "workload certificate could not be revoked")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "workload_certificate_not_found", "workload certificate was not found")
		return
	}
	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleCABundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	bundle, err := s.store.GetCertificateAuthorityBundle()
	if err != nil {
		if errors.Is(err, jobs.ErrCertificateAuthorityDisabled) {
			s.writeError(w, http.StatusServiceUnavailable, "certificate_authority_unavailable", "certificate authority is not configured")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "ca_bundle_unavailable", "certificate authority bundle could not be loaded")
		return
	}
	s.writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) handleKMSKeys(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 100
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}

		items, err := s.store.ListKMSKeysForTenant(r.Context(), principal.OrganizationID, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_kms_keys_failed", "kms keys could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateKMSKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		actor := strings.TrimSpace(principal.Email)
		if actor == "" {
			actor = strings.TrimSpace(principal.UserID)
		}
		item, err := s.store.CreateKMSKeyForTenant(r.Context(), principal.OrganizationID, actor, request)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "create_kms_key_failed", err.Error())
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleKMSEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}
	defer r.Body.Close()

	var request models.KMSEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	response, err := s.store.EncryptWithKMSForTenant(r.Context(), principal.OrganizationID, request)
	if err != nil {
		switch {
		case errors.Is(err, jobs.ErrKMSKeyNotFound):
			s.writeError(w, http.StatusNotFound, "kms_key_not_found", "kms key was not found")
		case strings.Contains(strings.ToLower(err.Error()), "not configured"):
			s.writeError(w, http.StatusServiceUnavailable, "kms_unavailable", "kms service is not configured")
		default:
			s.writeError(w, http.StatusBadRequest, "kms_encrypt_failed", err.Error())
		}
		return
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleKMSDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}
	defer r.Body.Close()

	var request models.KMSDecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	response, err := s.store.DecryptWithKMSForTenant(r.Context(), principal.OrganizationID, request)
	if err != nil {
		switch {
		case errors.Is(err, jobs.ErrKMSKeyNotFound):
			s.writeError(w, http.StatusNotFound, "kms_key_not_found", "kms key was not found")
		case strings.Contains(strings.ToLower(err.Error()), "not configured"):
			s.writeError(w, http.StatusServiceUnavailable, "kms_unavailable", "kms service is not configured")
		default:
			s.writeError(w, http.StatusBadRequest, "kms_decrypt_failed", err.Error())
		}
		return
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleKMSSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}
	defer r.Body.Close()

	var request models.KMSSignRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	response, err := s.store.SignWithKMSForTenant(r.Context(), principal.OrganizationID, request)
	if err != nil {
		switch {
		case errors.Is(err, jobs.ErrKMSKeyNotFound):
			s.writeError(w, http.StatusNotFound, "kms_key_not_found", "kms key was not found")
		case strings.Contains(strings.ToLower(err.Error()), "not configured"):
			s.writeError(w, http.StatusServiceUnavailable, "kms_unavailable", "kms service is not configured")
		default:
			s.writeError(w, http.StatusBadRequest, "kms_sign_failed", err.Error())
		}
		return
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleKMSVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}
	defer r.Body.Close()

	var request models.KMSVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	response, err := s.store.VerifyWithKMSForTenant(r.Context(), principal.OrganizationID, request)
	if err != nil {
		switch {
		case errors.Is(err, jobs.ErrKMSKeyNotFound):
			s.writeError(w, http.StatusNotFound, "kms_key_not_found", "kms key was not found")
		case strings.Contains(strings.ToLower(err.Error()), "not configured"):
			s.writeError(w, http.StatusServiceUnavailable, "kms_unavailable", "kms service is not configured")
		default:
			s.writeError(w, http.StatusBadRequest, "kms_verify_failed", err.Error())
		}
		return
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleSecretReferences(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 100
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}
		items, err := s.store.ListSecretReferencesForTenant(r.Context(), principal.OrganizationID, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_secret_references_failed", "secret references could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()
		var request models.CreateSecretReferenceRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		actor := strings.TrimSpace(principal.Email)
		if actor == "" {
			actor = strings.TrimSpace(principal.UserID)
		}
		item, err := s.store.CreateSecretReferenceForTenant(r.Context(), principal.OrganizationID, actor, request)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "create_secret_reference_failed", err.Error())
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleSecretReferenceRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	referenceID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/secrets/references/"))
	if referenceID == "" || strings.Contains(referenceID, "/") {
		s.writeError(w, http.StatusNotFound, "secret_reference_not_found", "secret reference was not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		item, found, err := s.store.GetSecretReferenceForTenant(r.Context(), principal.OrganizationID, referenceID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "get_secret_reference_failed", "secret reference could not be loaded")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "secret_reference_not_found", "secret reference was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case http.MethodPut:
		defer r.Body.Close()
		var request models.UpdateSecretReferenceRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		actor := strings.TrimSpace(principal.Email)
		if actor == "" {
			actor = strings.TrimSpace(principal.UserID)
		}
		item, found, err := s.store.UpdateSecretReferenceForTenant(r.Context(), principal.OrganizationID, referenceID, actor, request)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "update_secret_reference_failed", err.Error())
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "secret_reference_not_found", "secret reference was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case http.MethodDelete:
		deleted, err := s.store.DeleteSecretReferenceForTenant(r.Context(), principal.OrganizationID, referenceID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "delete_secret_reference_failed", "secret reference could not be deleted")
			return
		}
		if !deleted {
			s.writeError(w, http.StatusNotFound, "secret_reference_not_found", "secret reference was not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleSecretLeases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
			return
		}
		limit = parsed
	}
	referenceID := strings.TrimSpace(r.URL.Query().Get("secret_reference_id"))
	items, err := s.store.ListSecretLeasesForTenant(r.Context(), principal.OrganizationID, referenceID, limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_secret_leases_failed", "secret leases could not be loaded")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

func (s *Server) handleSecretLeaseIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}
	defer r.Body.Close()

	var request models.IssueSecretLeaseRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	actor := strings.TrimSpace(principal.Email)
	if actor == "" {
		actor = strings.TrimSpace(principal.UserID)
	}
	lease, err := s.store.IssueSecretLeaseForTenant(r.Context(), principal.OrganizationID, actor, request)
	if err != nil {
		if errors.Is(err, jobs.ErrSecretReferenceNotFound) {
			s.writeError(w, http.StatusNotFound, "secret_reference_not_found", "secret reference was not found")
			return
		}
		s.writeError(w, http.StatusBadRequest, "issue_secret_lease_failed", err.Error())
		return
	}
	s.writeJSON(w, http.StatusCreated, lease)
}

func (s *Server) handleSecretLeaseRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/secrets/leases/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "revoke" {
		s.writeError(w, http.StatusNotFound, "secret_lease_route_not_found", "the requested secret lease route was not found")
		return
	}
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	actor := strings.TrimSpace(principal.Email)
	if actor == "" {
		actor = strings.TrimSpace(principal.UserID)
	}
	item, found, err := s.store.RevokeSecretLeaseForTenant(r.Context(), principal.OrganizationID, parts[0], actor)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "revoke_secret_lease_failed", "secret lease could not be revoked")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "secret_lease_not_found", "secret lease was not found")
		return
	}
	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleWorkerRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	defer r.Body.Close()

	var request models.WorkerRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	if strings.TrimSpace(request.WorkerID) == "" ||
		strings.TrimSpace(request.WorkerVersion) == "" ||
		strings.TrimSpace(request.OperatingSystem) == "" ||
		strings.TrimSpace(request.Hostname) == "" {
		s.writeError(w, http.StatusBadRequest, "validation_error", "worker_id, worker_version, operating_system, and hostname are required")
		return
	}

	if claims, ok := auth.WorkerIdentityClaimsFromContext(r.Context()); ok {
		if !strings.EqualFold(strings.TrimSpace(claims.WorkerID), strings.TrimSpace(request.WorkerID)) {
			s.writeError(w, http.StatusUnauthorized, "worker_identity_mismatch", "worker identity token does not match worker_id")
			return
		}
	}

	response, err := s.store.RegisterWorker(r.Context(), request)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "register_worker_failed", "worker could not be registered")
		return
	}

	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleWorkerHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	defer r.Body.Close()

	var request models.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	if strings.TrimSpace(request.WorkerID) == "" || strings.TrimSpace(request.LeaseID) == "" {
		s.writeError(w, http.StatusBadRequest, "validation_error", "worker_id and lease_id are required")
		return
	}

	if claims, ok := auth.WorkerIdentityClaimsFromContext(r.Context()); ok {
		if !strings.EqualFold(strings.TrimSpace(claims.WorkerID), strings.TrimSpace(request.WorkerID)) {
			s.writeError(w, http.StatusUnauthorized, "worker_identity_mismatch", "worker identity token does not match worker_id")
			return
		}
	}

	response, err := s.store.RecordHeartbeat(r.Context(), request)
	if err != nil {
		if errors.Is(err, jobs.ErrWorkerLeaseNotFound) {
			s.writeError(w, http.StatusNotFound, "worker_lease_not_found", "worker registration lease was not found")
			return
		}

		s.writeError(w, http.StatusInternalServerError, "heartbeat_failed", "worker heartbeat could not be recorded")
		return
	}

	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	findings, err := s.store.ListFindingsForTenant(r.Context(), principal.OrganizationID, 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_findings_failed", "findings could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": findings,
	})
}

func (s *Server) handleFindingSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
			return
		}
		limit = parsed
	}

	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "offset must be zero or a positive integer")
			return
		}
		offset = parsed
	}

	var overdue *bool
	if raw := strings.TrimSpace(r.URL.Query().Get("overdue")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "validation_error", "overdue must be true or false")
			return
		}
		overdue = &parsed
	}

	result, err := s.store.SearchFindingsForTenant(r.Context(), principal.OrganizationID, models.FindingSearchQuery{
		Query:    strings.TrimSpace(r.URL.Query().Get("q")),
		Severity: strings.TrimSpace(r.URL.Query().Get("severity")),
		Priority: strings.TrimSpace(r.URL.Query().Get("priority")),
		Layer:    strings.TrimSpace(r.URL.Query().Get("layer")),
		Status:   strings.TrimSpace(r.URL.Query().Get("status")),
		Overdue:  overdue,
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "search_findings_failed", "finding search could not be executed")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
			return
		}
		limit = parsed
	}

	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "offset must be zero or a positive integer")
			return
		}
		offset = parsed
	}

	var archived *bool
	if raw := strings.TrimSpace(r.URL.Query().Get("archived")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "validation_error", "archived must be true or false")
			return
		}
		archived = &parsed
	}

	result, err := s.store.ListEvidenceObjectsForTenant(r.Context(), principal.OrganizationID, models.EvidenceListQuery{
		ScanJobID: strings.TrimSpace(r.URL.Query().Get("scan_job_id")),
		TaskID:    strings.TrimSpace(r.URL.Query().Get("task_id")),
		FindingID: strings.TrimSpace(r.URL.Query().Get("finding_id")),
		Archived:  archived,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_evidence_failed", "evidence objects could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleEvidenceRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/evidence/"))
	if path == "" {
		s.writeError(w, http.StatusNotFound, "not_found", "requested evidence object was not found")
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "not_found", "requested evidence object was not found")
		return
	}
	evidenceID := strings.TrimSpace(parts[0])

	switch r.Method {
	case http.MethodGet:
		if len(parts) != 1 {
			s.writeError(w, http.StatusNotFound, "not_found", "requested evidence object was not found")
			return
		}
		item, found, err := s.store.GetEvidenceObjectForTenant(r.Context(), principal.OrganizationID, evidenceID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "get_evidence_failed", "evidence object could not be loaded")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "not_found", "requested evidence object was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case http.MethodPost:
		if len(parts) != 2 || parts[1] != "verify-integrity" {
			s.writeError(w, http.StatusNotFound, "not_found", "requested evidence route was not found")
			return
		}
		result, found, err := s.store.VerifyEvidenceObjectIntegrityForTenant(r.Context(), principal.OrganizationID, evidenceID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "verify_evidence_integrity_failed", "evidence integrity could not be verified")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "not_found", "requested evidence object was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, result)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleEvidenceRetentionRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
			return
		}
		limit = parsed
	}

	runs, err := s.store.ListEvidenceRetentionRunsForTenant(r.Context(), principal.OrganizationID, limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_evidence_retention_runs_failed", "evidence retention run history could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": runs,
	})
}

func (s *Server) handleEvidenceRetentionRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	var request models.RunEvidenceRetentionRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
	}

	actor := strings.TrimSpace(principal.Email)
	if actor == "" {
		actor = strings.TrimSpace(principal.UserID)
	}

	run, err := s.store.RunEvidenceRetentionForTenant(r.Context(), principal.OrganizationID, actor, request)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "run_evidence_retention_failed", "evidence retention run could not be executed")
		return
	}

	s.writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleBackupSnapshots(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 100
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}

		items, err := s.store.ListBackupSnapshotsForTenant(r.Context(), principal.OrganizationID, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_backup_snapshots_failed", "backup snapshots could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		var request models.CreateBackupSnapshotRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		actor := strings.TrimSpace(principal.Email)
		if actor == "" {
			actor = strings.TrimSpace(principal.UserID)
		}

		item, err := s.store.CreateBackupSnapshotForTenant(r.Context(), principal.OrganizationID, actor, request)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "create_backup_snapshot_failed", err.Error())
			return
		}

		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleRecoveryDrills(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 100
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}

		items, err := s.store.ListRecoveryDrillsForTenant(r.Context(), principal.OrganizationID, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_recovery_drills_failed", "recovery drills could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		var request models.CreateRecoveryDrillRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		actor := strings.TrimSpace(principal.Email)
		if actor == "" {
			actor = strings.TrimSpace(principal.UserID)
		}

		item, err := s.store.CreateRecoveryDrillForTenant(r.Context(), principal.OrganizationID, actor, request)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "create_recovery_drill_failed", err.Error())
			return
		}

		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleFindingRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/findings/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "waivers" {
		s.writeError(w, http.StatusNotFound, "finding_route_not_found", "the requested finding route was not found")
		return
	}

	findingID := strings.TrimSpace(parts[0])
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListFindingWaiversForTenant(r.Context(), principal.OrganizationID, findingID, 200)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_finding_waivers_failed", "finding waivers could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateFindingWaiverRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.RemediationID) == "" || strings.TrimSpace(request.Reason) == "" || request.Reduction <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "remediation_id, reason, and a positive reduction are required")
			return
		}
		if request.ExpiresAt != nil && !request.ExpiresAt.After(time.Now().UTC()) {
			s.writeError(w, http.StatusBadRequest, "validation_error", "expires_at must be in the future")
			return
		}

		waiver, err := s.store.CreateFindingWaiverForTenant(r.Context(), principal.OrganizationID, findingID, request)
		if err != nil {
			if errors.Is(err, jobs.ErrInvalidWaiver) {
				s.writeError(w, http.StatusConflict, "invalid_finding_waiver", "the waiver dependencies are not valid for this finding")
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_finding_waiver_failed", "finding waiver could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, waiver)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleRiskSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	summary, err := s.store.ListRiskSummaryForTenant(r.Context(), principal.OrganizationID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "risk_summary_failed", "risk summary could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, summary)
}

type findingReportFilter struct {
	Severity string `json:"severity,omitempty"`
	Priority string `json:"priority,omitempty"`
	Layer    string `json:"layer,omitempty"`
	Status   string `json:"status,omitempty"`
	Search   string `json:"search,omitempty"`
	Overdue  *bool  `json:"overdue,omitempty"`
}

func (s *Server) handleReportSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	findings, err := s.store.ListFindingsForTenant(r.Context(), principal.OrganizationID, 5000)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_findings_failed", "findings could not be loaded")
		return
	}

	filter := parseFindingReportFilter(r.URL.Query())
	filtered := applyFindingReportFilter(findings, filter)

	globalRiskSummary, err := s.store.ListRiskSummaryForTenant(r.Context(), principal.OrganizationID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "risk_summary_failed", "risk summary could not be loaded")
		return
	}

	filteredPriority := make(map[string]int64)
	filteredSeverity := make(map[string]int64)
	filteredLayer := make(map[string]int64)
	var filteredOverdue int64
	for _, finding := range filtered {
		priority := strings.ToLower(strings.TrimSpace(finding.Risk.Priority))
		if priority == "" {
			priority = "unknown"
		}
		filteredPriority[priority]++

		severity := strings.ToLower(strings.TrimSpace(finding.Severity))
		if severity == "" {
			severity = "unknown"
		}
		filteredSeverity[severity]++

		layer := strings.ToLower(strings.TrimSpace(finding.Source.Layer))
		if layer == "" {
			layer = "unknown"
		}
		filteredLayer[layer]++

		if finding.Risk.Overdue {
			filteredOverdue++
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC(),
		"filter":       filter,
		"sample_size":  len(findings),
		"filtered": map[string]any{
			"total_findings": len(filtered),
			"overdue":        filteredOverdue,
			"priority":       filteredPriority,
			"severity":       filteredSeverity,
			"layer":          filteredLayer,
		},
		"risk_summary": globalRiskSummary,
	})
}

func (s *Server) handleFindingsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		s.writeError(w, http.StatusBadRequest, "validation_error", "format must be either json or csv")
		return
	}

	findings, err := s.store.ListFindingsForTenant(r.Context(), principal.OrganizationID, 5000)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_findings_failed", "findings could not be loaded")
		return
	}

	filter := parseFindingReportFilter(r.URL.Query())
	filtered := applyFindingReportFilter(findings, filter)
	now := time.Now().UTC()

	if format == "csv" {
		filename := fmt.Sprintf("uss-findings-%s.csv", now.Format("20060102-150405"))
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.WriteHeader(http.StatusOK)

		writer := csv.NewWriter(w)
		_ = writer.Write([]string{
			"finding_id",
			"title",
			"category",
			"severity",
			"status",
			"priority",
			"overall_score",
			"sla_class",
			"sla_due_at",
			"overdue",
			"layer",
			"tool",
			"asset_id",
			"asset_name",
			"asset_type",
			"environment",
			"exposure",
			"owner_team",
			"first_seen_at",
			"last_seen_at",
			"tags",
		})
		for _, item := range filtered {
			slaDue := ""
			if item.Risk.SLADueAt != nil {
				slaDue = item.Risk.SLADueAt.UTC().Format(time.RFC3339)
			}
			_ = writer.Write([]string{
				item.FindingID,
				item.Title,
				item.Category,
				item.Severity,
				item.Status,
				item.Risk.Priority,
				fmt.Sprintf("%.2f", item.Risk.OverallScore),
				item.Risk.SLAClass,
				slaDue,
				strconv.FormatBool(item.Risk.Overdue),
				item.Source.Layer,
				item.Source.Tool,
				item.Asset.AssetID,
				item.Asset.AssetName,
				item.Asset.AssetType,
				item.Asset.Environment,
				item.Asset.Exposure,
				item.Asset.OwnerTeam,
				item.FirstSeenAt.UTC().Format(time.RFC3339),
				item.LastSeenAt.UTC().Format(time.RFC3339),
				strings.Join(item.Tags, ";"),
			})
		}
		writer.Flush()
		return
	}

	filename := fmt.Sprintf("uss-findings-%s.json", now.Format("20060102-150405"))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	s.writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": now,
		"format":       "json",
		"filter":       filter,
		"count":        len(filtered),
		"items":        filtered,
	})
}

func parseFindingReportFilter(values url.Values) findingReportFilter {
	filter := findingReportFilter{
		Severity: strings.ToLower(strings.TrimSpace(values.Get("severity"))),
		Priority: strings.ToLower(strings.TrimSpace(values.Get("priority"))),
		Layer:    strings.ToLower(strings.TrimSpace(values.Get("layer"))),
		Status:   strings.ToLower(strings.TrimSpace(values.Get("status"))),
		Search:   strings.ToLower(strings.TrimSpace(values.Get("search"))),
	}

	if raw := strings.ToLower(strings.TrimSpace(values.Get("overdue"))); raw != "" {
		if raw == "true" || raw == "1" || raw == "yes" {
			value := true
			filter.Overdue = &value
		} else if raw == "false" || raw == "0" || raw == "no" {
			value := false
			filter.Overdue = &value
		}
	}

	return filter
}

func applyFindingReportFilter(items []models.CanonicalFinding, filter findingReportFilter) []models.CanonicalFinding {
	out := make([]models.CanonicalFinding, 0, len(items))
	for _, item := range items {
		if filter.Severity != "" && strings.ToLower(strings.TrimSpace(item.Severity)) != filter.Severity {
			continue
		}
		if filter.Priority != "" && strings.ToLower(strings.TrimSpace(item.Risk.Priority)) != filter.Priority {
			continue
		}
		if filter.Layer != "" && strings.ToLower(strings.TrimSpace(item.Source.Layer)) != filter.Layer {
			continue
		}
		if filter.Status != "" && strings.ToLower(strings.TrimSpace(item.Status)) != filter.Status {
			continue
		}
		if filter.Overdue != nil && item.Risk.Overdue != *filter.Overdue {
			continue
		}
		if filter.Search != "" {
			title := strings.ToLower(strings.TrimSpace(item.Title))
			category := strings.ToLower(strings.TrimSpace(item.Category))
			assetID := strings.ToLower(strings.TrimSpace(item.Asset.AssetID))
			assetName := strings.ToLower(strings.TrimSpace(item.Asset.AssetName))
			if !strings.Contains(title, filter.Search) &&
				!strings.Contains(category, filter.Search) &&
				!strings.Contains(assetID, filter.Search) &&
				!strings.Contains(assetName, filter.Search) {
				continue
			}
		}
		out = append(out, item)
	}
	return out
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	assets, err := s.store.ListAssetsForTenant(r.Context(), principal.OrganizationID, 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_assets_failed", "assets could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": assets,
	})
}

func (s *Server) handleAssetContextEvents(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}

		assetID := strings.TrimSpace(r.URL.Query().Get("asset_id"))
		eventKind := strings.TrimSpace(r.URL.Query().Get("event_kind"))
		items, err := s.store.ListAssetContextEventsForTenant(r.Context(), principal.OrganizationID, assetID, eventKind, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_asset_context_events_failed", "asset context events could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateAssetContextEventRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		actor := strings.TrimSpace(principal.Email)
		if actor == "" {
			actor = strings.TrimSpace(principal.UserID)
		}

		item, err := s.store.CreateAssetContextEventForTenant(r.Context(), principal.OrganizationID, actor, request)
		if err != nil {
			lower := strings.ToLower(err.Error())
			if strings.Contains(lower, "required") || strings.Contains(lower, "event_kind") {
				s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_asset_context_event_failed", "asset context event could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleAPIAssets(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}

		items, err := s.store.ListAPIAssetsForTenant(r.Context(), principal.OrganizationID, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_api_assets_failed", "api assets could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.ImportOpenAPIRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		actor := strings.TrimSpace(principal.Email)
		if actor == "" {
			actor = strings.TrimSpace(principal.UserID)
		}

		imported, err := s.store.ImportOpenAPIForTenant(r.Context(), principal.OrganizationID, actor, request)
		if err != nil {
			lower := strings.ToLower(err.Error())
			if strings.Contains(lower, "required") || strings.Contains(lower, "valid openapi json") || strings.Contains(lower, "spec") {
				s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
				return
			}
			s.writeError(w, http.StatusInternalServerError, "import_openapi_failed", "openapi spec could not be imported")
			return
		}

		s.writeJSON(w, http.StatusCreated, imported)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleGraphQLAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	defer r.Body.Close()

	var request models.ImportGraphQLSchemaRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	actor := strings.TrimSpace(principal.Email)
	if actor == "" {
		actor = strings.TrimSpace(principal.UserID)
	}

	imported, err := s.store.ImportGraphQLSchemaForTenant(r.Context(), principal.OrganizationID, actor, request)
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "required") || strings.Contains(lower, "schema") {
			s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
			return
		}
		s.writeError(w, http.StatusInternalServerError, "import_graphql_failed", "graphql schema could not be imported")
		return
	}

	s.writeJSON(w, http.StatusCreated, imported)
}

func (s *Server) handleAPIAssetRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/assets/apis/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "endpoints" {
		s.writeError(w, http.StatusNotFound, "api_asset_route_not_found", "the requested api asset route was not found")
		return
	}

	limit := 1000
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
			return
		}
		limit = parsed
	}

	items, err := s.store.ListAPIEndpointsForTenant(r.Context(), principal.OrganizationID, parts[0], limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_api_endpoints_failed", "api endpoints could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

func (s *Server) handleExternalAssets(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 500
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}
		assetType := strings.TrimSpace(r.URL.Query().Get("asset_type"))
		items, err := s.store.ListExternalAssetsForTenant(r.Context(), principal.OrganizationID, assetType, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_external_assets_failed", "external assets could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.UpsertExternalAssetRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		actor := strings.TrimSpace(principal.Email)
		if actor == "" {
			actor = strings.TrimSpace(principal.UserID)
		}
		item, err := s.store.UpsertExternalAssetForTenant(r.Context(), principal.OrganizationID, actor, request)
		if err != nil {
			lower := strings.ToLower(err.Error())
			if strings.Contains(lower, "required") || strings.Contains(lower, "supported") {
				s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
				return
			}
			s.writeError(w, http.StatusInternalServerError, "upsert_external_asset_failed", "external asset could not be saved")
			return
		}

		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleExternalAssetSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	defer r.Body.Close()

	var request models.SyncExternalAssetsRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	if len(request.Assets) == 0 {
		s.writeError(w, http.StatusBadRequest, "validation_error", "assets must contain at least one item")
		return
	}

	actor := strings.TrimSpace(principal.Email)
	if actor == "" {
		actor = strings.TrimSpace(principal.UserID)
	}

	result, err := s.store.SyncExternalAssetsForTenant(r.Context(), principal.OrganizationID, actor, request)
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "required") || strings.Contains(lower, "supported") || strings.Contains(lower, "must contain at least one item") {
			s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
			return
		}
		s.writeError(w, http.StatusInternalServerError, "sync_external_assets_failed", "external assets could not be synchronized")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAssetSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	defer r.Body.Close()

	var request models.SyncAssetProfilesRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	if len(request.Assets) == 0 {
		s.writeError(w, http.StatusBadRequest, "validation_error", "assets must contain at least one item")
		return
	}

	result, err := s.store.SyncAssetProfilesForTenant(r.Context(), principal.OrganizationID, request)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "asset_sync_failed", "asset profiles could not be synchronized")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAssetRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/assets/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "asset_route_not_found", "the requested asset route was not found")
		return
	}

	assetID, err := url.PathUnescape(strings.TrimSpace(parts[0]))
	if err != nil || strings.TrimSpace(assetID) == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_asset_id", "asset id is invalid")
		return
	}

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			profile, found, err := s.store.GetAssetProfileForTenant(r.Context(), principal.OrganizationID, assetID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_asset_profile_failed", "asset profile could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "asset_profile_not_found", "asset profile was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, profile)
			return
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpsertAssetProfileRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.AssetType) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "asset_type is required")
				return
			}

			profile, err := s.store.UpsertAssetProfileForTenant(r.Context(), principal.OrganizationID, assetID, request)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "upsert_asset_profile_failed", "asset profile could not be saved")
				return
			}

			s.writeJSON(w, http.StatusOK, profile)
			return
		default:
			s.writeMethodNotAllowed(w)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "controls" {
		switch r.Method {
		case http.MethodGet:
			controls, err := s.store.ListCompensatingControlsForTenant(r.Context(), principal.OrganizationID, assetID, 200)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "list_compensating_controls_failed", "compensating controls could not be loaded")
				return
			}
			s.writeJSON(w, http.StatusOK, map[string]any{
				"items": controls,
			})
			return
		case http.MethodPost:
			defer r.Body.Close()

			var request models.CreateCompensatingControlRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.Name) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "name is required")
				return
			}

			control, err := s.store.CreateCompensatingControlForTenant(r.Context(), principal.OrganizationID, assetID, request)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "create_compensating_control_failed", "compensating control could not be created")
				return
			}

			s.writeJSON(w, http.StatusCreated, control)
			return
		default:
			s.writeMethodNotAllowed(w)
			return
		}
	}

	s.writeError(w, http.StatusNotFound, "asset_route_not_found", "the requested asset route was not found")
}

func (s *Server) handleValidationEngagements(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}
		status := strings.TrimSpace(r.URL.Query().Get("status"))

		items, err := s.store.ListValidationEngagementsForTenant(r.Context(), principal.OrganizationID, status, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_validation_engagements_failed", "validation engagements could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateValidationEngagementRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.Name) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "name is required")
			return
		}

		item, err := s.store.CreateValidationEngagementForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeValidationEngagementMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_validation_engagement_failed", "validation engagement could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleValidationEngagementRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/validation-engagements/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "validation_engagement_route_not_found", "the requested validation engagement route was not found")
		return
	}

	engagementID := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			item, found, err := s.store.GetValidationEngagementForTenant(r.Context(), principal.OrganizationID, engagementID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_validation_engagement_failed", "validation engagement could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "validation_engagement_not_found", "validation engagement was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpdateValidationEngagementRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			item, found, err := s.store.UpdateValidationEngagementForTenant(r.Context(), principal.OrganizationID, engagementID, principal.Email, request)
			if err != nil {
				if s.writeValidationEngagementMutationError(w, err) {
					return
				}
				s.writeError(w, http.StatusInternalServerError, "update_validation_engagement_failed", "validation engagement could not be updated")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "validation_engagement_not_found", "validation engagement was not found")
				return
			}

			s.writeJSON(w, http.StatusOK, item)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	if len(parts) != 2 || r.Method != http.MethodPost {
		s.writeError(w, http.StatusNotFound, "validation_engagement_route_not_found", "the requested validation engagement route was not found")
		return
	}

	defer r.Body.Close()
	var decision models.ValidationEngagementDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&decision); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	action := strings.TrimSpace(parts[1])
	switch action {
	case "approve":
		item, found, err := s.store.ApproveValidationEngagementForTenant(r.Context(), principal.OrganizationID, engagementID, principal.Email, decision.Reason)
		if err != nil {
			if s.writeValidationEngagementMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "approve_validation_engagement_failed", "validation engagement could not be approved")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "validation_engagement_not_found", "validation engagement was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case "activate":
		item, found, err := s.store.ActivateValidationEngagementForTenant(r.Context(), principal.OrganizationID, engagementID, principal.Email)
		if err != nil {
			if s.writeValidationEngagementMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "activate_validation_engagement_failed", "validation engagement could not be activated")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "validation_engagement_not_found", "validation engagement was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case "close":
		item, found, err := s.store.CloseValidationEngagementForTenant(r.Context(), principal.OrganizationID, engagementID, principal.Email, decision.Reason)
		if err != nil {
			if s.writeValidationEngagementMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "close_validation_engagement_failed", "validation engagement could not be closed")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "validation_engagement_not_found", "validation engagement was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	default:
		s.writeError(w, http.StatusNotFound, "validation_engagement_route_not_found", "the requested validation engagement route was not found")
	}
}

func (s *Server) handleValidationEnvelopeRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/validation/envelopes/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "validation_envelope_route_not_found", "the requested validation execution envelope route was not found")
		return
	}
	engagementID := strings.TrimSpace(parts[0])

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			item, found, err := s.store.GetValidationExecutionEnvelopeForTenant(r.Context(), principal.OrganizationID, engagementID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_validation_execution_envelope_failed", "validation execution envelope could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "validation_execution_envelope_not_found", "validation execution envelope was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpsertValidationExecutionEnvelopeRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			item, err := s.store.UpsertValidationExecutionEnvelopeForTenant(r.Context(), principal.OrganizationID, engagementID, principal.Email, request)
			if err != nil {
				if s.writeValidationEngagementMutationError(w, err) {
					return
				}
				s.writeError(w, http.StatusInternalServerError, "upsert_validation_execution_envelope_failed", "validation execution envelope could not be saved")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	if len(parts) != 2 || r.Method != http.MethodPost {
		s.writeError(w, http.StatusNotFound, "validation_envelope_route_not_found", "the requested validation execution envelope route was not found")
		return
	}

	defer r.Body.Close()
	var decision models.ValidationEngagementDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&decision); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	action := strings.TrimSpace(parts[1])
	switch action {
	case "approve":
		item, found, err := s.store.ApproveValidationExecutionEnvelopeForTenant(r.Context(), principal.OrganizationID, engagementID, principal.Email, decision.Reason)
		if err != nil {
			if s.writeValidationEngagementMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "approve_validation_execution_envelope_failed", "validation execution envelope could not be approved")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "validation_execution_envelope_not_found", "validation execution envelope was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case "activate":
		item, found, err := s.store.ActivateValidationExecutionEnvelopeForTenant(r.Context(), principal.OrganizationID, engagementID, principal.Email)
		if err != nil {
			if s.writeValidationEngagementMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "activate_validation_execution_envelope_failed", "validation execution envelope could not be activated")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "validation_execution_envelope_not_found", "validation execution envelope was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case "close":
		item, found, err := s.store.CloseValidationExecutionEnvelopeForTenant(r.Context(), principal.OrganizationID, engagementID, principal.Email, decision.Reason)
		if err != nil {
			if s.writeValidationEngagementMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "close_validation_execution_envelope_failed", "validation execution envelope could not be closed")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "validation_execution_envelope_not_found", "validation execution envelope was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	default:
		s.writeError(w, http.StatusNotFound, "validation_envelope_route_not_found", "the requested validation execution envelope route was not found")
	}
}

func (s *Server) handleValidationPlanSteps(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}
		engagementID := strings.TrimSpace(r.URL.Query().Get("engagement_id"))
		status := strings.TrimSpace(r.URL.Query().Get("status"))

		items, err := s.store.ListValidationPlanStepsForTenant(r.Context(), principal.OrganizationID, engagementID, status, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_validation_plan_steps_failed", "validation plan steps could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateValidationPlanStepRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.EngagementID) == "" || strings.TrimSpace(request.Name) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "engagement_id and name are required")
			return
		}

		item, err := s.store.CreateValidationPlanStepForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeValidationEngagementMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_validation_plan_step_failed", "validation plan step could not be created")
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleValidationPlanStepRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/validation/plan-steps/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "validation_plan_step_route_not_found", "the requested validation plan step route was not found")
		return
	}

	approved := false
	switch strings.TrimSpace(parts[1]) {
	case "approve":
		approved = true
	case "deny":
		approved = false
	default:
		s.writeError(w, http.StatusNotFound, "validation_plan_step_route_not_found", "the requested validation plan step route was not found")
		return
	}

	defer r.Body.Close()
	var decision models.ValidationPlanStepDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&decision); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	item, found, err := s.store.DecideValidationPlanStepForTenant(r.Context(), principal.OrganizationID, strings.TrimSpace(parts[0]), approved, principal.Email, decision.Reason)
	if err != nil {
		if s.writeValidationEngagementMutationError(w, err) {
			return
		}
		s.writeError(w, http.StatusInternalServerError, "decide_validation_plan_step_failed", "validation plan step could not be decided")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "validation_plan_step_not_found", "validation plan step was not found")
		return
	}
	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleValidationAttackTraces(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}
		engagementID := strings.TrimSpace(r.URL.Query().Get("engagement_id"))

		items, err := s.store.ListValidationAttackTracesForTenant(r.Context(), principal.OrganizationID, engagementID, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_validation_attack_traces_failed", "validation attack traces could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateValidationAttackTraceRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.EngagementID) == "" || strings.TrimSpace(request.Title) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "engagement_id and title are required")
			return
		}

		item, err := s.store.CreateValidationAttackTraceForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeValidationEngagementMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_validation_attack_trace_failed", "validation attack trace could not be created")
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleValidationManualTests(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}
		engagementID := strings.TrimSpace(r.URL.Query().Get("engagement_id"))
		status := strings.TrimSpace(r.URL.Query().Get("status"))

		items, err := s.store.ListValidationManualTestsForTenant(r.Context(), principal.OrganizationID, engagementID, status, limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_validation_manual_tests_failed", "validation manual tests could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateValidationManualTestCaseRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.EngagementID) == "" || strings.TrimSpace(request.Title) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "engagement_id and title are required")
			return
		}

		item, err := s.store.CreateValidationManualTestForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeValidationEngagementMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_validation_manual_test_failed", "validation manual test case could not be created")
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleValidationManualTestRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	testCaseID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/validation/manual-tests/"))
	if testCaseID == "" || strings.Contains(testCaseID, "/") {
		s.writeError(w, http.StatusNotFound, "validation_manual_test_not_found", "validation manual test case was not found")
		return
	}

	defer r.Body.Close()

	var request models.UpdateValidationManualTestCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	item, found, err := s.store.UpdateValidationManualTestForTenant(r.Context(), principal.OrganizationID, testCaseID, principal.Email, request)
	if err != nil {
		if s.writeValidationEngagementMutationError(w, err) {
			return
		}
		s.writeError(w, http.StatusInternalServerError, "update_validation_manual_test_failed", "validation manual test case could not be updated")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "validation_manual_test_not_found", "validation manual test case was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		policies, err := s.store.ListPoliciesForTenant(r.Context(), principal.OrganizationID, 200)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_policies_failed", "policies could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": policies,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreatePolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		if strings.TrimSpace(request.Name) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "name is required")
			return
		}

		request.UpdatedBy = principal.Email
		tenantID := principal.OrganizationID
		if request.Global {
			if principal.Role != auth.RolePlatformAdmin {
				s.writeError(w, http.StatusForbidden, "permission_denied", "only platform administrators can create global policies")
				return
			}
			tenantID = ""
			if strings.TrimSpace(request.Scope) == "" {
				request.Scope = "global"
			}
		}

		policy, err := s.store.CreatePolicyForTenant(r.Context(), tenantID, request)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "create_policy_failed", "policy could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, policy)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handlePolicyRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/policies/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "policy_route_not_found", "the requested policy route was not found")
		return
	}

	policyID := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			policy, found, err := s.store.GetPolicyForTenant(r.Context(), principal.OrganizationID, policyID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_policy_failed", "policy could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "policy_not_found", "policy was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, policy)
			return
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpdatePolicyRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.Name) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "name is required")
				return
			}

			request.UpdatedBy = principal.Email
			targetTenantID := principal.OrganizationID
			current, found, err := s.store.GetPolicyForTenant(r.Context(), principal.OrganizationID, policyID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_policy_failed", "policy could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "policy_not_found", "policy was not found")
				return
			}
			if current.TenantID == "" {
				if principal.Role != auth.RolePlatformAdmin {
					s.writeError(w, http.StatusForbidden, "permission_denied", "only platform administrators can modify global policies")
					return
				}
				targetTenantID = ""
			}

			updated, found, err := s.store.UpdatePolicyForTenant(r.Context(), targetTenantID, policyID, request)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "update_policy_failed", "policy could not be updated")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "policy_not_found", "policy was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, updated)
			return
		default:
			s.writeMethodNotAllowed(w)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "versions" && r.Method == http.MethodGet {
		versions, err := s.store.ListPolicyVersionsForTenant(r.Context(), principal.OrganizationID, policyID, 200)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_policy_versions_failed", "policy versions could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": versions,
		})
		return
	}

	if len(parts) == 2 && parts[1] == "rollback" && r.Method == http.MethodPost {
		defer r.Body.Close()

		var request models.PolicyRollbackRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if request.VersionNumber <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "version_number must be greater than zero")
			return
		}

		targetTenantID := principal.OrganizationID
		current, found, err := s.store.GetPolicyForTenant(r.Context(), principal.OrganizationID, policyID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "get_policy_failed", "policy could not be loaded")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "policy_not_found", "policy was not found")
			return
		}
		if current.TenantID == "" {
			if principal.Role != auth.RolePlatformAdmin {
				s.writeError(w, http.StatusForbidden, "permission_denied", "only platform administrators can rollback global policies")
				return
			}
			targetTenantID = ""
		}

		rolledBack, found, err := s.store.RollbackPolicyForTenant(r.Context(), targetTenantID, policyID, request.VersionNumber, principal.Email)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "rollback_policy_failed", "policy could not be rolled back")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "policy_version_not_found", "policy version was not found")
			return
		}

		s.writeJSON(w, http.StatusOK, rolledBack)
		return
	}

	s.writeError(w, http.StatusNotFound, "policy_route_not_found", "the requested policy route was not found")
}

func (s *Server) handlePolicyApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	items, err := s.store.ListPolicyApprovalsForTenant(r.Context(), principal.OrganizationID, 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_policy_approvals_failed", "policy approvals could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

func (s *Server) handlePolicyApprovalDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/policy-approvals/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "policy_approval_route_not_found", "the requested policy approval route was not found")
		return
	}

	approved := false
	switch parts[1] {
	case "approve":
		approved = true
	case "deny":
		approved = false
	default:
		s.writeError(w, http.StatusNotFound, "policy_approval_route_not_found", "the requested policy approval route was not found")
		return
	}

	defer r.Body.Close()

	var request models.PolicyApprovalDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	item, found, err := s.store.DecidePolicyApproval(r.Context(), principal.OrganizationID, parts[0], approved, principal.Email, request.Reason)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "policy_approval_decision_failed", "policy approval could not be updated")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "policy_approval_not_found", "policy approval was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleRemediations(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListRemediationsForTenant(r.Context(), principal.OrganizationID, 200)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_remediations_failed", "remediation actions could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateRemediationRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		if strings.TrimSpace(request.FindingID) == "" || strings.TrimSpace(request.Title) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "finding_id and title are required")
			return
		}

		item, err := s.store.CreateRemediationForTenant(r.Context(), principal.OrganizationID, request)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "create_remediation_failed", "remediation action could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleRemediationRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediations/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "remediation_route_not_found", "the requested remediation route was not found")
		return
	}

	remediationID := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			s.writeMethodNotAllowed(w)
			return
		}

		item, found, err := s.store.GetRemediationForTenant(r.Context(), principal.OrganizationID, remediationID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "get_remediation_failed", "remediation action could not be loaded")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
			return
		}

		s.writeJSON(w, http.StatusOK, item)
		return
	}

	if len(parts) == 2 {
		switch parts[1] {
		case "transition":
			if r.Method != http.MethodPost {
				s.writeMethodNotAllowed(w)
				return
			}

			defer r.Body.Close()

			var request models.TransitionRemediationRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.Status) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "status is required")
				return
			}

			item, found, err := s.store.TransitionRemediationForTenant(r.Context(), principal.OrganizationID, remediationID, request)
			if err != nil {
				if errors.Is(err, jobs.ErrInvalidRemediationTransition) {
					s.writeError(w, http.StatusConflict, "invalid_remediation_transition", "the requested remediation transition is not allowed")
					return
				}
				s.writeError(w, http.StatusInternalServerError, "transition_remediation_failed", "remediation action could not be transitioned")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
				return
			}

			s.writeJSON(w, http.StatusOK, item)
			return
		case "activity":
			if r.Method != http.MethodGet {
				s.writeMethodNotAllowed(w)
				return
			}

			items, err := s.store.ListRemediationActivityForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "list_remediation_activity_failed", "remediation activity could not be loaded")
				return
			}

			s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			return
		case "comments":
			if r.Method != http.MethodPost {
				s.writeMethodNotAllowed(w)
				return
			}
			defer r.Body.Close()

			var request models.CreateRemediationCommentRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.Comment) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "comment is required")
				return
			}

			item, err := s.store.CreateRemediationCommentForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
			if err != nil {
				if errors.Is(err, jobs.ErrTaskNotFound) {
					s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
					return
				}
				s.writeError(w, http.StatusInternalServerError, "create_remediation_comment_failed", "remediation comment could not be created")
				return
			}

			s.writeJSON(w, http.StatusCreated, item)
			return
		case "evidence":
			switch r.Method {
			case http.MethodGet:
				items, err := s.store.ListRemediationEvidenceForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
				if err != nil {
					s.writeError(w, http.StatusInternalServerError, "list_remediation_evidence_failed", "remediation evidence could not be loaded")
					return
				}
				s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			case http.MethodPost:
				defer r.Body.Close()

				var request models.CreateRemediationEvidenceRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
					return
				}
				if strings.TrimSpace(request.Kind) == "" || strings.TrimSpace(request.Ref) == "" {
					s.writeError(w, http.StatusBadRequest, "validation_error", "kind and ref are required")
					return
				}

				item, err := s.store.CreateRemediationEvidenceForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
				if err != nil {
					if errors.Is(err, jobs.ErrTaskNotFound) {
						s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
						return
					}
					s.writeError(w, http.StatusInternalServerError, "create_remediation_evidence_failed", "remediation evidence could not be created")
					return
				}
				s.writeJSON(w, http.StatusCreated, item)
			default:
				s.writeMethodNotAllowed(w)
			}
			return
		case "verifications":
			if r.Method != http.MethodGet {
				s.writeMethodNotAllowed(w)
				return
			}

			items, err := s.store.ListRemediationVerificationsForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "list_remediation_verifications_failed", "remediation verifications could not be loaded")
				return
			}

			s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			return
		case "retest":
			if r.Method != http.MethodPost {
				s.writeMethodNotAllowed(w)
				return
			}
			defer r.Body.Close()

			var request models.CreateRetestRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			verification, job, err := s.store.RequestRemediationRetestForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
			if err != nil {
				switch {
				case errors.Is(err, jobs.ErrTaskNotFound):
					s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
				case errors.Is(err, jobs.ErrInvalidVerification), errors.Is(err, jobs.ErrInvalidRemediationTransition):
					s.writeError(w, http.StatusConflict, "invalid_retest_request", "the remediation is not in a state that allows retest")
				default:
					s.writeError(w, http.StatusInternalServerError, "request_retest_failed", "retest could not be requested")
				}
				return
			}

			s.writeJSON(w, http.StatusCreated, map[string]any{
				"verification": verification,
				"scan_job":     job,
			})
			return
		case "verify":
			if r.Method != http.MethodPost {
				s.writeMethodNotAllowed(w)
				return
			}
			defer r.Body.Close()

			var request models.RecordRemediationVerificationRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.VerificationID) == "" || strings.TrimSpace(request.Outcome) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "verification_id and outcome are required")
				return
			}

			item, found, err := s.store.RecordRemediationVerificationForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
			if err != nil {
				if errors.Is(err, jobs.ErrInvalidVerification) {
					s.writeError(w, http.StatusConflict, "invalid_remediation_verification", "the remediation verification could not be completed")
					return
				}
				s.writeError(w, http.StatusInternalServerError, "complete_remediation_verification_failed", "remediation verification could not be completed")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "remediation_verification_not_found", "remediation verification was not found")
				return
			}

			s.writeJSON(w, http.StatusOK, item)
			return
		case "exceptions":
			switch r.Method {
			case http.MethodGet:
				items, err := s.store.ListRemediationExceptionsForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
				if err != nil {
					s.writeError(w, http.StatusInternalServerError, "list_remediation_exceptions_failed", "remediation exceptions could not be loaded")
					return
				}
				s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			case http.MethodPost:
				defer r.Body.Close()

				var request models.CreateRemediationExceptionRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
					return
				}
				if strings.TrimSpace(request.Reason) == "" || request.Reduction <= 0 {
					s.writeError(w, http.StatusBadRequest, "validation_error", "reason and a positive reduction are required")
					return
				}

				item, err := s.store.CreateRemediationExceptionForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
				if err != nil {
					switch {
					case errors.Is(err, jobs.ErrTaskNotFound):
						s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
					case errors.Is(err, jobs.ErrInvalidExceptionDecision):
						s.writeError(w, http.StatusConflict, "invalid_remediation_exception", "the remediation exception is not valid")
					default:
						s.writeError(w, http.StatusInternalServerError, "create_remediation_exception_failed", "remediation exception could not be created")
					}
					return
				}
				s.writeJSON(w, http.StatusCreated, item)
			default:
				s.writeMethodNotAllowed(w)
			}
			return
		case "tickets":
			switch r.Method {
			case http.MethodGet:
				items, err := s.store.ListRemediationTicketLinksForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
				if err != nil {
					s.writeError(w, http.StatusInternalServerError, "list_remediation_tickets_failed", "remediation tickets could not be loaded")
					return
				}
				s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			case http.MethodPost:
				defer r.Body.Close()

				var request models.CreateRemediationTicketLinkRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
					return
				}
				if strings.TrimSpace(request.Provider) == "" || strings.TrimSpace(request.ExternalID) == "" {
					s.writeError(w, http.StatusBadRequest, "validation_error", "provider and external_id are required")
					return
				}

				item, err := s.store.CreateRemediationTicketLinkForTenant(r.Context(), principal.OrganizationID, remediationID, request)
				if err != nil {
					switch {
					case errors.Is(err, jobs.ErrTaskNotFound):
						s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
					case errors.Is(err, jobs.ErrInvalidExceptionDecision):
						s.writeError(w, http.StatusConflict, "invalid_remediation_ticket", "the remediation ticket link is not valid")
					default:
						s.writeError(w, http.StatusInternalServerError, "create_remediation_ticket_failed", "remediation ticket could not be created")
					}
					return
				}
				s.writeJSON(w, http.StatusCreated, item)
			default:
				s.writeMethodNotAllowed(w)
			}
			return
		case "assignment-requests":
			switch r.Method {
			case http.MethodGet:
				items, err := s.store.ListRemediationAssignmentRequestsForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
				if err != nil {
					s.writeError(w, http.StatusInternalServerError, "list_remediation_assignment_requests_failed", "remediation assignment requests could not be loaded")
					return
				}
				s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			case http.MethodPost:
				defer r.Body.Close()

				var request models.CreateRemediationAssignmentRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
					return
				}
				if strings.TrimSpace(request.RequestedOwner) == "" {
					s.writeError(w, http.StatusBadRequest, "validation_error", "requested_owner is required")
					return
				}

				item, err := s.store.CreateRemediationAssignmentRequestForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
				if err != nil {
					if errors.Is(err, jobs.ErrTaskNotFound) {
						s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
						return
					}
					s.writeError(w, http.StatusInternalServerError, "create_remediation_assignment_request_failed", "remediation assignment request could not be created")
					return
				}
				s.writeJSON(w, http.StatusCreated, item)
			default:
				s.writeMethodNotAllowed(w)
			}
			return
		}
	}

	if len(parts) == 4 && parts[1] == "tickets" && parts[3] == "sync" {
		if r.Method != http.MethodPost {
			s.writeMethodNotAllowed(w)
			return
		}
		if strings.TrimSpace(parts[2]) == "" {
			s.writeError(w, http.StatusNotFound, "remediation_route_not_found", "the requested remediation route was not found")
			return
		}

		defer r.Body.Close()

		var request models.SyncRemediationTicketLinkRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		item, found, err := s.store.SyncRemediationTicketLinkForTenant(r.Context(), principal.OrganizationID, remediationID, strings.TrimSpace(parts[2]), request)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "sync_remediation_ticket_failed", "remediation ticket could not be synchronized")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "remediation_ticket_not_found", "remediation ticket was not found")
			return
		}

		s.writeJSON(w, http.StatusOK, item)
		return
	}

	s.writeError(w, http.StatusNotFound, "remediation_route_not_found", "the requested remediation route was not found")
}

func (s *Server) handleRemediationExceptionDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediation-exceptions/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "remediation_exception_route_not_found", "the requested remediation exception route was not found")
		return
	}

	approved := false
	switch parts[1] {
	case "approve":
		approved = true
	case "deny":
		approved = false
	default:
		s.writeError(w, http.StatusNotFound, "remediation_exception_route_not_found", "the requested remediation exception route was not found")
		return
	}

	defer r.Body.Close()

	var request models.DecideRemediationExceptionRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	item, found, err := s.store.DecideRemediationExceptionForTenant(r.Context(), principal.OrganizationID, parts[0], approved, principal.Email, request.Reason)
	if err != nil {
		if errors.Is(err, jobs.ErrInvalidExceptionDecision) {
			s.writeError(w, http.StatusConflict, "invalid_remediation_exception_decision", "the remediation exception could not be decided")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "decide_remediation_exception_failed", "remediation exception could not be updated")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "remediation_exception_not_found", "remediation exception was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleRemediationAssignmentDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediation-assignments/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "remediation_assignment_route_not_found", "the requested remediation assignment route was not found")
		return
	}

	approved := false
	switch parts[1] {
	case "approve":
		approved = true
	case "deny":
		approved = false
	default:
		s.writeError(w, http.StatusNotFound, "remediation_assignment_route_not_found", "the requested remediation assignment route was not found")
		return
	}

	defer r.Body.Close()

	var request models.DecideRemediationAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	item, found, err := s.store.DecideRemediationAssignmentRequestForTenant(r.Context(), principal.OrganizationID, parts[0], approved, principal.Email, request.Reason)
	if err != nil {
		if errors.Is(err, jobs.ErrInvalidAssignmentDecision) {
			s.writeError(w, http.StatusConflict, "invalid_remediation_assignment_decision", "the remediation assignment request could not be decided")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "decide_remediation_assignment_failed", "remediation assignment request could not be updated")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "remediation_assignment_not_found", "remediation assignment request was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	items, err := s.store.ListNotificationEventsForTenant(r.Context(), principal.OrganizationID, 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_notifications_failed", "notification events could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleNotificationRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/notifications/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "ack" {
		s.writeError(w, http.StatusNotFound, "notification_route_not_found", "the requested notification route was not found")
		return
	}

	item, found, err := s.store.AcknowledgeNotificationEventForTenant(r.Context(), principal.OrganizationID, parts[0], principal.Email)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "acknowledge_notification_failed", "notification event could not be acknowledged")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "notification_not_found", "notification event was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleRemediationEscalationSweep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	result, err := s.store.SweepRemediationEscalationsForTenant(r.Context(), principal.OrganizationID, principal.Email)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "sweep_remediation_escalations_failed", "remediation escalations could not be processed")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) writeValidationEngagementExecutionError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, jobs.ErrValidationEngagementRequired):
		s.writeError(w, http.StatusBadRequest, "validation_engagement_required", "validation engagement is required for restricted scan tools")
		return true
	case errors.Is(err, jobs.ErrValidationEngagementNotFound):
		s.writeError(w, http.StatusBadRequest, "validation_engagement_not_found", "validation engagement was not found")
		return true
	case errors.Is(err, jobs.ErrValidationEngagementInactive):
		s.writeError(w, http.StatusConflict, "validation_engagement_inactive", "validation engagement is not active")
		return true
	case errors.Is(err, jobs.ErrValidationEngagementScope):
		s.writeError(w, http.StatusBadRequest, "validation_engagement_scope_mismatch", "validation engagement does not match requested target")
		return true
	case errors.Is(err, jobs.ErrValidationEngagementTool):
		s.writeError(w, http.StatusBadRequest, "validation_engagement_tool_not_allowed", "validation engagement does not allow requested tools")
		return true
	case errors.Is(err, jobs.ErrValidationEnvelopeInactive):
		s.writeError(w, http.StatusConflict, "validation_execution_envelope_inactive", "validation execution envelope is not active")
		return true
	case errors.Is(err, jobs.ErrValidationPlanStepRequired):
		s.writeError(w, http.StatusBadRequest, "validation_plan_step_required", "validation plan step approval is required")
		return true
	case errors.Is(err, jobs.ErrValidationPlanStepNotFound):
		s.writeError(w, http.StatusBadRequest, "validation_plan_step_not_found", "validation plan step was not found")
		return true
	case errors.Is(err, jobs.ErrValidationPlanStepNotApproved):
		s.writeError(w, http.StatusConflict, "validation_plan_step_not_approved", "validation plan step is not approved")
		return true
	case errors.Is(err, jobs.ErrValidationPlanStepDependency):
		s.writeError(w, http.StatusConflict, "validation_plan_step_dependency_pending", "validation plan step dependencies are not approved")
		return true
	case errors.Is(err, jobs.ErrValidationPlanStepScope):
		s.writeError(w, http.StatusBadRequest, "validation_plan_step_scope_mismatch", "validation plan step does not match the requested scope")
		return true
	default:
		return false
	}
}

func (s *Server) writeValidationEngagementMutationError(w http.ResponseWriter, err error) bool {
	if s.writeValidationEngagementExecutionError(w, err) {
		return true
	}

	lower := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(lower, "name is required"),
		strings.Contains(lower, "end_at must"),
		strings.Contains(lower, "required"):
		s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
		return true
	case strings.Contains(lower, "cannot be"),
		strings.Contains(lower, "requires approval"),
		strings.Contains(lower, "in the past"):
		s.writeError(w, http.StatusConflict, "validation_engagement_state_invalid", err.Error())
		return true
	case strings.Contains(lower, "max_runtime_seconds must be greater than or equal to zero"):
		s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
		return true
	case strings.Contains(lower, "duplicate key"),
		strings.Contains(lower, "already exists"),
		strings.Contains(lower, "unique"):
		s.writeError(w, http.StatusConflict, "validation_engagement_conflict", "validation engagement already exists for this tenant")
		return true
	default:
		return false
	}
}

func (s *Server) createScanJob(w http.ResponseWriter, r *http.Request, principal models.AuthPrincipal) {
	defer r.Body.Close()

	var request models.CreateScanJobRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	if strings.TrimSpace(request.TargetKind) == "" ||
		strings.TrimSpace(request.Target) == "" ||
		strings.TrimSpace(request.Profile) == "" {
		s.writeError(w, http.StatusBadRequest, "validation_error", "target_kind, target, and profile are required")
		return
	}

	if request.TenantID != "" && strings.TrimSpace(request.TenantID) != principal.OrganizationID {
		s.writeError(w, http.StatusForbidden, "tenant_scope_violation", "scan jobs can only be created in the authenticated tenant")
		return
	}

	request.TenantID = principal.OrganizationID
	request.RequestedBy = principal.Email

	job, err := s.store.CreateForTenant(r.Context(), principal.OrganizationID, request)
	if err != nil {
		if s.writeValidationEngagementExecutionError(w, err) {
			return
		}
		var denied *jobs.PolicyDeniedError
		if errors.As(err, &denied) {
			s.writeJSON(w, http.StatusForbidden, map[string]any{
				"code":      "policy_denied",
				"message":   denied.Error(),
				"policy_id": denied.PolicyID,
				"rule_hits": denied.RuleHits,
			})
			return
		}
		var engineDenied *jobs.EngineControlDeniedError
		if errors.As(err, &engineDenied) {
			s.writeJSON(w, http.StatusForbidden, map[string]any{
				"code":        "engine_control_denied",
				"message":     engineDenied.Error(),
				"adapter_id":  strings.TrimSpace(engineDenied.AdapterID),
				"target_kind": strings.TrimSpace(engineDenied.TargetKind),
			})
			return
		}
		var limitExceeded *jobs.TenantLimitExceededError
		if errors.As(err, &limitExceeded) {
			s.writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"code":    "tenant_limit_exceeded",
				"message": limitExceeded.Error(),
				"metric":  limitExceeded.Metric,
				"limit":   limitExceeded.Limit,
				"current": limitExceeded.Current,
			})
			return
		}
		var controlViolation *jobs.ExecutionControlViolationError
		if errors.As(err, &controlViolation) {
			s.writeJSON(w, http.StatusConflict, map[string]any{
				"code":        strings.TrimSpace(controlViolation.Code),
				"message":     controlViolation.Error(),
				"reason":      strings.TrimSpace(controlViolation.Reason),
				"window_id":   strings.TrimSpace(controlViolation.WindowID),
				"window_name": strings.TrimSpace(controlViolation.WindowName),
			})
			return
		}
		s.writeError(w, http.StatusInternalServerError, "create_scan_job_failed", "scan job could not be created")
		return
	}

	s.writeJSON(w, http.StatusCreated, job)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	http.Redirect(w, r, s.primaryUIRedirectPath(), http.StatusTemporaryRedirect)
}

func (s *Server) handleAppRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/app" {
		http.NotFound(w, r)
		return
	}

	http.Redirect(w, r, "/app/", http.StatusTemporaryRedirect)
}

func (s *Server) handleUIDistRoot(w http.ResponseWriter, r *http.Request) {
	if !s.uiDistEnabled || r.URL.Path != "/ui" {
		http.NotFound(w, r)
		return
	}

	http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
}

func (s *Server) handleUIDist(w http.ResponseWriter, r *http.Request) {
	if !s.uiDistEnabled || !strings.HasPrefix(r.URL.Path, "/ui/") {
		http.NotFound(w, r)
		return
	}

	relativePath := strings.TrimPrefix(r.URL.Path, "/ui/")
	relativePath = strings.TrimSpace(relativePath)
	if relativePath == "" {
		relativePath = "index.html"
	}

	cleanPath := filepath.Clean(relativePath)
	if cleanPath == "." {
		cleanPath = "index.html"
	}
	if strings.HasPrefix(cleanPath, "..") {
		http.NotFound(w, r)
		return
	}

	assetPath := filepath.Join(s.uiDistPath, cleanPath)
	if stat, err := os.Stat(assetPath); err == nil && !stat.IsDir() {
		http.ServeFile(w, r, assetPath)
		return
	}

	http.ServeFile(w, r, filepath.Join(s.uiDistPath, "index.html"))
}

func (s *Server) primaryUIRedirectPath() string {
	if s.uiDistEnabled {
		return "/ui/"
	}
	return "/app/"
}

func hasUIDist(uiDistPath string) bool {
	uiDistPath = strings.TrimSpace(uiDistPath)
	if uiDistPath == "" {
		return false
	}

	indexPath := filepath.Join(uiDistPath, "index.html")
	stat, err := os.Stat(indexPath)
	if err != nil {
		return false
	}

	return !stat.IsDir()
}

func (s *Server) withUserAuth(permission auth.Permission, action string, resourceType string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := s.extractAuthToken(r)
		if token == "" {
			s.writeError(w, http.StatusUnauthorized, "authentication_required", "an api token or browser session is required")
			return
		}

		principal, ok, err := s.store.AuthenticateToken(r.Context(), token)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "authentication_failed", "authentication could not be completed")
			return
		}
		if !ok {
			s.writeError(w, http.StatusUnauthorized, "invalid_bearer_token", "the supplied bearer token is invalid")
			return
		}

		if err := tenant.RequirePrincipalOrganization(principal); err != nil {
			s.recordAuditEvent(r.Context(), principal, action, resourceType, "", "denied", r, map[string]any{
				"permission": string(permission),
				"reason":     "tenant",
			})
			s.writeError(w, http.StatusForbidden, "permission_denied", "the current identity is not allowed to perform this action")
			return
		}

		if err := rbac.Authorize(principal, permission); err != nil {
			reason := rbac.Reason(err)
			if reason == "" {
				reason = "authorization"
			}
			s.recordAuditEvent(r.Context(), principal, action, resourceType, "", "denied", r, map[string]any{
				"permission": string(permission),
				"reason":     reason,
			})
			s.writeError(w, http.StatusForbidden, "permission_denied", "the current identity is not allowed to perform this action")
			return
		}

		recorder := &auditedResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next(recorder, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
		s.recordAuditEvent(r.Context(), principal, action, resourceType, s.resourceIDFromRequest(r), http.StatusText(recorder.status), r, map[string]any{
			"permission":  string(permission),
			"status_code": recorder.status,
		})
	}
}

func (s *Server) withUserAuthForMethod(permissions map[string]auth.Permission, actionPrefix string, resourceType string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		permission, ok := permissions[r.Method]
		if !ok {
			s.writeMethodNotAllowed(w)
			return
		}

		action := actionPrefix + "." + strings.ToLower(r.Method)
		s.withUserAuth(permission, action, resourceType, next)(w, r)
	}
}

func (s *Server) withWorkerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sharedSecret := strings.TrimSpace(s.cfg.WorkerSharedSecret)
		providedSecret := strings.TrimSpace(r.Header.Get(auth.WorkerSecretHeader))
		if sharedSecret != "" && providedSecret != "" {
			if providedSecret != sharedSecret {
				s.writeError(w, http.StatusUnauthorized, "invalid_worker_secret", "the worker secret is invalid")
				return
			}
			next(w, r)
			return
		}

		if token := auth.ParseBearerToken(r.Header.Get("Authorization")); token != "" {
			claims, err := auth.ValidateWorkerIdentityToken(s.cfg.WorkloadIdentitySigningKey, token, time.Now().UTC())
			if err != nil {
				s.writeError(w, http.StatusUnauthorized, "invalid_worker_identity_token", "the worker identity token is invalid")
				return
			}
			next(w, r.WithContext(auth.WithWorkerIdentityClaims(r.Context(), claims)))
			return
		}

		if sharedSecret != "" {
			s.writeError(w, http.StatusUnauthorized, "invalid_worker_secret", "the worker secret is invalid")
			return
		}
		if strings.TrimSpace(s.cfg.WorkloadIdentitySigningKey) != "" {
			s.writeError(w, http.StatusUnauthorized, "invalid_worker_identity_token", "the worker identity token is invalid")
			return
		}

		next(w, r)
	}
}

func (s *Server) recordAuditEvent(ctx context.Context, principal models.AuthPrincipal, action string, resourceType string, resourceID string, statusText string, r *http.Request, details map[string]any) {
	statusText = strings.ToLower(strings.TrimSpace(statusText))
	if statusText == "" {
		statusText = "unknown"
	}

	_ = s.store.RecordAuditEvent(ctx, models.AuditEvent{
		OrganizationID: principal.OrganizationID,
		ActorUserID:    principal.UserID,
		ActorEmail:     principal.Email,
		Action:         action,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		Status:         statusText,
		RequestMethod:  r.Method,
		RequestPath:    r.URL.Path,
		RemoteAddr:     r.RemoteAddr,
		Details:        details,
		CreatedAt:      time.Now().UTC(),
	})
}

func (s *Server) resourceIDFromRequest(r *http.Request) string {
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/scan-jobs/"):
		return strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/scan-jobs/"))
	case strings.HasPrefix(r.URL.Path, "/v1/scan-targets/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/scan-targets/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/scan-engine-controls/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/scan-engine-controls/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/ingestion/sources/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/ingestion/sources/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/integrations/webhooks/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/integrations/webhooks/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/auth/tokens/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/auth/tokens/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/policies/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/policies/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/policy-approvals/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/policy-approvals/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/remediations/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediations/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/remediation-exceptions/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediation-exceptions/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/remediation-assignments/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediation-assignments/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/notifications/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/notifications/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/findings/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/findings/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			path = strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/assets/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/assets/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			path = strings.TrimSpace(path[:idx])
		}
		assetID, err := url.PathUnescape(path)
		if err != nil {
			return path
		}
		return strings.TrimSpace(assetID)
	case strings.HasPrefix(r.URL.Path, "/v1/design-reviews/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/design-reviews/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/runtime/telemetry/connectors/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/runtime/telemetry/connectors/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/compliance/mappings/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/compliance/mappings/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/compliance/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/compliance/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/detection/rulepacks/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/detection/rulepacks/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/detection/distributions/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/detection/distributions/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/ai/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/ai/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/reports/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/reports/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	default:
		return ""
	}
}

func (s *Server) extractAuthToken(r *http.Request) string {
	if token := auth.ParseBearerToken(r.Header.Get("Authorization")); token != "" {
		return token
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(cookie.Value)
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func (s *Server) writeMethodNotAllowed(w http.ResponseWriter) {
	s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "the requested method is not supported")
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	s.writeJSON(w, status, models.APIError{
		Code:    code,
		Message: message,
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

type auditedResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditedResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
