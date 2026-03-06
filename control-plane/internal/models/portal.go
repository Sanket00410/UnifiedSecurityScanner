package models

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type AssetSummary struct {
	AssetID                  string     `json:"asset_id"`
	AssetType                string     `json:"asset_type"`
	Environment              string     `json:"environment,omitempty"`
	Exposure                 string     `json:"exposure,omitempty"`
	Criticality              float64    `json:"criticality,omitempty"`
	OwnerTeam                string     `json:"owner_team,omitempty"`
	OwnerHierarchy           []string   `json:"owner_hierarchy,omitempty"`
	ServiceName              string     `json:"service_name,omitempty"`
	ServiceTier              string     `json:"service_tier,omitempty"`
	ServiceCriticalityClass  string     `json:"service_criticality_class,omitempty"`
	ExternalSource           string     `json:"external_source,omitempty"`
	LastSyncedAt             *time.Time `json:"last_synced_at,omitempty"`
	CompensatingControlCount int64      `json:"compensating_control_count,omitempty"`
	LastScannedAt            time.Time  `json:"last_scanned_at"`
	ScanCount                int64      `json:"scan_count"`
	FindingCount             int64      `json:"finding_count"`
}

type AssetProfile struct {
	TenantID                string     `json:"tenant_id,omitempty"`
	AssetID                 string     `json:"asset_id"`
	AssetType               string     `json:"asset_type"`
	AssetName               string     `json:"asset_name"`
	Environment             string     `json:"environment"`
	Exposure                string     `json:"exposure"`
	Criticality             float64    `json:"criticality"`
	OwnerTeam               string     `json:"owner_team,omitempty"`
	OwnerHierarchy          []string   `json:"owner_hierarchy,omitempty"`
	ServiceName             string     `json:"service_name,omitempty"`
	ServiceTier             string     `json:"service_tier,omitempty"`
	ServiceCriticalityClass string     `json:"service_criticality_class,omitempty"`
	ExternalSource          string     `json:"external_source,omitempty"`
	ExternalReference       string     `json:"external_reference,omitempty"`
	LastSyncedAt            *time.Time `json:"last_synced_at,omitempty"`
	Tags                    []string   `json:"tags,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

type UpsertAssetProfileRequest struct {
	AssetType               string     `json:"asset_type"`
	AssetName               string     `json:"asset_name"`
	Environment             string     `json:"environment"`
	Exposure                string     `json:"exposure"`
	Criticality             float64    `json:"criticality"`
	OwnerTeam               string     `json:"owner_team"`
	OwnerHierarchy          []string   `json:"owner_hierarchy"`
	ServiceName             string     `json:"service_name"`
	ServiceTier             string     `json:"service_tier"`
	ServiceCriticalityClass string     `json:"service_criticality_class"`
	ExternalSource          string     `json:"external_source"`
	ExternalReference       string     `json:"external_reference"`
	LastSyncedAt            *time.Time `json:"last_synced_at"`
	Tags                    []string   `json:"tags"`
}

type SyncAssetProfile struct {
	AssetID                 string     `json:"asset_id"`
	AssetType               string     `json:"asset_type"`
	AssetName               string     `json:"asset_name"`
	Environment             string     `json:"environment"`
	Exposure                string     `json:"exposure"`
	Criticality             float64    `json:"criticality"`
	OwnerTeam               string     `json:"owner_team"`
	OwnerHierarchy          []string   `json:"owner_hierarchy"`
	ServiceName             string     `json:"service_name"`
	ServiceTier             string     `json:"service_tier"`
	ServiceCriticalityClass string     `json:"service_criticality_class"`
	ExternalSource          string     `json:"external_source"`
	ExternalReference       string     `json:"external_reference"`
	LastSyncedAt            *time.Time `json:"last_synced_at"`
	Tags                    []string   `json:"tags"`
}

type SyncAssetProfilesRequest struct {
	Source string             `json:"source"`
	Assets []SyncAssetProfile `json:"assets"`
}

type SyncAssetProfilesResult struct {
	ImportedCount int            `json:"imported_count"`
	Items         []AssetProfile `json:"items"`
}

type CompensatingControl struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id,omitempty"`
	AssetID       string    `json:"asset_id"`
	Name          string    `json:"name"`
	ControlType   string    `json:"control_type"`
	ScopeLayer    string    `json:"scope_layer"`
	Effectiveness float64   `json:"effectiveness"`
	Enabled       bool      `json:"enabled"`
	Notes         string    `json:"notes,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type CreateCompensatingControlRequest struct {
	Name          string  `json:"name"`
	ControlType   string  `json:"control_type"`
	ScopeLayer    string  `json:"scope_layer"`
	Effectiveness float64 `json:"effectiveness"`
	Enabled       bool    `json:"enabled"`
	Notes         string  `json:"notes"`
}

type FindingWaiver struct {
	ID               string     `json:"id"`
	TenantID         string     `json:"tenant_id,omitempty"`
	FindingID        string     `json:"finding_id"`
	RemediationID    string     `json:"remediation_id,omitempty"`
	PolicyApprovalID string     `json:"policy_approval_id,omitempty"`
	Reason           string     `json:"reason"`
	Reduction        float64    `json:"reduction"`
	Status           string     `json:"status"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type CreateFindingWaiverRequest struct {
	RemediationID    string     `json:"remediation_id"`
	PolicyApprovalID string     `json:"policy_approval_id"`
	Reason           string     `json:"reason"`
	Reduction        float64    `json:"reduction"`
	ExpiresAt        *time.Time `json:"expires_at"`
}

type RiskSummary struct {
	GeneratedAt      time.Time        `json:"generated_at"`
	TotalFindings    int64            `json:"total_findings"`
	OverdueFindings  int64            `json:"overdue_findings"`
	ReopenedFindings int64            `json:"reopened_findings"`
	NewFindings7d    int64            `json:"new_findings_7d"`
	Observations7d   int64            `json:"observations_7d"`
	AverageAgeDays   float64          `json:"average_age_days"`
	PriorityCounts   map[string]int64 `json:"priority_counts"`
	AgingBuckets     map[string]int64 `json:"aging_buckets"`
}

type Policy struct {
	ID            string        `json:"id"`
	TenantID      string        `json:"tenant_id,omitempty"`
	VersionNumber int64         `json:"version_number"`
	Name          string        `json:"name"`
	Scope         string        `json:"scope"`
	Mode          string        `json:"mode"`
	Enabled       bool          `json:"enabled"`
	Rules         PolicyRuleSet `json:"rules"`
	UpdatedBy     string        `json:"updated_by"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

type CreatePolicyRequest struct {
	Name      string        `json:"name"`
	Scope     string        `json:"scope"`
	Mode      string        `json:"mode"`
	Enabled   bool          `json:"enabled"`
	Rules     PolicyRuleSet `json:"rules"`
	UpdatedBy string        `json:"updated_by"`
	Global    bool          `json:"global"`
}

type UpdatePolicyRequest struct {
	Name      string        `json:"name"`
	Scope     string        `json:"scope"`
	Mode      string        `json:"mode"`
	Enabled   bool          `json:"enabled"`
	Rules     PolicyRuleSet `json:"rules"`
	UpdatedBy string        `json:"updated_by"`
}

type PolicyVersion struct {
	ID            string    `json:"id"`
	PolicyID      string    `json:"policy_id"`
	VersionNumber int64     `json:"version_number"`
	ChangeType    string    `json:"change_type"`
	Snapshot      Policy    `json:"snapshot"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
}

type PolicyRollbackRequest struct {
	VersionNumber int64 `json:"version_number"`
}

type PolicyApproval struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	ScanJobID   string     `json:"scan_job_id"`
	TaskID      string     `json:"task_id"`
	PolicyID    string     `json:"policy_id,omitempty"`
	Action      string     `json:"action"`
	Status      string     `json:"status"`
	RequestedBy string     `json:"requested_by"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
}

type PolicyApprovalDecisionRequest struct {
	Reason string `json:"reason"`
}

type PolicyRule struct {
	Effect     string                `json:"effect"`
	Field      string                `json:"field"`
	Match      string                `json:"match"`
	Values     []string              `json:"values"`
	Exceptions []PolicyRuleException `json:"exceptions,omitempty"`
}

type PolicyRuleException struct {
	Field  string   `json:"field,omitempty"`
	Match  string   `json:"match"`
	Values []string `json:"values"`
}

type PolicyRuleSet []PolicyRule

func (s *PolicyRuleSet) UnmarshalJSON(data []byte) error {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 || string(data) == "null" {
		*s = nil
		return nil
	}

	var structured []PolicyRule
	if err := json.Unmarshal(data, &structured); err == nil {
		*s = NormalizePolicyRuleSet(structured)
		return nil
	}

	var legacy []string
	if err := json.Unmarshal(data, &legacy); err == nil {
		converted := make([]PolicyRule, 0, len(legacy))
		for _, item := range legacy {
			converted = append(converted, legacyRuleToStructured(item))
		}
		*s = NormalizePolicyRuleSet(converted)
		return nil
	}

	return fmt.Errorf("policy rules must be an array of rule objects or legacy strings")
}

func NormalizePolicyRuleSet(items []PolicyRule) PolicyRuleSet {
	out := make([]PolicyRule, 0, len(items))
	for _, item := range items {
		rule := normalizePolicyRule(item)
		if rule.Field == "" || rule.Effect == "" {
			continue
		}
		out = append(out, rule)
	}
	return PolicyRuleSet(out)
}

func normalizePolicyRule(rule PolicyRule) PolicyRule {
	rule.Effect = strings.ToLower(strings.TrimSpace(rule.Effect))
	rule.Field = normalizeRuleField(rule.Field)
	rule.Match = normalizeRuleMatch(rule.Match)
	rule.Values = normalizeRuleValues(rule.Values)

	exceptions := make([]PolicyRuleException, 0, len(rule.Exceptions))
	for _, item := range rule.Exceptions {
		normalized := PolicyRuleException{
			Field:  normalizeRuleField(item.Field),
			Match:  normalizeRuleMatch(item.Match),
			Values: normalizeRuleValues(item.Values),
		}
		if normalized.Match != "any" && len(normalized.Values) == 0 {
			continue
		}
		exceptions = append(exceptions, normalized)
	}
	rule.Exceptions = exceptions

	return rule
}

func normalizeRuleField(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tool", "adapter":
		return "tool"
	case "target", "target_name":
		return "target"
	case "target_kind", "asset_type":
		return "target_kind"
	case "profile":
		return "profile"
	case "provider", "source_provider":
		return "provider"
	case "event_type", "event":
		return "event_type"
	case "repo", "repository", "repo_name":
		return "repo"
	case "branch", "git_branch":
		return "branch"
	case "requested_by", "requester", "actor":
		return "requested_by"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeRuleMatch(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "exact":
		return "exact"
	case "prefix":
		return "prefix"
	case "suffix":
		return "suffix"
	case "contains":
		return "contains"
	case "any":
		return "any"
	default:
		return "exact"
	}
}

func normalizeRuleValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func legacyRuleToStructured(rule string) PolicyRule {
	normalized := strings.ToLower(strings.TrimSpace(rule))
	parts := strings.SplitN(normalized, ":", 2)
	if len(parts) != 2 {
		return PolicyRule{
			Effect: "monitor",
			Field:  "target",
			Match:  "exact",
			Values: normalizeRuleValues([]string{normalized}),
		}
	}

	effect := parts[0]
	field := "tool"
	switch effect {
	case "allow_target":
		effect = "allow"
		field = "target_kind"
	case "block_target":
		effect = "block"
		field = "target_kind"
	case "allow_profile":
		effect = "allow"
		field = "profile"
	case "block_profile":
		effect = "block"
		field = "profile"
	case "allow_tool":
		effect = "allow"
		field = "tool"
	case "block_tool":
		effect = "block"
		field = "tool"
	case "require_approval":
		effect = "require_approval"
		field = "tool"
	default:
		effect = strings.TrimSpace(effect)
	}

	return normalizePolicyRule(PolicyRule{
		Effect: effect,
		Field:  field,
		Match:  "exact",
		Values: []string{parts[1]},
	})
}

type RemediationAction struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id,omitempty"`
	FindingID string     `json:"finding_id"`
	Title     string     `json:"title"`
	Status    string     `json:"status"`
	Owner     string     `json:"owner"`
	DueAt     *time.Time `json:"due_at,omitempty"`
	Notes     string     `json:"notes,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type CreateRemediationRequest struct {
	FindingID string     `json:"finding_id"`
	Title     string     `json:"title"`
	Status    string     `json:"status"`
	Owner     string     `json:"owner"`
	DueAt     *time.Time `json:"due_at,omitempty"`
	Notes     string     `json:"notes,omitempty"`
}

type TransitionRemediationRequest struct {
	Status string     `json:"status"`
	Owner  string     `json:"owner,omitempty"`
	DueAt  *time.Time `json:"due_at,omitempty"`
	Notes  string     `json:"notes,omitempty"`
}

type RemediationActivity struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id,omitempty"`
	RemediationID string         `json:"remediation_id"`
	EventType     string         `json:"event_type"`
	Actor         string         `json:"actor,omitempty"`
	Comment       string         `json:"comment,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

type CreateRemediationCommentRequest struct {
	Comment string `json:"comment"`
}

type RemediationEvidence struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id,omitempty"`
	RemediationID string    `json:"remediation_id"`
	Kind          string    `json:"kind"`
	Name          string    `json:"name,omitempty"`
	Ref           string    `json:"ref"`
	Summary       string    `json:"summary,omitempty"`
	CreatedBy     string    `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type CreateRemediationEvidenceRequest struct {
	Kind    string `json:"kind"`
	Name    string `json:"name,omitempty"`
	Ref     string `json:"ref"`
	Summary string `json:"summary,omitempty"`
}

type RemediationVerification struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id,omitempty"`
	RemediationID string     `json:"remediation_id"`
	FindingID     string     `json:"finding_id"`
	ScanJobID     string     `json:"scan_job_id,omitempty"`
	Status        string     `json:"status"`
	Outcome       string     `json:"outcome,omitempty"`
	RequestedBy   string     `json:"requested_by,omitempty"`
	VerifiedBy    string     `json:"verified_by,omitempty"`
	Notes         string     `json:"notes,omitempty"`
	RequestedAt   time.Time  `json:"requested_at"`
	VerifiedAt    *time.Time `json:"verified_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type CreateRetestRequest struct {
	Notes string `json:"notes,omitempty"`
}

type RecordRemediationVerificationRequest struct {
	VerificationID string `json:"verification_id"`
	Outcome        string `json:"outcome"`
	Notes          string `json:"notes,omitempty"`
}

type RemediationException struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id,omitempty"`
	RemediationID string     `json:"remediation_id"`
	FindingID     string     `json:"finding_id"`
	Reason        string     `json:"reason"`
	Reduction     float64    `json:"reduction"`
	Notes         string     `json:"notes,omitempty"`
	Status        string     `json:"status"`
	RequestedBy   string     `json:"requested_by,omitempty"`
	DecidedBy     string     `json:"decided_by,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
}

type CreateRemediationExceptionRequest struct {
	Reason    string     `json:"reason"`
	Reduction float64    `json:"reduction"`
	Notes     string     `json:"notes,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type DecideRemediationExceptionRequest struct {
	Reason string `json:"reason,omitempty"`
}

type RemediationTicketLink struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id,omitempty"`
	RemediationID string    `json:"remediation_id"`
	Provider      string    `json:"provider"`
	ExternalID    string    `json:"external_id"`
	Title         string    `json:"title,omitempty"`
	URL           string    `json:"url,omitempty"`
	Status        string    `json:"status,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type CreateRemediationTicketLinkRequest struct {
	Provider   string `json:"provider"`
	ExternalID string `json:"external_id"`
	Title      string `json:"title,omitempty"`
	URL        string `json:"url,omitempty"`
	Status     string `json:"status,omitempty"`
}

type SyncRemediationTicketLinkRequest struct {
	Title  string `json:"title,omitempty"`
	URL    string `json:"url,omitempty"`
	Status string `json:"status,omitempty"`
}

type RemediationAssignmentRequest struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id,omitempty"`
	RemediationID  string     `json:"remediation_id"`
	FindingID      string     `json:"finding_id"`
	RequestedBy    string     `json:"requested_by,omitempty"`
	RequestedOwner string     `json:"requested_owner"`
	Reason         string     `json:"reason,omitempty"`
	Status         string     `json:"status"`
	DecidedBy      string     `json:"decided_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
}

type CreateRemediationAssignmentRequest struct {
	RequestedOwner string `json:"requested_owner"`
	Reason         string `json:"reason,omitempty"`
}

type DecideRemediationAssignmentRequest struct {
	Reason string `json:"reason,omitempty"`
}

type NotificationEvent struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id,omitempty"`
	RemediationID  string     `json:"remediation_id,omitempty"`
	FindingID      string     `json:"finding_id,omitempty"`
	Category       string     `json:"category"`
	Severity       string     `json:"severity"`
	Channel        string     `json:"channel"`
	Status         string     `json:"status"`
	Recipient      string     `json:"recipient,omitempty"`
	Subject        string     `json:"subject"`
	Body           string     `json:"body,omitempty"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
}

type NotificationSweepResult struct {
	Created int                 `json:"created"`
	Items   []NotificationEvent `json:"items"`
}
