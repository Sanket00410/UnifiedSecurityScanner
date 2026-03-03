package models

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type AssetSummary struct {
	AssetID       string    `json:"asset_id"`
	AssetType     string    `json:"asset_type"`
	LastScannedAt time.Time `json:"last_scanned_at"`
	ScanCount     int64     `json:"scan_count"`
	FindingCount  int64     `json:"finding_count"`
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
