package jobs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

type owaspSuggestion struct {
	framework string
	category  string
	controlID string
	title     string
}

func (s *Store) SyncOWASPMappingsForTenant(ctx context.Context, tenantID string, actor string, request models.SyncOWASPMappingRequest) (models.OWASPMappingSyncResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	limit := request.Limit
	if limit <= 0 || limit > 5000 {
		limit = 500
	}

	frameworkSet := normalizeOWASPFrameworks(request.Frameworks)
	findings, err := s.ListFindingsForTenant(ctx, tenantID, limit)
	if err != nil {
		return models.OWASPMappingSyncResult{}, fmt.Errorf("list findings for owasp sync: %w", err)
	}

	now := time.Now().UTC()
	result := models.OWASPMappingSyncResult{
		FrameworkTotals: map[string]int64{},
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.OWASPMappingSyncResult{}, fmt.Errorf("begin owasp sync tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, finding := range findings {
		findingID := strings.TrimSpace(finding.FindingID)
		if findingID == "" {
			result.SkippedFindings++
			continue
		}

		suggestions := suggestOWASPMappingsForFinding(finding, frameworkSet)
		if len(suggestions) == 0 {
			result.SkippedFindings++
			continue
		}

		result.ProcessedFindings++
		evidenceRef := ""
		if len(finding.Evidence) > 0 {
			evidenceRef = strings.TrimSpace(finding.Evidence[0].Ref)
		}
		note := buildAutoOWASPNote(finding)

		for _, suggestion := range suggestions {
			var exists bool
			if err := tx.QueryRow(ctx, `
				SELECT EXISTS(
					SELECT 1
					FROM compliance_control_mappings
					WHERE tenant_id = $1
					  AND source_kind = 'finding'
					  AND source_id = $2
					  AND framework = $3
					  AND control_id = $4
				)
			`, tenantID, findingID, suggestion.framework, suggestion.controlID).Scan(&exists); err != nil {
				return models.OWASPMappingSyncResult{}, fmt.Errorf("check existing owasp mapping: %w", err)
			}

			if exists {
				if !request.Overwrite {
					continue
				}

				commandTag, err := tx.Exec(ctx, `
					UPDATE compliance_control_mappings
					SET finding_id = $5,
					    category = $6,
					    control_title = $7,
					    evidence_ref = $8,
					    notes = $9,
					    updated_by = $10,
					    updated_at = $11
					WHERE tenant_id = $1
					  AND source_kind = 'finding'
					  AND source_id = $2
					  AND framework = $3
					  AND control_id = $4
				`, tenantID, findingID, suggestion.framework, suggestion.controlID, findingID, suggestion.category, suggestion.title, evidenceRef, note, actor, now)
				if err != nil {
					return models.OWASPMappingSyncResult{}, fmt.Errorf("update existing owasp mapping: %w", err)
				}
				if commandTag.RowsAffected() > 0 {
					result.UpdatedMappings++
					result.FrameworkTotals[suggestion.framework]++
				}
				continue
			}

			_, err := tx.Exec(ctx, `
				INSERT INTO compliance_control_mappings (
					id, tenant_id, source_kind, source_id, finding_id, framework, category,
					control_id, control_title, status, evidence_ref, notes,
					created_by, updated_by, created_at, updated_at
				) VALUES (
					$1, $2, 'finding', $3, $4, $5, $6,
					$7, $8, 'identified', $9, $10,
					$11, $11, $12, $12
				)
			`, nextComplianceMappingID(), tenantID, findingID, findingID, suggestion.framework, suggestion.category, suggestion.controlID, suggestion.title, evidenceRef, note, actor, now)
			if err != nil {
				return models.OWASPMappingSyncResult{}, fmt.Errorf("insert owasp mapping: %w", err)
			}
			result.CreatedMappings++
			result.FrameworkTotals[suggestion.framework]++
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return models.OWASPMappingSyncResult{}, fmt.Errorf("commit owasp sync tx: %w", err)
	}

	return result, nil
}

func normalizeOWASPFrameworks(values []string) map[string]struct{} {
	out := map[string]struct{}{
		"owasp_top10":     {},
		"owasp_api_top10": {},
	}
	if len(values) == 0 {
		return out
	}

	out = map[string]struct{}{}
	for _, value := range values {
		normalized := normalizeComplianceFramework(value)
		switch normalized {
		case "owasp_top10", "owasp_api_top10":
			out[normalized] = struct{}{}
		}
	}
	if len(out) == 0 {
		out["owasp_top10"] = struct{}{}
		out["owasp_api_top10"] = struct{}{}
	}
	return out
}

func suggestOWASPMappingsForFinding(finding models.CanonicalFinding, frameworks map[string]struct{}) []owaspSuggestion {
	text := strings.ToLower(strings.TrimSpace(strings.Join([]string{
		finding.Category,
		finding.Title,
		finding.Description,
		finding.Source.Layer,
		finding.Source.Tool,
		finding.Asset.AssetType,
		strings.Join(finding.Tags, " "),
	}, " ")))

	out := make([]owaspSuggestion, 0, 2)
	added := map[string]struct{}{}
	add := func(item owaspSuggestion) {
		key := item.framework + "|" + item.controlID
		if _, exists := added[key]; exists {
			return
		}
		added[key] = struct{}{}
		out = append(out, item)
	}

	if _, enabled := frameworks["owasp_top10"]; enabled {
		if top10, ok := mapOWASPTop10(text); ok {
			add(owaspSuggestion{
				framework: "owasp_top10",
				category:  top10.category,
				controlID: top10.controlID,
				title:     top10.title,
			})
		}
	}

	if _, enabled := frameworks["owasp_api_top10"]; enabled && isAPIFinding(finding, text) {
		if apiTop10, ok := mapOWASPAPITop10(text); ok {
			add(owaspSuggestion{
				framework: "owasp_api_top10",
				category:  apiTop10.category,
				controlID: apiTop10.controlID,
				title:     apiTop10.title,
			})
		}
	}

	return out
}

func mapOWASPTop10(text string) (owaspSuggestion, bool) {
	switch {
	case containsAny(text, "access control", "broken access", "authorization", "idor", "bola", "bfla"):
		return owaspSuggestion{
			category:  "A01:2021",
			controlID: "A01-BROKEN-ACCESS-CONTROL",
			title:     "Broken Access Control",
		}, true
	case containsAny(text, "crypto", "cipher", "encryption", "tls", "ssl", "weak hash", "hardcoded key"):
		return owaspSuggestion{
			category:  "A02:2021",
			controlID: "A02-CRYPTOGRAPHIC-FAILURES",
			title:     "Cryptographic Failures",
		}, true
	case containsAny(text, "inject", "sqli", "xss", "command injection", "nosql", "ldap injection", "template injection", "deserialization"):
		return owaspSuggestion{
			category:  "A03:2021",
			controlID: "A03-INJECTION",
			title:     "Injection",
		}, true
	case containsAny(text, "insecure design", "abuse case", "business logic flaw", "threat model"):
		return owaspSuggestion{
			category:  "A04:2021",
			controlID: "A04-INSECURE-DESIGN",
			title:     "Insecure Design",
		}, true
	case containsAny(text, "misconfig", "default credential", "exposed admin", "cors", "debug", "security header"):
		return owaspSuggestion{
			category:  "A05:2021",
			controlID: "A05-SECURITY-MISCONFIGURATION",
			title:     "Security Misconfiguration",
		}, true
	case containsAny(text, "dependency", "package", "library", "sca", "cve", "vulnerable component"):
		return owaspSuggestion{
			category:  "A06:2021",
			controlID: "A06-VULNERABLE-AND-OUTDATED-COMPONENTS",
			title:     "Vulnerable and Outdated Components",
		}, true
	case containsAny(text, "authentication", "session", "credential", "password", "token"):
		return owaspSuggestion{
			category:  "A07:2021",
			controlID: "A07-IDENTIFICATION-AND-AUTHENTICATION-FAILURES",
			title:     "Identification and Authentication Failures",
		}, true
	case containsAny(text, "integrity", "supply chain", "provenance", "signature", "artifact tamper", "ci/cd"):
		return owaspSuggestion{
			category:  "A08:2021",
			controlID: "A08-SOFTWARE-AND-DATA-INTEGRITY-FAILURES",
			title:     "Software and Data Integrity Failures",
		}, true
	case containsAny(text, "logging", "monitoring", "alerting", "audit trail"):
		return owaspSuggestion{
			category:  "A09:2021",
			controlID: "A09-SECURITY-LOGGING-AND-MONITORING-FAILURES",
			title:     "Security Logging and Monitoring Failures",
		}, true
	case containsAny(text, "ssrf", "server-side request forgery"):
		return owaspSuggestion{
			category:  "A10:2021",
			controlID: "A10-SERVER-SIDE-REQUEST-FORGERY",
			title:     "Server-Side Request Forgery",
		}, true
	default:
		return owaspSuggestion{}, false
	}
}

func mapOWASPAPITop10(text string) (owaspSuggestion, bool) {
	switch {
	case containsAny(text, "bola", "idor", "object level authorization"):
		return owaspSuggestion{
			category:  "API1:2023",
			controlID: "API1-BROKEN-OBJECT-LEVEL-AUTHORIZATION",
			title:     "Broken Object Level Authorization",
		}, true
	case containsAny(text, "authentication", "auth token", "session", "credential", "api key"):
		return owaspSuggestion{
			category:  "API2:2023",
			controlID: "API2-BROKEN-AUTHENTICATION",
			title:     "Broken Authentication",
		}, true
	case containsAny(text, "property level authorization", "mass assignment", "object property"):
		return owaspSuggestion{
			category:  "API3:2023",
			controlID: "API3-BROKEN-OBJECT-PROPERTY-LEVEL-AUTHORIZATION",
			title:     "Broken Object Property Level Authorization",
		}, true
	case containsAny(text, "rate limit", "resource consumption", "denial of service", "dos", "flood"):
		return owaspSuggestion{
			category:  "API4:2023",
			controlID: "API4-UNRESTRICTED-RESOURCE-CONSUMPTION",
			title:     "Unrestricted Resource Consumption",
		}, true
	case containsAny(text, "function level authorization", "bfla", "privilege escalation"):
		return owaspSuggestion{
			category:  "API5:2023",
			controlID: "API5-BROKEN-FUNCTION-LEVEL-AUTHORIZATION",
			title:     "Broken Function Level Authorization",
		}, true
	case containsAny(text, "business flow", "workflow abuse", "automation abuse"):
		return owaspSuggestion{
			category:  "API6:2023",
			controlID: "API6-UNRESTRICTED-ACCESS-TO-SENSITIVE-BUSINESS-FLOWS",
			title:     "Unrestricted Access to Sensitive Business Flows",
		}, true
	case containsAny(text, "ssrf", "server-side request forgery"):
		return owaspSuggestion{
			category:  "API7:2023",
			controlID: "API7-SERVER-SIDE-REQUEST-FORGERY",
			title:     "Server-Side Request Forgery",
		}, true
	case containsAny(text, "misconfig", "security misconfiguration", "cors", "debug"):
		return owaspSuggestion{
			category:  "API8:2023",
			controlID: "API8-SECURITY-MISCONFIGURATION",
			title:     "Security Misconfiguration",
		}, true
	case containsAny(text, "inventory", "undocumented endpoint", "deprecated api", "shadow api"):
		return owaspSuggestion{
			category:  "API9:2023",
			controlID: "API9-IMPROPER-INVENTORY-MANAGEMENT",
			title:     "Improper Inventory Management",
		}, true
	case containsAny(text, "third-party api", "unsafe api consumption", "external api trust"):
		return owaspSuggestion{
			category:  "API10:2023",
			controlID: "API10-UNSAFE-CONSUMPTION-OF-APIS",
			title:     "Unsafe Consumption of APIs",
		}, true
	default:
		return owaspSuggestion{}, false
	}
}

func containsAny(value string, needles ...string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(strings.TrimSpace(needle))) {
			return true
		}
	}
	return false
}

func isAPIFinding(finding models.CanonicalFinding, normalizedText string) bool {
	if containsAny(normalizedText, "api", "graphql", "openapi", "endpoint", "operation") {
		return true
	}

	if containsAny(strings.ToLower(strings.TrimSpace(finding.Asset.AssetType)), "api") {
		return true
	}

	if strings.EqualFold(strings.TrimSpace(finding.Source.Layer), "dast") && containsAny(normalizedText, "http", "route", "endpoint") {
		return true
	}

	return false
}

func buildAutoOWASPNote(finding models.CanonicalFinding) string {
	category := strings.TrimSpace(finding.Category)
	if category == "" {
		category = "unknown"
	}
	severity := strings.TrimSpace(finding.Severity)
	if severity == "" {
		severity = "unknown"
	}
	return fmt.Sprintf("auto-mapped from finding category=%s severity=%s", category, severity)
}
