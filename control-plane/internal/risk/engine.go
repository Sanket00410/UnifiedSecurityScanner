package risk

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func Enrich(finding models.CanonicalFinding) models.CanonicalFinding {
	finding.Source.Layer = normalizeLayer(finding.Source.Layer, finding.Scanner.AdapterID)
	finding.Asset.Environment = normalizeEnvironment(finding.Asset.Environment, finding.Asset.AssetType, finding.Asset.AssetName)
	finding.Asset.Exposure = normalizeExposure(finding.Asset.Exposure, finding.Asset.AssetType, finding.Asset.AssetName)

	assetCriticality := clamp10(calculateAssetCriticality(finding))
	businessImpact := clamp10(calculateBusinessImpact(finding, assetCriticality))
	exploitability := clamp10(calculateExploitability(finding))
	reachability := clamp10(calculateReachability(finding))
	exposure := clamp10(exposureScore(finding.Asset.Exposure))
	policyImpact := clamp10(calculatePolicyImpact(finding))

	overallScore := clamp100((businessImpact*0.35 + exploitability*0.20 + reachability*0.20 + exposure*0.15 + policyImpact*0.10) * confidenceMultiplier(finding.Confidence) * 10)
	priority := priorityForScore(overallScore)
	slaClass, slaDuration := slaForPriority(priority)

	referenceTime := finding.FirstSeenAt
	if referenceTime.IsZero() {
		referenceTime = time.Now().UTC()
	}
	slaDueAt := referenceTime.Add(slaDuration)

	finding.Risk = models.CanonicalRisk{
		Priority:         priority,
		OverallScore:     overallScore,
		BusinessImpact:   businessImpact,
		Exploitability:   exploitability,
		Reachability:     reachability,
		Exposure:         exposure,
		AssetCriticality: assetCriticality,
		PolicyImpact:     policyImpact,
		SLAClass:         slaClass,
		SLADueAt:         &slaDueAt,
	}

	return finding
}

func LayerForAdapter(adapterID string) string {
	return normalizeLayer("", adapterID)
}

func normalizeLayer(current string, adapterID string) string {
	current = strings.ToLower(strings.TrimSpace(current))
	if current != "" {
		return current
	}

	switch strings.ToLower(strings.TrimSpace(adapterID)) {
	case "semgrep":
		return "sast"
	case "trivy":
		return "sca"
	case "gitleaks":
		return "secrets"
	case "checkov":
		return "iac"
	case "zap":
		return "dast"
	case "nmap", "metasploit":
		return "pentest"
	default:
		return "pentest"
	}
}

func normalizeEnvironment(current string, assetType string, assetName string) string {
	current = strings.ToLower(strings.TrimSpace(current))
	if current != "" && current != "unknown" {
		return current
	}

	target := strings.ToLower(strings.TrimSpace(assetName))
	switch {
	case containsAny(target, "staging", "stage", "preprod", "uat", "qa"):
		return "staging"
	case containsAny(target, "dev", "test", "sandbox", "local"):
		return "development"
	}

	switch normalizeAssetType(assetType) {
	case "repository", "repo", "codebase", "filesystem", "image":
		return "development"
	default:
		return "production"
	}
}

func normalizeExposure(current string, assetType string, assetName string) string {
	current = strings.ToLower(strings.TrimSpace(current))
	if current == "internal" || current == "partner" || current == "internet" {
		return current
	}

	switch normalizeAssetType(assetType) {
	case "repository", "repo", "codebase", "filesystem", "image":
		return "internal"
	}

	target := strings.ToLower(strings.TrimSpace(assetName))
	switch {
	case containsAny(target, ".partner", "partner-", "vendor-", "thirdparty-"):
		return "partner"
	case isInternalTarget(target):
		return "internal"
	default:
		return "internet"
	}
}

func normalizeAssetType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func containsAny(value string, parts ...string) bool {
	for _, part := range parts {
		if strings.Contains(value, part) {
			return true
		}
	}
	return false
}

func isInternalTarget(target string) bool {
	if target == "" {
		return false
	}

	if strings.Contains(target, "://") {
		if parsed, err := netip.ParseAddr(extractHost(target)); err == nil {
			return parsed.IsPrivate() || parsed.IsLoopback()
		}
	}

	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}

	if parsed, err := netip.ParseAddr(target); err == nil {
		return parsed.IsPrivate() || parsed.IsLoopback()
	}

	return target == "localhost" || target == "127.0.0.1" || target == "::1" || containsAny(target, ".internal", ".corp", ".local")
}

func extractHost(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}

	parts := strings.SplitN(target, "://", 2)
	if len(parts) == 2 {
		target = parts[1]
	}
	if idx := strings.Index(target, "/"); idx >= 0 {
		target = target[:idx]
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return target
}

func calculateAssetCriticality(finding models.CanonicalFinding) float64 {
	base := 6.0
	switch normalizeAssetType(finding.Asset.AssetType) {
	case "cloud_account":
		base = 9.5
	case "domain", "api":
		base = 8.0
	case "image":
		base = 7.0
	case "host":
		base = 7.0
	case "repository", "repo", "codebase", "filesystem":
		base = 6.0
	}

	switch strings.ToLower(strings.TrimSpace(finding.Asset.Environment)) {
	case "production":
		base += 1.0
	case "staging":
		base -= 1.0
	case "development":
		base -= 2.0
	}

	switch strings.ToLower(strings.TrimSpace(finding.Asset.Exposure)) {
	case "internet":
		base += 1.0
	case "partner":
		base += 0.5
	}

	return base
}

func calculateBusinessImpact(finding models.CanonicalFinding, assetCriticality float64) float64 {
	score := assetCriticality*0.60 + severityBand(finding.Severity)*0.40
	if strings.EqualFold(strings.TrimSpace(finding.Asset.Environment), "production") {
		score += 0.5
	}
	return score
}

func calculateExploitability(finding models.CanonicalFinding) float64 {
	score := 5.0
	switch strings.ToLower(strings.TrimSpace(finding.Category)) {
	case "exploit_confirmed":
		score = 10.0
	case "secret_exposure":
		score = 9.0
	case "dependency_vulnerability":
		score = 7.0
	case "web_application_exposure":
		score = 7.0
	case "open_network_service":
		score = 6.0
	case "iac_misconfiguration":
		score = 6.0
	case "sast_rule_match":
		score = 5.0
	}

	switch strings.ToLower(strings.TrimSpace(finding.Source.Layer)) {
	case "pentest":
		score += 1.0
	case "dast", "secrets":
		score += 0.5
	}

	switch strings.ToLower(strings.TrimSpace(finding.Severity)) {
	case "critical":
		score += 1.0
	case "high":
		score += 0.5
	case "low", "info":
		score -= 1.0
	}

	return score
}

func calculateReachability(finding models.CanonicalFinding) float64 {
	score := exposureScore(finding.Asset.Exposure)

	switch strings.ToLower(strings.TrimSpace(finding.Source.Layer)) {
	case "pentest", "dast":
		score += 1.0
	}

	for _, location := range finding.Locations {
		if strings.EqualFold(strings.TrimSpace(location.Kind), "endpoint") && strings.TrimSpace(location.Endpoint) != "" {
			score += 0.5
			break
		}
	}

	switch normalizeAssetType(finding.Asset.AssetType) {
	case "repository", "repo", "codebase", "filesystem":
		if score > 4.0 {
			score = 4.0
		}
	case "image":
		if score > 5.0 {
			score = 5.0
		}
	}

	return score
}

func calculatePolicyImpact(finding models.CanonicalFinding) float64 {
	score := 4.0
	switch strings.ToLower(strings.TrimSpace(finding.Category)) {
	case "exploit_confirmed":
		score = 10.0
	case "secret_exposure":
		score = 9.0
	case "dependency_vulnerability":
		score = 6.5
	case "web_application_exposure":
		score = 7.0
	case "iac_misconfiguration":
		score = 6.0
	case "open_network_service":
		score = 5.5
	case "sast_rule_match":
		score = 5.0
	}

	if strings.EqualFold(strings.TrimSpace(finding.Asset.Environment), "production") {
		score += 0.5
	}
	if strings.EqualFold(strings.TrimSpace(finding.Asset.Exposure), "internet") {
		score += 0.5
	}

	return score
}

func severityBand(severity string) float64 {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 10.0
	case "high":
		return 8.0
	case "medium":
		return 6.0
	case "low":
		return 3.0
	default:
		return 1.0
	}
}

func exposureScore(exposure string) float64 {
	switch strings.ToLower(strings.TrimSpace(exposure)) {
	case "internet":
		return 9.0
	case "partner":
		return 5.0
	default:
		return 2.0
	}
}

func confidenceMultiplier(confidence string) float64 {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high":
		return 1.10
	case "low":
		return 0.85
	default:
		return 1.00
	}
}

func priorityForScore(score float64) string {
	switch {
	case score >= 90:
		return "p0"
	case score >= 75:
		return "p1"
	case score >= 55:
		return "p2"
	case score >= 30:
		return "p3"
	default:
		return "p4"
	}
}

func slaForPriority(priority string) (string, time.Duration) {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "p0":
		return "24h", 24 * time.Hour
	case "p1":
		return "72h", 72 * time.Hour
	case "p2":
		return "14d", 14 * 24 * time.Hour
	case "p3":
		return "30d", 30 * 24 * time.Hour
	default:
		return "90d", 90 * 24 * time.Hour
	}
}

func clamp10(value float64) float64 {
	switch {
	case value < 0:
		return 0
	case value > 10:
		return 10
	default:
		return value
	}
}

func clamp100(value float64) float64 {
	switch {
	case value < 0:
		return 0
	case value > 100:
		return 100
	default:
		return value
	}
}
