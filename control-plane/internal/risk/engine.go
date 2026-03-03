package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
)

type Inputs struct {
	EnvironmentOverride          string
	ExposureOverride             string
	AssetCriticalityOverride     float64
	OwnerTeam                    string
	OwnerHierarchy               []string
	ServiceName                  string
	ServiceTier                  string
	ServiceCriticalityClass      string
	ExternalSource               string
	ExternalReference            string
	LastSyncedAt                 *time.Time
	CompensatingControlReduction float64
}

func Enrich(finding models.CanonicalFinding) models.CanonicalFinding {
	return EnrichWithInputs(finding, Inputs{})
}

func EnrichWithInputs(finding models.CanonicalFinding, inputs Inputs) models.CanonicalFinding {
	finding.Source.Layer = normalizeLayer(finding.Source.Layer, finding.Scanner.AdapterID)
	if strings.TrimSpace(inputs.OwnerTeam) != "" {
		finding.Asset.OwnerTeam = strings.TrimSpace(inputs.OwnerTeam)
	}
	if len(inputs.OwnerHierarchy) > 0 {
		finding.Asset.OwnerHierarchy = append([]string(nil), inputs.OwnerHierarchy...)
	}
	if strings.TrimSpace(inputs.ServiceName) != "" {
		finding.Asset.ServiceName = strings.TrimSpace(inputs.ServiceName)
	}
	if strings.TrimSpace(inputs.ServiceTier) != "" {
		finding.Asset.ServiceTier = strings.TrimSpace(inputs.ServiceTier)
	}
	if strings.TrimSpace(inputs.ServiceCriticalityClass) != "" {
		finding.Asset.ServiceCriticalityClass = strings.TrimSpace(inputs.ServiceCriticalityClass)
	}
	if strings.TrimSpace(inputs.ExternalSource) != "" {
		finding.Asset.ExternalSource = strings.TrimSpace(inputs.ExternalSource)
	}
	if strings.TrimSpace(inputs.ExternalReference) != "" {
		finding.Asset.ExternalReference = strings.TrimSpace(inputs.ExternalReference)
	}
	if inputs.LastSyncedAt != nil {
		syncedAt := inputs.LastSyncedAt.UTC()
		finding.Asset.LastSyncedAt = &syncedAt
	}
	if strings.TrimSpace(inputs.EnvironmentOverride) != "" {
		finding.Asset.Environment = strings.TrimSpace(inputs.EnvironmentOverride)
	}
	if strings.TrimSpace(inputs.ExposureOverride) != "" {
		finding.Asset.Exposure = strings.TrimSpace(inputs.ExposureOverride)
	}
	finding.Asset.Environment = normalizeEnvironment(finding.Asset.Environment, finding.Asset.AssetType, finding.Asset.AssetName)
	finding.Asset.Exposure = normalizeExposure(finding.Asset.Exposure, finding.Asset.AssetType, finding.Asset.AssetName)

	assetCriticality := clamp10(calculateAssetCriticality(finding))
	if inputs.AssetCriticalityOverride > 0 {
		assetCriticality = clamp10(inputs.AssetCriticalityOverride)
	}
	assetCriticality = clamp10(assetCriticality + serviceCriticalityBoost(inputs.ServiceCriticalityClass))
	businessImpact := clamp10(calculateBusinessImpact(finding, assetCriticality))
	exploitability := clamp10(calculateExploitability(finding))
	reachability := clamp10(calculateReachability(finding))
	exposure := clamp10(exposureScore(finding.Asset.Exposure))
	policyImpact := clamp10(calculatePolicyImpact(finding))

	baseScore := clamp100((businessImpact*0.35 + exploitability*0.20 + reachability*0.20 + exposure*0.15 + policyImpact*0.10) * confidenceMultiplier(finding.Confidence) * 10)
	controlReduction := clamp10(inputs.CompensatingControlReduction)
	overallScore := clamp100(baseScore - (controlReduction * 4))
	priority := priorityForScore(overallScore)
	slaClass, slaDuration := slaForPriority(priority)
	effectiveSeverity, severityReason := applySeverityOverrideRules(finding, overallScore)

	referenceTime := finding.FirstSeenAt
	if referenceTime.IsZero() {
		referenceTime = time.Now().UTC()
	}
	slaDueAt := referenceTime.Add(slaDuration)

	finding.Risk = models.CanonicalRisk{
		Priority:                     priority,
		PriorityQueue:                priorityQueueFor(priority, slaClass),
		OverallScore:                 overallScore,
		BusinessImpact:               businessImpact,
		Exploitability:               exploitability,
		Reachability:                 reachability,
		Exposure:                     exposure,
		AssetCriticality:             assetCriticality,
		PolicyImpact:                 policyImpact,
		CompensatingControlReduction: controlReduction,
		EffectiveSeverity:            effectiveSeverity,
		SeverityOverrideReason:       severityReason,
		SLAClass:                     slaClass,
		SLADueAt:                     &slaDueAt,
	}

	if strings.TrimSpace(finding.Fingerprint) == "" {
		finding.Fingerprint = Fingerprint(finding)
	}

	return finding
}

func ApplyWaiverReduction(finding models.CanonicalFinding, reduction float64) models.CanonicalFinding {
	reduction = clamp100(reduction)
	finding.Risk.WaiverReduction = reduction
	if reduction <= 0 {
		return finding
	}

	adjustedScore := clamp100(finding.Risk.OverallScore - reduction)
	priority := priorityForScore(adjustedScore)
	slaClass, slaDuration := slaForPriority(priority)
	finding.Risk.OverallScore = adjustedScore
	finding.Risk.Priority = priority
	finding.Risk.PriorityQueue = priorityQueueFor(priority, slaClass)
	finding.Risk.SLAClass = slaClass

	referenceTime := finding.FirstSeenAt
	if referenceTime.IsZero() {
		referenceTime = time.Now().UTC()
	}
	slaDueAt := referenceTime.Add(slaDuration)
	finding.Risk.SLADueAt = &slaDueAt

	return finding
}

func ApplyTemporalSignals(finding models.CanonicalFinding, reference time.Time) models.CanonicalFinding {
	if reference.IsZero() {
		reference = time.Now().UTC()
	}
	reference = reference.UTC()

	if !finding.FirstSeenAt.IsZero() {
		age := reference.Sub(finding.FirstSeenAt)
		if age < 0 {
			age = 0
		}
		ageDays := int64(age / (24 * time.Hour))
		finding.Risk.AgeDays = ageDays
		finding.Risk.AgingBucket = agingBucketForDays(ageDays)
	}

	finding.Risk.Overdue = false
	if finding.Risk.SLADueAt != nil && !resolvedLikeStatus(finding.Status) {
		finding.Risk.Overdue = reference.After(finding.Risk.SLADueAt.UTC())
	}
	finding.Risk.TrendScore = trendScoreForFinding(finding)

	return finding
}

func LayerForAdapter(adapterID string) string {
	return normalizeLayer("", adapterID)
}

func Fingerprint(finding models.CanonicalFinding) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(firstNonEmpty(finding.Source.Tool, finding.Scanner.AdapterID))),
		strings.ToLower(strings.TrimSpace(finding.Category)),
		strings.ToLower(strings.TrimSpace(finding.Title)),
		strings.ToLower(strings.TrimSpace(finding.Asset.AssetID)),
		strings.ToLower(strings.TrimSpace(finding.Asset.AssetType)),
	}

	if len(finding.Locations) > 0 {
		parts = append(parts,
			strings.ToLower(strings.TrimSpace(finding.Locations[0].Path)),
			strings.ToLower(strings.TrimSpace(finding.Locations[0].Endpoint)),
			strconv.Itoa(finding.Locations[0].Line),
		)
	} else {
		parts = append(parts, "", "", "0")
	}

	tags := append([]string(nil), finding.Tags...)
	for index := range tags {
		tags[index] = strings.ToLower(strings.TrimSpace(tags[index]))
	}
	sort.Strings(tags)
	parts = append(parts, strings.Join(tags, "|"))

	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:16])
}

func StableFindingID(fingerprint string) string {
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if fingerprint == "" {
		return ""
	}

	if len(fingerprint) > 24 {
		fingerprint = fingerprint[:24]
	}
	return "finding-" + fingerprint
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func normalizeLayer(current string, adapterID string) string {
	current = strings.ToLower(strings.TrimSpace(current))
	if current != "" {
		return current
	}

	switch strings.ToLower(strings.TrimSpace(adapterID)) {
	case "semgrep", "gosec", "spotbugs", "pmd", "brakeman", "devskim", "bandit", "eslint", "phpstan", "shellcheck":
		return "sast"
	case "syft", "trivy", "trivy-image", "grype", "bundler-audit", "dotnet-audit", "npm-audit", "composer-audit", "osv-scanner":
		return "sca"
	case "trivy-secrets", "gitleaks":
		return "secrets"
	case "trivy-config", "checkov", "cfn-lint", "hadolint", "kics", "prowler", "kubesec", "kube-score", "tfsec":
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
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "go_repo":
		return "repo"
	case "java_repo", "node_repo", "dotnet_repo", "ruby_repo", "php_repo", "shell_script", "dockerfile", "terraform", "kubernetes", "cloudformation":
		return "repo"
	case "aws_account", "gcp_project", "azure_subscription":
		return "cloud_account"
	case "container_image":
		return "image"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
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
	case "container_image_vulnerability":
		score = 7.5
	case "web_application_exposure":
		score = 7.0
	case "open_network_service":
		score = 6.0
	case "iac_misconfiguration":
		score = 6.0
	case "container_misconfiguration":
		score = 6.5
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
	case "container_image_vulnerability":
		score = 7.0
	case "web_application_exposure":
		score = 7.0
	case "iac_misconfiguration":
		score = 6.0
	case "container_misconfiguration":
		score = 6.5
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

func serviceCriticalityBoost(value string) float64 {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tier0", "mission_critical", "platinum":
		return 1.5
	case "tier1", "business_critical", "gold":
		return 1.0
	case "tier2", "standard", "silver":
		return 0.5
	case "tier3", "low", "bronze":
		return -0.5
	default:
		return 0
	}
}

func applySeverityOverrideRules(finding models.CanonicalFinding, overallScore float64) (string, string) {
	effective := strings.ToLower(strings.TrimSpace(finding.Severity))
	if effective == "" {
		effective = "medium"
	}

	overrideTo := ""
	reason := ""
	switch {
	case strings.EqualFold(strings.TrimSpace(finding.Category), "exploit_confirmed"):
		overrideTo = "critical"
		reason = "exploit_confirmed"
	case strings.EqualFold(strings.TrimSpace(finding.Category), "secret_exposure") &&
		(strings.EqualFold(strings.TrimSpace(finding.Asset.Environment), "production") || strings.EqualFold(strings.TrimSpace(finding.Asset.Exposure), "internet")):
		overrideTo = "critical"
		reason = "secret_exposure_on_sensitive_asset"
	case overallScore >= 90:
		overrideTo = "critical"
		reason = "risk_score_threshold"
	case overallScore >= 75:
		overrideTo = "high"
		reason = "priority_threshold"
	case overallScore >= 55:
		overrideTo = "medium"
		reason = "priority_threshold"
	}

	if severityWeight(overrideTo) > severityWeight(effective) {
		return overrideTo, reason
	}

	return effective, ""
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

func severityWeight(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
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

func priorityQueueFor(priority string, slaClass string) string {
	priority = strings.ToLower(strings.TrimSpace(priority))
	slaClass = strings.ToLower(strings.TrimSpace(slaClass))
	if priority == "" {
		priority = "p4"
	}
	if slaClass == "" {
		slaClass = "90d"
	}
	return "queue:" + priority + ":" + slaClass
}

func agingBucketForDays(ageDays int64) string {
	switch {
	case ageDays >= 90:
		return "90d+"
	case ageDays >= 31:
		return "31-89d"
	case ageDays >= 7:
		return "7-30d"
	default:
		return "0-6d"
	}
}

func trendScoreForFinding(finding models.CanonicalFinding) float64 {
	score := 0.0
	score += minFloat(10, float64(finding.OccurrenceCount)*1.25)
	score += minFloat(10, float64(finding.ReopenedCount)*2.5)

	switch {
	case finding.Risk.AgeDays <= 7:
		score += 2.5
	case finding.Risk.AgeDays <= 30:
		score += 1.0
	}

	if finding.Risk.Overdue {
		score += 2.0
	}

	return clamp100(score)
}

func resolvedLikeStatus(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "resolved", "closed", "accepted", "suppressed":
		return true
	default:
		return false
	}
}

func minFloat(a float64, b float64) float64 {
	if a < b {
		return a
	}
	return b
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
