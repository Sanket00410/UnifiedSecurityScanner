package policy

import (
	"strings"

	"unifiedsecurityscanner/control-plane/internal/models"
)

type TaskDecisionStatus string

const (
	TaskDecisionApproved        TaskDecisionStatus = "approved"
	TaskDecisionPendingApproval TaskDecisionStatus = "pending_approval"
)

type TaskDecision struct {
	Tool      string
	Status    TaskDecisionStatus
	PolicyID  string
	Reason    string
	RuleHits  []string
	Monitored []string
}

type Plan struct {
	ApprovalMode string
	Decisions    map[string]TaskDecision
}

type Rejection struct {
	PolicyID string
	Reason   string
	RuleHits []string
}

type IngestionRequest struct {
	Provider   string
	EventType  string
	TargetKind string
	Target     string
	Profile    string
	Tools      []string
}

type boundRule struct {
	PolicyID string
	Rule     models.PolicyRule
}

func EvaluateSubmission(policies []models.Policy, request models.CreateScanJobRequest, tools []string) (Plan, *Rejection) {
	applicable := applicablePolicies(policies, request)
	enforced := make([]models.Policy, 0, len(applicable))
	for _, policy := range applicable {
		if isEnforced(policy.Mode) {
			enforced = append(enforced, policy)
		}
	}

	jobContext := map[string]string{
		"target_kind": strings.ToLower(strings.TrimSpace(request.TargetKind)),
		"profile":     strings.ToLower(strings.TrimSpace(request.Profile)),
		"target":      strings.ToLower(strings.TrimSpace(request.Target)),
	}

	for _, field := range []string{"target_kind", "profile", "target"} {
		if rejection := evaluateFieldRules(enforced, field, jobContext); rejection != nil {
			return Plan{}, rejection
		}
	}

	plan := Plan{
		ApprovalMode: "standard",
		Decisions:    make(map[string]TaskDecision, len(tools)),
	}

	for _, tool := range tools {
		normalizedTool := strings.ToLower(strings.TrimSpace(tool))
		if normalizedTool == "" {
			continue
		}

		toolContext := map[string]string{
			"tool":        normalizedTool,
			"target_kind": jobContext["target_kind"],
			"profile":     jobContext["profile"],
			"target":      jobContext["target"],
		}

		if rejection := evaluateFieldRules(enforced, "tool", toolContext); rejection != nil {
			return Plan{}, rejection
		}

		decision := TaskDecision{
			Tool:   normalizedTool,
			Status: TaskDecisionApproved,
		}

		approvalRules := make([]boundRule, 0)
		approvalRules = append(approvalRules, matchingRules(enforced, "tool", "require_approval", toolContext)...)
		approvalRules = append(approvalRules, matchingRules(enforced, "target", "require_approval", toolContext)...)
		approvalRules = append(approvalRules, matchingRules(enforced, "target_kind", "require_approval", toolContext)...)
		approvalRules = append(approvalRules, matchingRules(enforced, "profile", "require_approval", toolContext)...)

		for _, item := range approvalRules {
			decision.Status = TaskDecisionPendingApproval
			if decision.PolicyID == "" {
				decision.PolicyID = item.PolicyID
				decision.Reason = approvalReasonForField(normalizeField(item.Rule.Field))
			}
			decision.RuleHits = append(decision.RuleHits, summarizeRule(item.Rule))
		}
		if decision.Status == TaskDecisionPendingApproval {
			plan.ApprovalMode = "manual-approval"
		}

		for _, item := range matchingRules(applicable, "tool", "monitor", toolContext) {
			decision.Monitored = append(decision.Monitored, summarizeRule(item.Rule))
		}

		plan.Decisions[normalizedTool] = decision
	}

	return plan, nil
}

func EvaluateIngestionSubmission(policies []models.Policy, request IngestionRequest) *Rejection {
	applicable := applicablePolicies(policies, models.CreateScanJobRequest{
		TargetKind: request.TargetKind,
		Profile:    request.Profile,
		Target:     request.Target,
	})
	enforced := make([]models.Policy, 0, len(applicable))
	for _, policy := range applicable {
		if isEnforced(policy.Mode) {
			enforced = append(enforced, policy)
		}
	}

	context := map[string]string{
		"provider":    strings.ToLower(strings.TrimSpace(request.Provider)),
		"event_type":  strings.ToLower(strings.TrimSpace(request.EventType)),
		"target_kind": strings.ToLower(strings.TrimSpace(request.TargetKind)),
		"profile":     strings.ToLower(strings.TrimSpace(request.Profile)),
		"target":      strings.ToLower(strings.TrimSpace(request.Target)),
	}

	for _, field := range []string{"provider", "event_type", "target_kind", "profile", "target"} {
		if rejection := evaluateFieldRules(enforced, field, context); rejection != nil {
			return rejection
		}
	}

	for _, tool := range request.Tools {
		context["tool"] = strings.ToLower(strings.TrimSpace(tool))
		if rejection := evaluateFieldRules(enforced, "tool", context); rejection != nil {
			return rejection
		}
	}

	return nil
}

func applicablePolicies(policies []models.Policy, request models.CreateScanJobRequest) []models.Policy {
	targetKind := strings.ToLower(strings.TrimSpace(request.TargetKind))
	out := make([]models.Policy, 0, len(policies))
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		if policyAppliesToTarget(policy.Scope, targetKind) {
			out = append(out, policy)
		}
	}
	return out
}

func policyAppliesToTarget(scope string, targetKind string) bool {
	scope = strings.ToLower(strings.TrimSpace(scope))
	targetKind = strings.ToLower(strings.TrimSpace(targetKind))

	switch scope {
	case "", "global", "tenant", "all":
		return true
	case "repository", "repo", "codebase":
		return targetKind == "repository" || targetKind == "repo" || targetKind == "codebase" || targetKind == "filesystem"
	case "runtime", "web":
		return targetKind != "repository" && targetKind != "repo" && targetKind != "codebase" && targetKind != "filesystem"
	default:
		return scope == targetKind
	}
}

func isEnforced(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "enforce", "block", "protect", "policy-gated", "approval":
		return true
	default:
		return false
	}
}

func evaluateFieldRules(policies []models.Policy, field string, ctx map[string]string) *Rejection {
	allowRules := rulesForField(policies, field, "allow")
	if len(allowRules) > 0 {
		matchedAllowRules := filterMatchingRules(allowRules, ctx)
		if len(matchedAllowRules) == 0 {
			return &Rejection{
				PolicyID: allowRules[0].PolicyID,
				Reason:   rejectionReason(field, "allow"),
				RuleHits: summarizeBoundRules(allowRules),
			}
		}
	}

	blockRules := filterMatchingRules(rulesForField(policies, field, "block"), ctx)
	if len(blockRules) > 0 {
		return &Rejection{
			PolicyID: blockRules[0].PolicyID,
			Reason:   rejectionReason(field, "block"),
			RuleHits: summarizeBoundRules(blockRules),
		}
	}

	return nil
}

func matchingRules(policies []models.Policy, field string, effect string, ctx map[string]string) []boundRule {
	return filterMatchingRules(rulesForField(policies, field, effect), ctx)
}

func rulesForField(policies []models.Policy, field string, effect string) []boundRule {
	out := make([]boundRule, 0)
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if strings.ToLower(strings.TrimSpace(rule.Effect)) != effect {
				continue
			}
			if normalizeField(rule.Field) != field {
				continue
			}
			out = append(out, boundRule{
				PolicyID: policy.ID,
				Rule:     rule,
			})
		}
	}
	return out
}

func filterMatchingRules(rules []boundRule, ctx map[string]string) []boundRule {
	out := make([]boundRule, 0, len(rules))
	for _, item := range rules {
		if !ruleMatches(item.Rule, ctx) {
			continue
		}
		if ruleExcepted(item.Rule, ctx) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func ruleMatches(rule models.PolicyRule, ctx map[string]string) bool {
	field := normalizeField(rule.Field)
	value := strings.ToLower(strings.TrimSpace(ctx[field]))
	if field == "" {
		return false
	}
	if strings.ToLower(strings.TrimSpace(rule.Match)) == "any" {
		return true
	}
	if len(rule.Values) == 0 {
		return false
	}

	for _, candidate := range rule.Values {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		switch strings.ToLower(strings.TrimSpace(rule.Match)) {
		case "", "exact":
			if value == candidate {
				return true
			}
		case "prefix":
			if strings.HasPrefix(value, candidate) {
				return true
			}
		case "suffix":
			if strings.HasSuffix(value, candidate) {
				return true
			}
		case "contains":
			if strings.Contains(value, candidate) {
				return true
			}
		}
	}

	return false
}

func ruleExcepted(rule models.PolicyRule, ctx map[string]string) bool {
	for _, exception := range rule.Exceptions {
		field := normalizeField(exception.Field)
		if field == "" {
			field = normalizeField(rule.Field)
		}

		matcher := models.PolicyRule{
			Field:  field,
			Match:  exception.Match,
			Values: exception.Values,
		}
		if ruleMatches(matcher, ctx) {
			return true
		}
	}
	return false
}

func normalizeField(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tool":
		return "tool"
	case "target":
		return "target"
	case "target_kind":
		return "target_kind"
	case "profile":
		return "profile"
	case "provider":
		return "provider"
	case "event_type":
		return "event_type"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func rejectionReason(field string, effect string) string {
	switch field {
	case "tool":
		if effect == "allow" {
			return "requested tool is not allow-listed by enforced policy"
		}
		return "requested tool is blocked by enforced policy"
	case "target_kind":
		if effect == "allow" {
			return "target kind is not allow-listed by enforced policy"
		}
		return "target kind is blocked by enforced policy"
	case "profile":
		if effect == "allow" {
			return "scan profile is not allow-listed by enforced policy"
		}
		return "scan profile is blocked by enforced policy"
	case "target":
		if effect == "allow" {
			return "scan target is not allow-listed by enforced policy"
		}
		return "scan target is blocked by enforced policy"
	case "provider":
		if effect == "allow" {
			return "ingestion provider is not allow-listed by enforced policy"
		}
		return "ingestion provider is blocked by enforced policy"
	case "event_type":
		if effect == "allow" {
			return "ingestion event type is not allow-listed by enforced policy"
		}
		return "ingestion event type is blocked by enforced policy"
	default:
		if effect == "allow" {
			return "requested operation is not allow-listed by enforced policy"
		}
		return "requested operation is blocked by enforced policy"
	}
}

func approvalReasonForField(field string) string {
	switch field {
	case "tool":
		return "restricted adapter requires explicit approval before dispatch"
	case "target":
		return "scan target requires explicit approval before dispatch"
	case "target_kind":
		return "target kind requires explicit approval before dispatch"
	case "profile":
		return "scan profile requires explicit approval before dispatch"
	default:
		return "scan task requires explicit approval before dispatch"
	}
}

func summarizeRule(rule models.PolicyRule) string {
	match := strings.ToLower(strings.TrimSpace(rule.Match))
	if match == "" {
		match = "exact"
	}

	values := strings.Join(rule.Values, ",")
	if values == "" {
		values = "*"
	}
	return strings.ToLower(strings.TrimSpace(rule.Effect)) + ":" + normalizeField(rule.Field) + ":" + match + ":" + values
}

func summarizeBoundRules(rules []boundRule) []string {
	out := make([]string, 0, len(rules))
	for _, item := range rules {
		out = append(out, summarizeRule(item.Rule))
	}
	return out
}
