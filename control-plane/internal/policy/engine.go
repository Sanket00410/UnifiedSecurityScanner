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

func EvaluateSubmission(policies []models.Policy, request models.CreateScanJobRequest, tools []string) (Plan, *Rejection) {
	applicable := applicablePolicies(policies, request)
	enforced := make([]models.Policy, 0, len(applicable))
	for _, policy := range applicable {
		if isEnforced(policy.Mode) {
			enforced = append(enforced, policy)
		}
	}

	targetAllow := make(map[string]string)
	targetAllowHits := make(map[string]string)
	targetBlock := make(map[string]string)
	targetBlockHits := make(map[string]string)
	profileAllow := make(map[string]string)
	profileAllowHits := make(map[string]string)
	profileBlock := make(map[string]string)
	profileBlockHits := make(map[string]string)
	toolAllow := make(map[string]string)
	toolAllowHits := make(map[string]string)
	toolBlock := make(map[string]string)
	toolBlockHits := make(map[string]string)
	toolApproval := make(map[string]string)
	toolApprovalHits := make(map[string]string)

	for _, policy := range enforced {
		for _, rule := range policy.Rules {
			kind, value := splitRule(rule)
			switch kind {
			case "allow_target":
				targetAllow[value] = policy.ID
				targetAllowHits[value] = rule
			case "block_target":
				targetBlock[value] = policy.ID
				targetBlockHits[value] = rule
			case "allow_profile":
				profileAllow[value] = policy.ID
				profileAllowHits[value] = rule
			case "block_profile":
				profileBlock[value] = policy.ID
				profileBlockHits[value] = rule
			case "allow_tool":
				toolAllow[value] = policy.ID
				toolAllowHits[value] = rule
			case "block_tool":
				toolBlock[value] = policy.ID
				toolBlockHits[value] = rule
			case "require_approval":
				toolApproval[value] = policy.ID
				toolApprovalHits[value] = rule
			}
		}
	}

	targetKind := strings.ToLower(strings.TrimSpace(request.TargetKind))
	profile := strings.ToLower(strings.TrimSpace(request.Profile))
	if len(targetAllow) > 0 {
		if _, ok := targetAllow[targetKind]; !ok {
			return Plan{}, &Rejection{
				PolicyID: firstPolicyID(targetAllow),
				Reason:   "target kind is not allow-listed by enforced policy",
				RuleHits: []string{firstRule(targetAllowHits)},
			}
		}
	}
	if policyID, blocked := targetBlock[targetKind]; blocked {
		return Plan{}, &Rejection{
			PolicyID: policyID,
			Reason:   "target kind is blocked by enforced policy",
			RuleHits: []string{targetBlockHits[targetKind]},
		}
	}
	if len(profileAllow) > 0 {
		if _, ok := profileAllow[profile]; !ok {
			return Plan{}, &Rejection{
				PolicyID: firstPolicyID(profileAllow),
				Reason:   "scan profile is not allow-listed by enforced policy",
				RuleHits: []string{firstRule(profileAllowHits)},
			}
		}
	}
	if policyID, blocked := profileBlock[profile]; blocked {
		return Plan{}, &Rejection{
			PolicyID: policyID,
			Reason:   "scan profile is blocked by enforced policy",
			RuleHits: []string{profileBlockHits[profile]},
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

		if len(toolAllow) > 0 {
			if _, ok := toolAllow[normalizedTool]; !ok {
				return Plan{}, &Rejection{
					PolicyID: firstPolicyID(toolAllow),
					Reason:   "requested tool is not allow-listed by enforced policy",
					RuleHits: []string{firstRule(toolAllowHits)},
				}
			}
		}
		if policyID, blocked := toolBlock[normalizedTool]; blocked {
			return Plan{}, &Rejection{
				PolicyID: policyID,
				Reason:   "requested tool is blocked by enforced policy",
				RuleHits: []string{toolBlockHits[normalizedTool]},
			}
		}

		decision := TaskDecision{
			Tool:   normalizedTool,
			Status: TaskDecisionApproved,
		}
		if policyID, requiresApproval := toolApproval[normalizedTool]; requiresApproval {
			decision.Status = TaskDecisionPendingApproval
			decision.PolicyID = policyID
			decision.Reason = "restricted adapter requires explicit approval before dispatch"
			decision.RuleHits = []string{toolApprovalHits[normalizedTool]}
			plan.ApprovalMode = "manual-approval"
		}

		plan.Decisions[normalizedTool] = decision
	}

	return plan, nil
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

func splitRule(rule string) (string, string) {
	normalized := strings.ToLower(strings.TrimSpace(rule))
	parts := strings.SplitN(normalized, ":", 2)
	if len(parts) != 2 {
		return normalized, ""
	}
	return parts[0], strings.TrimSpace(parts[1])
}

func firstPolicyID(items map[string]string) string {
	for _, policyID := range items {
		return policyID
	}
	return ""
}

func firstRule(items map[string]string) string {
	for _, rule := range items {
		return rule
	}
	return ""
}
