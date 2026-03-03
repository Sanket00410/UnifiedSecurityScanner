package policy

import (
	"testing"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestEvaluateSubmissionRequiresApprovalForRestrictedTool(t *testing.T) {
	t.Parallel()

	plan, rejection := EvaluateSubmission([]models.Policy{
		{
			ID:      "policy-1",
			Enabled: true,
			Scope:   "runtime",
			Mode:    "enforce",
			Rules: []string{
				"require_approval:metasploit",
			},
		},
	}, models.CreateScanJobRequest{
		TargetKind: "domain",
		Profile:    "default",
	}, []string{"metasploit"})

	if rejection != nil {
		t.Fatalf("unexpected rejection: %v", rejection)
	}

	decision := plan.Decisions["metasploit"]
	if decision.Status != TaskDecisionPendingApproval {
		t.Fatalf("expected pending approval, got %s", decision.Status)
	}
	if plan.ApprovalMode != "manual-approval" {
		t.Fatalf("unexpected approval mode: %s", plan.ApprovalMode)
	}
}

func TestEvaluateSubmissionRejectsBlockedTool(t *testing.T) {
	t.Parallel()

	_, rejection := EvaluateSubmission([]models.Policy{
		{
			ID:      "policy-2",
			Enabled: true,
			Scope:   "global",
			Mode:    "enforce",
			Rules: []string{
				"block_tool:metasploit",
			},
		},
	}, models.CreateScanJobRequest{
		TargetKind: "domain",
		Profile:    "default",
	}, []string{"metasploit"})

	if rejection == nil {
		t.Fatal("expected blocked tool to be rejected")
	}
	if rejection.PolicyID != "policy-2" {
		t.Fatalf("unexpected policy id: %s", rejection.PolicyID)
	}
}

func TestEvaluateSubmissionHonorsAllowLists(t *testing.T) {
	t.Parallel()

	_, rejection := EvaluateSubmission([]models.Policy{
		{
			ID:      "policy-3",
			Enabled: true,
			Scope:   "repository",
			Mode:    "enforce",
			Rules: []string{
				"allow_tool:semgrep",
				"allow_target:repository",
				"allow_profile:enterprise",
			},
		},
	}, models.CreateScanJobRequest{
		TargetKind: "repository",
		Profile:    "default",
	}, []string{"semgrep"})

	if rejection == nil {
		t.Fatal("expected profile allow-list mismatch to be rejected")
	}
}
