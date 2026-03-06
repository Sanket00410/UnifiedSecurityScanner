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
			Rules: models.PolicyRuleSet{
				{
					Effect: "require_approval",
					Field:  "tool",
					Match:  "exact",
					Values: []string{"metasploit"},
				},
			},
		},
	}, models.CreateScanJobRequest{
		TargetKind: "domain",
		Profile:    "default",
		Target:     "example.com",
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
			Rules: models.PolicyRuleSet{
				{
					Effect: "block",
					Field:  "tool",
					Match:  "exact",
					Values: []string{"metasploit"},
				},
			},
		},
	}, models.CreateScanJobRequest{
		TargetKind: "domain",
		Profile:    "default",
		Target:     "example.com",
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
			Rules: models.PolicyRuleSet{
				{
					Effect: "allow",
					Field:  "tool",
					Match:  "exact",
					Values: []string{"semgrep"},
				},
				{
					Effect: "allow",
					Field:  "target_kind",
					Match:  "exact",
					Values: []string{"repository"},
				},
				{
					Effect: "allow",
					Field:  "profile",
					Match:  "exact",
					Values: []string{"enterprise"},
				},
			},
		},
	}, models.CreateScanJobRequest{
		TargetKind: "repository",
		Profile:    "default",
		Target:     "C:/repo",
	}, []string{"semgrep"})

	if rejection == nil {
		t.Fatal("expected profile allow-list mismatch to be rejected")
	}
	if rejection.Reason != "scan profile is not allow-listed by enforced policy" {
		t.Fatalf("unexpected rejection reason: %s", rejection.Reason)
	}
}

func TestEvaluateSubmissionSupportsMatchTypesAndExceptions(t *testing.T) {
	t.Parallel()

	plan, rejection := EvaluateSubmission([]models.Policy{
		{
			ID:      "policy-4",
			Enabled: true,
			Scope:   "runtime",
			Mode:    "enforce",
			Rules: models.PolicyRuleSet{
				{
					Effect: "require_approval",
					Field:  "tool",
					Match:  "prefix",
					Values: []string{"meta"},
					Exceptions: []models.PolicyRuleException{
						{
							Field:  "target",
							Match:  "suffix",
							Values: []string{".internal"},
						},
					},
				},
			},
		},
	}, models.CreateScanJobRequest{
		TargetKind: "domain",
		Profile:    "default",
		Target:     "portal.internal",
	}, []string{"metasploit"})

	if rejection != nil {
		t.Fatalf("unexpected rejection: %v", rejection)
	}

	decision := plan.Decisions["metasploit"]
	if decision.Status != TaskDecisionApproved {
		t.Fatalf("expected exception to keep task approved, got %s", decision.Status)
	}
	if plan.ApprovalMode != "standard" {
		t.Fatalf("unexpected approval mode: %s", plan.ApprovalMode)
	}
}

func TestEvaluateSubmissionRequiresApprovalForTargetRule(t *testing.T) {
	t.Parallel()

	plan, rejection := EvaluateSubmission([]models.Policy{
		{
			ID:      "policy-target-approval",
			Enabled: true,
			Scope:   "runtime",
			Mode:    "enforce",
			Rules: models.PolicyRuleSet{
				{
					Effect: "require_approval",
					Field:  "target",
					Match:  "suffix",
					Values: []string{"corp.example.com"},
				},
			},
		},
	}, models.CreateScanJobRequest{
		TargetKind: "domain",
		Profile:    "default",
		Target:     "api.corp.example.com",
	}, []string{"zap"})

	if rejection != nil {
		t.Fatalf("unexpected rejection: %v", rejection)
	}

	decision := plan.Decisions["zap"]
	if decision.Status != TaskDecisionPendingApproval {
		t.Fatalf("expected pending approval for target rule, got %s", decision.Status)
	}
	if decision.Reason != "scan target requires explicit approval before dispatch" {
		t.Fatalf("unexpected target approval reason: %s", decision.Reason)
	}
	if plan.ApprovalMode != "manual-approval" {
		t.Fatalf("unexpected approval mode: %s", plan.ApprovalMode)
	}
}

func TestEvaluateIngestionSubmissionRejectsBlockedEventType(t *testing.T) {
	t.Parallel()

	rejection := EvaluateIngestionSubmission([]models.Policy{
		{
			ID:      "policy-ingestion-event",
			Enabled: true,
			Scope:   "repository",
			Mode:    "enforce",
			Rules: models.PolicyRuleSet{
				{
					Effect: "block",
					Field:  "event_type",
					Match:  "exact",
					Values: []string{"github.push"},
				},
			},
		},
	}, IngestionRequest{
		Provider:   "github",
		EventType:  "github.push",
		TargetKind: "repo",
		Target:     "https://github.com/acme/core",
		Profile:    "balanced",
		Tools:      []string{"semgrep"},
	})
	if rejection == nil {
		t.Fatal("expected blocked ingestion event type to be rejected")
	}
	if rejection.Reason != "ingestion event type is blocked by enforced policy" {
		t.Fatalf("unexpected rejection reason: %s", rejection.Reason)
	}
}

func TestEvaluateIngestionSubmissionRejectsBlockedProvider(t *testing.T) {
	t.Parallel()

	rejection := EvaluateIngestionSubmission([]models.Policy{
		{
			ID:      "policy-ingestion-provider",
			Enabled: true,
			Scope:   "repository",
			Mode:    "enforce",
			Rules: models.PolicyRuleSet{
				{
					Effect: "block",
					Field:  "provider",
					Match:  "exact",
					Values: []string{"gitlab"},
				},
			},
		},
	}, IngestionRequest{
		Provider:   "gitlab",
		EventType:  "gitlab.push_hook",
		TargetKind: "repo",
		Target:     "https://gitlab.com/acme/platform",
		Profile:    "balanced",
		Tools:      []string{"semgrep"},
	})
	if rejection == nil {
		t.Fatal("expected blocked ingestion provider to be rejected")
	}
	if rejection.Reason != "ingestion provider is blocked by enforced policy" {
		t.Fatalf("unexpected rejection reason: %s", rejection.Reason)
	}
}
