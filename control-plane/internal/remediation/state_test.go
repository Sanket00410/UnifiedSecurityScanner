package remediation

import (
	"testing"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestNormalizeStatusAndTransitions(t *testing.T) {
	t.Parallel()

	if got := NormalizeStatus("READY-FOR-VERIFY"); got != "ready_for_verify" {
		t.Fatalf("expected ready_for_verify, got %s", got)
	}
	if IsValidTransition("open", "assigned") == false {
		t.Fatal("expected open -> assigned to be valid")
	}
	if IsValidTransition("verified", "in_progress") {
		t.Fatal("expected verified -> in_progress to be invalid")
	}
}

func TestResolveOwner(t *testing.T) {
	t.Parallel()

	if result := ResolveOwner("manual-owner", nil); result.Owner != "manual-owner" || result.Source != "request" {
		t.Fatalf("expected manual request owner, got %+v", result)
	}

	finding := &models.CanonicalFinding{
		Severity: "high",
		Asset: models.CanonicalAssetInfo{
			OwnerTeam: "edge",
		},
	}
	if result := ResolveOwner("", finding); result.Owner != "edge" || result.Source != "asset_owner_team" {
		t.Fatalf("expected asset owner team resolution, got %+v", result)
	}

	finding.Asset.OwnerTeam = ""
	finding.Risk.Priority = "p1"
	if result := ResolveOwner("", finding); result.Owner != "appsec-escalation" || result.Source != "risk_priority" {
		t.Fatalf("expected risk priority routing, got %+v", result)
	}
}
