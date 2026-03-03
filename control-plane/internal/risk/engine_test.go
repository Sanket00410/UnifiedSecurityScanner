package risk

import (
	"testing"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestEnrichPrioritizesInternetExploitableFindings(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 3, 10, 0, 0, 0, time.UTC)
	finding := Enrich(models.CanonicalFinding{
		SchemaVersion: "1.0.0",
		FindingID:     "finding-1",
		TenantID:      "tenant-1",
		Scanner: models.CanonicalScannerInfo{
			AdapterID: "metasploit",
		},
		Source: models.CanonicalSourceInfo{
			Tool: "metasploit",
		},
		Category:    "exploit_confirmed",
		Title:       "Exploit confirmed",
		Severity:    "critical",
		Confidence:  "high",
		Status:      "open",
		FirstSeenAt: now,
		LastSeenAt:  now,
		Asset: models.CanonicalAssetInfo{
			AssetID:   "prod.example.com",
			AssetType: "domain",
			AssetName: "prod.example.com",
		},
		Locations: []models.CanonicalLocation{
			{
				Kind:     "endpoint",
				Endpoint: "prod.example.com",
			},
		},
	})

	if finding.Asset.Environment != "production" {
		t.Fatalf("expected production environment, got %s", finding.Asset.Environment)
	}
	if finding.Asset.Exposure != "internet" {
		t.Fatalf("expected internet exposure, got %s", finding.Asset.Exposure)
	}
	if finding.Risk.Priority != "p0" {
		t.Fatalf("expected p0 priority, got %s", finding.Risk.Priority)
	}
	if finding.Risk.OverallScore < 90 {
		t.Fatalf("expected a top-tier overall score, got %.2f", finding.Risk.OverallScore)
	}
	if finding.Risk.SLAClass != "24h" {
		t.Fatalf("expected 24h sla class, got %s", finding.Risk.SLAClass)
	}
	if finding.Risk.SLADueAt == nil || !finding.Risk.SLADueAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("expected 24h due date, got %#v", finding.Risk.SLADueAt)
	}
}

func TestEnrichLowersPriorityForInternalCodebaseFindings(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 3, 10, 0, 0, 0, time.UTC)
	finding := Enrich(models.CanonicalFinding{
		SchemaVersion: "1.0.0",
		FindingID:     "finding-2",
		TenantID:      "tenant-1",
		Scanner: models.CanonicalScannerInfo{
			AdapterID: "semgrep",
		},
		Source: models.CanonicalSourceInfo{
			Tool: "semgrep",
		},
		Category:    "sast_rule_match",
		Title:       "Unsafe call path",
		Severity:    "high",
		Confidence:  "high",
		Status:      "open",
		FirstSeenAt: now,
		LastSeenAt:  now,
		Asset: models.CanonicalAssetInfo{
			AssetID:   "C:/repo",
			AssetType: "repository",
			AssetName: "C:/repo",
		},
	})

	if finding.Source.Layer != "sast" {
		t.Fatalf("expected sast layer, got %s", finding.Source.Layer)
	}
	if finding.Asset.Environment != "development" {
		t.Fatalf("expected development environment, got %s", finding.Asset.Environment)
	}
	if finding.Asset.Exposure != "internal" {
		t.Fatalf("expected internal exposure, got %s", finding.Asset.Exposure)
	}
	if finding.Risk.Priority != "p3" {
		t.Fatalf("expected p3 priority, got %s", finding.Risk.Priority)
	}
	if finding.Risk.OverallScore >= 55 {
		t.Fatalf("expected lower score than p2 threshold, got %.2f", finding.Risk.OverallScore)
	}
	if finding.Risk.SLAClass != "30d" {
		t.Fatalf("expected 30d sla class, got %s", finding.Risk.SLAClass)
	}
}

func TestLayerForAdapterNormalizesCodeAndRuntimeTools(t *testing.T) {
	t.Parallel()

	if got := LayerForAdapter("gitleaks"); got != "secrets" {
		t.Fatalf("expected gitleaks layer secrets, got %s", got)
	}
	if got := LayerForAdapter("zap"); got != "dast" {
		t.Fatalf("expected zap layer dast, got %s", got)
	}
}
