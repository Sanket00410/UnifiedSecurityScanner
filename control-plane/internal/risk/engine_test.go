package risk

import (
	"strings"
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

func TestEnrichWithInputsAppliesAssetOverridesAndControls(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 3, 10, 0, 0, 0, time.UTC)
	finding := EnrichWithInputs(models.CanonicalFinding{
		SchemaVersion: "1.0.0",
		TenantID:      "tenant-1",
		Scanner: models.CanonicalScannerInfo{
			AdapterID: "zap",
		},
		Source: models.CanonicalSourceInfo{
			Tool: "zap",
		},
		Category:    "web_application_exposure",
		Title:       "SQL injection",
		Severity:    "high",
		Confidence:  "high",
		Status:      "open",
		FirstSeenAt: now,
		LastSeenAt:  now,
		Asset: models.CanonicalAssetInfo{
			AssetID:   "public.example.com",
			AssetType: "domain",
			AssetName: "public.example.com",
		},
	}, Inputs{
		EnvironmentOverride:          "production",
		ExposureOverride:             "internet",
		AssetCriticalityOverride:     9.5,
		OwnerTeam:                    "edge-security",
		CompensatingControlReduction: 4,
	})

	if finding.Asset.OwnerTeam != "edge-security" {
		t.Fatalf("expected owner team override, got %s", finding.Asset.OwnerTeam)
	}
	if finding.Risk.AssetCriticality != 9.5 {
		t.Fatalf("expected criticality override, got %.2f", finding.Risk.AssetCriticality)
	}
	if finding.Risk.CompensatingControlReduction != 4 {
		t.Fatalf("expected control reduction, got %.2f", finding.Risk.CompensatingControlReduction)
	}
	if finding.Risk.OverallScore >= 90 {
		t.Fatalf("expected controls to reduce score below p0 threshold, got %.2f", finding.Risk.OverallScore)
	}
}

func TestFingerprintIsStableForEquivalentFindings(t *testing.T) {
	t.Parallel()

	findingA := models.CanonicalFinding{
		Source:   models.CanonicalSourceInfo{Tool: "semgrep"},
		Category: "sast_rule_match",
		Title:    "Unsafe sink",
		Asset: models.CanonicalAssetInfo{
			AssetID:   "C:/repo",
			AssetType: "repository",
		},
		Locations: []models.CanonicalLocation{
			{Path: "main.go", Line: 42},
		},
		Tags: []string{"rule:x", "lang:go"},
	}
	findingB := models.CanonicalFinding{
		Source:   models.CanonicalSourceInfo{Tool: "semgrep"},
		Category: "sast_rule_match",
		Title:    "Unsafe sink",
		Asset: models.CanonicalAssetInfo{
			AssetID:   "C:/repo",
			AssetType: "repository",
		},
		Locations: []models.CanonicalLocation{
			{Path: "main.go", Line: 42},
		},
		Tags: []string{"lang:go", "rule:x"},
	}

	if Fingerprint(findingA) != Fingerprint(findingB) {
		t.Fatal("expected equivalent findings to have the same fingerprint")
	}
	if !strings.HasPrefix(StableFindingID(Fingerprint(findingA)), "finding-") {
		t.Fatal("expected stable finding id prefix")
	}
}

func TestApplyWaiverReductionRecomputesPriorityAndSLA(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 3, 10, 0, 0, 0, time.UTC)
	finding := Enrich(models.CanonicalFinding{
		SchemaVersion: "1.0.0",
		Category:      "exploit_confirmed",
		Title:         "Confirmed exploitable condition",
		Severity:      "critical",
		Confidence:    "high",
		Status:        "open",
		FirstSeenAt:   now,
		LastSeenAt:    now,
		Asset: models.CanonicalAssetInfo{
			AssetID:   "prod.example.com",
			AssetType: "domain",
			AssetName: "prod.example.com",
		},
	})

	adjusted := ApplyWaiverReduction(finding, 22)
	if adjusted.Risk.WaiverReduction != 22 {
		t.Fatalf("expected waiver reduction 22, got %.2f", adjusted.Risk.WaiverReduction)
	}
	if adjusted.Risk.OverallScore >= finding.Risk.OverallScore {
		t.Fatalf("expected reduced score below %.2f, got %.2f", finding.Risk.OverallScore, adjusted.Risk.OverallScore)
	}
	if adjusted.Risk.Priority == finding.Risk.Priority {
		t.Fatalf("expected priority change after waiver, still %s", adjusted.Risk.Priority)
	}
	if adjusted.Risk.SLADueAt == nil {
		t.Fatal("expected sla due date after waiver adjustment")
	}
}

func TestApplyTemporalSignalsSetsAgeAndOverdue(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 3, 10, 0, 0, 0, time.UTC)
	dueAt := now.Add(-24 * time.Hour)
	finding := ApplyTemporalSignals(models.CanonicalFinding{
		Status:      "open",
		FirstSeenAt: now.Add(-45 * 24 * time.Hour),
		Risk: models.CanonicalRisk{
			SLAClass: "24h",
			SLADueAt: &dueAt,
		},
	}, now)

	if finding.Risk.AgeDays != 45 {
		t.Fatalf("expected age_days 45, got %d", finding.Risk.AgeDays)
	}
	if finding.Risk.AgingBucket != "31-89d" {
		t.Fatalf("expected aging bucket 31-89d, got %s", finding.Risk.AgingBucket)
	}
	if !finding.Risk.Overdue {
		t.Fatal("expected overdue finding")
	}
}

func TestEnrichWithInputsUsesServiceCriticalityBoost(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 3, 10, 0, 0, 0, time.UTC)
	base := Enrich(models.CanonicalFinding{
		SchemaVersion: "1.0.0",
		Category:      "sast_rule_match",
		Title:         "Unsafe pattern",
		Severity:      "medium",
		Confidence:    "high",
		Status:        "open",
		FirstSeenAt:   now,
		LastSeenAt:    now,
		Asset: models.CanonicalAssetInfo{
			AssetID:   "service-a",
			AssetType: "repository",
			AssetName: "service-a",
		},
	})

	boosted := EnrichWithInputs(base, Inputs{
		ServiceName:             "payments",
		ServiceCriticalityClass: "tier0",
	})

	if boosted.Asset.ServiceName != "payments" {
		t.Fatalf("expected service name to be carried through, got %s", boosted.Asset.ServiceName)
	}
	if boosted.Asset.ServiceCriticalityClass != "tier0" {
		t.Fatalf("expected service criticality class tier0, got %s", boosted.Asset.ServiceCriticalityClass)
	}
	if boosted.Risk.AssetCriticality <= base.Risk.AssetCriticality {
		t.Fatalf("expected service criticality boost above %.2f, got %.2f", base.Risk.AssetCriticality, boosted.Risk.AssetCriticality)
	}
}
