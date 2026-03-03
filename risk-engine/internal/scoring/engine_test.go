package scoring

import (
	"testing"
	"time"

	controlmodels "unifiedsecurityscanner/control-plane/internal/models"
	riskmodels "unifiedsecurityscanner/control-plane/risk-engine/internal/models"
)

func TestScoreAppliesOverridesWaiversAndTemporalSignals(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 3, 10, 0, 0, 0, time.UTC)
	response := Score(riskmodels.ScoreRequest{
		Finding: controlmodels.CanonicalFinding{
			SchemaVersion:   "1.0.0",
			Category:        "web_application_exposure",
			Title:           "SQL injection",
			Severity:        "high",
			Confidence:      "high",
			Status:          "open",
			FirstSeenAt:     now.Add(-15 * 24 * time.Hour),
			LastSeenAt:      now,
			OccurrenceCount: 3,
			ReopenedCount:   1,
			Asset: controlmodels.CanonicalAssetInfo{
				AssetID:   "payments.example.com",
				AssetType: "domain",
				AssetName: "payments.example.com",
			},
		},
		Inputs: riskmodels.ScoreInputs{
			EnvironmentOverride:     "production",
			ExposureOverride:        "internet",
			ServiceCriticalityClass: "tier0",
			WaiverReduction:         12,
		},
		ReferenceTime: &now,
	})

	if response.Finding.Risk.PriorityQueue == "" {
		t.Fatal("expected priority queue")
	}
	if response.Finding.Risk.EffectiveSeverity == "" {
		t.Fatal("expected effective severity")
	}
	if response.Finding.Risk.WaiverReduction != 12 {
		t.Fatalf("expected waiver reduction 12, got %.2f", response.Finding.Risk.WaiverReduction)
	}
	if response.Finding.Risk.AgingBucket != "7-30d" {
		t.Fatalf("expected aging bucket 7-30d, got %s", response.Finding.Risk.AgingBucket)
	}
	if response.Finding.Risk.TrendScore <= 0 {
		t.Fatalf("expected positive trend score, got %.2f", response.Finding.Risk.TrendScore)
	}
}
