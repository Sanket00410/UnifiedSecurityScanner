package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	controlmodels "unifiedsecurityscanner/control-plane/internal/models"
	riskmodels "unifiedsecurityscanner/control-plane/risk-engine/internal/models"
)

func TestScoreEndpointReturnsEnrichedFinding(t *testing.T) {
	t.Parallel()

	server := New(":0")
	recorder := httptest.NewRecorder()

	payload, err := json.Marshal(riskmodels.ScoreRequest{
		Finding: controlmodels.CanonicalFinding{
			SchemaVersion: "1.0.0",
			Category:      "exploit_confirmed",
			Title:         "Confirmed exploit",
			Severity:      "high",
			Confidence:    "high",
			Status:        "open",
			FirstSeenAt:   time.Date(2026, time.March, 1, 10, 0, 0, 0, time.UTC),
			LastSeenAt:    time.Date(2026, time.March, 3, 10, 0, 0, 0, time.UTC),
			Asset: controlmodels.CanonicalAssetInfo{
				AssetID:   "prod.example.com",
				AssetType: "domain",
				AssetName: "prod.example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/score", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var response riskmodels.ScoreResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Finding.Risk.Priority != "p0" {
		t.Fatalf("expected p0 priority, got %s", response.Finding.Risk.Priority)
	}
	if response.Finding.Risk.PriorityQueue == "" {
		t.Fatal("expected priority queue in response")
	}
	if response.Finding.Risk.EffectiveSeverity != "critical" {
		t.Fatalf("expected effective severity critical, got %s", response.Finding.Risk.EffectiveSeverity)
	}
}
