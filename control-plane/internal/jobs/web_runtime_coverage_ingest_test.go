package jobs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseBrowserProbeCoveragePayload_FromCoverageObject(t *testing.T) {
	payload := []byte(`{
		"coverage": {
			"route_coverage": 82.5,
			"api_coverage": 71.0,
			"auth_coverage": 63.5,
			"discovered_route_count": 120,
			"discovered_api_operation_count": 44,
			"discovered_auth_state_count": 6
		}
	}`)

	request, found, err := parseBrowserProbeCoveragePayload(payload)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if !found {
		t.Fatal("expected coverage payload to be found")
	}
	if request.RouteCoverage != 82.5 || request.APICoverage != 71 || request.AuthCoverage != 63.5 {
		t.Fatalf("unexpected coverage values: %#v", request)
	}
	if request.DiscoveredRouteCount != 120 || request.DiscoveredAPIOperationCount != 44 || request.DiscoveredAuthStateCount != 6 {
		t.Fatalf("unexpected discovered counts: %#v", request)
	}
}

func TestParseBrowserProbeCoveragePayload_FromTopLevelCamelCase(t *testing.T) {
	payload := []byte(`{
		"routeCoverage": 90,
		"apiCoverage": 80,
		"authCoverage": 75,
		"discoveredRouteCount": 200,
		"discoveredApiOperationCount": 70,
		"discoveredAuthStateCount": 8
	}`)

	request, found, err := parseBrowserProbeCoveragePayload(payload)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if !found {
		t.Fatal("expected top-level coverage payload to be found")
	}
	if request.RouteCoverage != 90 || request.APICoverage != 80 || request.AuthCoverage != 75 {
		t.Fatalf("unexpected coverage values: %#v", request)
	}
	if request.DiscoveredRouteCount != 200 || request.DiscoveredAPIOperationCount != 70 || request.DiscoveredAuthStateCount != 8 {
		t.Fatalf("unexpected discovered counts: %#v", request)
	}
}

func TestParseBrowserProbeCoveragePayload_NonJSONReturnsNotFound(t *testing.T) {
	request, found, err := parseBrowserProbeCoveragePayload([]byte("not-json"))
	if err != nil {
		t.Fatalf("expected non-json to be skipped without error, got %v", err)
	}
	if found {
		t.Fatalf("expected no coverage payload for non-json input, got %#v", request)
	}
}

func TestNormalizeRuntimeCoverageAdapterID(t *testing.T) {
	if value := normalizeRuntimeCoverageAdapterID(" browser-probe "); value != "browser-probe" {
		t.Fatalf("expected browser-probe adapter id, got %q", value)
	}
	if value := normalizeRuntimeCoverageAdapterID("ZAP-API"); value != "zap-api" {
		t.Fatalf("expected zap-api adapter id, got %q", value)
	}
	if value := normalizeRuntimeCoverageAdapterID("zap"); value != "" {
		t.Fatalf("expected unsupported adapter to return empty, got %q", value)
	}
}

func TestExtractRuntimeCoverageFromEvidence_ZapAPI(t *testing.T) {
	tempDir := t.TempDir()
	evidencePath := filepath.Join(tempDir, "zap-api-output.log")
	payload := `{
		"coverage_summary": {
			"api_coverage": 78.5,
			"auth_coverage": 61.0,
			"discovered_api_operation_count": 41,
			"discovered_auth_state_count": 4
		}
	}`
	if err := os.WriteFile(evidencePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write evidence fixture: %v", err)
	}

	request, evidenceRef, found, err := extractRuntimeCoverageFromEvidence("zap-api", []string{evidencePath})
	if err != nil {
		t.Fatalf("extract coverage: %v", err)
	}
	if !found {
		t.Fatal("expected coverage to be extracted")
	}
	if evidenceRef != evidencePath {
		t.Fatalf("expected evidence ref %s, got %s", evidencePath, evidenceRef)
	}
	if request.APICoverage != 78.5 || request.AuthCoverage != 61 {
		t.Fatalf("unexpected extracted coverage values: %#v", request)
	}
	if request.DiscoveredAPIOperationCount != 41 || request.DiscoveredAuthStateCount != 4 {
		t.Fatalf("unexpected extracted coverage counts: %#v", request)
	}
}
