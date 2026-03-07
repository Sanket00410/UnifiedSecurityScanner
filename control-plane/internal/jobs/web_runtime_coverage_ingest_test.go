package jobs

import "testing"

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
