package normalize

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseNmapFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("nmap", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-nmap",
		AdapterID:  "nmap",
		TargetKind: "host",
		Target:     "scanner.internal",
	}, []string{filepath.Join("testdata", "nmap-open-ports.txt")})
	if err != nil {
		t.Fatalf("parse nmap fixture: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].Severity != "high" {
		t.Fatalf("expected first finding severity high, got %s", findings[0].Severity)
	}
	if findings[0].Category != "open_network_service" {
		t.Fatalf("unexpected first finding category: %s", findings[0].Category)
	}
	if findings[0].Locations[0].Endpoint != "scanner.internal:22/tcp" {
		t.Fatalf("unexpected first finding endpoint: %s", findings[0].Locations[0].Endpoint)
	}

	if findings[1].Severity != "medium" {
		t.Fatalf("expected second finding severity medium, got %s", findings[1].Severity)
	}
	if findings[1].Locations[0].Endpoint != "scanner.internal:80/tcp" {
		t.Fatalf("unexpected second finding endpoint: %s", findings[1].Locations[0].Endpoint)
	}
}

func TestParseMetasploitFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("metasploit", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-msf",
		AdapterID:  "metasploit",
		TargetKind: "host",
		Target:     "10.0.0.5",
	}, []string{filepath.Join("testdata", "metasploit-vulnerable.log")})
	if err != nil {
		t.Fatalf("parse metasploit fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Severity != "critical" {
		t.Fatalf("unexpected finding severity: %s", finding.Severity)
	}
	if finding.Category != "exploit_confirmed" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if !strings.Contains(finding.Title, "auxiliary/scanner/http/http_version") {
		t.Fatalf("expected module name in finding title, got %s", finding.Title)
	}
}
