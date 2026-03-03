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
	if findings[0].Asset.Exposure != "internal" {
		t.Fatalf("expected internal exposure for internal host, got %s", findings[0].Asset.Exposure)
	}
	if findings[0].Risk.Priority != "p2" {
		t.Fatalf("expected p2 priority for internal nmap finding, got %s", findings[0].Risk.Priority)
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
	if finding.Risk.Priority != "p1" {
		t.Fatalf("expected p1 priority for internal metasploit host, got %s", finding.Risk.Priority)
	}
	if finding.Risk.SLAClass != "72h" {
		t.Fatalf("expected 72h sla class, got %s", finding.Risk.SLAClass)
	}
}

func TestParseSemgrepFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("semgrep", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-semgrep",
		AdapterID:  "semgrep",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "semgrep-results.json")})
	if err != nil {
		t.Fatalf("parse semgrep fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sast" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Severity != "high" {
		t.Fatalf("unexpected finding severity: %s", finding.Severity)
	}
	if finding.Risk.Priority != "p3" {
		t.Fatalf("expected p3 priority for repo semgrep finding, got %s", finding.Risk.Priority)
	}
	if finding.Locations[0].Path != "cmd/api/main.go" {
		t.Fatalf("unexpected finding path: %s", finding.Locations[0].Path)
	}
}

func TestParseBanditFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("bandit", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-bandit",
		AdapterID:  "bandit",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "bandit-results.json")})
	if err != nil {
		t.Fatalf("parse bandit fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sast" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "sast_rule_match" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Severity != "high" {
		t.Fatalf("unexpected finding severity: %s", finding.Severity)
	}
	if finding.Locations[0].Line != 41 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParseTrivyFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("trivy", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-trivy",
		AdapterID:  "trivy",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "trivy-results.json")})
	if err != nil {
		t.Fatalf("parse trivy fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sca" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Remediation == nil || !finding.Remediation.FixAvailable {
		t.Fatal("expected trivy finding to include a fixable remediation")
	}
	if finding.Risk.Priority != "p3" {
		t.Fatalf("expected p3 priority for dependency finding, got %s", finding.Risk.Priority)
	}
}

func TestParseTrivyImageFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("trivy-image", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-trivy-image",
		AdapterID:  "trivy-image",
		TargetKind: "image",
		Target:     "ghcr.io/acme/payments:1.4.2",
	}, []string{filepath.Join("testdata", "trivy-image-results.json")})
	if err != nil {
		t.Fatalf("parse trivy image fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sca" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "container_image_vulnerability" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Risk.Priority != "p2" {
		t.Fatalf("expected p2 priority for image vulnerability, got %s", finding.Risk.Priority)
	}
	if finding.Remediation == nil || !finding.Remediation.FixAvailable {
		t.Fatal("expected trivy image finding to include a fixable remediation")
	}
}

func TestParseTrivyConfigFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("trivy-config", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-trivy-config",
		AdapterID:  "trivy-config",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "trivy-config-results.json")})
	if err != nil {
		t.Fatalf("parse trivy config fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "iac" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "iac_misconfiguration" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Locations[0].Line != 18 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
	if finding.Risk.Priority != "p3" {
		t.Fatalf("expected p3 priority for config finding, got %s", finding.Risk.Priority)
	}
}

func TestParseTrivySecretsFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("trivy-secrets", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-trivy-secrets",
		AdapterID:  "trivy-secrets",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "trivy-secrets-results.json")})
	if err != nil {
		t.Fatalf("parse trivy secrets fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "secrets" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "secret_exposure" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Risk.Priority != "p2" {
		t.Fatalf("expected p2 priority for trivy secret finding, got %s", finding.Risk.Priority)
	}
}

func TestParseGrypeFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("grype", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-grype",
		AdapterID:  "grype",
		TargetKind: "image",
		Target:     "ghcr.io/acme/payments:1.4.2",
	}, []string{filepath.Join("testdata", "grype-results.json")})
	if err != nil {
		t.Fatalf("parse grype fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sca" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "container_image_vulnerability" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Remediation == nil || !finding.Remediation.FixAvailable {
		t.Fatal("expected grype finding to include a fixable remediation")
	}
	if finding.Risk.Priority != "p2" {
		t.Fatalf("expected p2 priority for grype image finding, got %s", finding.Risk.Priority)
	}
}

func TestParseGitleaksFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("gitleaks", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-gitleaks",
		AdapterID:  "gitleaks",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "gitleaks-results.json")})
	if err != nil {
		t.Fatalf("parse gitleaks fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "secrets" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "secret_exposure" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Risk.Priority != "p2" {
		t.Fatalf("expected p2 priority for secret exposure, got %s", finding.Risk.Priority)
	}
}

func TestParseCheckovFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("checkov", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-checkov",
		AdapterID:  "checkov",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "checkov-results.json")})
	if err != nil {
		t.Fatalf("parse checkov fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "iac" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Locations[0].Line != 12 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
	if finding.Risk.SLAClass != "30d" {
		t.Fatalf("expected 30d sla class for checkov finding, got %s", finding.Risk.SLAClass)
	}
}
