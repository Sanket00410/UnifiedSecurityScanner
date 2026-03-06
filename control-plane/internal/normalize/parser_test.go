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

func TestParseGosecFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("gosec", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-gosec",
		AdapterID:  "gosec",
		TargetKind: "go_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "gosec-results.json")})
	if err != nil {
		t.Fatalf("parse gosec fixture: %v", err)
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
	if finding.Risk.Priority != "p3" {
		t.Fatalf("expected p3 priority for gosec finding, got %s", finding.Risk.Priority)
	}
	if finding.Locations[0].Line != 42 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
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

func TestParseHadolintFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("hadolint", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-hadolint",
		AdapterID:  "hadolint",
		TargetKind: "dockerfile",
		Target:     "Dockerfile",
	}, []string{filepath.Join("testdata", "hadolint-results.json")})
	if err != nil {
		t.Fatalf("parse hadolint fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "iac" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "container_misconfiguration" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Risk.Priority != "p3" {
		t.Fatalf("expected p3 priority for hadolint finding, got %s", finding.Risk.Priority)
	}
	if finding.Locations[0].Line != 4 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParseSpotBugsFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("spotbugs", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-spotbugs",
		AdapterID:  "spotbugs",
		TargetKind: "java_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "spotbugs-results.xml")})
	if err != nil {
		t.Fatalf("parse spotbugs fixture: %v", err)
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
	if finding.Locations[0].Line != 27 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParsePmdFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("pmd", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-pmd",
		AdapterID:  "pmd",
		TargetKind: "java_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "pmd-results.json")})
	if err != nil {
		t.Fatalf("parse pmd fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sast" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Locations[0].Line != 12 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
	if finding.Risk.Priority == "" {
		t.Fatal("expected pmd finding to be risk-enriched")
	}
}

func TestParseSyftFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("syft", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-syft",
		AdapterID:  "syft",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "syft-results.json")})
	if err != nil {
		t.Fatalf("parse syft fixture: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseKubeScoreFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("kube-score", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-kube-score",
		AdapterID:  "kube-score",
		TargetKind: "kubernetes",
		Target:     "c:/repo/manifests",
	}, []string{filepath.Join("testdata", "kube-score-results.json")})
	if err != nil {
		t.Fatalf("parse kube-score fixture: %v", err)
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
}

func TestParseTfsecFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("tfsec", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-tfsec",
		AdapterID:  "tfsec",
		TargetKind: "terraform",
		Target:     "c:/repo/infra",
	}, []string{filepath.Join("testdata", "tfsec-results.json")})
	if err != nil {
		t.Fatalf("parse tfsec fixture: %v", err)
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
	if finding.Locations[0].Line != 14 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParseShellCheckFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("shellcheck", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-shellcheck",
		AdapterID:  "shellcheck",
		TargetKind: "shell_script",
		Target:     "scripts/deploy.sh",
	}, []string{filepath.Join("testdata", "shellcheck-results.json")})
	if err != nil {
		t.Fatalf("parse shellcheck fixture: %v", err)
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
	if finding.Locations[0].Line != 8 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParseOSVScannerFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("osv-scanner", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-osv",
		AdapterID:  "osv-scanner",
		TargetKind: "go_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "osv-scanner-results.json")})
	if err != nil {
		t.Fatalf("parse osv-scanner fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sca" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "dependency_vulnerability" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Risk.Priority == "" {
		t.Fatal("expected osv-scanner finding to be risk-enriched")
	}
}

func TestParseKICSFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("kics", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-kics",
		AdapterID:  "kics",
		TargetKind: "terraform",
		Target:     "c:/repo/infra",
	}, []string{filepath.Join("testdata", "kics-results.json")})
	if err != nil {
		t.Fatalf("parse kics fixture: %v", err)
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
	if finding.Locations[0].Line != 22 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParseESLintFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("eslint", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-eslint",
		AdapterID:  "eslint",
		TargetKind: "node_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "eslint-results.json")})
	if err != nil {
		t.Fatalf("parse eslint fixture: %v", err)
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
	if finding.Locations[0].Line != 14 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParseNPMAuditFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("npm-audit", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-npm-audit",
		AdapterID:  "npm-audit",
		TargetKind: "node_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "npm-audit-results.json")})
	if err != nil {
		t.Fatalf("parse npm-audit fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sca" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "dependency_vulnerability" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Risk.Priority == "" {
		t.Fatal("expected npm-audit finding to be risk-enriched")
	}
}

func TestParseKubeSecFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("kubesec", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-kubesec",
		AdapterID:  "kubesec",
		TargetKind: "kubernetes",
		Target:     "c:/repo/k8s",
	}, []string{filepath.Join("testdata", "kubesec-results.json")})
	if err != nil {
		t.Fatalf("parse kubesec fixture: %v", err)
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
	if finding.Locations[0].Path != "k8s/deployment.yaml" {
		t.Fatalf("unexpected finding path: %s", finding.Locations[0].Path)
	}
}

func TestParseDevSkimFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("devskim", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-devskim",
		AdapterID:  "devskim",
		TargetKind: "dotnet_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "devskim-results.json")})
	if err != nil {
		t.Fatalf("parse devskim fixture: %v", err)
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
	if finding.Locations[0].Line != 33 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParseDotnetAuditFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("dotnet-audit", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-dotnet-audit",
		AdapterID:  "dotnet-audit",
		TargetKind: "dotnet_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "dotnet-audit-results.json")})
	if err != nil {
		t.Fatalf("parse dotnet-audit fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sca" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "dependency_vulnerability" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Risk.Priority == "" {
		t.Fatal("expected dotnet-audit finding to be risk-enriched")
	}
}

func TestParseCFNLintFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("cfn-lint", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-cfn-lint",
		AdapterID:  "cfn-lint",
		TargetKind: "cloudformation",
		Target:     "templates/app.yaml",
	}, []string{filepath.Join("testdata", "cfn-lint-results.json")})
	if err != nil {
		t.Fatalf("parse cfn-lint fixture: %v", err)
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
	if finding.Locations[0].Line != 19 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParseBrakemanFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("brakeman", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-brakeman",
		AdapterID:  "brakeman",
		TargetKind: "ruby_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "brakeman-results.json")})
	if err != nil {
		t.Fatalf("parse brakeman fixture: %v", err)
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
	if finding.Locations[0].Line != 21 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParsePHPStanFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("phpstan", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-phpstan",
		AdapterID:  "phpstan",
		TargetKind: "php_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "phpstan-results.json")})
	if err != nil {
		t.Fatalf("parse phpstan fixture: %v", err)
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
	if finding.Locations[0].Line != 18 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParseComposerAuditFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("composer-audit", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-composer-audit",
		AdapterID:  "composer-audit",
		TargetKind: "php_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "composer-audit-results.json")})
	if err != nil {
		t.Fatalf("parse composer-audit fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sca" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "dependency_vulnerability" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Risk.Priority == "" {
		t.Fatal("expected composer-audit finding to be risk-enriched")
	}
}

func TestParseBundlerAuditFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("bundler-audit", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-bundler-audit",
		AdapterID:  "bundler-audit",
		TargetKind: "ruby_repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "bundler-audit-results.json")})
	if err != nil {
		t.Fatalf("parse bundler-audit fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sca" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "dependency_vulnerability" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Risk.Priority == "" {
		t.Fatal("expected bundler-audit finding to be risk-enriched")
	}
}

func TestParseProwlerFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("prowler", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-prowler",
		AdapterID:  "prowler",
		TargetKind: "aws_account",
		Target:     "123456789012",
	}, []string{filepath.Join("testdata", "prowler-results.json")})
	if err != nil {
		t.Fatalf("parse prowler fixture: %v", err)
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
	if finding.Asset.AssetID != "123456789012" {
		t.Fatalf("unexpected asset id: %s", finding.Asset.AssetID)
	}
	if finding.Risk.Priority == "" {
		t.Fatal("expected prowler finding to be risk-enriched")
	}
}

func TestParseProwlerGCPFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("prowler", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-prowler-gcp",
		AdapterID:  "prowler",
		TargetKind: "gcp_project",
		Target:     "acme-prod",
	}, []string{filepath.Join("testdata", "prowler-gcp-results.json")})
	if err != nil {
		t.Fatalf("parse prowler gcp fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Asset.AssetID != "acme-prod" {
		t.Fatalf("unexpected gcp asset id: %s", finding.Asset.AssetID)
	}
	if finding.Source.Layer != "iac" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
}

func TestParseProwlerAzureFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("prowler", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-prowler-azure",
		AdapterID:  "prowler",
		TargetKind: "azure_subscription",
		Target:     "sub-001",
	}, []string{filepath.Join("testdata", "prowler-azure-results.json")})
	if err != nil {
		t.Fatalf("parse prowler azure fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Asset.AssetID != "sub-001" {
		t.Fatalf("unexpected azure asset id: %s", finding.Asset.AssetID)
	}
	if finding.Source.Layer != "iac" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
}

func TestParseZapAPIFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("zap-api", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-zap-api",
		AdapterID:  "zap-api",
		TargetKind: "api_schema",
		Target:     "https://api.acme.example/openapi.json",
	}, []string{filepath.Join("testdata", "zap-api-output.log")})
	if err != nil {
		t.Fatalf("parse zap-api fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "dast" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "web_application_exposure" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Locations[0].Endpoint != "https://api.acme.example/openapi.json" {
		t.Fatalf("unexpected endpoint: %s", finding.Locations[0].Endpoint)
	}
}

func TestParseNucleiFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("nuclei", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-nuclei",
		AdapterID:  "nuclei",
		TargetKind: "url",
		Target:     "https://app.acme.example",
	}, []string{filepath.Join("testdata", "nuclei-results.jsonl")})
	if err != nil {
		t.Fatalf("parse nuclei fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "pentest" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Category != "web_application_exposure" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if !strings.Contains(strings.Join(finding.Tags, ","), "template:cves/2025/CVE-2025-0001") {
		t.Fatalf("expected nuclei template tag, got %v", finding.Tags)
	}
}

func TestParseDetectSecretsFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("detect-secrets", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-detect-secrets",
		AdapterID:  "detect-secrets",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "detect-secrets-results.json")})
	if err != nil {
		t.Fatalf("parse detect-secrets fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "secrets" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Confidence != "high" {
		t.Fatalf("expected high confidence for verified secret, got %s", finding.Confidence)
	}
	if !strings.Contains(strings.Join(finding.Tags, ","), "secret_type:AWS Access Key") {
		t.Fatalf("expected secret type tag, got %v", finding.Tags)
	}
}

func TestParseMobSFScanFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("mobsfscan", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-mobsfscan",
		AdapterID:  "mobsfscan",
		TargetKind: "mobile_repo",
		Target:     "c:/mobile",
	}, []string{filepath.Join("testdata", "mobsfscan-results.json")})
	if err != nil {
		t.Fatalf("parse mobsfscan fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source.Layer != "sast" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Asset.AssetType != "mobile_repo" {
		t.Fatalf("unexpected asset type: %s", finding.Asset.AssetType)
	}
	if finding.Locations[0].Line != 18 {
		t.Fatalf("unexpected finding line: %d", finding.Locations[0].Line)
	}
}

func TestParseSemgrepFixtureV2(t *testing.T) {
	t.Parallel()

	findings, err := Parse("semgrep", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-semgrep-v2",
		AdapterID:  "semgrep",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "semgrep-results-v2.json")})
	if err != nil {
		t.Fatalf("parse semgrep v2 fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Locations[0].Line != 64 {
		t.Fatalf("unexpected semgrep v2 finding line: %d", findings[0].Locations[0].Line)
	}
}

func TestParseTrivyFixtureV2(t *testing.T) {
	t.Parallel()

	findings, err := Parse("trivy", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-trivy-v2",
		AdapterID:  "trivy",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "trivy-results-v2.json")})
	if err != nil {
		t.Fatalf("parse trivy v2 fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("unexpected trivy v2 severity: %s", findings[0].Severity)
	}
}

func TestParseGitleaksFixtureV2(t *testing.T) {
	t.Parallel()

	findings, err := Parse("gitleaks", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-gitleaks-v2",
		AdapterID:  "gitleaks",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "gitleaks-results-v2.json")})
	if err != nil {
		t.Fatalf("parse gitleaks v2 fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Locations[0].Line != 27 {
		t.Fatalf("unexpected gitleaks v2 line: %d", findings[0].Locations[0].Line)
	}
}

func TestParseCheckovFixtureV2(t *testing.T) {
	t.Parallel()

	findings, err := Parse("checkov", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-checkov-v2",
		AdapterID:  "checkov",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "checkov-results-v2.json")})
	if err != nil {
		t.Fatalf("parse checkov v2 fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "high" {
		t.Fatalf("unexpected checkov v2 severity: %s", findings[0].Severity)
	}
}

func TestParseSyftLicenseFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("syft", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-syft-license",
		AdapterID:  "syft",
		TargetKind: "repo",
		Target:     "c:/repo",
	}, []string{filepath.Join("testdata", "syft-results-v2.json")})
	if err != nil {
		t.Fatalf("parse syft v2 fixture: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Category != "dependency_license_risk" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
	if finding.Source.Layer != "sca" {
		t.Fatalf("unexpected source layer: %s", finding.Source.Layer)
	}
	if finding.Severity != "high" {
		t.Fatalf("unexpected syft v2 severity: %s", finding.Severity)
	}
}

func TestParseBrowserProbeFixture(t *testing.T) {
	t.Parallel()

	findings, err := Parse("browser-probe", Context{
		TenantID:   "tenant-test",
		ScanJobID:  "scan-test",
		TaskID:     "task-browser-probe",
		AdapterID:  "browser-probe",
		TargetKind: "url",
		Target:     "https://app.example.com",
	}, []string{filepath.Join("testdata", "browser-probe-results.json")})
	if err != nil {
		t.Fatalf("parse browser-probe fixture: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].Source.Layer != "dast" {
		t.Fatalf("expected dast source layer, got %s", findings[0].Source.Layer)
	}
	if findings[0].Severity != "high" {
		t.Fatalf("expected first finding severity high, got %s", findings[0].Severity)
	}
	if findings[0].Locations[0].Endpoint != "https://app.example.com/search?q=test" {
		t.Fatalf("unexpected first finding endpoint: %s", findings[0].Locations[0].Endpoint)
	}
	if findings[1].Category != "session_management" {
		t.Fatalf("unexpected second finding category: %s", findings[1].Category)
	}
}
