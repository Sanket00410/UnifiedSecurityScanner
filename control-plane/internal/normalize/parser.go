package normalize

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
	"unifiedsecurityscanner/control-plane/internal/risk"
)

var (
	nmapPortPattern       = regexp.MustCompile(`^(\d+)/(tcp|udp)\s+open\s+([^\s]+)`)
	metasploitModuleRegex = regexp.MustCompile(`(?i)^\[\*\]\s+Using auxiliary module\s+(.+)$`)
)

type Context struct {
	TenantID   string
	ScanJobID  string
	TaskID     string
	AdapterID  string
	TargetKind string
	Target     string
}

func Parse(adapterID string, ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	switch strings.ToLower(strings.TrimSpace(adapterID)) {
	case "zap":
		return parseZap(ctx, evidencePaths)
	case "nmap":
		return parseNmap(ctx, evidencePaths)
	case "metasploit":
		return parseMetasploit(ctx, evidencePaths)
	case "semgrep":
		return parseSemgrep(ctx, evidencePaths)
	case "trivy":
		return parseTrivy(ctx, evidencePaths)
	case "trivy-image":
		return parseTrivyImage(ctx, evidencePaths)
	case "trivy-config":
		return parseTrivyConfig(ctx, evidencePaths)
	case "trivy-secrets":
		return parseTrivySecrets(ctx, evidencePaths)
	case "gitleaks":
		return parseGitleaks(ctx, evidencePaths)
	case "checkov":
		return parseCheckov(ctx, evidencePaths)
	default:
		return nil, fmt.Errorf("unsupported parser for adapter %s", adapterID)
	}
}

func parseZap(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open zap evidence %s: %w", path, err)
		}

		scanner := bufio.NewScanner(file)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			severity, category, ok := zapSeverity(line)
			if !ok {
				continue
			}

			findings = append(findings, baseFinding(ctx, now, category, line, severity, "high", models.CanonicalLocation{
				Kind:     "endpoint",
				Path:     filepath.Base(path),
				Line:     lineNumber,
				Endpoint: ctx.Target,
			}, models.CanonicalEvidence{
				Kind:    "log",
				Ref:     path,
				Summary: "ZAP scan output",
			}))
		}

		_ = file.Close()

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scan zap evidence %s: %w", path, err)
		}
	}

	return findings, nil
}

func parseNmap(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open nmap evidence %s: %w", path, err)
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			match := nmapPortPattern.FindStringSubmatch(line)
			if len(match) != 4 {
				continue
			}

			port := match[1]
			protocol := match[2]
			service := match[3]
			title := fmt.Sprintf("Open %s/%s service detected on %s", port, protocol, ctx.Target)
			category := "open_network_service"
			severity := "medium"
			if port == "22" || port == "3389" || port == "445" {
				severity = "high"
			}

			findings = append(findings, baseFinding(ctx, now, category, title, severity, "medium", models.CanonicalLocation{
				Kind:     "endpoint",
				Endpoint: fmt.Sprintf("%s:%s/%s", ctx.Target, port, protocol),
				Path:     service,
			}, models.CanonicalEvidence{
				Kind:    "log",
				Ref:     path,
				Summary: "Nmap open port observation",
			}))
		}

		_ = file.Close()

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scan nmap evidence %s: %w", path, err)
		}
	}

	return findings, nil
}

func parseMetasploit(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()
	currentModule := ""

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open metasploit evidence %s: %w", path, err)
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			if moduleMatch := metasploitModuleRegex.FindStringSubmatch(line); len(moduleMatch) == 2 {
				currentModule = strings.TrimSpace(moduleMatch[1])
				continue
			}

			lower := strings.ToLower(line)
			if strings.Contains(lower, "appears to be vulnerable") || strings.Contains(lower, "exploit completed") {
				title := "Metasploit confirmed exploitable condition"
				if currentModule != "" {
					title = fmt.Sprintf("Metasploit module %s confirmed an exploitable condition", currentModule)
				}

				findings = append(findings, baseFinding(ctx, now, "exploit_confirmed", title, "critical", "high", models.CanonicalLocation{
					Kind:     "endpoint",
					Endpoint: ctx.Target,
				}, models.CanonicalEvidence{
					Kind:    "log",
					Ref:     path,
					Summary: "Metasploit validation output",
				}))
			}
		}

		_ = file.Close()

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scan metasploit evidence %s: %w", path, err)
		}
	}

	return findings, nil
}

func parseSemgrep(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type semgrepResult struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct {
				Category string `json:"category"`
			} `json:"metadata"`
		} `json:"extra"`
	}
	type semgrepOutput struct {
		Results []semgrepResult `json:"results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open semgrep evidence %s: %w", path, err)
		}

		var payload semgrepOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode semgrep evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload.Results {
			category := "sast_rule_match"
			if strings.TrimSpace(item.Extra.Metadata.Category) != "" {
				category = strings.ToLower(strings.TrimSpace(item.Extra.Metadata.Category))
			}

			title := strings.TrimSpace(item.Extra.Message)
			if title == "" {
				title = strings.TrimSpace(item.CheckID)
			}

			findings = append(findings, baseFinding(ctx, now, category, title, normalizeSeverity(item.Extra.Severity, "medium"), "high", models.CanonicalLocation{
				Kind:   "file",
				Path:   item.Path,
				Line:   item.Start.Line,
				Column: item.Start.Col,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "Semgrep rule match",
			}))
		}
	}

	return findings, nil
}

func parseTrivy(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type trivyVulnerability struct {
		VulnerabilityID  string `json:"VulnerabilityID"`
		PkgName          string `json:"PkgName"`
		InstalledVersion string `json:"InstalledVersion"`
		FixedVersion     string `json:"FixedVersion"`
		Severity         string `json:"Severity"`
		Title            string `json:"Title"`
		Description      string `json:"Description"`
		PrimaryURL       string `json:"PrimaryURL"`
	}
	type trivyResult struct {
		Target          string               `json:"Target"`
		Type            string               `json:"Type"`
		Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
	}
	type trivyOutput struct {
		Results []trivyResult `json:"Results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open trivy evidence %s: %w", path, err)
		}

		var payload trivyOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode trivy evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, result := range payload.Results {
			for _, vuln := range result.Vulnerabilities {
				title := strings.TrimSpace(vuln.Title)
				if title == "" {
					title = strings.TrimSpace(vuln.VulnerabilityID)
				}

				finding := baseFinding(ctx, now, "dependency_vulnerability", title, normalizeSeverity(vuln.Severity, "medium"), "high", models.CanonicalLocation{
					Kind: "dependency",
					Path: result.Target,
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "Trivy dependency vulnerability",
				})
				finding.Description = strings.TrimSpace(vuln.Description)
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      fixedVersionSummary(vuln.FixedVersion),
					FixAvailable: strings.TrimSpace(vuln.FixedVersion) != "",
					References:   nonEmptyStrings(vuln.PrimaryURL),
				}
				if strings.TrimSpace(vuln.PkgName) != "" {
					finding.Tags = append(finding.Tags, "package:"+vuln.PkgName)
				}
				if strings.TrimSpace(vuln.InstalledVersion) != "" {
					finding.Tags = append(finding.Tags, "version:"+vuln.InstalledVersion)
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func parseTrivyImage(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type trivyVulnerability struct {
		VulnerabilityID  string `json:"VulnerabilityID"`
		PkgName          string `json:"PkgName"`
		InstalledVersion string `json:"InstalledVersion"`
		FixedVersion     string `json:"FixedVersion"`
		Severity         string `json:"Severity"`
		Title            string `json:"Title"`
		Description      string `json:"Description"`
		PrimaryURL       string `json:"PrimaryURL"`
	}
	type trivyResult struct {
		Target          string               `json:"Target"`
		Type            string               `json:"Type"`
		Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
	}
	type trivyOutput struct {
		Results []trivyResult `json:"Results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open trivy image evidence %s: %w", path, err)
		}

		var payload trivyOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode trivy image evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, result := range payload.Results {
			for _, vuln := range result.Vulnerabilities {
				title := strings.TrimSpace(vuln.Title)
				if title == "" {
					title = strings.TrimSpace(vuln.VulnerabilityID)
				}

				finding := baseFinding(ctx, now, "container_image_vulnerability", title, normalizeSeverity(vuln.Severity, "medium"), "high", models.CanonicalLocation{
					Kind: "image",
					Path: result.Target,
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "Trivy container image vulnerability",
				})
				finding.Description = strings.TrimSpace(vuln.Description)
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      fixedVersionSummary(vuln.FixedVersion),
					FixAvailable: strings.TrimSpace(vuln.FixedVersion) != "",
					References:   nonEmptyStrings(vuln.PrimaryURL),
				}
				if strings.TrimSpace(vuln.PkgName) != "" {
					finding.Tags = append(finding.Tags, "package:"+vuln.PkgName)
				}
				if strings.TrimSpace(vuln.InstalledVersion) != "" {
					finding.Tags = append(finding.Tags, "version:"+vuln.InstalledVersion)
				}
				if strings.TrimSpace(result.Type) != "" {
					finding.Tags = append(finding.Tags, "artifact_type:"+strings.ToLower(strings.TrimSpace(result.Type)))
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func parseTrivyConfig(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type causeMetadata struct {
		Resource  string `json:"Resource"`
		StartLine int    `json:"StartLine"`
	}
	type trivyMisconfiguration struct {
		ID            string        `json:"ID"`
		Type          string        `json:"Type"`
		Title         string        `json:"Title"`
		Description   string        `json:"Description"`
		Message       string        `json:"Message"`
		Resolution    string        `json:"Resolution"`
		Severity      string        `json:"Severity"`
		PrimaryURL    string        `json:"PrimaryURL"`
		CauseMetadata causeMetadata `json:"CauseMetadata"`
	}
	type trivyResult struct {
		Target            string                  `json:"Target"`
		Type              string                  `json:"Type"`
		Misconfigurations []trivyMisconfiguration `json:"Misconfigurations"`
	}
	type trivyOutput struct {
		Results []trivyResult `json:"Results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open trivy config evidence %s: %w", path, err)
		}

		var payload trivyOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode trivy config evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, result := range payload.Results {
			for _, item := range result.Misconfigurations {
				title := strings.TrimSpace(item.Title)
				if title == "" {
					title = strings.TrimSpace(item.ID)
				}

				category := "iac_misconfiguration"
				switch strings.ToLower(strings.TrimSpace(ctx.TargetKind)) {
				case "image", "container_image":
					category = "container_misconfiguration"
				}

				finding := baseFinding(ctx, now, category, title, normalizeSeverity(item.Severity, "medium"), "high", models.CanonicalLocation{
					Kind: "file",
					Path: result.Target,
					Line: item.CauseMetadata.StartLine,
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "Trivy configuration misconfiguration",
				})
				description := strings.TrimSpace(item.Description)
				if description == "" {
					description = strings.TrimSpace(item.Message)
				}
				finding.Description = description
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      strings.TrimSpace(item.Resolution),
					FixAvailable: strings.TrimSpace(item.Resolution) != "",
					References:   nonEmptyStrings(item.PrimaryURL),
				}
				if strings.TrimSpace(item.CauseMetadata.Resource) != "" {
					finding.Tags = append(finding.Tags, "resource:"+strings.TrimSpace(item.CauseMetadata.Resource))
				}
				if strings.TrimSpace(item.Type) != "" {
					finding.Tags = append(finding.Tags, "config_type:"+strings.ToLower(strings.TrimSpace(item.Type)))
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func parseTrivySecrets(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type trivySecret struct {
		RuleID    string `json:"RuleID"`
		Category  string `json:"Category"`
		Severity  string `json:"Severity"`
		Title     string `json:"Title"`
		StartLine int    `json:"StartLine"`
		Match     string `json:"Match"`
	}
	type trivyResult struct {
		Target  string        `json:"Target"`
		Type    string        `json:"Type"`
		Secrets []trivySecret `json:"Secrets"`
	}
	type trivyOutput struct {
		Results []trivyResult `json:"Results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open trivy secrets evidence %s: %w", path, err)
		}

		var payload trivyOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode trivy secrets evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, result := range payload.Results {
			for _, item := range result.Secrets {
				title := strings.TrimSpace(item.Title)
				if title == "" {
					title = "Potential secret exposure"
				}

				finding := baseFinding(ctx, now, "secret_exposure", title, normalizeSeverity(item.Severity, "high"), "high", models.CanonicalLocation{
					Kind: "file",
					Path: result.Target,
					Line: item.StartLine,
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "Trivy secret finding",
				})
				finding.Description = "Potential secret material was detected. Rotate the credential and remove it from source control history."
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      "Rotate the exposed secret and replace it with a managed secret reference.",
					FixAvailable: true,
				}
				if strings.TrimSpace(item.RuleID) != "" {
					finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.RuleID))
				}
				if strings.TrimSpace(item.Category) != "" {
					finding.Tags = append(finding.Tags, "secret_category:"+strings.ToLower(strings.TrimSpace(item.Category)))
				}
				if strings.TrimSpace(item.Match) != "" {
					finding.Tags = append(finding.Tags, "match:redacted")
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func parseGitleaks(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type gitleaksFinding struct {
		RuleID      string `json:"RuleID"`
		Description string `json:"Description"`
		File        string `json:"File"`
		StartLine   int    `json:"StartLine"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open gitleaks evidence %s: %w", path, err)
		}

		payload := make([]gitleaksFinding, 0)
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode gitleaks evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload {
			title := strings.TrimSpace(item.Description)
			if title == "" {
				title = "Potential secret exposure"
			}

			finding := baseFinding(ctx, now, "secret_exposure", title, "high", "high", models.CanonicalLocation{
				Kind: "file",
				Path: item.File,
				Line: item.StartLine,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "Gitleaks secret match",
			})
			finding.Description = "Potential secret material was detected. Rotate the credential and remove it from source control history."
			if strings.TrimSpace(item.RuleID) != "" {
				finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.RuleID))
			}
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Rotate the exposed secret and replace it with a managed secret reference.",
				FixAvailable: true,
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func parseCheckov(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type checkovFailedCheck struct {
		CheckID       string `json:"check_id"`
		CheckName     string `json:"check_name"`
		FilePath      string `json:"file_path"`
		Resource      string `json:"resource"`
		Severity      string `json:"severity"`
		FileLineRange []int  `json:"file_line_range"`
	}
	type checkovOutput struct {
		Results struct {
			FailedChecks []checkovFailedCheck `json:"failed_checks"`
		} `json:"results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open checkov evidence %s: %w", path, err)
		}

		var payload checkovOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode checkov evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload.Results.FailedChecks {
			title := strings.TrimSpace(item.CheckName)
			if title == "" {
				title = strings.TrimSpace(item.CheckID)
			}

			line := 0
			if len(item.FileLineRange) > 0 {
				line = item.FileLineRange[0]
			}

			finding := baseFinding(ctx, now, "iac_misconfiguration", title, normalizeSeverity(item.Severity, "medium"), "high", models.CanonicalLocation{
				Kind: "file",
				Path: item.FilePath,
				Line: line,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "Checkov failed policy",
			})
			if strings.TrimSpace(item.Resource) != "" {
				finding.Tags = append(finding.Tags, "resource:"+strings.TrimSpace(item.Resource))
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func zapSeverity(line string) (severity string, category string, ok bool) {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "high"):
		return "high", "web_application_exposure", true
	case strings.Contains(lower, "medium"):
		return "medium", "web_application_exposure", true
	case strings.Contains(lower, "low"):
		return "low", "web_application_exposure", true
	case strings.Contains(lower, "alert"):
		return "medium", "web_application_exposure", true
	default:
		return "", "", false
	}
}

func baseFinding(
	ctx Context,
	now time.Time,
	category string,
	title string,
	severity string,
	confidence string,
	location models.CanonicalLocation,
	evidence models.CanonicalEvidence,
) models.CanonicalFinding {
	findingID := fmt.Sprintf("%s-%s-%d", ctx.TaskID, category, len(title))
	finding := models.CanonicalFinding{
		SchemaVersion: "1.0.0",
		FindingID:     findingID,
		TenantID:      ctx.TenantID,
		Scanner: models.CanonicalScannerInfo{
			Engine:    ctx.AdapterID,
			AdapterID: ctx.AdapterID,
			ScanJobID: ctx.ScanJobID,
		},
		Source: models.CanonicalSourceInfo{
			Layer: risk.LayerForAdapter(ctx.AdapterID),
			Tool:  ctx.AdapterID,
		},
		Category:    category,
		Title:       title,
		Description: title,
		Severity:    severity,
		Confidence:  confidence,
		Status:      "open",
		FirstSeenAt: now,
		LastSeenAt:  now,
		Asset: models.CanonicalAssetInfo{
			AssetID:     ctx.Target,
			AssetType:   ctx.TargetKind,
			AssetName:   ctx.Target,
			Environment: "unknown",
			Exposure:    "unknown",
		},
		Locations: []models.CanonicalLocation{location},
		Evidence:  []models.CanonicalEvidence{evidence},
		Risk: models.CanonicalRisk{
			Priority: "p4",
		},
	}

	return risk.Enrich(finding)
}

func normalizeSeverity(value string, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "error":
		return "critical"
	case "high":
		return "high"
	case "medium", "warning", "warn":
		return "medium"
	case "low", "info", "informational":
		return "low"
	default:
		return fallback
	}
}

func fixedVersionSummary(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}

	return fmt.Sprintf("Upgrade to fixed version %s.", strings.TrimSpace(value))
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
