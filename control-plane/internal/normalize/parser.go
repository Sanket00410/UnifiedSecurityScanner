package normalize

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	case "gosec":
		return parseGosec(ctx, evidencePaths)
	case "spotbugs":
		return parseSpotBugs(ctx, evidencePaths)
	case "pmd":
		return parsePmd(ctx, evidencePaths)
	case "bandit":
		return parseBandit(ctx, evidencePaths)
	case "syft":
		return parseSyft(ctx, evidencePaths)
	case "trivy":
		return parseTrivy(ctx, evidencePaths)
	case "trivy-image":
		return parseTrivyImage(ctx, evidencePaths)
	case "trivy-config":
		return parseTrivyConfig(ctx, evidencePaths)
	case "trivy-secrets":
		return parseTrivySecrets(ctx, evidencePaths)
	case "grype":
		return parseGrype(ctx, evidencePaths)
	case "gitleaks":
		return parseGitleaks(ctx, evidencePaths)
	case "checkov":
		return parseCheckov(ctx, evidencePaths)
	case "hadolint":
		return parseHadolint(ctx, evidencePaths)
	case "kube-score":
		return parseKubeScore(ctx, evidencePaths)
	case "tfsec":
		return parseTfsec(ctx, evidencePaths)
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

func parseGosec(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type gosecCWE struct {
		ID int `json:"id"`
	}
	type gosecIssue struct {
		Severity   string   `json:"severity"`
		Confidence string   `json:"confidence"`
		CWE        gosecCWE `json:"cwe"`
		RuleID     string   `json:"rule_id"`
		Details    string   `json:"details"`
		File       string   `json:"file"`
		Line       string   `json:"line"`
		Column     string   `json:"column"`
	}
	type gosecOutput struct {
		Issues []gosecIssue `json:"Issues"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open gosec evidence %s: %w", path, err)
		}

		var payload gosecOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode gosec evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload.Issues {
			title := strings.TrimSpace(item.Details)
			if title == "" {
				title = strings.TrimSpace(item.RuleID)
			}

			line := parseStringInt(item.Line)
			column := parseStringInt(item.Column)
			confidence := normalizeConfidence(item.Confidence)

			finding := baseFinding(ctx, now, "sast_rule_match", title, normalizeSeverity(item.Severity, "medium"), confidence, models.CanonicalLocation{
				Kind:   "file",
				Path:   item.File,
				Line:   line,
				Column: column,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "Gosec security rule match",
			})
			finding.Description = title
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Refactor the insecure code path and replace it with a safer Go API or defensive control.",
				FixAvailable: true,
			}
			if strings.TrimSpace(item.RuleID) != "" {
				finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.RuleID))
			}
			if item.CWE.ID > 0 {
				finding.Tags = append(finding.Tags, fmt.Sprintf("cwe:%d", item.CWE.ID))
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func parseSpotBugs(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type spotBugsSourceLine struct {
		SourcePath string `xml:"sourcepath,attr"`
		SourceFile string `xml:"sourcefile,attr"`
		Start      int    `xml:"start,attr"`
	}
	type spotBugsClass struct {
		SourceLine spotBugsSourceLine `xml:"SourceLine"`
	}
	type spotBugsBugInstance struct {
		Type         string             `xml:"type,attr"`
		Priority     int                `xml:"priority,attr"`
		Rank         int                `xml:"rank,attr"`
		Category     string             `xml:"category,attr"`
		ShortMessage string             `xml:"ShortMessage"`
		LongMessage  string             `xml:"LongMessage"`
		SourceLine   spotBugsSourceLine `xml:"SourceLine"`
		Class        spotBugsClass      `xml:"Class"`
	}
	type spotBugsOutput struct {
		BugInstances []spotBugsBugInstance `xml:"BugInstance"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open spotbugs evidence %s: %w", path, err)
		}

		var payload spotBugsOutput
		if err := xml.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode spotbugs evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload.BugInstances {
			title := strings.TrimSpace(item.ShortMessage)
			if title == "" {
				title = strings.TrimSpace(item.LongMessage)
			}
			if title == "" {
				title = strings.TrimSpace(item.Type)
			}

			location := firstNonEmptyString(
				item.SourceLine.SourcePath,
				item.Class.SourceLine.SourcePath,
				item.SourceLine.SourceFile,
				item.Class.SourceLine.SourceFile,
			)
			line := firstPositiveInt(item.SourceLine.Start, item.Class.SourceLine.Start)

			finding := baseFinding(ctx, now, "sast_rule_match", title, spotBugsSeverity(item.Priority, item.Rank), "medium", models.CanonicalLocation{
				Kind: "file",
				Path: location,
				Line: line,
			}, models.CanonicalEvidence{
				Kind:    "xml",
				Ref:     path,
				Summary: "SpotBugs Java static analysis finding",
			})
			finding.Description = strings.TrimSpace(item.LongMessage)
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Refactor the Java code path to satisfy the static analysis rule and remove the unsafe pattern.",
				FixAvailable: true,
			}
			if strings.TrimSpace(item.Type) != "" {
				finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.Type))
			}
			if strings.TrimSpace(item.Category) != "" {
				finding.Tags = append(finding.Tags, "category:"+strings.ToLower(strings.TrimSpace(item.Category)))
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func parsePmd(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type pmdViolation struct {
		BeginLine   int    `json:"beginline"`
		BeginColumn int    `json:"begincolumn"`
		Description string `json:"description"`
		Rule        string `json:"rule"`
		Ruleset     string `json:"ruleset"`
		Priority    int    `json:"priority"`
	}
	type pmdFile struct {
		Filename   string         `json:"filename"`
		Violations []pmdViolation `json:"violations"`
	}
	type pmdOutput struct {
		Files []pmdFile `json:"files"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open pmd evidence %s: %w", path, err)
		}

		var payload pmdOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode pmd evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, fileEntry := range payload.Files {
			for _, item := range fileEntry.Violations {
				title := strings.TrimSpace(item.Description)
				if title == "" {
					title = strings.TrimSpace(item.Rule)
				}

				finding := baseFinding(ctx, now, "sast_rule_match", title, pmdSeverity(item.Priority), "medium", models.CanonicalLocation{
					Kind:   "file",
					Path:   fileEntry.Filename,
					Line:   item.BeginLine,
					Column: item.BeginColumn,
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "PMD Java static analysis finding",
				})
				finding.Description = title
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      "Refactor the Java implementation to comply with the PMD rule and remove the unsafe construct.",
					FixAvailable: true,
				}
				if strings.TrimSpace(item.Rule) != "" {
					finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.Rule))
				}
				if strings.TrimSpace(item.Ruleset) != "" {
					finding.Tags = append(finding.Tags, "ruleset:"+strings.ToLower(strings.TrimSpace(item.Ruleset)))
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func parseBandit(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type banditResult struct {
		Filename      string `json:"filename"`
		IssueText     string `json:"issue_text"`
		IssueSeverity string `json:"issue_severity"`
		IssueCWE      struct {
			ID int `json:"id"`
		} `json:"issue_cwe"`
		TestID     string `json:"test_id"`
		TestName   string `json:"test_name"`
		LineNumber int    `json:"line_number"`
		MoreInfo   string `json:"more_info"`
	}
	type banditOutput struct {
		Results []banditResult `json:"results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open bandit evidence %s: %w", path, err)
		}

		var payload banditOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode bandit evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload.Results {
			title := strings.TrimSpace(item.IssueText)
			if title == "" {
				title = strings.TrimSpace(item.TestName)
			}
			if title == "" {
				title = strings.TrimSpace(item.TestID)
			}

			finding := baseFinding(ctx, now, "sast_rule_match", title, normalizeSeverity(item.IssueSeverity, "medium"), "high", models.CanonicalLocation{
				Kind: "file",
				Path: item.Filename,
				Line: item.LineNumber,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "Bandit security rule match",
			})
			finding.Description = title
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Review the insecure code path and apply the safer library or API usage recommended by the Bandit rule.",
				FixAvailable: true,
				References:   nonEmptyStrings(item.MoreInfo),
			}
			if strings.TrimSpace(item.TestID) != "" {
				finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.TestID))
			}
			if strings.TrimSpace(item.TestName) != "" {
				finding.Tags = append(finding.Tags, "test:"+strings.ToLower(strings.TrimSpace(item.TestName)))
			}
			if item.IssueCWE.ID > 0 {
				finding.Tags = append(finding.Tags, fmt.Sprintf("cwe:%d", item.IssueCWE.ID))
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func parseSyft(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open syft evidence %s: %w", path, err)
		}

		var payload any
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode syft evidence %s: %w", path, err)
		}
		_ = file.Close()
	}

	return make([]models.CanonicalFinding, 0), nil
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

func parseGrype(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type grypeLocation struct {
		Path string `json:"path"`
	}
	type grypeArtifact struct {
		Name      string          `json:"name"`
		Version   string          `json:"version"`
		Type      string          `json:"type"`
		Locations []grypeLocation `json:"locations"`
	}
	type grypeFix struct {
		Versions []string `json:"versions"`
	}
	type grypeVulnerability struct {
		ID          string   `json:"id"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		DataSource  string   `json:"dataSource"`
		Fix         grypeFix `json:"fix"`
	}
	type grypeMatch struct {
		Artifact      grypeArtifact      `json:"artifact"`
		Vulnerability grypeVulnerability `json:"vulnerability"`
	}
	type grypeOutput struct {
		Matches []grypeMatch `json:"matches"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open grype evidence %s: %w", path, err)
		}

		var payload grypeOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode grype evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload.Matches {
			title := strings.TrimSpace(item.Vulnerability.ID)
			if title == "" {
				title = "Dependency vulnerability"
			}
			if strings.TrimSpace(item.Artifact.Name) != "" {
				title = fmt.Sprintf("%s in %s", title, strings.TrimSpace(item.Artifact.Name))
			}

			category := "dependency_vulnerability"
			locationKind := "dependency"
			if targetKind := strings.ToLower(strings.TrimSpace(ctx.TargetKind)); targetKind == "image" || targetKind == "container_image" {
				category = "container_image_vulnerability"
				locationKind = "image"
			}

			locationPath := ctx.Target
			if len(item.Artifact.Locations) > 0 && strings.TrimSpace(item.Artifact.Locations[0].Path) != "" {
				locationPath = strings.TrimSpace(item.Artifact.Locations[0].Path)
			}

			finding := baseFinding(ctx, now, category, title, normalizeSeverity(item.Vulnerability.Severity, "medium"), "high", models.CanonicalLocation{
				Kind: locationKind,
				Path: locationPath,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "Grype package vulnerability",
			})
			finding.Description = strings.TrimSpace(item.Vulnerability.Description)
			firstFixedVersion := ""
			if len(item.Vulnerability.Fix.Versions) > 0 {
				firstFixedVersion = strings.TrimSpace(item.Vulnerability.Fix.Versions[0])
			}
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      fixedVersionSummary(firstFixedVersion),
				FixAvailable: firstFixedVersion != "",
				References:   nonEmptyStrings(item.Vulnerability.DataSource),
			}
			if strings.TrimSpace(item.Artifact.Name) != "" {
				finding.Tags = append(finding.Tags, "package:"+strings.TrimSpace(item.Artifact.Name))
			}
			if strings.TrimSpace(item.Artifact.Version) != "" {
				finding.Tags = append(finding.Tags, "version:"+strings.TrimSpace(item.Artifact.Version))
			}
			if strings.TrimSpace(item.Artifact.Type) != "" {
				finding.Tags = append(finding.Tags, "artifact_type:"+strings.ToLower(strings.TrimSpace(item.Artifact.Type)))
			}

			findings = append(findings, finding)
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

func parseHadolint(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type hadolintIssue struct {
		Code    string `json:"code"`
		Column  int    `json:"column"`
		File    string `json:"file"`
		Level   string `json:"level"`
		Line    int    `json:"line"`
		Message string `json:"message"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open hadolint evidence %s: %w", path, err)
		}

		payload := make([]hadolintIssue, 0)
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode hadolint evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload {
			title := strings.TrimSpace(item.Message)
			if title == "" {
				title = strings.TrimSpace(item.Code)
			}

			finding := baseFinding(ctx, now, "container_misconfiguration", title, hadolintSeverity(item.Level), "low", models.CanonicalLocation{
				Kind:   "file",
				Path:   item.File,
				Line:   item.Line,
				Column: item.Column,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "Hadolint Dockerfile rule match",
			})
			finding.Description = title
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Update the Dockerfile to satisfy the container build security rule.",
				FixAvailable: true,
			}
			if strings.TrimSpace(item.Code) != "" {
				finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.Code))
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func parseKubeScore(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type kubeScoreComment struct {
		Path     string `json:"path"`
		Line     int    `json:"line"`
		Severity string `json:"severity"`
		Summary  string `json:"summary"`
	}
	type kubeScoreCheck struct {
		Check    string             `json:"check"`
		Grade    string             `json:"grade"`
		Target   string             `json:"target"`
		File     string             `json:"file"`
		Comments []kubeScoreComment `json:"comments"`
	}
	type kubeScoreWrapped struct {
		Checks []kubeScoreCheck `json:"checks"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		content, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read kube-score evidence %s: %w", path, err)
		}

		payload := make([]kubeScoreCheck, 0)
		if err := json.Unmarshal(content, &payload); err != nil {
			var wrapped kubeScoreWrapped
			if err := json.Unmarshal(content, &wrapped); err != nil {
				return nil, fmt.Errorf("decode kube-score evidence %s: %w", path, err)
			}
			payload = wrapped.Checks
		}

		for _, item := range payload {
			if len(item.Comments) == 0 {
				title := strings.TrimSpace(item.Check)
				if title == "" {
					title = "Kubernetes workload misconfiguration"
				}

				finding := baseFinding(ctx, now, "iac_misconfiguration", title, kubeScoreSeverity(item.Grade), "medium", models.CanonicalLocation{
					Kind: "file",
					Path: firstNonEmptyString(item.File, item.Target),
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "Kube-score policy violation",
				})
				finding.Description = title
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      "Update the Kubernetes manifest to satisfy the kube-score control.",
					FixAvailable: true,
				}
				if strings.TrimSpace(item.Check) != "" {
					finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.Check))
				}
				if strings.TrimSpace(item.Target) != "" {
					finding.Tags = append(finding.Tags, "resource:"+strings.TrimSpace(item.Target))
				}
				findings = append(findings, finding)
				continue
			}

			for _, comment := range item.Comments {
				title := strings.TrimSpace(comment.Summary)
				if title == "" {
					title = strings.TrimSpace(item.Check)
				}
				if title == "" {
					title = "Kubernetes workload misconfiguration"
				}

				finding := baseFinding(ctx, now, "iac_misconfiguration", title, kubeScoreSeverity(firstNonEmptyString(comment.Severity, item.Grade)), "medium", models.CanonicalLocation{
					Kind: "file",
					Path: firstNonEmptyString(comment.Path, item.File, item.Target),
					Line: comment.Line,
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "Kube-score policy violation",
				})
				finding.Description = title
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      "Update the Kubernetes manifest to satisfy the kube-score control.",
					FixAvailable: true,
				}
				if strings.TrimSpace(item.Check) != "" {
					finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.Check))
				}
				if strings.TrimSpace(item.Target) != "" {
					finding.Tags = append(finding.Tags, "resource:"+strings.TrimSpace(item.Target))
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func parseTfsec(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type tfsecLocation struct {
		Filename  string `json:"filename"`
		StartLine int    `json:"start_line"`
	}
	type tfsecResult struct {
		RuleID          string        `json:"rule_id"`
		LongID          string        `json:"long_id"`
		RuleDescription string        `json:"rule_description"`
		Severity        string        `json:"severity"`
		Description     string        `json:"description"`
		Impact          string        `json:"impact"`
		Resolution      string        `json:"resolution"`
		Resource        string        `json:"resource"`
		Location        tfsecLocation `json:"location"`
	}
	type tfsecOutput struct {
		Results []tfsecResult `json:"results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open tfsec evidence %s: %w", path, err)
		}

		var payload tfsecOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode tfsec evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload.Results {
			title := strings.TrimSpace(item.RuleDescription)
			if title == "" {
				title = firstNonEmptyString(item.LongID, item.RuleID)
			}

			finding := baseFinding(ctx, now, "iac_misconfiguration", title, normalizeSeverity(item.Severity, "medium"), "high", models.CanonicalLocation{
				Kind: "file",
				Path: item.Location.Filename,
				Line: item.Location.StartLine,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "tfsec failed policy",
			})
			description := strings.TrimSpace(item.Description)
			if description == "" {
				description = strings.TrimSpace(item.Impact)
			}
			finding.Description = description
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      strings.TrimSpace(item.Resolution),
				FixAvailable: strings.TrimSpace(item.Resolution) != "",
			}
			if strings.TrimSpace(item.RuleID) != "" {
				finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.RuleID))
			}
			if strings.TrimSpace(item.LongID) != "" {
				finding.Tags = append(finding.Tags, "policy:"+strings.TrimSpace(item.LongID))
			}
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

func normalizeConfidence(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return "high"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func hadolintSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "error":
		return "high"
	case "warning", "warn":
		return "medium"
	case "style", "info", "ignore":
		return "low"
	default:
		return "medium"
	}
}

func parseStringInt(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstPositiveInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func spotBugsSeverity(priority int, rank int) string {
	switch {
	case priority <= 1 || (rank > 0 && rank <= 4):
		return "high"
	case priority == 2 || (rank > 0 && rank <= 9):
		return "medium"
	default:
		return "low"
	}
}

func pmdSeverity(priority int) string {
	switch {
	case priority <= 2:
		return "high"
	case priority == 3:
		return "medium"
	default:
		return "low"
	}
}

func kubeScoreSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "error", "fail", "failed":
		return "high"
	case "warning", "warn":
		return "medium"
	default:
		return "low"
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
