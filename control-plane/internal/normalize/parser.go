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
	case "zap", "zap-api":
		return parseZap(ctx, evidencePaths)
	case "nmap":
		return parseNmap(ctx, evidencePaths)
	case "nuclei":
		return parseNuclei(ctx, evidencePaths)
	case "metasploit":
		return parseMetasploit(ctx, evidencePaths)
	case "semgrep":
		return parseSemgrep(ctx, evidencePaths)
	case "mobsfscan":
		return parseMobSFScan(ctx, evidencePaths)
	case "gosec":
		return parseGosec(ctx, evidencePaths)
	case "spotbugs":
		return parseSpotBugs(ctx, evidencePaths)
	case "pmd":
		return parsePmd(ctx, evidencePaths)
	case "bundler-audit":
		return parseBundlerAudit(ctx, evidencePaths)
	case "brakeman":
		return parseBrakeman(ctx, evidencePaths)
	case "devskim":
		return parseDevSkim(ctx, evidencePaths)
	case "bandit":
		return parseBandit(ctx, evidencePaths)
	case "eslint":
		return parseESLint(ctx, evidencePaths)
	case "phpstan":
		return parsePHPStan(ctx, evidencePaths)
	case "detect-secrets":
		return parseDetectSecrets(ctx, evidencePaths)
	case "shellcheck":
		return parseShellCheck(ctx, evidencePaths)
	case "dotnet-audit":
		return parseDotnetAudit(ctx, evidencePaths)
	case "npm-audit":
		return parseNPMAudit(ctx, evidencePaths)
	case "composer-audit":
		return parseComposerAudit(ctx, evidencePaths)
	case "osv-scanner":
		return parseOSVScanner(ctx, evidencePaths)
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
	case "cfn-lint":
		return parseCFNLint(ctx, evidencePaths)
	case "hadolint":
		return parseHadolint(ctx, evidencePaths)
	case "kics":
		return parseKICS(ctx, evidencePaths)
	case "prowler":
		return parseProwler(ctx, evidencePaths)
	case "kubesec":
		return parseKubeSec(ctx, evidencePaths)
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

func parseNuclei(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type nucleiInfo struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	}
	type nucleiFinding struct {
		TemplateID       string     `json:"template-id"`
		Type             string     `json:"type"`
		Host             string     `json:"host"`
		MatchedAt        string     `json:"matched-at"`
		ExtractedResults []string   `json:"extracted-results"`
		Info             nucleiInfo `json:"info"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open nuclei evidence %s: %w", path, err)
		}

		scanner := bufio.NewScanner(file)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			var payload nucleiFinding
			if err := json.Unmarshal([]byte(line), &payload); err != nil {
				continue
			}

			title := firstNonEmptyString(payload.Info.Name, payload.TemplateID, "Nuclei detection")
			endpoint := firstNonEmptyString(payload.MatchedAt, payload.Host, ctx.Target)
			finding := baseFinding(ctx, now, "web_application_exposure", title, normalizeSeverity(payload.Info.Severity, "medium"), "medium", models.CanonicalLocation{
				Kind:     "endpoint",
				Path:     filepath.Base(path),
				Line:     lineNumber,
				Endpoint: endpoint,
			}, models.CanonicalEvidence{
				Kind:    "jsonl",
				Ref:     path,
				Summary: "Nuclei template match",
			})
			finding.Description = strings.TrimSpace(payload.Info.Description)
			if strings.TrimSpace(payload.TemplateID) != "" {
				finding.Tags = append(finding.Tags, "template:"+strings.TrimSpace(payload.TemplateID))
			}
			if strings.TrimSpace(payload.Type) != "" {
				finding.Tags = append(finding.Tags, "protocol:"+strings.ToLower(strings.TrimSpace(payload.Type)))
			}
			if len(payload.ExtractedResults) > 0 && strings.TrimSpace(payload.ExtractedResults[0]) != "" {
				finding.Evidence[0].Summary = "Nuclei template match: " + strings.TrimSpace(payload.ExtractedResults[0])
			}

			findings = append(findings, finding)
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("scan nuclei evidence %s: %w", path, err)
		}
		_ = file.Close()
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

func parseMobSFScan(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type mobsfFinding struct {
		RuleID      string `json:"rule_id"`
		Rule        string `json:"rule"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Path        string `json:"path"`
		File        string `json:"file"`
		Line        int    `json:"line"`
	}
	type mobsfOutput struct {
		Results []mobsfFinding `json:"results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open mobsfscan evidence %s: %w", path, err)
		}

		var payload mobsfOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode mobsfscan evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload.Results {
			title := firstNonEmptyString(item.Description, item.Rule, item.RuleID, "Mobile security issue")
			locationPath := firstNonEmptyString(item.Path, item.File)
			finding := baseFinding(ctx, now, "sast_rule_match", title, normalizeSeverity(item.Severity, "medium"), "high", models.CanonicalLocation{
				Kind: "file",
				Path: locationPath,
				Line: item.Line,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "MobSFScan static analysis finding",
			})
			if ruleID := firstNonEmptyString(item.RuleID, item.Rule); ruleID != "" {
				finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(ruleID))
			}

			findings = append(findings, finding)
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

func parseBundlerAudit(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type bundlerAdvisory struct {
		ID          string `json:"id"`
		Gem         string `json:"gem"`
		Title       string `json:"title"`
		CVE         string `json:"cve"`
		URL         string `json:"url"`
		Criticality string `json:"criticality"`
	}
	type bundlerAuditOutput struct {
		Advisories []bundlerAdvisory `json:"advisories"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open bundler-audit evidence %s: %w", path, err)
		}

		var payload bundlerAuditOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode bundler-audit evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, advisory := range payload.Advisories {
			title := firstNonEmptyString(advisory.Title, advisory.ID)
			if title == "" {
				title = "Dependency vulnerability"
			}

			finding := baseFinding(ctx, now, "dependency_vulnerability", title, normalizeSeverity(advisory.Criticality, "medium"), "high", models.CanonicalLocation{
				Kind: "dependency",
				Path: "Gemfile.lock",
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "Bundler dependency vulnerability",
			})
			finding.Description = title
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Upgrade the vulnerable Ruby gem to a fixed version and refresh Gemfile.lock.",
				FixAvailable: true,
				References:   nonEmptyStrings(advisory.URL),
			}
			if strings.TrimSpace(advisory.Gem) != "" {
				finding.Tags = append(finding.Tags, "package:"+strings.TrimSpace(advisory.Gem))
			}
			if strings.TrimSpace(advisory.ID) != "" {
				finding.Tags = append(finding.Tags, "advisory:"+strings.TrimSpace(advisory.ID))
			}
			if strings.TrimSpace(advisory.CVE) != "" {
				finding.Tags = append(finding.Tags, "cve:"+strings.TrimSpace(advisory.CVE))
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func parseBrakeman(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type brakemanWarning struct {
		WarningType string `json:"warning_type"`
		WarningCode int    `json:"warning_code"`
		Message     string `json:"message"`
		File        string `json:"file"`
		Line        int    `json:"line"`
		Confidence  string `json:"confidence"`
		Link        string `json:"link"`
	}
	type brakemanOutput struct {
		Warnings []brakemanWarning `json:"warnings"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open brakeman evidence %s: %w", path, err)
		}

		var payload brakemanOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode brakeman evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload.Warnings {
			title := firstNonEmptyString(item.Message, item.WarningType)
			if title == "" {
				title = "Ruby application security issue"
			}

			finding := baseFinding(ctx, now, "sast_rule_match", title, brakemanSeverity(item.Confidence), normalizeConfidence(item.Confidence), models.CanonicalLocation{
				Kind: "file",
				Path: item.File,
				Line: item.Line,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "Brakeman security warning",
			})
			finding.Description = title
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Refactor the Ruby or Rails code path to remove the insecure pattern identified by Brakeman.",
				FixAvailable: true,
				References:   nonEmptyStrings(item.Link),
			}
			if strings.TrimSpace(item.WarningType) != "" {
				finding.Tags = append(finding.Tags, "rule:"+strings.ToLower(strings.TrimSpace(item.WarningType)))
			}
			if item.WarningCode > 0 {
				finding.Tags = append(finding.Tags, fmt.Sprintf("warning_code:%d", item.WarningCode))
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func parseDevSkim(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type devSkimResult struct {
		RuleID         string   `json:"ruleId"`
		Severity       string   `json:"severity"`
		Recommendation string   `json:"recommendation"`
		Message        string   `json:"message"`
		FileName       string   `json:"fileName"`
		StartLine      int      `json:"startLine"`
		StartColumn    int      `json:"startColumn"`
		Tags           []string `json:"tags"`
	}
	type devSkimOutput struct {
		Results []devSkimResult `json:"results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open devskim evidence %s: %w", path, err)
		}

		var payload devSkimOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode devskim evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload.Results {
			title := firstNonEmptyString(item.Message, item.Recommendation, item.RuleID)
			if title == "" {
				title = "Potential .NET security issue"
			}

			finding := baseFinding(ctx, now, "sast_rule_match", title, normalizeSeverity(item.Severity, "medium"), "medium", models.CanonicalLocation{
				Kind:   "file",
				Path:   item.FileName,
				Line:   item.StartLine,
				Column: item.StartColumn,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "DevSkim security rule match",
			})
			finding.Description = title
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Update the .NET code to satisfy the DevSkim security rule and remove the insecure pattern.",
				FixAvailable: true,
			}
			if strings.TrimSpace(item.RuleID) != "" {
				finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.RuleID))
			}
			for _, tag := range item.Tags {
				trimmed := strings.TrimSpace(tag)
				if trimmed == "" {
					continue
				}
				finding.Tags = append(finding.Tags, "tag:"+strings.ToLower(trimmed))
			}

			findings = append(findings, finding)
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

func parseESLint(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type eslintMessage struct {
		RuleID   string `json:"ruleId"`
		Severity int    `json:"severity"`
		Message  string `json:"message"`
		Line     int    `json:"line"`
		Column   int    `json:"column"`
	}
	type eslintFile struct {
		FilePath     string          `json:"filePath"`
		Messages     []eslintMessage `json:"messages"`
		ErrorCount   int             `json:"errorCount"`
		WarningCount int             `json:"warningCount"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open eslint evidence %s: %w", path, err)
		}

		payload := make([]eslintFile, 0)
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode eslint evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, fileEntry := range payload {
			for _, item := range fileEntry.Messages {
				title := strings.TrimSpace(item.Message)
				if title == "" {
					title = "JavaScript or TypeScript security issue"
				}

				finding := baseFinding(ctx, now, "sast_rule_match", title, eslintSeverity(item.Severity), "medium", models.CanonicalLocation{
					Kind:   "file",
					Path:   fileEntry.FilePath,
					Line:   item.Line,
					Column: item.Column,
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "ESLint rule match",
				})
				finding.Description = title
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      "Refactor the JavaScript or TypeScript code to satisfy the lint rule and remove the unsafe pattern.",
					FixAvailable: true,
				}
				if strings.TrimSpace(item.RuleID) != "" {
					finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.RuleID))
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func parsePHPStan(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type phpStanMessage struct {
		Message    string `json:"message"`
		Line       int    `json:"line"`
		Identifier string `json:"identifier"`
	}
	type phpStanFile struct {
		Messages []phpStanMessage `json:"messages"`
	}
	type phpStanOutput struct {
		Files map[string]phpStanFile `json:"files"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open phpstan evidence %s: %w", path, err)
		}

		var payload phpStanOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode phpstan evidence %s: %w", path, err)
		}
		_ = file.Close()

		for filePath, fileEntry := range payload.Files {
			for _, item := range fileEntry.Messages {
				title := strings.TrimSpace(item.Message)
				if title == "" {
					title = "PHP code issue"
				}

				finding := baseFinding(ctx, now, "sast_rule_match", title, phpStanSeverity(item.Identifier), "medium", models.CanonicalLocation{
					Kind: "file",
					Path: filePath,
					Line: item.Line,
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "PHPStan analysis finding",
				})
				finding.Description = title
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      "Refactor the PHP code path to resolve the static analysis issue and remove the unsafe behavior.",
					FixAvailable: true,
				}
				if strings.TrimSpace(item.Identifier) != "" {
					finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.Identifier))
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func parseShellCheck(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type shellCheckComment struct {
		File    string `json:"file"`
		Line    int    `json:"line"`
		Column  int    `json:"column"`
		Level   string `json:"level"`
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	type shellCheckOutput struct {
		Comments []shellCheckComment `json:"comments"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open shellcheck evidence %s: %w", path, err)
		}

		var payload shellCheckOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode shellcheck evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload.Comments {
			title := strings.TrimSpace(item.Message)
			if title == "" {
				title = "Shell script security issue"
			}

			finding := baseFinding(ctx, now, "sast_rule_match", title, shellCheckSeverity(item.Level), "medium", models.CanonicalLocation{
				Kind:   "file",
				Path:   item.File,
				Line:   item.Line,
				Column: item.Column,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "ShellCheck rule match",
			})
			finding.Description = title
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Update the shell script to satisfy the ShellCheck rule and remove the unsafe pattern.",
				FixAvailable: true,
			}
			if item.Code > 0 {
				finding.Tags = append(finding.Tags, fmt.Sprintf("rule:SC%d", item.Code))
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func parseDotnetAudit(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type dotnetAdvisory struct {
		Severity    string `json:"severity"`
		AdvisoryURL string `json:"advisoryurl"`
	}
	type dotnetPackage struct {
		ID              string           `json:"id"`
		ResolvedVersion string           `json:"resolvedVersion"`
		Vulnerabilities []dotnetAdvisory `json:"vulnerabilities"`
	}
	type dotnetFramework struct {
		TopLevelPackages   []dotnetPackage `json:"topLevelPackages"`
		TransitivePackages []dotnetPackage `json:"transitivePackages"`
	}
	type dotnetProject struct {
		Path       string            `json:"path"`
		Frameworks []dotnetFramework `json:"frameworks"`
	}
	type dotnetAuditOutput struct {
		Projects []dotnetProject `json:"projects"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open dotnet-audit evidence %s: %w", path, err)
		}

		var payload dotnetAuditOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode dotnet-audit evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, project := range payload.Projects {
			for _, framework := range project.Frameworks {
				packageSets := [][]dotnetPackage{framework.TopLevelPackages, framework.TransitivePackages}
				for _, packages := range packageSets {
					for _, pkg := range packages {
						for _, advisory := range pkg.Vulnerabilities {
							title := "Dependency vulnerability"
							if strings.TrimSpace(pkg.ID) != "" {
								title = fmt.Sprintf("Dependency vulnerability in %s", strings.TrimSpace(pkg.ID))
							}

							finding := baseFinding(ctx, now, "dependency_vulnerability", title, normalizeSeverity(advisory.Severity, "medium"), "high", models.CanonicalLocation{
								Kind: "dependency",
								Path: firstNonEmptyString(project.Path, "packages.lock.json"),
							}, models.CanonicalEvidence{
								Kind:    "json",
								Ref:     path,
								Summary: ".NET package vulnerability",
							})
							finding.Description = title
							finding.Remediation = &models.CanonicalRemediation{
								Summary:      "Upgrade the affected NuGet dependency to a fixed version and restore packages again.",
								FixAvailable: true,
								References:   nonEmptyStrings(advisory.AdvisoryURL),
							}
							if strings.TrimSpace(pkg.ID) != "" {
								finding.Tags = append(finding.Tags, "package:"+strings.TrimSpace(pkg.ID))
							}
							if strings.TrimSpace(pkg.ResolvedVersion) != "" {
								finding.Tags = append(finding.Tags, "version:"+strings.TrimSpace(pkg.ResolvedVersion))
							}

							findings = append(findings, finding)
						}
					}
				}
			}
		}
	}

	return findings, nil
}

func parseNPMAudit(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type npmVia struct {
		Source   int    `json:"source"`
		Name     string `json:"name"`
		Title    string `json:"title"`
		URL      string `json:"url"`
		Severity string `json:"severity"`
	}
	type npmVulnerability struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Via      []npmVia `json:"via"`
	}
	type npmAuditOutput struct {
		Vulnerabilities map[string]npmVulnerability `json:"vulnerabilities"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open npm-audit evidence %s: %w", path, err)
		}

		var payload npmAuditOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode npm-audit evidence %s: %w", path, err)
		}
		_ = file.Close()

		for packageName, vuln := range payload.Vulnerabilities {
			title := fmt.Sprintf("Dependency vulnerability in %s", packageName)
			if strings.TrimSpace(vuln.Name) != "" {
				title = fmt.Sprintf("Dependency vulnerability in %s", strings.TrimSpace(vuln.Name))
			}
			description := ""
			references := make([]string, 0)
			if len(vuln.Via) > 0 {
				first := vuln.Via[0]
				if strings.TrimSpace(first.Title) != "" {
					title = strings.TrimSpace(first.Title)
				}
				description = firstNonEmptyString(first.Title, description)
				if strings.TrimSpace(first.URL) != "" {
					references = append(references, strings.TrimSpace(first.URL))
				}
			}

			finding := baseFinding(ctx, now, "dependency_vulnerability", title, normalizeSeverity(vuln.Severity, "medium"), "high", models.CanonicalLocation{
				Kind: "dependency",
				Path: "package-lock.json",
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "npm audit dependency vulnerability",
			})
			finding.Description = description
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Upgrade the vulnerable npm dependency to a fixed version and refresh the lockfile.",
				FixAvailable: true,
				References:   references,
			}
			name := strings.TrimSpace(vuln.Name)
			if name == "" {
				name = strings.TrimSpace(packageName)
			}
			if name != "" {
				finding.Tags = append(finding.Tags, "package:"+name)
			}
			for _, via := range vuln.Via {
				if strings.TrimSpace(via.Name) != "" {
					finding.Tags = append(finding.Tags, "advisory:"+strings.TrimSpace(via.Name))
				}
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func parseComposerAudit(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type composerAdvisory struct {
		AdvisoryID  string `json:"advisoryId"`
		PackageName string `json:"packageName"`
		Title       string `json:"title"`
		CVE         string `json:"cve"`
		Link        string `json:"link"`
		Severity    string `json:"severity"`
	}
	type composerAuditOutput struct {
		Advisories map[string][]composerAdvisory `json:"advisories"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open composer-audit evidence %s: %w", path, err)
		}

		var payload composerAuditOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode composer-audit evidence %s: %w", path, err)
		}
		_ = file.Close()

		for packageName, advisories := range payload.Advisories {
			for _, advisory := range advisories {
				resolvedPackage := firstNonEmptyString(advisory.PackageName, packageName)
				title := firstNonEmptyString(advisory.Title, advisory.AdvisoryID)
				if title == "" {
					title = "Dependency vulnerability"
				}

				finding := baseFinding(ctx, now, "dependency_vulnerability", title, normalizeSeverity(advisory.Severity, "medium"), "high", models.CanonicalLocation{
					Kind: "dependency",
					Path: "composer.lock",
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "Composer dependency vulnerability",
				})
				finding.Description = title
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      "Upgrade the vulnerable Composer dependency to a fixed version and refresh the lockfile.",
					FixAvailable: true,
					References:   nonEmptyStrings(advisory.Link),
				}
				if resolvedPackage != "" {
					finding.Tags = append(finding.Tags, "package:"+resolvedPackage)
				}
				if strings.TrimSpace(advisory.AdvisoryID) != "" {
					finding.Tags = append(finding.Tags, "advisory:"+strings.TrimSpace(advisory.AdvisoryID))
				}
				if strings.TrimSpace(advisory.CVE) != "" {
					finding.Tags = append(finding.Tags, "cve:"+strings.TrimSpace(advisory.CVE))
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func parseOSVScanner(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type osvPackageDetails struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	}
	type osvVulnerability struct {
		ID       string   `json:"id"`
		Severity string   `json:"severity"`
		Summary  string   `json:"summary"`
		Details  string   `json:"details"`
		Aliases  []string `json:"aliases"`
	}
	type osvPackageResult struct {
		Package         osvPackageDetails  `json:"package"`
		Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
	}
	type osvSource struct {
		Path string `json:"path"`
	}
	type osvResult struct {
		Source   osvSource          `json:"source"`
		Packages []osvPackageResult `json:"packages"`
	}
	type osvOutput struct {
		Results []osvResult `json:"results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open osv-scanner evidence %s: %w", path, err)
		}

		var payload osvOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode osv-scanner evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, result := range payload.Results {
			for _, pkg := range result.Packages {
				for _, vuln := range pkg.Vulnerabilities {
					title := strings.TrimSpace(vuln.Summary)
					if title == "" {
						title = strings.TrimSpace(vuln.ID)
					}
					if title == "" {
						title = "Dependency vulnerability"
					}

					locationPath := strings.TrimSpace(result.Source.Path)
					if locationPath == "" {
						locationPath = ctx.Target
					}

					finding := baseFinding(ctx, now, "dependency_vulnerability", title, osvSeverity(vuln.Severity), "high", models.CanonicalLocation{
						Kind: "dependency",
						Path: locationPath,
					}, models.CanonicalEvidence{
						Kind:    "json",
						Ref:     path,
						Summary: "OSV-Scanner dependency vulnerability",
					})
					finding.Description = firstNonEmptyString(vuln.Details, vuln.Summary)
					finding.Remediation = &models.CanonicalRemediation{
						Summary:      "Upgrade the affected dependency to a non-vulnerable version referenced by the advisory.",
						FixAvailable: true,
					}
					if strings.TrimSpace(pkg.Package.Name) != "" {
						finding.Tags = append(finding.Tags, "package:"+strings.TrimSpace(pkg.Package.Name))
					}
					if strings.TrimSpace(pkg.Package.Ecosystem) != "" {
						finding.Tags = append(finding.Tags, "ecosystem:"+strings.ToLower(strings.TrimSpace(pkg.Package.Ecosystem)))
					}
					if strings.TrimSpace(vuln.ID) != "" {
						finding.Tags = append(finding.Tags, "advisory:"+strings.TrimSpace(vuln.ID))
					}
					for _, alias := range vuln.Aliases {
						trimmed := strings.TrimSpace(alias)
						if trimmed == "" {
							continue
						}
						finding.Tags = append(finding.Tags, "alias:"+trimmed)
					}

					findings = append(findings, finding)
				}
			}
		}
	}

	return findings, nil
}

func parseSyft(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type syftLicense struct {
		Value string `json:"value"`
	}
	type syftArtifact struct {
		ID       string        `json:"id"`
		Name     string        `json:"name"`
		Version  string        `json:"version"`
		Type     string        `json:"type"`
		Licenses []syftLicense `json:"licenses"`
	}
	type syftOutput struct {
		Artifacts []syftArtifact `json:"artifacts"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open syft evidence %s: %w", path, err)
		}

		var payload syftOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode syft evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, artifact := range payload.Artifacts {
			for _, license := range artifact.Licenses {
				licenseValue := strings.TrimSpace(license.Value)
				severity := licenseRiskSeverity(licenseValue)
				if severity == "" {
					continue
				}

				title := fmt.Sprintf("Potential %s license risk in %s", licenseValue, firstNonEmptyString(artifact.Name, artifact.ID, "dependency"))
				finding := baseFinding(ctx, now, "dependency_license_risk", title, severity, "medium", models.CanonicalLocation{
					Kind: "dependency",
					Path: firstNonEmptyString(artifact.Name, artifact.ID),
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "Syft SBOM license signal",
				})
				finding.Description = "The dependency uses a reciprocal or otherwise restricted license that may require legal review before release."
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      "Review the license obligations and replace or explicitly approve the dependency if required.",
					FixAvailable: false,
				}
				if strings.TrimSpace(artifact.Name) != "" {
					finding.Tags = append(finding.Tags, "package:"+strings.TrimSpace(artifact.Name))
				}
				if strings.TrimSpace(artifact.Version) != "" {
					finding.Tags = append(finding.Tags, "version:"+strings.TrimSpace(artifact.Version))
				}
				finding.Tags = append(finding.Tags, "license:"+licenseValue)
				if strings.TrimSpace(artifact.Type) != "" {
					finding.Tags = append(finding.Tags, "artifact_type:"+strings.ToLower(strings.TrimSpace(artifact.Type)))
				}

				findings = append(findings, finding)
			}
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

func parseDetectSecrets(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type detectSecretsFinding struct {
		Type         string `json:"type"`
		LineNumber   int    `json:"line_number"`
		HashedSecret string `json:"hashed_secret"`
		IsVerified   bool   `json:"is_verified"`
	}
	type detectSecretsOutput struct {
		Results map[string][]detectSecretsFinding `json:"results"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open detect-secrets evidence %s: %w", path, err)
		}

		var payload detectSecretsOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode detect-secrets evidence %s: %w", path, err)
		}
		_ = file.Close()

		for filePath, matches := range payload.Results {
			for _, item := range matches {
				secretType := firstNonEmptyString(item.Type, "Potential secret")
				confidence := "medium"
				if item.IsVerified {
					confidence = "high"
				}

				finding := baseFinding(ctx, now, "secret_exposure", "Potential secret exposure ("+secretType+")", "high", confidence, models.CanonicalLocation{
					Kind: "file",
					Path: filePath,
					Line: item.LineNumber,
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "Detect-secrets detector match",
				})
				finding.Description = "A structured secret detector matched likely credential material. Remove the secret from source control and rotate the credential."
				finding.Tags = append(finding.Tags, "secret_type:"+secretType)
				if item.IsVerified {
					finding.Tags = append(finding.Tags, "verified:true")
				}
				if hashed := strings.TrimSpace(item.HashedSecret); hashed != "" {
					if len(hashed) > 12 {
						hashed = hashed[:12]
					}
					finding.Tags = append(finding.Tags, "secret_hash:"+hashed)
				}
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      "Rotate the exposed secret and replace it with a managed secret reference.",
					FixAvailable: true,
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

func parseCFNLint(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type cfnLocationStart struct {
		Line   int `json:"line"`
		Column int `json:"column"`
	}
	type cfnLocation struct {
		Path  string           `json:"path"`
		Start cfnLocationStart `json:"start"`
	}
	type cfnLintIssue struct {
		Rule     string      `json:"Rule"`
		Message  string      `json:"Message"`
		Level    string      `json:"Level"`
		Location cfnLocation `json:"Location"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open cfn-lint evidence %s: %w", path, err)
		}

		payload := make([]cfnLintIssue, 0)
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode cfn-lint evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload {
			title := firstNonEmptyString(item.Message, item.Rule)
			if title == "" {
				title = "CloudFormation policy violation"
			}

			finding := baseFinding(ctx, now, "iac_misconfiguration", title, cfnLintSeverity(item.Level), "medium", models.CanonicalLocation{
				Kind:   "file",
				Path:   firstNonEmptyString(item.Location.Path, ctx.Target),
				Line:   item.Location.Start.Line,
				Column: item.Location.Start.Column,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "cfn-lint policy violation",
			})
			finding.Description = title
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Update the CloudFormation template to satisfy the cfn-lint rule.",
				FixAvailable: true,
			}
			if strings.TrimSpace(item.Rule) != "" {
				finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.Rule))
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

func parseKICS(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type kicsResult struct {
		FileName     string `json:"file_name"`
		Line         int    `json:"line"`
		ResourceName string `json:"resource_name"`
		IssueType    string `json:"issue_type"`
	}
	type kicsQuery struct {
		QueryName string       `json:"query_name"`
		QueryID   string       `json:"query_id"`
		Severity  string       `json:"severity"`
		Platform  string       `json:"platform"`
		Results   []kicsResult `json:"results"`
	}
	type kicsOutput struct {
		Queries []kicsQuery `json:"queries"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open kics evidence %s: %w", path, err)
		}

		var payload kicsOutput
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode kics evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, query := range payload.Queries {
			if len(query.Results) == 0 {
				title := firstNonEmptyString(query.QueryName, query.QueryID)
				if title == "" {
					title = "Infrastructure policy violation"
				}

				finding := baseFinding(ctx, now, "iac_misconfiguration", title, normalizeSeverity(query.Severity, "medium"), "high", models.CanonicalLocation{
					Kind: "file",
					Path: ctx.Target,
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "KICS failed policy",
				})
				if strings.TrimSpace(query.QueryID) != "" {
					finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(query.QueryID))
				}
				findings = append(findings, finding)
				continue
			}

			for _, item := range query.Results {
				title := firstNonEmptyString(query.QueryName, query.QueryID)
				if title == "" {
					title = "Infrastructure policy violation"
				}

				finding := baseFinding(ctx, now, "iac_misconfiguration", title, normalizeSeverity(query.Severity, "medium"), "high", models.CanonicalLocation{
					Kind: "file",
					Path: firstNonEmptyString(item.FileName, ctx.Target),
					Line: item.Line,
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "KICS failed policy",
				})
				finding.Description = "The infrastructure definition violates a KICS policy and should be updated to remove the insecure configuration."
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      "Update the infrastructure definition to satisfy the KICS rule.",
					FixAvailable: true,
				}
				if strings.TrimSpace(query.QueryID) != "" {
					finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(query.QueryID))
				}
				if strings.TrimSpace(item.ResourceName) != "" {
					finding.Tags = append(finding.Tags, "resource:"+strings.TrimSpace(item.ResourceName))
				}
				if strings.TrimSpace(item.IssueType) != "" {
					finding.Tags = append(finding.Tags, "issue_type:"+strings.ToLower(strings.TrimSpace(item.IssueType)))
				}
				if strings.TrimSpace(query.Platform) != "" {
					finding.Tags = append(finding.Tags, "platform:"+strings.ToLower(strings.TrimSpace(query.Platform)))
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func parseProwler(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type prowlerFinding struct {
		Provider       string `json:"Provider"`
		AccountID      string `json:"AccountId"`
		ProjectID      string `json:"ProjectId"`
		SubscriptionID string `json:"SubscriptionId"`
		Region         string `json:"Region"`
		CheckID        string `json:"CheckID"`
		CheckTitle     string `json:"CheckTitle"`
		Severity       string `json:"Severity"`
		Status         string `json:"Status"`
		StatusExtended string `json:"StatusExtended"`
		ResourceID     string `json:"ResourceId"`
		ResourceARN    string `json:"ResourceArn"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open prowler evidence %s: %w", path, err)
		}

		payload := make([]prowlerFinding, 0)
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode prowler evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload {
			if status := strings.ToUpper(strings.TrimSpace(item.Status)); status != "" && status != "FAIL" {
				continue
			}

			title := firstNonEmptyString(item.CheckTitle, item.CheckID)
			if title == "" {
				title = "Cloud posture finding"
			}

			locationPath := firstNonEmptyString(item.ResourceARN, item.ResourceID, item.Region, ctx.Target)
			finding := baseFinding(ctx, now, "iac_misconfiguration", title, normalizeSeverity(item.Severity, "medium"), "high", models.CanonicalLocation{
				Kind: "resource",
				Path: locationPath,
			}, models.CanonicalEvidence{
				Kind:    "json",
				Ref:     path,
				Summary: "Prowler cloud posture finding",
			})
			finding.Description = firstNonEmptyString(item.StatusExtended, title)
			finding.Remediation = &models.CanonicalRemediation{
				Summary:      "Update the cloud account configuration to satisfy the failed control and remove the exposure.",
				FixAvailable: true,
			}
			if strings.TrimSpace(item.Provider) != "" {
				finding.Tags = append(finding.Tags, "provider:"+strings.ToLower(strings.TrimSpace(item.Provider)))
			}
			if strings.TrimSpace(item.CheckID) != "" {
				finding.Tags = append(finding.Tags, "rule:"+strings.TrimSpace(item.CheckID))
			}
			if strings.TrimSpace(item.Region) != "" {
				finding.Tags = append(finding.Tags, "region:"+strings.TrimSpace(item.Region))
			}
			if strings.TrimSpace(item.ResourceID) != "" {
				finding.Tags = append(finding.Tags, "resource:"+strings.TrimSpace(item.ResourceID))
			}
			assetID := firstNonEmptyString(item.AccountID, item.ProjectID, item.SubscriptionID)
			if assetID != "" {
				finding.Asset.AssetID = assetID
				finding.Asset.AssetName = assetID
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func parseKubeSec(ctx Context, evidencePaths []string) ([]models.CanonicalFinding, error) {
	type kubeSecAdvice struct {
		Selector string `json:"selector"`
		Reason   string `json:"reason"`
	}
	type kubeSecScoring struct {
		Advise []kubeSecAdvice `json:"advise"`
	}
	type kubeSecObject struct {
		Name string `json:"name"`
	}
	type kubeSecResult struct {
		Object  kubeSecObject  `json:"object"`
		File    string         `json:"file"`
		Scoring kubeSecScoring `json:"scoring"`
	}

	findings := make([]models.CanonicalFinding, 0)
	now := time.Now().UTC()

	for _, path := range evidencePaths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open kubesec evidence %s: %w", path, err)
		}

		payload := make([]kubeSecResult, 0)
		if err := json.NewDecoder(file).Decode(&payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("decode kubesec evidence %s: %w", path, err)
		}
		_ = file.Close()

		for _, item := range payload {
			if len(item.Scoring.Advise) == 0 {
				continue
			}
			for _, advice := range item.Scoring.Advise {
				title := firstNonEmptyString(advice.Reason, advice.Selector)
				if title == "" {
					title = "Kubernetes workload misconfiguration"
				}

				finding := baseFinding(ctx, now, "iac_misconfiguration", title, "medium", "medium", models.CanonicalLocation{
					Kind: "file",
					Path: firstNonEmptyString(item.File, ctx.Target),
				}, models.CanonicalEvidence{
					Kind:    "json",
					Ref:     path,
					Summary: "KubeSec policy advisory",
				})
				finding.Description = title
				finding.Remediation = &models.CanonicalRemediation{
					Summary:      "Update the Kubernetes manifest to satisfy the KubeSec control.",
					FixAvailable: true,
				}
				if strings.TrimSpace(advice.Selector) != "" {
					finding.Tags = append(finding.Tags, "selector:"+strings.TrimSpace(advice.Selector))
				}
				if strings.TrimSpace(item.Object.Name) != "" {
					finding.Tags = append(finding.Tags, "resource:"+strings.TrimSpace(item.Object.Name))
				}

				findings = append(findings, finding)
			}
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

func eslintSeverity(value int) string {
	if value >= 2 {
		return "high"
	}
	if value == 1 {
		return "medium"
	}
	return "low"
}

func cfnLintSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	default:
		return "low"
	}
}

func brakemanSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return "high"
	case "weak":
		return "low"
	default:
		return "medium"
	}
}

func phpStanSeverity(identifier string) string {
	normalized := strings.ToLower(strings.TrimSpace(identifier))
	switch {
	case strings.Contains(normalized, "security"), strings.Contains(normalized, "unsafe"), strings.Contains(normalized, "taint"):
		return "high"
	case normalized != "":
		return "medium"
	default:
		return "low"
	}
}

func shellCheckSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	default:
		return "low"
	}
}

func osvSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func licenseRiskSeverity(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch {
	case normalized == "":
		return ""
	case strings.Contains(normalized, "agpl"), strings.Contains(normalized, "sspl"):
		return "high"
	case strings.Contains(normalized, "gpl"):
		return "medium"
	case strings.Contains(normalized, "lgpl"), strings.Contains(normalized, "mpl"):
		return "low"
	default:
		return ""
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
