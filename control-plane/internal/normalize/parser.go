package normalize

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
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
	score := riskScore(severity)
	findingID := fmt.Sprintf("%s-%s-%d", ctx.TaskID, category, len(title))

	return models.CanonicalFinding{
		SchemaVersion: "1.0.0",
		FindingID:     findingID,
		TenantID:      ctx.TenantID,
		Scanner: models.CanonicalScannerInfo{
			Engine:    ctx.AdapterID,
			AdapterID: ctx.AdapterID,
			ScanJobID: ctx.ScanJobID,
		},
		Source: models.CanonicalSourceInfo{
			Layer: sourceLayer(ctx.AdapterID),
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
			Exposure:    "internet",
		},
		Locations: []models.CanonicalLocation{location},
		Evidence:  []models.CanonicalEvidence{evidence},
		Risk: models.CanonicalRisk{
			Priority:       priorityForSeverity(severity),
			OverallScore:   score,
			BusinessImpact: score / 10,
			Exploitability: score / 10,
			Reachability:   8,
			Exposure:       8,
		},
	}
}

func riskScore(severity string) float64 {
	switch severity {
	case "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 60
	case "low":
		return 30
	default:
		return 10
	}
}

func priorityForSeverity(severity string) string {
	switch severity {
	case "critical":
		return "p0"
	case "high":
		return "p1"
	case "medium":
		return "p2"
	case "low":
		return "p3"
	default:
		return "p4"
	}
}

func sourceLayer(adapterID string) string {
	switch adapterID {
	case "zap":
		return "dast"
	case "nmap", "metasploit":
		return "pentest"
	default:
		return "pentest"
	}
}
