package remediation

import (
	"strings"

	"unifiedsecurityscanner/control-plane/internal/models"
)

type OwnerResolution struct {
	Owner  string
	Source string
}

func ResolveOwner(requestedOwner string, finding *models.CanonicalFinding) OwnerResolution {
	if trimmed := strings.TrimSpace(requestedOwner); trimmed != "" {
		return OwnerResolution{
			Owner:  trimmed,
			Source: "request",
		}
	}

	if finding != nil {
		if owner := strings.TrimSpace(finding.Asset.OwnerTeam); owner != "" {
			return OwnerResolution{
				Owner:  owner,
				Source: "asset_owner_team",
			}
		}

		for _, candidate := range finding.Asset.OwnerHierarchy {
			if owner := strings.TrimSpace(candidate); owner != "" {
				return OwnerResolution{
					Owner:  owner,
					Source: "asset_owner_hierarchy",
				}
			}
		}

		switch strings.ToLower(strings.TrimSpace(finding.Risk.Priority)) {
		case "p0", "p1":
			return OwnerResolution{
				Owner:  "appsec-escalation",
				Source: "risk_priority",
			}
		case "p2":
			return OwnerResolution{
				Owner:  "platform-sec",
				Source: "risk_priority",
			}
		}

		switch strings.ToLower(strings.TrimSpace(finding.Asset.ServiceTier)) {
		case "tier-0", "tier-1":
			return OwnerResolution{
				Owner:  "platform-sec",
				Source: "service_tier",
			}
		}

		switch strings.ToLower(strings.TrimSpace(finding.Severity)) {
		case "critical", "high":
			return OwnerResolution{
				Owner:  "appsec-triage",
				Source: "severity",
			}
		}
	}

	return OwnerResolution{
		Owner:  "unassigned",
		Source: "default",
	}
}
