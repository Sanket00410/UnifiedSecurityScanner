package remediation

import "strings"

func NormalizeStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return ""
	case "open":
		return "open"
	case "assigned":
		return "assigned"
	case "in_progress", "in-progress":
		return "in_progress"
	case "blocked":
		return "blocked"
	case "ready_for_verify", "ready-for-verify":
		return "ready_for_verify"
	case "verified":
		return "verified"
	case "accepted_risk", "accepted-risk":
		return "accepted_risk"
	case "closed":
		return "closed"
	default:
		return ""
	}
}

func IsValidTransition(current string, next string) bool {
	current = NormalizeStatus(current)
	next = NormalizeStatus(next)
	if next == "" {
		return false
	}
	if current == next {
		return true
	}

	allowed := map[string]map[string]struct{}{
		"open": {
			"assigned":      {},
			"in_progress":   {},
			"blocked":       {},
			"accepted_risk": {},
			"closed":        {},
		},
		"assigned": {
			"in_progress":      {},
			"blocked":          {},
			"ready_for_verify": {},
			"accepted_risk":    {},
		},
		"in_progress": {
			"blocked":          {},
			"ready_for_verify": {},
			"accepted_risk":    {},
		},
		"blocked": {
			"assigned":      {},
			"in_progress":   {},
			"accepted_risk": {},
		},
		"ready_for_verify": {
			"verified":    {},
			"in_progress": {},
			"blocked":     {},
		},
		"verified": {
			"closed": {},
		},
		"accepted_risk": {
			"closed": {},
		},
	}

	nextSet, ok := allowed[current]
	if !ok {
		return false
	}
	_, ok = nextSet[next]
	return ok
}
