package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"unifiedsecurityscanner/control-plane/internal/models"
)

type Permission string

const (
	PermissionMetaRead          Permission = "meta:read"
	PermissionSessionRead       Permission = "session:read"
	PermissionTokensRead        Permission = "auth_tokens:read"
	PermissionTokensWrite       Permission = "auth_tokens:write"
	PermissionAuditRead         Permission = "audit:read"
	PermissionScanJobsRead      Permission = "scan_jobs:read"
	PermissionScanJobsWrite     Permission = "scan_jobs:write"
	PermissionFindingsRead      Permission = "findings:read"
	PermissionAssetsRead        Permission = "assets:read"
	PermissionAssetsWrite       Permission = "assets:write"
	PermissionPoliciesRead      Permission = "policies:read"
	PermissionPoliciesWrite     Permission = "policies:write"
	PermissionRemediationsRead  Permission = "remediations:read"
	PermissionRemediationsWrite Permission = "remediations:write"
)

const (
	RolePlatformAdmin = "platform_admin"
	RoleAppSecAdmin   = "appsec_admin"
	RoleDeveloper     = "developer"
	RoleViewer        = "viewer"
)

const (
	WorkerSecretHeader   = "X-USS-Worker-Secret"
	WorkerSecretMetadata = "x-uss-worker-secret"
)

const ScopeWildcard = "*"

type contextKey string

const principalContextKey contextKey = "auth.principal"

var ErrInvalidScope = errors.New("invalid scope")

var rolePermissions = map[string]map[Permission]struct{}{
	RolePlatformAdmin: {
		PermissionMetaRead:          {},
		PermissionSessionRead:       {},
		PermissionTokensRead:        {},
		PermissionTokensWrite:       {},
		PermissionAuditRead:         {},
		PermissionScanJobsRead:      {},
		PermissionScanJobsWrite:     {},
		PermissionFindingsRead:      {},
		PermissionAssetsRead:        {},
		PermissionAssetsWrite:       {},
		PermissionPoliciesRead:      {},
		PermissionPoliciesWrite:     {},
		PermissionRemediationsRead:  {},
		PermissionRemediationsWrite: {},
	},
	RoleAppSecAdmin: {
		PermissionMetaRead:          {},
		PermissionSessionRead:       {},
		PermissionTokensRead:        {},
		PermissionTokensWrite:       {},
		PermissionScanJobsRead:      {},
		PermissionScanJobsWrite:     {},
		PermissionFindingsRead:      {},
		PermissionAssetsRead:        {},
		PermissionAssetsWrite:       {},
		PermissionPoliciesRead:      {},
		PermissionPoliciesWrite:     {},
		PermissionRemediationsRead:  {},
		PermissionRemediationsWrite: {},
	},
	RoleDeveloper: {
		PermissionMetaRead:          {},
		PermissionSessionRead:       {},
		PermissionScanJobsRead:      {},
		PermissionScanJobsWrite:     {},
		PermissionFindingsRead:      {},
		PermissionAssetsRead:        {},
		PermissionPoliciesRead:      {},
		PermissionRemediationsRead:  {},
		PermissionRemediationsWrite: {},
	},
	RoleViewer: {
		PermissionMetaRead:         {},
		PermissionSessionRead:      {},
		PermissionScanJobsRead:     {},
		PermissionFindingsRead:     {},
		PermissionAssetsRead:       {},
		PermissionPoliciesRead:     {},
		PermissionRemediationsRead: {},
	},
}

func Allowed(role string, permission Permission) bool {
	permissions, ok := rolePermissions[strings.ToLower(strings.TrimSpace(role))]
	if !ok {
		return false
	}

	_, ok = permissions[permission]
	return ok
}

func DefaultScopesForRole(role string) []string {
	permissions, ok := rolePermissions[strings.ToLower(strings.TrimSpace(role))]
	if !ok {
		return nil
	}

	out := make([]string, 0, len(permissions))
	for permission := range permissions {
		out = append(out, string(permission))
	}
	sort.Strings(out)
	return out
}

func ScopeAllows(scopes []string, permission Permission) bool {
	for _, scope := range scopes {
		normalized := strings.TrimSpace(scope)
		if normalized == ScopeWildcard || normalized == string(permission) {
			return true
		}
	}
	return false
}

func NormalizeRequestedScopes(role string, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return DefaultScopesForRole(role), nil
	}

	permissions, ok := rolePermissions[strings.ToLower(strings.TrimSpace(role))]
	if !ok {
		return nil, ErrInvalidScope
	}

	deduped := make(map[string]struct{}, len(requested))
	out := make([]string, 0, len(requested))
	for _, scope := range requested {
		normalized := strings.TrimSpace(scope)
		if normalized == "" {
			continue
		}

		if normalized == ScopeWildcard {
			if _, seen := deduped[ScopeWildcard]; !seen {
				deduped[ScopeWildcard] = struct{}{}
				out = append(out, ScopeWildcard)
			}
			continue
		}

		permission := Permission(normalized)
		if _, allowed := permissions[permission]; !allowed {
			return nil, ErrInvalidScope
		}
		if _, seen := deduped[normalized]; seen {
			continue
		}
		deduped[normalized] = struct{}{}
		out = append(out, normalized)
	}

	if len(out) == 0 {
		return DefaultScopesForRole(role), nil
	}

	sort.Strings(out)
	return out, nil
}

func WithPrincipal(ctx context.Context, principal models.AuthPrincipal) context.Context {
	return context.WithValue(ctx, principalContextKey, principal)
}

func PrincipalFromContext(ctx context.Context) (models.AuthPrincipal, bool) {
	principal, ok := ctx.Value(principalContextKey).(models.AuthPrincipal)
	return principal, ok
}

func TokenHash(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

func ParseBearerToken(headerValue string) string {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return ""
	}

	if !strings.HasPrefix(strings.ToLower(headerValue), "bearer ") {
		return ""
	}

	token := strings.TrimSpace(headerValue[len("Bearer "):])
	if token == "" {
		return ""
	}

	return token
}

func IsBootstrapToken(principal models.AuthPrincipal) bool {
	return strings.HasPrefix(principal.UserID, "bootstrap-user-")
}
