package rbac

import (
	"errors"
	"strings"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/models"
)

const (
	ReasonRole  = "role"
	ReasonScope = "scope"
)

type AuthorizationError struct {
	Reason     string
	Permission auth.Permission
}

func (e *AuthorizationError) Error() string {
	switch strings.ToLower(strings.TrimSpace(e.Reason)) {
	case ReasonRole:
		return "role does not permit requested action"
	case ReasonScope:
		return "token scope does not permit requested action"
	default:
		return "authorization failed"
	}
}

func Authorize(principal models.AuthPrincipal, permission auth.Permission) error {
	if !auth.Allowed(principal.Role, permission) {
		return &AuthorizationError{
			Reason:     ReasonRole,
			Permission: permission,
		}
	}

	if !auth.ScopeAllows(principal.Scopes, permission) {
		return &AuthorizationError{
			Reason:     ReasonScope,
			Permission: permission,
		}
	}

	return nil
}

func Reason(err error) string {
	var authErr *AuthorizationError
	if !errors.As(err, &authErr) {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(authErr.Reason))
}
