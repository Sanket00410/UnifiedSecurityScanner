package tenant

import (
	"errors"
	"strings"

	"unifiedsecurityscanner/control-plane/internal/models"
)

var (
	ErrMissingOrganization = errors.New("principal organization is required")
	ErrScopeViolation      = errors.New("tenant scope violation")
)

func RequirePrincipalOrganization(principal models.AuthPrincipal) error {
	if strings.TrimSpace(principal.OrganizationID) == "" {
		return ErrMissingOrganization
	}
	return nil
}

func RequireTenantAccess(principal models.AuthPrincipal, tenantID string) error {
	if err := RequirePrincipalOrganization(principal); err != nil {
		return err
	}

	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil
	}
	if tenantID != strings.TrimSpace(principal.OrganizationID) {
		return ErrScopeViolation
	}
	return nil
}
