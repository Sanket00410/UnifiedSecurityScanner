package tenant

import (
	"errors"
	"testing"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestRequirePrincipalOrganization(t *testing.T) {
	principal := models.AuthPrincipal{
		OrganizationID: "org-1",
	}
	if err := RequirePrincipalOrganization(principal); err != nil {
		t.Fatalf("expected organization check to pass, got %v", err)
	}
}

func TestRequirePrincipalOrganizationMissing(t *testing.T) {
	principal := models.AuthPrincipal{}
	err := RequirePrincipalOrganization(principal)
	if !errors.Is(err, ErrMissingOrganization) {
		t.Fatalf("expected ErrMissingOrganization, got %v", err)
	}
}

func TestRequireTenantAccessAllowsSameTenant(t *testing.T) {
	principal := models.AuthPrincipal{
		OrganizationID: "org-1",
	}
	if err := RequireTenantAccess(principal, "org-1"); err != nil {
		t.Fatalf("expected tenant access to pass, got %v", err)
	}
}

func TestRequireTenantAccessRejectsDifferentTenant(t *testing.T) {
	principal := models.AuthPrincipal{
		OrganizationID: "org-1",
	}
	err := RequireTenantAccess(principal, "org-2")
	if !errors.Is(err, ErrScopeViolation) {
		t.Fatalf("expected ErrScopeViolation, got %v", err)
	}
}
