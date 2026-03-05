package rbac

import (
	"testing"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestAuthorizeAllowsRoleAndScope(t *testing.T) {
	principal := models.AuthPrincipal{
		Role:   auth.RoleAppSecAdmin,
		Scopes: []string{string(auth.PermissionPoliciesWrite)},
	}

	err := Authorize(principal, auth.PermissionPoliciesWrite)
	if err != nil {
		t.Fatalf("expected authorization to pass, got %v", err)
	}
}

func TestAuthorizeRejectsRole(t *testing.T) {
	principal := models.AuthPrincipal{
		Role:   auth.RoleViewer,
		Scopes: []string{string(auth.PermissionPoliciesWrite)},
	}

	err := Authorize(principal, auth.PermissionPoliciesWrite)
	if err == nil {
		t.Fatal("expected authorization error")
	}
	if Reason(err) != ReasonRole {
		t.Fatalf("expected reason %q, got %q", ReasonRole, Reason(err))
	}
}

func TestAuthorizeRejectsScope(t *testing.T) {
	principal := models.AuthPrincipal{
		Role:   auth.RoleAppSecAdmin,
		Scopes: []string{string(auth.PermissionPoliciesRead)},
	}

	err := Authorize(principal, auth.PermissionPoliciesWrite)
	if err == nil {
		t.Fatal("expected authorization error")
	}
	if Reason(err) != ReasonScope {
		t.Fatalf("expected reason %q, got %q", ReasonScope, Reason(err))
	}
}
