package auth

import "testing"

func TestAllowed(t *testing.T) {
	t.Parallel()

	if !Allowed(RolePlatformAdmin, PermissionPoliciesWrite) {
		t.Fatal("expected platform admin to be allowed to write policies")
	}

	if Allowed(RoleViewer, PermissionPoliciesWrite) {
		t.Fatal("expected viewer to be denied policy writes")
	}
}

func TestParseBearerToken(t *testing.T) {
	t.Parallel()

	token := ParseBearerToken("Bearer test-token")
	if token != "test-token" {
		t.Fatalf("unexpected bearer token: %s", token)
	}

	if ParseBearerToken("Basic abc") != "" {
		t.Fatal("expected non-bearer authorization to be ignored")
	}

	if ParseBearerToken("   bearer  spaced-token   ") != "spaced-token" {
		t.Fatal("expected bearer token with leading whitespace to be parsed")
	}
}

func TestScopeAllows(t *testing.T) {
	t.Parallel()

	if !ScopeAllows([]string{ScopeWildcard}, PermissionPoliciesWrite) {
		t.Fatal("expected wildcard scope to allow requested permission")
	}

	if !ScopeAllows([]string{string(PermissionPoliciesRead)}, PermissionPoliciesRead) {
		t.Fatal("expected exact scope to allow requested permission")
	}

	if ScopeAllows([]string{string(PermissionPoliciesRead)}, PermissionPoliciesWrite) {
		t.Fatal("expected unrelated scope to deny requested permission")
	}
}

func TestNormalizeRequestedScopes(t *testing.T) {
	t.Parallel()

	scopes, err := NormalizeRequestedScopes(RoleDeveloper, nil)
	if err != nil {
		t.Fatalf("normalize default scopes: %v", err)
	}
	if len(scopes) == 0 {
		t.Fatal("expected default scopes for developer")
	}

	scopes, err = NormalizeRequestedScopes(RoleDeveloper, []string{
		string(PermissionScanJobsRead),
		"  " + string(PermissionScanJobsRead) + " ",
		string(PermissionFindingsRead),
	})
	if err != nil {
		t.Fatalf("normalize requested scopes: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("expected deduped scopes, got %d", len(scopes))
	}

	if _, err := NormalizeRequestedScopes(RoleViewer, []string{string(PermissionPoliciesWrite)}); err == nil {
		t.Fatal("expected invalid elevated scope to be rejected")
	}
}
