package auth

import (
	"testing"
	"time"
)

func TestIssueAndValidateWorkerIdentityToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 6, 12, 0, 0, 0, time.UTC)
	token, issuedClaims, err := IssueWorkerIdentityToken("test-workload-key", "worker-1", "org-1", 45*time.Minute, now)
	if err != nil {
		t.Fatalf("issue workload identity token: %v", err)
	}
	if token == "" {
		t.Fatal("expected issued workload identity token")
	}
	if issuedClaims.WorkerID != "worker-1" {
		t.Fatalf("unexpected worker id claim: %s", issuedClaims.WorkerID)
	}

	validatedClaims, err := ValidateWorkerIdentityToken("test-workload-key", token, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("validate workload identity token: %v", err)
	}
	if validatedClaims.TokenID != issuedClaims.TokenID {
		t.Fatalf("expected token id %s, got %s", issuedClaims.TokenID, validatedClaims.TokenID)
	}
	if validatedClaims.Audience != WorkerIdentityAudience {
		t.Fatalf("unexpected audience claim: %s", validatedClaims.Audience)
	}
}

func TestValidateWorkerIdentityTokenRejectsTamperedPayload(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 6, 12, 0, 0, 0, time.UTC)
	token, _, err := IssueWorkerIdentityToken("test-workload-key", "worker-1", "org-1", time.Hour, now)
	if err != nil {
		t.Fatalf("issue workload identity token: %v", err)
	}

	tampered := "x" + token[1:]
	if _, err := ValidateWorkerIdentityToken("test-workload-key", tampered, now.Add(5*time.Minute)); err == nil {
		t.Fatal("expected tampered workload identity token to fail validation")
	}
}

func TestValidateWorkerIdentityTokenRejectsExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 6, 12, 0, 0, 0, time.UTC)
	token, _, err := IssueWorkerIdentityToken("test-workload-key", "worker-1", "org-1", 30*time.Second, now)
	if err != nil {
		t.Fatalf("issue workload identity token: %v", err)
	}

	if _, err := ValidateWorkerIdentityToken("test-workload-key", token, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expected expired workload identity token to fail validation")
	}
}
