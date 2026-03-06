package jobs

import (
	"testing"
	"time"
)

func TestSecretLeaseTTLForTask_Default(t *testing.T) {
	ttl := secretLeaseTTLForTask(0, 0)
	if ttl != 10*time.Minute {
		t.Fatalf("expected default ttl 10m, got %s", ttl)
	}
}

func TestSecretLeaseTTLForTask_ExpandsWithTaskRuntime(t *testing.T) {
	ttl := secretLeaseTTLForTask(900, 0)
	expected := 17 * time.Minute
	if ttl != expected {
		t.Fatalf("expected ttl %s, got %s", expected, ttl)
	}
}

func TestSecretLeaseTTLForTask_RespectsConfiguredMax(t *testing.T) {
	ttl := secretLeaseTTLForTask(3600, 20*time.Minute)
	if ttl != 20*time.Minute {
		t.Fatalf("expected capped ttl 20m, got %s", ttl)
	}
}
