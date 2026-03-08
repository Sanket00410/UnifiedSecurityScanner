package store

import (
	"testing"
	"time"
)

func TestComputeRetryDelayCapsAtMax(t *testing.T) {
	delay := computeRetryDelay(10, 5, 30)
	if delay != 30*time.Second {
		t.Fatalf("expected max delay, got %s", delay)
	}
}

func TestShouldRetryJobClientError(t *testing.T) {
	if shouldRetryJob(1, 5, 400, "bad request") {
		t.Fatalf("expected no retry for 400 response")
	}
}

func TestShouldRetryJobServerError(t *testing.T) {
	if !shouldRetryJob(1, 5, 502, "upstream failure") {
		t.Fatalf("expected retry for 5xx response")
	}
}
