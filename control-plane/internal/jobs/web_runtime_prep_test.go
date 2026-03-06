package jobs

import (
	"errors"
	"testing"
)

func TestValidateWebRuntimeToolsSafeModeDisallowsRestrictedTools(t *testing.T) {
	err := validateWebRuntimeTools("url", true, []string{"zap", "metasploit"})
	if err == nil {
		t.Fatal("expected safe mode to block metasploit")
	}
	if !errors.Is(err, ErrWebRuntimeToolNotAllowed) {
		t.Fatalf("expected ErrWebRuntimeToolNotAllowed, got %v", err)
	}
}

func TestValidateWebRuntimeToolsUnsafeModeAllowsRestrictedToolsForURL(t *testing.T) {
	if err := validateWebRuntimeTools("url", false, []string{"zap", "metasploit", "sqlmap", "nmap"}); err != nil {
		t.Fatalf("expected unrestricted url mode to allow explicit tools, got %v", err)
	}
}

func TestValidateWebRuntimeToolsAPISchemaDisallowsNetworkTools(t *testing.T) {
	err := validateWebRuntimeTools("api_schema", false, []string{"zap-api", "nmap"})
	if err == nil {
		t.Fatal("expected api_schema mode to reject nmap")
	}
	if !errors.Is(err, ErrWebRuntimeToolNotAllowed) {
		t.Fatalf("expected ErrWebRuntimeToolNotAllowed, got %v", err)
	}
}
