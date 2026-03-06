package jobs

import (
	"testing"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestNormalizeIngestionWebhookRequestGitHubInfersFromHeadersAndPayload(t *testing.T) {
	t.Parallel()

	source := modelsIngestionSource("github")
	request := normalizeIngestionWebhookRequest(source, ingestionRequest{
		Headers: map[string]string{
			"x-github-event":    "push",
			"x-github-delivery": "gh-delivery-42",
		},
		Payload: map[string]any{
			"ref":   "refs/heads/main",
			"after": "abc123",
			"repository": map[string]any{
				"full_name": "acme/core",
				"clone_url": "https://github.com/acme/core.git",
			},
			"sender": map[string]any{
				"login": "octocat",
			},
		},
	})

	if request.EventType != "github.push" {
		t.Fatalf("expected github.push event type, got %s", request.EventType)
	}
	if request.ExternalID != "gh-delivery-42" {
		t.Fatalf("expected external id from github delivery header, got %s", request.ExternalID)
	}
	if request.TargetKind != "repo" {
		t.Fatalf("expected inferred repo target kind, got %s", request.TargetKind)
	}
	if request.Target != "https://github.com/acme/core.git" {
		t.Fatalf("expected inferred repo target, got %s", request.Target)
	}
	if request.Labels["repo"] != "acme/core" {
		t.Fatalf("expected repo label to be inferred, got %#v", request.Labels["repo"])
	}
	if request.Labels["branch"] != "main" {
		t.Fatalf("expected branch label to be inferred, got %#v", request.Labels["branch"])
	}
	if request.Labels["commit"] != "abc123" {
		t.Fatalf("expected commit label to be inferred, got %#v", request.Labels["commit"])
	}
	if request.Metadata["provider"] != "github" {
		t.Fatalf("expected github provider metadata, got %#v", request.Metadata["provider"])
	}
	if request.Metadata["sender"] != "octocat" {
		t.Fatalf("expected sender metadata, got %#v", request.Metadata["sender"])
	}
}

func TestNormalizeIngestionWebhookRequestGitLabInfersFromHeadersAndPayload(t *testing.T) {
	t.Parallel()

	source := modelsIngestionSource("gitlab")
	request := normalizeIngestionWebhookRequest(source, ingestionRequest{
		Headers: map[string]string{
			"x-gitlab-event":      "Push Hook",
			"x-gitlab-event-uuid": "gl-event-99",
		},
		Payload: map[string]any{
			"ref":          "refs/heads/release/1.2",
			"checkout_sha": "def456",
			"project": map[string]any{
				"path_with_namespace": "acme/platform",
				"http_url":            "https://gitlab.com/acme/platform.git",
			},
			"user_username": "gitlab-bot",
		},
	})

	if request.EventType != "gitlab.push_hook" {
		t.Fatalf("expected gitlab.push_hook event type, got %s", request.EventType)
	}
	if request.ExternalID != "gl-event-99" {
		t.Fatalf("expected external id from gitlab event uuid header, got %s", request.ExternalID)
	}
	if request.TargetKind != "repo" {
		t.Fatalf("expected inferred repo target kind, got %s", request.TargetKind)
	}
	if request.Target != "https://gitlab.com/acme/platform.git" {
		t.Fatalf("expected inferred repo target, got %s", request.Target)
	}
	if request.Labels["repo"] != "acme/platform" {
		t.Fatalf("expected repo label to be inferred, got %#v", request.Labels["repo"])
	}
	if request.Labels["branch"] != "release/1.2" {
		t.Fatalf("expected branch label to be inferred, got %#v", request.Labels["branch"])
	}
	if request.Labels["commit"] != "def456" {
		t.Fatalf("expected commit label to be inferred, got %#v", request.Labels["commit"])
	}
	if request.Metadata["provider"] != "gitlab" {
		t.Fatalf("expected gitlab provider metadata, got %#v", request.Metadata["provider"])
	}
	if request.Metadata["sender"] != "gitlab-bot" {
		t.Fatalf("expected sender metadata, got %#v", request.Metadata["sender"])
	}
}

func TestNormalizeIngestionWebhookRequestJenkinsInfersFromHeadersAndPayload(t *testing.T) {
	t.Parallel()

	source := modelsIngestionSource("jenkins")
	request := normalizeIngestionWebhookRequest(source, ingestionRequest{
		Headers: map[string]string{
			"x-jenkins-event":        "build",
			"x-jenkins-build-number": "502",
			"x-jenkins-job":          "platform-nightly",
		},
		Payload: map[string]any{
			"scm_url":    "https://github.com/acme/platform.git",
			"branch":     "refs/heads/main",
			"build_url":  "https://jenkins.local/job/platform-nightly/502/",
			"build_id":   "build-502",
			"job_name":   "platform-nightly",
			"build_name": "nightly",
		},
	})

	if request.EventType != "jenkins.build" {
		t.Fatalf("expected jenkins.build event type, got %s", request.EventType)
	}
	if request.ExternalID != "build-502" {
		t.Fatalf("expected external id from build payload, got %s", request.ExternalID)
	}
	if request.TargetKind != "repo" {
		t.Fatalf("expected inferred repo target kind, got %s", request.TargetKind)
	}
	if request.Target != "https://github.com/acme/platform.git" {
		t.Fatalf("expected inferred repo target, got %s", request.Target)
	}
	if request.Labels["job"] != "platform-nightly" {
		t.Fatalf("expected job label to be inferred, got %#v", request.Labels["job"])
	}
	if request.Labels["branch"] != "main" {
		t.Fatalf("expected branch label to be inferred, got %#v", request.Labels["branch"])
	}
	if request.Metadata["provider"] != "jenkins" {
		t.Fatalf("expected jenkins provider metadata, got %#v", request.Metadata["provider"])
	}
	if request.Metadata["build_url"] != "https://jenkins.local/job/platform-nightly/502/" {
		t.Fatalf("expected build_url metadata, got %#v", request.Metadata["build_url"])
	}
}

type ingestionRequest = models.IngestionWebhookRequest

func modelsIngestionSource(provider string) models.IngestionSource {
	return models.IngestionSource{
		Provider: provider,
		Labels:   map[string]any{},
	}
}
