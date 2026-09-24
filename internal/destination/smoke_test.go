//go:build smoke

// Smoke tests against the real Slack workspace and the real GitHub repository.
//
// Behind a build tag because they post a visible message and open a real issue.
// They exist because the things most likely to be wrong on a first deploy are
// not reachable from a unit test: whether the bot was invited to the channel,
// whether the fine-grained PAT was granted the repository, and whether every
// label the renderer applies exists. Each of those fails as a permanent
// delivery error in production, and each is a minute's fix if you find it here.
//
//	make smoke   # see the Makefile for the credentials it expects
package destination_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/destination/github"
	"github.com/samma-io/alert-destination/internal/destination/slack"
	"github.com/samma-io/alert-destination/internal/httpx"
)

func env(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s is not set", key)
	}
	return v
}

func smokeClient() *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &httpx.RetryTransport{MaxRetries: 2, MaxWait: 5 * time.Second},
	}
}

// smokeAlert is deliberately marked as a test in every field a human will read,
// so nobody triaging the channel or the issue tracker mistakes it for a real
// detection.
func smokeAlert() alert.Alert {
	return alert.Alert{
		SchemaVersion: alert.SchemaVersion,
		ID:            "det_smoketest_" + time.Now().UTC().Format("20060102T150405Z"),
		AlertedAt:     time.Now().UTC(),
		LogSource:     "aws",
		Rule: alert.Rule{
			RuleID: "smoke-test",
			Title:  "TEST ALERT — alert-destination delivery check, please ignore",
			Level:  "critical",
			Description: "Synthetic alert produced by the alert-destination smoke test. " +
				"It is not a detection and needs no triage.",
			Tags: []string{"test.smoke"},
			File: "smoke/test.yml",
		},
		Provenance: alert.Provenance{
			Bucket:     "not-a-real-bucket",
			Key:        "smoke/test",
			EventIndex: 0,
		},
		Event:       map[string]any{"eventName": "SmokeTest", "note": "synthetic"},
		EventSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		EventBytes:  42,
	}
}

func TestSmoke_SlackAcceptsARenderedAlert(t *testing.T) {
	channel := env(t, "ALERTDEST_SMOKE_SLACK_CHANNEL")
	token := env(t, "ALERTDEST_SMOKE_SLACK_TOKEN")

	c := &slack.Client{
		HTTP:  smokeClient(),
		Token: func(context.Context) (string, error) { return token, nil },
	}

	if err := c.Deliver(context.Background(), smokeAlert(), channel); err != nil {
		t.Fatalf("slack rejected the message: %v\n"+
			"  channel_not_found -> wrong id, or the bot cannot see it\n"+
			"  not_in_channel    -> the bot was never invited to %s\n"+
			"  invalid_blocks    -> the renderer produced Block Kit slack will not take",
			err, channel)
	}
	t.Logf("delivered to %s", channel)
}

func TestSmoke_GitHubAcceptsARenderedAlert(t *testing.T) {
	repo := env(t, "ALERTDEST_SMOKE_GITHUB_REPO")
	token := env(t, "ALERTDEST_SMOKE_GITHUB_TOKEN")

	c := &github.Client{
		HTTP:  smokeClient(),
		Token: func(context.Context) (string, error) { return token, nil },
	}

	if err := c.Deliver(context.Background(), smokeAlert(), repo); err != nil {
		t.Fatalf("github rejected the issue: %v\n"+
			"  404 -> the fine-grained PAT was not granted %s\n"+
			"  422 -> a label the renderer applies does not exist in that repo\n"+
			"  410 -> issues are disabled there",
			err, repo)
	}
	t.Logf("issue opened in %s", repo)
}

// A wrong credential must be reported as an auth failure rather than as
// something retryable, because that is what decides whether the alarm says
// "rotate a token" or "a destination is flaky".
func TestSmoke_ABadTokenIsAnAuthFailure(t *testing.T) {
	repo := env(t, "ALERTDEST_SMOKE_GITHUB_REPO")

	c := &github.Client{
		HTTP:  smokeClient(),
		Token: func(context.Context) (string, error) { return "github_pat_obviously_invalid", nil },
	}

	err := c.Deliver(context.Background(), smokeAlert(), repo)
	if err == nil {
		t.Fatal("github accepted an invalid token")
	}
	if !destination.IsAuthFailure(err) {
		t.Errorf("a rejected credential was not classified as an auth failure: %v", err)
	}
	if !destination.IsPermanent(err) {
		t.Errorf("an auth failure must also be permanent: %v", err)
	}
}
