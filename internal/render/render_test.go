package render_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/render"
)

func sample() alert.Alert {
	return alert.Alert{
		SchemaVersion: alert.SchemaVersion,
		ID:            "det_3436971c",
		AlertedAt:     time.Date(2026, 9, 2, 15, 7, 22, 0, time.UTC),
		LogSource:     "aws",
		Rule: alert.Rule{
			RuleID: "7f8b1c42", Title: "CloudTrail Logging Disabled", Level: "critical",
			Description: "Someone disabled a trail.",
			Tags:        []string{"attack.defense_evasion", "attack.t1562.008"},
			References:  []string{"https://example.invalid/rule"},
			File:        "aws/cloudtrail_logging_disabled.yml",
		},
		Provenance: alert.Provenance{
			Bucket: "filtered-1-us-east-1", Key: "aws/date=2026-09-02/x.ndjson.gz", EventIndex: 4,
		},
		Event:       map[string]any{"eventName": "StopLogging", "userIdentity": map[string]any{"type": "IAMUser"}},
		EventSHA256: "abc123",
		EventBytes:  412,
	}
}

func huge() alert.Alert {
	a := sample()
	a.Event = map[string]any{"blob": strings.Repeat("x", 200_000)}
	a.EventBytes = 200_000
	return a
}

func truncated() alert.Alert {
	a := sample()
	a.Event = nil
	a.Truncated = true
	a.EventBytes = 300_000
	return a
}

// --- GitHub ----------------------------------------------------------------

// The id in the title is what lets a human find a duplicate that slipped through
// the crash window between delivery and the ledger write.
func TestGitHubTitle_CarriesTheAlertID(t *testing.T) {
	if got := render.GitHubTitle(sample()); !strings.Contains(got, "det_3436971c") {
		t.Errorf("title = %q, want it to contain the alert id", got)
	}
}

func TestGitHubTitle_CarriesTheRuleTitle(t *testing.T) {
	if got := render.GitHubTitle(sample()); !strings.Contains(got, "CloudTrail Logging Disabled") {
		t.Errorf("title = %q, want it to name the rule", got)
	}
}

func TestGitHubTitle_StaysUnderTheAPILimit(t *testing.T) {
	a := sample()
	a.Rule.Title = strings.Repeat("long ", 200)

	if got := len(render.GitHubTitle(a)); got > render.GitHubTitleLimit {
		t.Errorf("title length = %d, over the %d limit", got, render.GitHubTitleLimit)
	}
}

func TestGitHubBody_StaysUnderTheAPILimit(t *testing.T) {
	if got := len(render.GitHubBody(huge())); got > render.GitHubBodyLimit {
		t.Errorf("body length = %d, over the %d limit (GitHub answers 422)", got, render.GitHubBodyLimit)
	}
}

func TestGitHubBody_NamesTheObjectTheEventCameFrom(t *testing.T) {
	body := render.GitHubBody(sample())

	for _, want := range []string{"filtered-1-us-east-1", "aws/date=2026-09-02/x.ndjson.gz", "4"} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing provenance %q", want)
		}
	}
}

// Provenance is the only way back to the original record, so a truncated alert
// must lead with it rather than bury it.
func TestGitHubBody_SaysWhenTheEventWasDropped(t *testing.T) {
	body := render.GitHubBody(truncated())

	if !strings.Contains(strings.ToLower(body), "truncated") {
		t.Errorf("body does not mention truncation: %q", body)
	}
	if !strings.Contains(body, "aws/date=2026-09-02/x.ndjson.gz") {
		t.Error("body dropped the provenance of a truncated alert")
	}
}

func TestGitHubLabels_CarrySeverityAndSource(t *testing.T) {
	got := strings.Join(render.GitHubLabels(sample()), ",")

	for _, want := range []string{"detection", "severity:critical", "source:aws"} {
		if !strings.Contains(got, want) {
			t.Errorf("labels = %s, missing %q", got, want)
		}
	}
}

// --- Slack -----------------------------------------------------------------

func TestSlackBlocks_AreValidJSON(t *testing.T) {
	if _, err := json.Marshal(render.SlackBlocks(sample())); err != nil {
		t.Fatalf("blocks do not marshal: %v", err)
	}
}

func TestSlackBlocks_NameTheRuleAndSeverity(t *testing.T) {
	encoded, err := json.Marshal(render.SlackBlocks(sample()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{"CloudTrail Logging Disabled", "critical", "det_3436971c"} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("blocks are missing %q", want)
		}
	}
}

// Slack answers msg_too_long, a permanent failure -- an alert that never reaches
// a human because it was too interesting.
func TestSlackBlocks_NoSectionExceedsSlacksTextLimit(t *testing.T) {
	for _, a := range []alert.Alert{sample(), huge(), truncated()} {
		for i, b := range render.SlackBlocks(a) {
			text, ok := b["text"].(map[string]any)
			if !ok {
				continue
			}
			if got := len(text["text"].(string)); got > render.SlackSectionLimit {
				t.Errorf("block %d text is %d chars, over Slack's %d limit",
					i, got, render.SlackSectionLimit)
			}
		}
	}
}

func TestSlackBlocks_StayUnderSlacksBlockCount(t *testing.T) {
	if got := len(render.SlackBlocks(huge())); got > render.SlackBlockLimit {
		t.Errorf("blocks = %d, over the %d limit", got, render.SlackBlockLimit)
	}
}

func TestSlackBlocks_SayWhenTheEventWasDropped(t *testing.T) {
	encoded, _ := json.Marshal(render.SlackBlocks(truncated()))

	if !strings.Contains(strings.ToLower(string(encoded)), "truncated") {
		t.Error("blocks do not mention truncation")
	}
}

func TestSlackFallbackText_IsSetForNotifications(t *testing.T) {
	if got := render.SlackFallbackText(sample()); got == "" {
		t.Error("fallback text is empty; the notification would be blank")
	}
}

// --- determinism -----------------------------------------------------------

// A retry that renders different bytes breaks "same alert, same issue": the
// duplicate stops being recognisable as one.
func TestRendering_IsDeterministic(t *testing.T) {
	a := huge()

	for i := 0; i < 20; i++ {
		if got, want := render.GitHubBody(a), render.GitHubBody(a); got != want {
			t.Fatal("GitHubBody is not deterministic across calls")
		}
		first, _ := json.Marshal(render.SlackBlocks(a))
		second, _ := json.Marshal(render.SlackBlocks(a))
		if string(first) != string(second) {
			t.Fatal("SlackBlocks is not deterministic across calls")
		}
	}
}

// Maps iterate in random order, so an event rendered straight out of one would
// differ between attempts.
func TestRendering_IsStableForAManyFieldEvent(t *testing.T) {
	a := sample()
	a.Event = map[string]any{}
	for i := 'a'; i <= 'z'; i++ {
		a.Event[string(i)] = string(i)
	}

	want := render.GitHubBody(a)
	for i := 0; i < 20; i++ {
		if got := render.GitHubBody(a); got != want {
			t.Fatal("GitHubBody varies with map iteration order")
		}
	}
}
