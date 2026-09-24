// Package render turns an alert into what each destination shows a human.
//
// Two constraints shape everything here.
//
// Size. The producer allows an alert body up to ~240 KB, and neither
// destination will take that: a Slack section caps at 3,000 characters and
// answers msg_too_long, which is a permanent failure -- an alert that never
// reaches anyone because it was too interesting -- and a GitHub issue body caps
// at 65,536 and answers 422. So every field that can grow is budgeted, and the
// event is summarised rather than shipped whole. That is also a data
// minimisation control: these records are CloudTrail, GitHub and Workspace
// audit events, they carry actor identities and source addresses, and the full
// record is already in S3 with the provenance naming it exactly.
//
// Determinism. A redelivery must render byte-identical output, or "the same
// alert produces the same issue" quietly stops being true and a duplicate
// becomes unrecognisable as one. Go map iteration is randomised, so every map is
// walked through sorted keys and never ranged over directly.
package render

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

import "github.com/samma-io/alert-destination/internal/alert"

// Destination limits, with the margins we render at.
const (
	// GitHubTitleLimit is where GitHub starts rejecting titles.
	GitHubTitleLimit = 256
	// GitHubBodyLimit is the issue body cap; over it GitHub answers 422.
	GitHubBodyLimit = 65_536
	// GitHubEventBudget is how much of the event we are willing to include.
	GitHubEventBudget = 30_000

	// SlackSectionLimit is the cap on one section block's text.
	SlackSectionLimit = 3_000
	// SlackBlockLimit is the cap on blocks in one message.
	SlackBlockLimit = 50
	// SlackEventBudget is how much of the event we are willing to include.
	SlackEventBudget = 2_500
)

// ellipsis marks where truncation happened. One rune, so budgets stay honest.
const ellipsis = "…"

// GitHubTitle is the issue title.
//
// The alert id is in the title, not only the body, so that a duplicate created
// in the crash window between a delivery and its ledger write is visible at a
// glance and findable with `gh issue list --search det_…`.
func GitHubTitle(a alert.Alert) string {
	title := fmt.Sprintf("[%s] %s (%s)", strings.ToUpper(a.Rule.Level), a.Rule.Title, a.ID)
	return clip(title, GitHubTitleLimit)
}

// GitHubLabels are the labels applied to the issue.
func GitHubLabels(a alert.Alert) []string {
	labels := []string{"detection"}
	if a.Rule.Level != "" {
		labels = append(labels, "severity:"+a.Rule.Level)
	}
	if a.LogSource != "" {
		labels = append(labels, "source:"+a.LogSource)
	}
	return labels
}

// GitHubBody is the issue body.
func GitHubBody(a alert.Alert) string {
	var b strings.Builder

	if a.Truncated {
		b.WriteString("> **Truncated: the event body was dropped** because the alert exceeded " +
			"the SQS message limit. The provenance below still names the record exactly.\n\n")
	}
	if !a.KnownSchema() {
		fmt.Fprintf(&b, "> Delivered by a consumer built for `%s`; this alert says `%s`.\n\n",
			alert.SchemaVersion, a.SchemaVersion)
	}

	fmt.Fprintf(&b, "**%s**\n\n", a.Rule.Title)
	if a.Rule.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", a.Rule.Description)
	}

	b.WriteString("| | |\n|---|---|\n")
	for _, row := range [][2]string{
		{"Alert", "`" + a.ID + "`"},
		{"Severity", a.Rule.Level},
		{"Log source", a.LogSource},
		{"Rule", fmt.Sprintf("`%s` (`%s`)", a.Rule.RuleID, a.Rule.File)},
		{"Detected", a.AlertedAt.Format("2006-01-02 15:04:05 UTC")},
		{"Bucket", "`" + a.Provenance.Bucket + "`"},
		{"Key", "`" + a.Provenance.Key + "`"},
		{"Record", fmt.Sprintf("%d", a.Provenance.EventIndex)},
		{"Event SHA-256", "`" + a.EventSHA256 + "`"},
		{"Event bytes", fmt.Sprintf("%d", a.EventBytes)},
	} {
		if row[1] != "" && row[1] != "``" {
			fmt.Fprintf(&b, "| %s | %s |\n", row[0], row[1])
		}
	}

	if len(a.Rule.Tags) > 0 {
		fmt.Fprintf(&b, "\nTags: %s\n", "`"+strings.Join(sorted(a.Rule.Tags), "`, `")+"`")
	}
	if len(a.Rule.References) > 0 {
		b.WriteString("\nReferences:\n")
		for _, ref := range a.Rule.References {
			fmt.Fprintf(&b, "- %s\n", ref)
		}
	}

	if event := eventJSON(a.Event, GitHubEventBudget); event != "" {
		fmt.Fprintf(&b, "\n<details><summary>Matched record</summary>\n\n```json\n%s\n```\n</details>\n", event)
	}

	b.WriteString("\n<sub>Delivered by alert-destination. Upserted on the alert id; " +
		"a second issue with the same id means a delivery was recorded twice.</sub>\n")

	return clip(b.String(), GitHubBodyLimit)
}

// SlackFallbackText is the notification preview, shown where blocks are not
// rendered. Without it the push notification is blank.
func SlackFallbackText(a alert.Alert) string {
	return clip(fmt.Sprintf("[%s] %s — %s", strings.ToUpper(a.Rule.Level), a.Rule.Title, a.LogSource), 300)
}

// SlackBlocks is the Block Kit payload.
//
// Returned as plain maps rather than a library's types so that the only thing
// between this package and Slack is encoding/json, and so a test can assert on
// the exact bytes that will be sent.
func SlackBlocks(a alert.Alert) []map[string]any {
	blocks := []map[string]any{
		section(fmt.Sprintf("%s *%s*", severityEmoji(a.Rule.Level), a.Rule.Title)),
	}

	fields := []string{
		"*Severity*\n" + orDash(a.Rule.Level),
		"*Log source*\n" + orDash(a.LogSource),
		"*Rule*\n`" + orDash(a.Rule.RuleID) + "`",
		"*Detected*\n" + a.AlertedAt.Format("2006-01-02 15:04:05 UTC"),
	}
	blocks = append(blocks, map[string]any{
		"type":   "section",
		"fields": textObjects(fields),
	})

	if a.Rule.Description != "" {
		blocks = append(blocks, section(clip(a.Rule.Description, SlackSectionLimit)))
	}

	if a.Truncated {
		blocks = append(blocks, section(":warning: *Truncated: the event body was dropped* — it "+
			"exceeded the SQS message limit. The provenance below still names the record."))
	}

	blocks = append(blocks, section(clip(fmt.Sprintf(
		"*Provenance*\n`s3://%s/%s` record %d",
		a.Provenance.Bucket, a.Provenance.Key, a.Provenance.EventIndex), SlackSectionLimit)))

	if event := eventJSON(a.Event, SlackEventBudget); event != "" {
		blocks = append(blocks, section(clip("```\n"+event+"\n```", SlackSectionLimit)))
	}

	blocks = append(blocks, map[string]any{
		"type": "context",
		"elements": []map[string]any{
			{"type": "mrkdwn", "text": "`" + a.ID + "`"},
		},
	})

	if len(blocks) > SlackBlockLimit {
		blocks = blocks[:SlackBlockLimit]
	}
	return blocks
}

func section(text string) map[string]any {
	return map[string]any{
		"type": "section",
		"text": map[string]any{"type": "mrkdwn", "text": clip(text, SlackSectionLimit)},
	}
}

func textObjects(texts []string) []map[string]any {
	out := make([]map[string]any, 0, len(texts))
	for _, t := range texts {
		out = append(out, map[string]any{"type": "mrkdwn", "text": clip(t, SlackSectionLimit)})
	}
	return out
}

// eventJSON renders the matched record within a byte budget.
//
// Marshalled with sorted keys (encoding/json sorts map keys, unlike range) and
// indented, then clipped. Nil for a truncated alert, whose event the producer
// already dropped.
func eventJSON(event map[string]any, budget int) string {
	if len(event) == 0 {
		return ""
	}
	encoded, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return fmt.Sprintf("<the matched record could not be rendered: %v>", err)
	}
	return clip(string(encoded), budget)
}

func severityEmoji(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return ":rotating_light:"
	case "high":
		return ":red_circle:"
	case "medium":
		return ":large_orange_diamond:"
	case "low":
		return ":large_blue_circle:"
	default:
		return ":white_circle:"
	}
}

// clip shortens s to at most n characters, counting runes so a multi-byte
// character is never cut in half.
func clip(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	runes := []rune(s)
	// Re-check: len() counted bytes, and the rune count may already fit.
	if len(runes) <= n-1 {
		return s
	}
	for cut := n - 1; cut > 0; cut-- {
		if candidate := string(runes[:cut]) + ellipsis; len(candidate) <= n {
			return candidate
		}
	}
	return ""
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
