package routing_test

import (
	"strings"
	"testing"

	"github.com/samma-io/alert-destination/internal/routing"
)

const valid = `
routes:
  - level: critical
    log_source: "*"
    deliveries:
      - {to: slack, target: "C0CRIT"}
      - {to: github, target: "example-org/detections"}
  - level: high
    log_source: aws
    deliveries:
      - {to: slack, target: "C0AWS"}
  - level: "*"
    log_source: "*"
    deliveries:
      - {to: slack, target: "C0ALL"}
default:
  deliveries:
    - {to: slack, target: "C0FALLBK"}
`

func load(t *testing.T, src string) *routing.Table {
	t.Helper()
	tbl, err := routing.Load([]byte(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return tbl
}

func targets(ds []routing.Delivery) string {
	var b []string
	for _, d := range ds {
		b = append(b, d.To+":"+d.Target)
	}
	return strings.Join(b, ",")
}

func TestResolve_ExactLevelAndWildcardSourceMatches(t *testing.T) {
	got, m := load(t, valid).Resolve("critical", "github")

	if want := "slack:C0CRIT,github:example-org/detections"; targets(got) != want {
		t.Errorf("deliveries = %s, want %s", targets(got), want)
	}
	if m.UsedDefault {
		t.Error("UsedDefault = true, want false")
	}
}

// A rule naming both level and log_source beats one that wildcards the source,
// however they are ordered in the file.
func TestResolve_MostSpecificRuleWins(t *testing.T) {
	got, _ := load(t, valid).Resolve("high", "aws")

	if want := "slack:C0AWS"; targets(got) != want {
		t.Errorf("deliveries = %s, want %s", targets(got), want)
	}
}

func TestResolve_FallsThroughToTheWildcardRule(t *testing.T) {
	got, m := load(t, valid).Resolve("high", "gcp")

	if want := "slack:C0ALL"; targets(got) != want {
		t.Errorf("deliveries = %s, want %s", targets(got), want)
	}
	if m.UsedDefault {
		t.Error("UsedDefault = true; the wildcard rule should have matched")
	}
}

// An unknown level must still be delivered. DLQ-ing a real detection over a
// metadata typo is worse than over-delivering it.
func TestResolve_UnknownLevelIsFlaggedButStillDelivered(t *testing.T) {
	got, m := load(t, valid).Resolve("sev1", "aws")

	if len(got) == 0 {
		t.Fatal("no deliveries for an unknown level; an alert would be dropped")
	}
	if !m.UnknownLevel {
		t.Error("UnknownLevel = false, want true")
	}
}

func TestResolve_UnknownLogSourceIsFlaggedButStillDelivered(t *testing.T) {
	got, m := load(t, valid).Resolve("high", "okta")

	if len(got) == 0 {
		t.Fatal("no deliveries for an unknown log source; an alert would be dropped")
	}
	if !m.UnknownLogSource {
		t.Error("UnknownLogSource = false, want true")
	}
}

// The cloudflare lane is a real lane, so its alerts must not be counted as
// coming from somewhere unknown.
func TestResolve_CloudflareIsAKnownLogSource(t *testing.T) {
	if _, m := load(t, valid).Resolve("high", "cloudflare"); m.UnknownLogSource {
		t.Error("cloudflare alerts are flagged as an unknown log source")
	}
}

// The k8s, scanner, wazuh, osquery and traefik lanes exist only on Kubernetes, but they are real lanes
// there, so their alerts must not be counted as coming from somewhere unknown.
func TestResolve_KubernetesLanesAreKnownLogSources(t *testing.T) {
	tbl := load(t, valid)
	for _, src := range []string{"k8s", "scanner", "wazuh", "osquery", "traefik", "keycloak"} {
		if _, m := tbl.Resolve("high", src); m.UnknownLogSource {
			t.Errorf("%s alerts are flagged as an unknown log source", src)
		}
	}
}

// Every (level, log_source) pair, known or not, must resolve to at least one
// delivery. This is the guard against the whole silent-drop bug class.
func TestResolve_IsTotal(t *testing.T) {
	tbl := load(t, valid)
	levels := append(routing.KnownLevels(), "", "sev1", "SEVERE")
	sources := append(routing.KnownLogSources(), "", "okta", "azure")

	for _, lvl := range levels {
		for _, src := range sources {
			if got, _ := tbl.Resolve(lvl, src); len(got) == 0 {
				t.Errorf("Resolve(%q, %q) returned no deliveries", lvl, src)
			}
		}
	}
}

func TestLoad_RejectsAMissingDefault(t *testing.T) {
	_, err := routing.Load([]byte(`
routes:
  - {level: "*", log_source: "*", deliveries: [{to: slack, target: "C0"}]}
`))
	if err == nil {
		t.Fatal("Load succeeded with no default; want an error")
	}
}

func TestLoad_RejectsAnEmptyDefault(t *testing.T) {
	_, err := routing.Load([]byte(`
routes: []
default:
  deliveries: []
`))
	if err == nil {
		t.Fatal("Load succeeded with an empty default; want an error")
	}
}

func TestLoad_RejectsAnUnknownDestination(t *testing.T) {
	_, err := routing.Load([]byte(`
routes:
  - {level: "*", log_source: "*", deliveries: [{to: pagerduty, target: "x"}]}
default:
  deliveries: [{to: slack, target: "C0"}]
`))
	if err == nil {
		t.Fatal("Load succeeded with an unknown destination; want an error")
	}
	if !strings.Contains(err.Error(), "pagerduty") {
		t.Errorf("error does not name the offending destination: %v", err)
	}
}

func TestLoad_RejectsADeliveryWithNoTarget(t *testing.T) {
	_, err := routing.Load([]byte(`
routes: []
default:
  deliveries: [{to: slack, target: ""}]
`))
	if err == nil {
		t.Fatal("Load succeeded with an empty target; want an error")
	}
}

// Nobody watches an issue tracker in real time, so a route that reaches GitHub
// but not Slack can fail without anyone noticing.
func TestLoad_RejectsARouteThatDoesNotIncludeSlack(t *testing.T) {
	_, err := routing.Load([]byte(`
routes:
  - {level: low, log_source: "*", deliveries: [{to: github, target: "o/r"}]}
default:
  deliveries: [{to: slack, target: "C0"}]
`))
	if err == nil {
		t.Fatal("Load succeeded for a GitHub-only route; want an error")
	}
}

func TestLoad_PostgresOnlyNeedsAnExplicitOptOut(t *testing.T) {
	const body = `
routes:
  - {level: "*", log_source: "*", deliveries: [{to: postgres, target: siem_alerts}]}
default:
  deliveries: [{to: postgres, target: siem_alerts}]
`
	if _, err := routing.Load([]byte(body)); err == nil {
		t.Fatal("Load succeeded for a postgres-only table without require_slack: false")
	}
	if _, err := routing.Load([]byte("require_slack: false\n" + body)); err != nil {
		t.Fatalf("Load with require_slack: false: %v", err)
	}
}

func TestLoad_ReportsEveryProblemAtOnce(t *testing.T) {
	_, err := routing.Load([]byte(`
routes:
  - {level: low, log_source: "*", deliveries: [{to: pagerduty, target: ""}]}
`))
	if err == nil {
		t.Fatal("Load succeeded; want an error")
	}
	for _, want := range []string{"pagerduty", "target", "default"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is missing %q: %v", want, err)
		}
	}
}

// The shipped table is the one that actually runs; a broken one must fail the
// build, not the first alert.
func TestEmbedded_IsValidAndTotal(t *testing.T) {
	tbl, err := routing.Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	for _, lvl := range append(routing.KnownLevels(), "unknown") {
		for _, src := range append(routing.KnownLogSources(), "unknown") {
			if got, _ := tbl.Resolve(lvl, src); len(got) == 0 {
				t.Errorf("embedded table: Resolve(%q, %q) returned no deliveries", lvl, src)
			}
		}
	}
}
