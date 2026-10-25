// Package routing decides which destinations an alert reaches.
//
// The table is embedded rather than fetched, and every lookup is total: an
// unknown severity or a log source added upstream still resolves to a non-empty
// destination set. A router that can answer "nowhere" is a router that drains
// the queue while delivering nothing, which is indistinguishable on every
// dashboard from a quiet week.
package routing

import (
	_ "embed"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed routes.yaml
var embedded []byte

// Wildcard matches any value of a field. It is always written out; a missing
// field is a validation error rather than an implied wildcard.
const Wildcard = "*"

// slackDestination is the destination every route must include. Named rather
// than inlined so the reason travels with the constant.
const slackDestination = "slack"

// knownDestinations is the closed set of destination names a route may use.
// Adding one here without adding it to the deliver registry, or the reverse, is
// caught by the arch test.
var knownDestinations = map[string]bool{
	"slack":    true,
	"github":   true,
	"postgres": true,
}

// knownLevels is Sigma's closed severity set. The producer does not validate
// the level it copies out of a rule, so an unknown one is possible and must
// route rather than fail.
var knownLevels = []string{"informational", "low", "medium", "high", "critical"}

// knownLogSources duplicates the default lane list in aws-siem's Terraform (one
// SQS lane per log family feeding detection-engine). Duplicated on purpose: this
// list exists so the totality test can enumerate real inputs, and a lane added
// there but not here is flagged in metrics rather than by an undelivered alert.
var knownLogSources = []string{
	"aws", "github", "dns", "alb", "slack", "onepassword", "workspace", "gcp", "cloudflare",
}

// KnownLevels returns the severities the detection plane emits.
func KnownLevels() []string { return append([]string(nil), knownLevels...) }

// KnownLogSources returns the log sources the detection plane emits.
func KnownLogSources() []string { return append([]string(nil), knownLogSources...) }

// Delivery is one destination and the address within it.
//
// The address lives on the route rather than on the destination because there
// is exactly one Slack client and one GitHub client; which channel or repository
// they write to is a routing decision, not a property of the client.
type Delivery struct {
	To     string `yaml:"to"`
	Target string `yaml:"target"`
}

// Route is one matching rule.
type Route struct {
	Level      string     `yaml:"level"`
	LogSource  string     `yaml:"log_source"`
	Deliveries []Delivery `yaml:"deliveries"`
}

// Fallback is the mandatory catch-all.
type Fallback struct {
	Deliveries []Delivery `yaml:"deliveries"`
}

// Table is a validated routing table.
type Table struct {
	Routes  []Route  `yaml:"routes"`
	Default Fallback `yaml:"default"`

	// RequireSlack, when explicitly false, lifts the every-route-includes-slack
	// rule. It exists for the Kubernetes bootstrap, where alerts go only to
	// Postgres until Slack is wired. It is written in the table, never implied,
	// so anyone reading the table sees that nothing pages a human.
	RequireSlack *bool `yaml:"require_slack,omitempty"`
}

// Match describes how a lookup was answered, for logging and metrics.
//
// It is returned alongside the deliveries rather than folded into them because
// none of these conditions changes what we do -- we always deliver -- and all of
// them are worth counting.
type Match struct {
	// UsedDefault reports that no route matched and the fallback answered.
	UsedDefault bool
	// UnknownLevel reports a severity outside Sigma's closed set.
	UnknownLevel bool
	// UnknownLogSource reports a source the detection plane did not have when
	// this table was written.
	UnknownLogSource bool
}

// Embedded returns the table this binary ships with.
func Embedded() (*Table, error) { return Load(embedded) }

// Load parses and validates a routing table, reporting every problem at once.
//
// Validation happens at process start, not at first alert, so a bad table fails
// the deploy rather than one detection.
func Load(data []byte) (*Table, error) {
	var t Table
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing routing table: %w", err)
	}

	var problems []string
	for i, r := range t.Routes {
		where := fmt.Sprintf("routes[%d] (level=%q log_source=%q)", i, r.Level, r.LogSource)
		if r.Level == "" {
			problems = append(problems, where+": level is empty; write \"*\" for any")
		}
		if r.LogSource == "" {
			problems = append(problems, where+": log_source is empty; write \"*\" for any")
		}
		problems = append(problems, checkDeliveries(where, r.Deliveries, t.requireSlack())...)
	}
	problems = append(problems, checkDeliveries("default", t.Default.Deliveries, t.requireSlack())...)

	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, errors.New("invalid routing table:\n  " + strings.Join(problems, "\n  "))
	}
	return &t, nil
}

// requireSlack is true unless the table says otherwise in so many words.
func (t *Table) requireSlack() bool { return t.RequireSlack == nil || *t.RequireSlack }

func checkDeliveries(where string, ds []Delivery, requireSlack bool) []string {
	var problems []string
	if len(ds) == 0 {
		return []string{where + ": no deliveries; every route must reach at least one destination"}
	}

	var hasSlack bool
	for _, d := range ds {
		if !knownDestinations[d.To] {
			problems = append(problems, fmt.Sprintf("%s: unknown destination %q", where, d.To))
		}
		if d.Target == "" {
			problems = append(problems, fmt.Sprintf("%s: destination %q has an empty target", where, d.To))
		}
		if d.To == slackDestination {
			hasSlack = true
		}
	}
	if requireSlack && !hasSlack {
		problems = append(problems, where+": does not include slack; a route nobody watches in "+
			"real time can fail silently")
	}
	return problems
}

// Resolve answers where one alert goes. It never returns an empty slice.
func (t *Table) Resolve(level, logSource string) ([]Delivery, Match) {
	m := Match{
		UnknownLevel:     !contains(knownLevels, level),
		UnknownLogSource: !contains(knownLogSources, logSource),
	}

	best := -1
	bestScore := -1
	for i, r := range t.Routes {
		score, ok := specificity(r, level, logSource)
		if ok && score > bestScore {
			best, bestScore = i, score
		}
	}
	if best >= 0 {
		return t.Routes[best].Deliveries, m
	}

	m.UsedDefault = true
	return t.Default.Deliveries, m
}

// specificity scores a route against one alert. A higher score is a more
// specific match; an exact level outranks an exact log source because severity
// is the field operators actually route on.
func specificity(r Route, level, logSource string) (int, bool) {
	score := 0
	switch {
	case r.Level == level:
		score += 2
	case r.Level == Wildcard:
	default:
		return 0, false
	}
	switch {
	case r.LogSource == logSource:
		score++
	case r.LogSource == Wildcard:
	default:
		return 0, false
	}
	return score, true
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
