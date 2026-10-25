package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/config"
	"github.com/samma-io/alert-destination/internal/daemon"
	"github.com/samma-io/alert-destination/internal/deliver"
	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/ledger"
	"github.com/samma-io/alert-destination/internal/routing"
)

// Not shaped like real tokens, so no secret scanner mistakes them for one.
const (
	slackTokenA = "test-slack-token-alpha"
	slackTokenB = "test-slack-token-bravo"
	githubToken = "test-github-token-charlie"
)

// The table the k8s chart would mount for "everything to Postgres, critical
// also to Slack and GitHub". require_slack is the default (true), so every
// route names slack.
const natsRoutes = `
routes:
  - level: critical
    log_source: "*"
    deliveries:
      - {to: postgres, target: siem_alerts}
      - {to: slack, target: C0EXAMPLE1}
      - {to: github, target: example-org/detections}
  - level: "*"
    log_source: "*"
    deliveries:
      - {to: postgres, target: siem_alerts}
      - {to: slack, target: C0EXAMPLE1}
default:
  deliveries:
    - {to: postgres, target: siem_alerts}
    - {to: slack, target: C0EXAMPLE1}
`

const postgresOnlyRoutes = `
require_slack: false
routes:
  - {level: "*", log_source: "*", deliveries: [{to: postgres, target: siem_alerts}]}
default:
  deliveries: [{to: postgres, target: siem_alerts}]
`

const criticalAlert = `{"schema_version":"detection.alert.v1","id":"det_k8s","log_source":"aws",` +
	`"rule":{"id":"7f8b1c42","title":"CloudTrail Logging Disabled","level":"critical"},` +
	`"provenance":{"bucket":"b","key":"k","event_index":0}}`

// fakePostgres stands in for the postgres destination; its real behaviour is
// covered by the integration suite.
type fakePostgres struct{ calls int }

func (p *fakePostgres) Name() string { return "postgres" }
func (p *fakePostgres) Deliver(context.Context, alert.Alert, string) (destination.Ref, error) {
	p.calls++
	return destination.Ref{"table": "siem_alerts"}, nil
}

// fakeAPI is a Slack or GitHub server that records the Authorization header
// of every request and answers with whatever reply returns.
type fakeAPI struct {
	*httptest.Server
	mu    sync.Mutex
	auths []string
	reply func(auth string) (int, string)
}

func newFakeAPI(t *testing.T, reply func(auth string) (int, string)) *fakeAPI {
	t.Helper()
	f := &fakeAPI{reply: reply}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		auth := r.Header.Get("Authorization")
		f.mu.Lock()
		f.auths = append(f.auths, auth)
		reply := f.reply
		f.mu.Unlock()
		status, body := reply(auth)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAPI) setReply(reply func(auth string) (int, string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reply = reply
}

func (f *fakeAPI) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.auths...)
}

func slackOK(string) (int, string) {
	return http.StatusOK, `{"ok":true,"channel":"C0EXAMPLE1","ts":"1700000000.000100"}`
}
func githubOK(string) (int, string) {
	return http.StatusCreated, `{"number":7,"html_url":"https://github.invalid/example-org/detections/issues/7"}`
}
func githubRejects(string) (int, string) {
	return http.StatusUnprocessableEntity, `{"message":"Validation Failed"}`
}

// fakeQueue is the JetStream consumer as the daemon loop sees it: the same
// message comes back on every receive until it is acked, and the loop is
// stopped after a fixed number of receives.
type fakeQueue struct {
	body     string
	receives int
	acked    int
	stopAt   int
	stop     context.CancelFunc
}

func (q *fakeQueue) Receive(context.Context, int, time.Duration) ([]daemon.Message, error) {
	q.receives++
	if q.receives > q.stopAt {
		q.stop()
		return nil, nil
	}
	if q.acked > 0 {
		return nil, nil
	}
	return []daemon.Message{{ID: "samma.alerts.aws/1", Body: q.body, ReceiptHandle: "1"}}, nil
}

func (q *fakeQueue) Delete(context.Context, string) error {
	q.acked++
	return nil
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

func mustRoutes(t *testing.T, yaml string) *routing.Table {
	t.Helper()
	table, err := routing.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("routing.Load: %v", err)
	}
	return table
}

// natsHarness is the nats wiring with the network edges faked: buildNATS minus
// the JetStream connection and the database.
type natsHarness struct {
	slack, github *fakeAPI
	pg            *fakePostgres
	store         *memStore
	handler       *deliver.Handler
	logs          *bytes.Buffer
	slackFile     string
}

func newNATSHarness(t *testing.T) *natsHarness {
	t.Helper()
	dir := t.TempDir()
	h := &natsHarness{
		slack:  newFakeAPI(t, slackOK),
		github: newFakeAPI(t, githubOK),
		pg:     &fakePostgres{},
		store:  &memStore{rows: map[string]ledger.Record{}},
		logs:   &bytes.Buffer{},
	}
	// The way the chart mounts them: keys of one Secret, trailing newline and all.
	h.slackFile = writeFile(t, dir, "slack-token", slackTokenA+"\n")
	cfg := config.Config{
		Transport:       config.TransportNATS,
		SlackTokenFile:  h.slackFile,
		GitHubTokenFile: writeFile(t, dir, "github-token", githubToken+"\n"),
		SlackBaseURL:    h.slack.URL,
		GitHubBaseURL:   h.github.URL,
	}
	log := slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	routes := mustRoutes(t, natsRoutes)

	registry, err := natsRegistry(context.Background(), cfg, routes, h.pg, log)
	if err != nil {
		t.Fatalf("natsRegistry: %v", err)
	}
	h.handler = &deliver.Handler{
		Routes:   routes,
		Registry: registry,
		Ledger:   &ledger.Ledger{Store: h.store},
		Log:      log,
	}
	return h
}

// run drives the daemon loop exactly as main does, for receives receives
// (each one a delivery until the message is acked).
func (h *natsHarness) run(t *testing.T, receives int) *fakeQueue {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := &fakeQueue{body: criticalAlert, stopAt: receives, stop: cancel}
	loop := &daemon.Loop{
		Queue: q,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Handle: func(ctx context.Context, m daemon.Message) error {
			return handle(ctx, h.handler, slog.New(slog.NewJSONHandler(h.logs, nil)), []message{{ID: m.ID, Body: m.Body}})
		},
	}
	if err := loop.Run(ctx); err != nil {
		t.Fatalf("loop.Run: %v", err)
	}
	return q
}

func (h *natsHarness) row(t *testing.T, dest string) ledger.Record {
	t.Helper()
	for _, r := range h.store.rows {
		if r.Destination == dest {
			return r
		}
	}
	t.Fatalf("no ledger row for %s", dest)
	return ledger.Record{}
}

func (h *natsHarness) assertNoTokenLeaked(t *testing.T) {
	t.Helper()
	for _, tok := range []string{slackTokenA, slackTokenB, githubToken} {
		if strings.Contains(h.logs.String(), tok) {
			t.Errorf("a token reached the logs:\n%s", h.logs.String())
		}
		for _, r := range h.store.rows {
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), tok) {
				t.Errorf("a token reached the ledger: %s", raw)
			}
		}
	}
}

func TestNATS_DeliversToSlackGitHubAndPostgresThenAcks(t *testing.T) {
	h := newNATSHarness(t)
	q := h.run(t, 2)

	if q.acked != 1 {
		t.Fatalf("acked = %d, want 1", q.acked)
	}
	if h.pg.calls != 1 {
		t.Errorf("postgres calls = %d, want 1", h.pg.calls)
	}
	if got := h.slack.requests(); len(got) != 1 || got[0] != "Bearer "+slackTokenA {
		t.Errorf("slack requests = %q, want one with the token from the file, newline trimmed", got)
	}
	if got := h.github.requests(); len(got) != 1 || got[0] != "Bearer "+githubToken {
		t.Errorf("github requests = %q, want one with the token from the file", got)
	}
	for _, d := range []string{"postgres", "slack", "github"} {
		if r := h.row(t, d); r.Status != ledger.StatusDelivered {
			t.Errorf("%s row = %q, want delivered", d, r.Status)
		}
	}
	if gh := h.row(t, "github"); gh.Ref["number"] != "7" {
		t.Errorf("github ref = %v, want the issue number", gh.Ref)
	}
	h.assertNoTokenLeaked(t)
}

// The Lambda contract, unchanged on JetStream: nothing is acked while any
// routed destination is undelivered, the failed row accumulates attempts, and
// only the delivered rows suppress a retry.
func TestNATS_PartialFailureIsNotAckedAndOnlyDeliveredRowsSuppressARetry(t *testing.T) {
	h := newNATSHarness(t)
	h.github.setReply(githubRejects)

	const attempts = 3
	q := h.run(t, attempts)
	if q.acked != 0 {
		t.Fatalf("acked = %d with GitHub failing; the alert would be lost", q.acked)
	}
	if got := len(h.slack.requests()); got != 1 {
		t.Errorf("slack posts = %d across %d deliveries, want 1", got, attempts)
	}
	if h.pg.calls != 1 {
		t.Errorf("postgres calls = %d, want 1", h.pg.calls)
	}
	if got := len(h.github.requests()); got != attempts {
		t.Errorf("github requests = %d, want one per delivery (%d)", got, attempts)
	}
	gh := h.row(t, "github")
	if gh.Status != ledger.StatusFailed || gh.Attempts != attempts || !gh.Permanent || gh.HTTPStatus != 422 {
		t.Errorf("github row = %+v, want failed, permanent, 422, %d attempts", gh, attempts)
	}

	// GitHub recovers: the next delivery files the issue, skips the rest, acks.
	h.github.setReply(githubOK)
	q = h.run(t, 2)
	if q.acked != 1 {
		t.Fatalf("acked = %d after recovery, want 1", q.acked)
	}
	if got := len(h.slack.requests()); got != 1 {
		t.Errorf("slack posts = %d after recovery, want still 1", got)
	}
	if h.pg.calls != 1 {
		t.Errorf("postgres calls = %d after recovery, want still 1", h.pg.calls)
	}
	if r := h.row(t, "github"); r.Status != ledger.StatusDelivered {
		t.Errorf("github row = %q after recovery, want delivered", r.Status)
	}
	h.assertNoTokenLeaked(t)
}

// A rotated Secret is picked up with no restart: Slack's auth failure
// invalidates the cached token and the next delivery re-reads the file.
func TestNATS_ARotatedTokenFileIsReadAfterAnAuthFailure(t *testing.T) {
	h := newNATSHarness(t)
	h.slack.setReply(func(auth string) (int, string) {
		if auth != "Bearer "+slackTokenB {
			return http.StatusOK, `{"ok":false,"error":"invalid_auth"}`
		}
		return slackOK(auth)
	})

	if q := h.run(t, 1); q.acked != 0 {
		t.Fatalf("acked = %d with Slack rejecting the token", q.acked)
	}
	if err := os.WriteFile(h.slackFile, []byte(slackTokenB), 0o600); err != nil {
		t.Fatal(err)
	}
	if q := h.run(t, 2); q.acked != 1 {
		t.Fatalf("acked = %d after rotation, want 1", q.acked)
	}
	got := h.slack.requests()
	if len(got) != 2 || got[0] != "Bearer "+slackTokenA || got[1] != "Bearer "+slackTokenB {
		t.Errorf("slack requests = %q, want the old token then the rotated one", got)
	}
	h.assertNoTokenLeaked(t)
}

func TestNATSRegistry_BuildsOnlyTheRoutedDestinations(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		SlackTokenFile:  writeFile(t, dir, "slack-token", slackTokenA),
		GitHubTokenFile: writeFile(t, dir, "github-token", githubToken),
	}
	r, err := natsRegistry(context.Background(), cfg, mustRoutes(t, postgresOnlyRoutes), &fakePostgres{}, quiet())
	if err != nil {
		t.Fatalf("natsRegistry: %v", err)
	}
	if got := strings.Join(r.Names(), ","); got != "postgres" {
		t.Errorf("registered = %s, want postgres only", got)
	}

	// Without the token files a postgres-only table needs nothing more.
	if _, err := natsRegistry(context.Background(), config.Config{}, mustRoutes(t, postgresOnlyRoutes), &fakePostgres{}, quiet()); err != nil {
		t.Errorf("postgres-only table without token files: %v", err)
	}
}

// Each of these is a deploy that must fail at start, not one alert at a time.
func TestNATSRegistry_RefusesARoutedDestinationWithoutAReadableToken(t *testing.T) {
	dir := t.TempDir()
	slackFile := writeFile(t, dir, "slack-token", slackTokenA)
	githubFile := writeFile(t, dir, "github-token", githubToken)
	empty := writeFile(t, dir, "empty", " \n")
	absent := filepath.Join(dir, "absent")

	for name, tc := range map[string]struct {
		slack, github string
		want          []string
	}{
		"slack file unset":  {"", githubFile, []string{"ALERTDEST_SLACK_TOKEN_FILE", "names slack"}},
		"github file unset": {slackFile, "", []string{"ALERTDEST_GITHUB_TOKEN_FILE", "names github"}},
		"both unset":        {"", "", []string{"ALERTDEST_SLACK_TOKEN_FILE", "ALERTDEST_GITHUB_TOKEN_FILE"}},
		"slack file absent": {absent, githubFile, []string{"ALERTDEST_SLACK_TOKEN_FILE", absent}},
		"github file empty": {slackFile, empty, []string{"ALERTDEST_GITHUB_TOKEN_FILE", empty, "empty"}},
		"github file a dir": {slackFile, dir, []string{"ALERTDEST_GITHUB_TOKEN_FILE"}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.Config{SlackTokenFile: tc.slack, GitHubTokenFile: tc.github}
			_, err := natsRegistry(context.Background(), cfg, mustRoutes(t, natsRoutes), &fakePostgres{}, quiet())
			if err == nil {
				t.Fatal("natsRegistry succeeded")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error does not mention %q: %v", w, err)
				}
			}
			for _, tok := range []string{slackTokenA, githubToken} {
				if strings.Contains(err.Error(), tok) {
					t.Errorf("error carries a token: %v", err)
				}
			}
		})
	}
}
