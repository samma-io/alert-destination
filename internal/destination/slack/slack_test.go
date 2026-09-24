package slack_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/destination/slack"
)

func testAlert() alert.Alert {
	return alert.Alert{
		SchemaVersion: alert.SchemaVersion,
		ID:            "det_1",
		LogSource:     "aws",
		Rule:          alert.Rule{RuleID: "r1", Title: "CloudTrail Logging Disabled", Level: "critical"},
		Event:         map[string]any{"eventName": "StopLogging"},
	}
}

type capture struct {
	path  string
	auth  string
	ctype string
	body  map[string]any
}

// serve answers every chat.postMessage with the given status and body.
func serve(t *testing.T, status int, respBody string, got *capture) *slack.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got != nil {
			got.path = r.URL.Path
			got.auth = r.Header.Get("Authorization")
			got.ctype = r.Header.Get("Content-Type")
			raw, _ := io.ReadAll(r.Body)
			json.Unmarshal(raw, &got.body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)

	return &slack.Client{
		BaseURL: srv.URL,
		HTTP:    srv.Client(),
		Token:   func(context.Context) (string, error) { return "xoxb-test", nil },
	}
}

func TestName(t *testing.T) {
	if got := (&slack.Client{}).Name(); got != "slack" {
		t.Errorf("Name = %q, want slack", got)
	}
}

func TestDeliver_PostsTheAlertToTheRoutedChannel(t *testing.T) {
	var got capture
	c := serve(t, 200, `{"ok":true,"ts":"1700000000.000100","channel":"C0"}`, &got)

	if err := c.Deliver(context.Background(), testAlert(), "C0CRIT"); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	if !strings.HasSuffix(got.path, "/chat.postMessage") {
		t.Errorf("path = %q, want chat.postMessage", got.path)
	}
	if got.body["channel"] != "C0CRIT" {
		t.Errorf("channel = %v, want the routed target C0CRIT", got.body["channel"])
	}
	if got.body["blocks"] == nil {
		t.Error("no blocks in the payload")
	}
	if got.body["text"] == "" || got.body["text"] == nil {
		t.Error("no fallback text; the push notification would be blank")
	}
}

func TestDeliver_AuthenticatesWithTheBotToken(t *testing.T) {
	var got capture
	c := serve(t, 200, `{"ok":true}`, &got)

	if err := c.Deliver(context.Background(), testAlert(), "C0"); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	if got.auth != "Bearer xoxb-test" {
		t.Errorf("Authorization = %q, want Bearer xoxb-test", got.auth)
	}
	if !strings.HasPrefix(got.ctype, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", got.ctype)
	}
}

// Slack answers HTTP 200 with ok:false. Treating the status as the outcome
// silently drops every alert.
func TestDeliver_FailsOnOkFalseDespiteHTTP200(t *testing.T) {
	c := serve(t, 200, `{"ok":false,"error":"channel_not_found"}`, nil)

	err := c.Deliver(context.Background(), testAlert(), "C0")
	if err == nil {
		t.Fatal("Deliver reported success on ok:false")
	}
	if !strings.Contains(err.Error(), "channel_not_found") {
		t.Errorf("error does not carry the reason: %v", err)
	}
}

func TestDeliver_ChannelNotFoundIsPermanent(t *testing.T) {
	c := serve(t, 200, `{"ok":false,"error":"channel_not_found"}`, nil)

	err := c.Deliver(context.Background(), testAlert(), "C0")
	if !destination.IsPermanent(err) {
		t.Errorf("channel_not_found is not permanent: %v", err)
	}
}

func TestDeliver_MsgTooLongIsPermanent(t *testing.T) {
	c := serve(t, 200, `{"ok":false,"error":"msg_too_long"}`, nil)

	if err := c.Deliver(context.Background(), testAlert(), "C0"); !destination.IsPermanent(err) {
		t.Errorf("msg_too_long is not permanent: %v", err)
	}
}

// A revoked token stops every alert, not just this one, so it is worth its own
// alarm rather than being lost among ordinary permanent failures.
func TestDeliver_TokenRevokedIsAnAuthFailure(t *testing.T) {
	c := serve(t, 200, `{"ok":false,"error":"token_revoked"}`, nil)

	err := c.Deliver(context.Background(), testAlert(), "C0")
	if !destination.IsAuthFailure(err) {
		t.Errorf("token_revoked is not an auth failure: %v", err)
	}
	if !destination.IsPermanent(err) {
		t.Error("an auth failure must also be permanent")
	}
}

func TestDeliver_InvalidAuthIsAnAuthFailure(t *testing.T) {
	c := serve(t, 200, `{"ok":false,"error":"invalid_auth"}`, nil)

	if err := c.Deliver(context.Background(), testAlert(), "C0"); !destination.IsAuthFailure(err) {
		t.Errorf("invalid_auth is not an auth failure: %v", err)
	}
}

func TestDeliver_RatelimitedIsTransient(t *testing.T) {
	c := serve(t, 200, `{"ok":false,"error":"ratelimited"}`, nil)

	err := c.Deliver(context.Background(), testAlert(), "C0")
	if err == nil {
		t.Fatal("Deliver succeeded on ratelimited")
	}
	if destination.IsPermanent(err) {
		t.Error("ratelimited must be transient; retrying is exactly the right response")
	}
}

func TestDeliver_ServerErrorIsTransient(t *testing.T) {
	c := serve(t, 503, `{"ok":false,"error":"service_unavailable"}`, nil)

	err := c.Deliver(context.Background(), testAlert(), "C0")
	if err == nil {
		t.Fatal("Deliver succeeded on a 503")
	}
	if destination.IsPermanent(err) {
		t.Error("a 503 must be transient")
	}
}

// An unrecognised error code could be either; treating it as transient costs
// four redeliveries, treating it as permanent could drop a real detection.
func TestDeliver_UnknownErrorCodeIsTransient(t *testing.T) {
	c := serve(t, 200, `{"ok":false,"error":"some_new_slack_error"}`, nil)

	if err := c.Deliver(context.Background(), testAlert(), "C0"); destination.IsPermanent(err) {
		t.Error("an unrecognised error was classified permanent; prefer retrying")
	}
}

func TestDeliver_FailsWhenTheTokenCannotBeRead(t *testing.T) {
	var got capture
	c := serve(t, 200, `{"ok":true}`, &got)
	c.Token = func(context.Context) (string, error) { return "", context.DeadlineExceeded }

	if err := c.Deliver(context.Background(), testAlert(), "C0"); err == nil {
		t.Fatal("Deliver succeeded without a token")
	}
	if got.path != "" {
		t.Error("a request was sent despite having no token")
	}
}

// The token must never reach a log line or an error string.
func TestDeliver_ErrorsDoNotLeakTheToken(t *testing.T) {
	c := serve(t, 200, `{"ok":false,"error":"channel_not_found"}`, nil)

	err := c.Deliver(context.Background(), testAlert(), "C0")
	if strings.Contains(err.Error(), "xoxb-test") {
		t.Fatalf("the bot token appears in an error: %v", err)
	}
}
