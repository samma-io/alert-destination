package github_test

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
	"github.com/samma-io/alert-destination/internal/destination/github"
)

func testAlert() alert.Alert {
	return alert.Alert{
		SchemaVersion: alert.SchemaVersion,
		ID:            "det_3436971c",
		LogSource:     "aws",
		Rule:          alert.Rule{RuleID: "r1", Title: "CloudTrail Logging Disabled", Level: "critical"},
		Provenance:    alert.Provenance{Bucket: "b", Key: "k", EventIndex: 0},
		Event:         map[string]any{"eventName": "StopLogging"},
	}
}

type capture struct {
	method   string
	path     string
	auth     string
	accept   string
	apiVer   string
	requests int
	body     map[string]any
}

type handler struct {
	status  int
	body    string
	headers map[string]string
}

func serve(t *testing.T, h handler, got *capture) *github.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got != nil {
			got.requests++
			got.method, got.path = r.Method, r.URL.Path
			got.auth = r.Header.Get("Authorization")
			got.accept = r.Header.Get("Accept")
			got.apiVer = r.Header.Get("X-GitHub-Api-Version")
			raw, _ := io.ReadAll(r.Body)
			json.Unmarshal(raw, &got.body)
		}
		for k, v := range h.headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(h.status)
		io.WriteString(w, h.body)
	}))
	t.Cleanup(srv.Close)

	return &github.Client{
		BaseURL: srv.URL,
		HTTP:    srv.Client(),
		Token:   func(context.Context) (string, error) { return "github_pat_test", nil },
	}
}

const created = `{"number":412,"html_url":"https://github.invalid/o/r/issues/412"}`

func TestName(t *testing.T) {
	if got := (&github.Client{}).Name(); got != "github" {
		t.Errorf("Name = %q, want github", got)
	}
}

func TestDeliver_CreatesAnIssueInTheRoutedRepository(t *testing.T) {
	var got capture
	c := serve(t, handler{status: 201, body: created}, &got)

	if err := c.Deliver(context.Background(), testAlert(), "example-org/detections"); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if got.path != "/repos/example-org/detections/issues" {
		t.Errorf("path = %q", got.path)
	}
}

// The ledger is the dedup authority; the Search API is deliberately not called,
// because its index lags by about as long as our retry interval.
func TestDeliver_MakesExactlyOneAPICall(t *testing.T) {
	var got capture
	c := serve(t, handler{status: 201, body: created}, &got)

	if err := c.Deliver(context.Background(), testAlert(), "o/r"); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if got.requests != 1 {
		t.Errorf("requests = %d, want 1; a search would burn the rate limit for nothing", got.requests)
	}
}

func TestDeliver_SendsTheHeadersGitHubExpects(t *testing.T) {
	var got capture
	c := serve(t, handler{status: 201, body: created}, &got)

	if err := c.Deliver(context.Background(), testAlert(), "o/r"); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if got.auth != "Bearer github_pat_test" {
		t.Errorf("Authorization = %q", got.auth)
	}
	if got.accept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", got.accept)
	}
	if got.apiVer == "" {
		t.Error("X-GitHub-Api-Version is unset; the API version is then whatever GitHub defaults to")
	}
}

func TestDeliver_PutsTheAlertIDInTheTitle(t *testing.T) {
	var got capture
	c := serve(t, handler{status: 201, body: created}, &got)

	if err := c.Deliver(context.Background(), testAlert(), "o/r"); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	title, _ := got.body["title"].(string)
	if !strings.Contains(title, "det_3436971c") {
		t.Errorf("title = %q, want it to carry the alert id", title)
	}
}

func TestDeliver_AppliesSeverityAndSourceLabels(t *testing.T) {
	var got capture
	c := serve(t, handler{status: 201, body: created}, &got)

	if err := c.Deliver(context.Background(), testAlert(), "o/r"); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	raw, _ := json.Marshal(got.body["labels"])
	for _, want := range []string{"detection", "severity:critical", "source:aws"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("labels = %s, missing %q", raw, want)
		}
	}
}

func TestDeliver_RejectsAMalformedTarget(t *testing.T) {
	var got capture
	c := serve(t, handler{status: 201, body: created}, &got)

	err := c.Deliver(context.Background(), testAlert(), "not-a-repo")
	if err == nil {
		t.Fatal("Deliver succeeded with a target that is not owner/repo")
	}
	if !destination.IsPermanent(err) {
		t.Error("a malformed target is a config error; no retry will fix it")
	}
	if got.requests != 0 {
		t.Error("a request was sent for a malformed target")
	}
}

// --- classification --------------------------------------------------------

func TestDeliver_ValidationFailureIsPermanent(t *testing.T) {
	c := serve(t, handler{status: 422, body: `{"message":"Validation Failed"}`}, nil)

	err := c.Deliver(context.Background(), testAlert(), "o/r")
	if !destination.IsPermanent(err) {
		t.Errorf("422 is not permanent: %v", err)
	}
	if !strings.Contains(err.Error(), "Validation Failed") {
		t.Errorf("error loses GitHub's reason: %v", err)
	}
}

func TestDeliver_IssuesDisabledIsPermanent(t *testing.T) {
	c := serve(t, handler{status: 410, body: `{"message":"Issues are disabled"}`}, nil)

	if err := c.Deliver(context.Background(), testAlert(), "o/r"); !destination.IsPermanent(err) {
		t.Errorf("410 is not permanent: %v", err)
	}
}

func TestDeliver_UnauthorizedIsAnAuthFailure(t *testing.T) {
	c := serve(t, handler{status: 401, body: `{"message":"Bad credentials"}`}, nil)

	err := c.Deliver(context.Background(), testAlert(), "o/r")
	if !destination.IsAuthFailure(err) {
		t.Errorf("401 is not an auth failure: %v", err)
	}
}

// A 404 on a repo the PAT cannot see is indistinguishable from one that does not
// exist, and both mean every alert to this repo is undeliverable.
func TestDeliver_NotFoundIsAnAuthFailure(t *testing.T) {
	c := serve(t, handler{status: 404, body: `{"message":"Not Found"}`}, nil)

	if err := c.Deliver(context.Background(), testAlert(), "o/r"); !destination.IsAuthFailure(err) {
		t.Errorf("404 is not an auth failure: %v", err)
	}
}

// The trap: GitHub uses 403 both for "you may not do this" and for the primary
// rate limit. Only the headers tell them apart.
func TestDeliver_RateLimited403IsTransient(t *testing.T) {
	c := serve(t, handler{
		status:  403,
		body:    `{"message":"API rate limit exceeded"}`,
		headers: map[string]string{"X-RateLimit-Remaining": "0"},
	}, nil)

	err := c.Deliver(context.Background(), testAlert(), "o/r")
	if err == nil {
		t.Fatal("Deliver succeeded on a 403")
	}
	if destination.IsPermanent(err) {
		t.Error("a rate-limited 403 must be transient; the limit resets")
	}
}

func TestDeliver_RetryAfter403IsTransient(t *testing.T) {
	c := serve(t, handler{
		status:  403,
		body:    `{"message":"You have exceeded a secondary rate limit"}`,
		headers: map[string]string{"Retry-After": "60"},
	}, nil)

	if err := c.Deliver(context.Background(), testAlert(), "o/r"); destination.IsPermanent(err) {
		t.Error("a secondary-rate-limit 403 must be transient")
	}
}

func TestDeliver_PermissionDenied403IsPermanent(t *testing.T) {
	c := serve(t, handler{
		status: 403,
		body:   `{"message":"Resource protected by organization SAML enforcement"}`,
	}, nil)

	if err := c.Deliver(context.Background(), testAlert(), "o/r"); !destination.IsPermanent(err) {
		t.Errorf("a 403 with no rate-limit marker must be permanent: %v", err)
	}
}

func TestDeliver_ServerErrorIsTransient(t *testing.T) {
	c := serve(t, handler{status: 502, body: `{"message":"Bad gateway"}`}, nil)

	err := c.Deliver(context.Background(), testAlert(), "o/r")
	if err == nil {
		t.Fatal("Deliver succeeded on a 502")
	}
	if destination.IsPermanent(err) {
		t.Error("a 502 must be transient")
	}
}

func TestDeliver_TooManyRequestsIsTransient(t *testing.T) {
	c := serve(t, handler{status: 429, body: `{"message":"Too many requests"}`}, nil)

	if err := c.Deliver(context.Background(), testAlert(), "o/r"); destination.IsPermanent(err) {
		t.Error("a 429 must be transient")
	}
}

func TestDeliver_ErrorsDoNotLeakTheToken(t *testing.T) {
	c := serve(t, handler{status: 422, body: `{"message":"Validation Failed"}`}, nil)

	err := c.Deliver(context.Background(), testAlert(), "o/r")
	if strings.Contains(err.Error(), "github_pat_test") {
		t.Fatalf("the PAT appears in an error: %v", err)
	}
}

func TestDeliver_FailsWhenTheTokenCannotBeRead(t *testing.T) {
	var got capture
	c := serve(t, handler{status: 201, body: created}, &got)
	c.Token = func(context.Context) (string, error) { return "", context.DeadlineExceeded }

	if err := c.Deliver(context.Background(), testAlert(), "o/r"); err == nil {
		t.Fatal("Deliver succeeded without a token")
	}
	if got.requests != 0 {
		t.Error("a request was sent despite having no token")
	}
}
