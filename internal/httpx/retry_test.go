package httpx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/samma-io/alert-destination/internal/httpx"
)

func newClient(t *testing.T, rt *httpx.RetryTransport) *http.Client {
	t.Helper()
	rt.Sleep = func(context.Context, time.Duration) error { return nil } // tests do not wait
	return &http.Client{Transport: rt}
}

func post(t *testing.T, c *http.Client, url, body string) *http.Response {
	t.Helper()
	resp, err := c.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestRoundTrip_RetriesA503(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp := post(t, newClient(t, &httpx.RetryTransport{MaxRetries: 3}), srv.URL, "{}")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestRoundTrip_DoesNotRetryA422(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer srv.Close()

	post(t, newClient(t, &httpx.RetryTransport{MaxRetries: 3}), srv.URL, "{}")

	if attempts != 1 {
		t.Errorf("attempts = %d, want 1; a validation error will never succeed", attempts)
	}
}

func TestRoundTrip_GivesUpAfterMaxRetries(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	resp := post(t, newClient(t, &httpx.RetryTransport{MaxRetries: 2}), srv.URL, "{}")

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want the last response returned", resp.StatusCode)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3 (one try plus two retries)", attempts)
	}
}

// The body has to be replayed on every attempt or the retry sends an empty POST.
func TestRoundTrip_ResendsTheRequestBodyOnEveryAttempt(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64)
		n, _ := r.Body.Read(buf)
		bodies = append(bodies, string(buf[:n]))
		if len(bodies) < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	post(t, newClient(t, &httpx.RetryTransport{MaxRetries: 2}), srv.URL, `{"hello":"world"}`)

	if len(bodies) != 2 {
		t.Fatalf("attempts = %d, want 2", len(bodies))
	}
	if bodies[0] != bodies[1] {
		t.Errorf("retry sent %q, first attempt sent %q", bodies[1], bodies[0])
	}
}

// GitHub's secondary-rate-limit Retry-After is routinely 60s. Honouring it
// inside a 60s Lambda sleeps through the whole budget and the invocation dies
// with "Task timed out" and no structured log. SQS's 120s redelivery is the
// long backoff; this transport's job is to give up quickly.
func TestRoundTrip_DoesNotSleepPastTheCeiling(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	var slept []time.Duration
	rt := &httpx.RetryTransport{MaxRetries: 2, MaxWait: 2 * time.Second}
	rt.Sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}

	resp := post(t, &http.Client{Transport: rt}, srv.URL, "{}")

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 returned rather than waited out", resp.StatusCode)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1: a 600s Retry-After must end the attempt, not be slept", attempts)
	}
	for _, d := range slept {
		if d > 2*time.Second {
			t.Errorf("slept %s, over the %s ceiling", d, 2*time.Second)
		}
	}
}

func TestRoundTrip_HonoursARetryAfterInsideTheCeiling(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var slept []time.Duration
	rt := &httpx.RetryTransport{MaxRetries: 2, MaxWait: 10 * time.Second}
	rt.Sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}

	resp := post(t, &http.Client{Transport: rt}, srv.URL, "{}")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if len(slept) != 1 || slept[0] < time.Second {
		t.Errorf("slept = %v, want one wait of at least the advertised 1s", slept)
	}
}

// A destination may signal throttling in the body on an otherwise fine status;
// Slack answers 200 with {"ok":false,"error":"ratelimited"}.
func TestRoundTrip_PolicyCanForceARetryOnA200(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			w.Write([]byte(`{"ok":false,"error":"ratelimited"}`))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	rt := &httpx.RetryTransport{
		MaxRetries: 2,
		Policy: func(resp *http.Response) bool {
			body, err := httpx.Peek(resp, 1024)
			return err == nil && strings.Contains(string(body), "ratelimited")
		},
	}
	resp := post(t, newClient(t, rt), srv.URL, "{}")

	if attempts != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

// Peek must leave the body readable, or the caller that decides to retry can no
// longer parse the response it decided not to retry.
func TestPeek_RestoresTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
	}))
	defer srv.Close()

	resp := post(t, newClient(t, &httpx.RetryTransport{}), srv.URL, "{}")

	peeked, err := httpx.Peek(resp, 1024)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	rest := make([]byte, len(peeked))
	if _, err := resp.Body.Read(rest); err != nil && err.Error() != "EOF" {
		t.Fatalf("reading the restored body: %v", err)
	}
	if string(peeked) != string(rest) {
		t.Errorf("body after Peek = %q, want %q", rest, peeked)
	}
}

func TestRoundTrip_StopsWhenTheContextIsCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	rt := &httpx.RetryTransport{MaxRetries: 5}
	rt.Sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader("{}"))

	if _, err := (&http.Client{Transport: rt}).Do(req); err == nil {
		t.Fatal("Do succeeded despite a cancelled context")
	}
}
