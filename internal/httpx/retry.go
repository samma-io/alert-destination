// Package httpx is the retrying HTTP transport the destinations share.
//
// One choice is deliberate and unusual: Retry-After is capped. A long-running
// task can treat an advertised wait as a floor with no ceiling; a Lambda cannot.
// GitHub's secondary-rate-limit Retry-After is routinely 60s, and honouring that
// inside a 60s Lambda spends the whole budget asleep and ends in "Task timed
// out" with no structured log and nothing written to the ledger. SQS's 120s
// redelivery is the long backoff; this transport's job is to give up fast and
// let the message come back.
package httpx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// Defaults applied when a RetryTransport field is left zero.
const (
	DefaultInitial    = 500 * time.Millisecond
	DefaultMax        = 2 * time.Second
	DefaultMaxRetries = 2

	// DefaultMaxWait caps how long an advertised Retry-After may hold the
	// invocation. Past this we return the response and let SQS redeliver.
	DefaultMaxWait = 10 * time.Second

	// MaxErrorBody caps how much of a response a Policy may buffer to find a
	// reason code in it.
	MaxErrorBody = 1 << 20
)

// retryableStatus are the statuses always worth another attempt, whatever the
// API. Anything a particular service signals in a body belongs in its Policy.
var retryableStatus = map[int]bool{
	http.StatusTooManyRequests:     true,
	http.StatusInternalServerError: true,
	http.StatusBadGateway:          true,
	http.StatusServiceUnavailable:  true,
	http.StatusGatewayTimeout:      true,
}

// Policy decides whether one response warrants another attempt.
//
// It may read resp.Body -- use Peek, which restores it -- because several APIs
// report throttling in a body rather than in a status. Slack answers HTTP 200
// with {"ok":false,"error":"ratelimited"}.
type Policy func(resp *http.Response) bool

// RetryTransport retries idempotent-by-construction requests.
type RetryTransport struct {
	Base    http.RoundTripper
	Policy  Policy
	Initial time.Duration
	Max     time.Duration

	// MaxWait caps an advertised Retry-After. Zero means DefaultMaxWait.
	MaxWait time.Duration

	MaxRetries int

	// Sleep is injected so tests do not wait. Zero means a context-aware sleep.
	Sleep func(context.Context, time.Duration) error
}

// RoundTrip sends the request, retrying while the policy says to.
func (t *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !replayable(req) {
		// A body we cannot rewind would be sent empty on the second attempt,
		// which is worse than not retrying.
		return t.base().RoundTrip(req)
	}

	var resp *http.Response
	var err error

	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			if rerr := rewind(req); rerr != nil {
				return nil, rerr
			}
		}

		resp, err = t.base().RoundTrip(req)
		if err != nil {
			if attempt >= t.maxRetries() {
				return nil, err
			}
			if serr := t.sleep(req.Context(), t.backoff(attempt), 0); serr != nil {
				return nil, serr
			}
			continue
		}

		if attempt >= t.maxRetries() || !t.shouldRetry(resp) {
			return resp, nil
		}

		wait, ok := t.waitFor(resp, attempt)
		if !ok {
			// The server asked for longer than we are prepared to hold the
			// invocation. Hand the response back; the caller classifies it as
			// transient and the message is redelivered.
			return resp, nil
		}

		drain(resp)
		if serr := t.sleep(req.Context(), wait, 0); serr != nil {
			return nil, serr
		}
	}
}

// shouldRetry reports whether this response is worth another attempt.
func (t *RetryTransport) shouldRetry(resp *http.Response) bool {
	if retryableStatus[resp.StatusCode] {
		return true
	}
	return t.Policy != nil && t.Policy(resp)
}

// waitFor returns how long to wait before the next attempt, and whether waiting
// is worth it at all.
func (t *RetryTransport) waitFor(resp *http.Response, attempt int) (time.Duration, bool) {
	wait := t.backoff(attempt)
	if advertised := parseRetryAfter(resp.Header.Get("Retry-After")); advertised > 0 {
		if advertised > t.maxWait() {
			return 0, false
		}
		if advertised > wait {
			wait = advertised
		}
	}
	return wait, true
}

// backoff is exponential with jitter and a low ceiling.
func (t *RetryTransport) backoff(attempt int) time.Duration {
	d := t.initial() << uint(attempt)
	if d > t.max() {
		d = t.max()
	}
	return t.jitter(d)
}

// jitter spreads retries so concurrent invocations do not re-converge on the
// destination at the same instant.
func (t *RetryTransport) jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func (t *RetryTransport) sleep(ctx context.Context, d, _ time.Duration) error {
	if t.Sleep != nil {
		return t.Sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (t *RetryTransport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *RetryTransport) initial() time.Duration {
	if t.Initial > 0 {
		return t.Initial
	}
	return DefaultInitial
}

func (t *RetryTransport) max() time.Duration {
	if t.Max > 0 {
		return t.Max
	}
	return DefaultMax
}

func (t *RetryTransport) maxWait() time.Duration {
	if t.MaxWait > 0 {
		return t.MaxWait
	}
	return DefaultMaxWait
}

func (t *RetryTransport) maxRetries() int {
	if t.MaxRetries > 0 {
		return t.MaxRetries
	}
	return DefaultMaxRetries
}

// Peek reads up to n bytes of a response body and puts them back, so a Policy
// can look for a reason code without consuming the body the caller still needs.
func Peek(resp *http.Response, n int64) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	if n > MaxErrorBody {
		n = MaxErrorBody
	}

	buf, err := io.ReadAll(io.LimitReader(resp.Body, n))
	if err != nil {
		return nil, err
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body}
	return buf, nil
}

// replayable reports whether the request body can be sent again.
func replayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

func rewind(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if req.GetBody == nil {
		return errors.New("httpx: request body cannot be replayed")
	}
	body, err := req.GetBody()
	if err != nil {
		return err
	}
	req.Body = body
	return nil
}

// drain reads and closes a response we are discarding, so the connection is
// reused rather than abandoned mid-stream.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, MaxErrorBody))
	resp.Body.Close()
}

// parseRetryAfter reads both forms of the header: delta-seconds and HTTP-date.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}
