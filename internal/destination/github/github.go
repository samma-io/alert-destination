// Package github delivers an alert as a GitHub issue.
//
// One API call per alert: POST /repos/{owner}/{repo}/issues. There is
// deliberately no search-before-create. Deduplication belongs to the delivery
// ledger, which is strongly consistent and ours; GitHub's issue search index
// lags by seconds to minutes, which is about the same as the SQS redelivery
// interval, so a search-based check misses in exactly the window it would exist
// to protect -- and at 30 requests a minute it starts refusing during any burst,
// at which point it is a second failure mode rather than a safeguard.
//
// The residual risk is a crash in the few milliseconds between GitHub answering
// 201 and the ledger row landing, which produces a second issue on redelivery.
// That is why the alert id is in the issue title: the duplicate is obvious, and
// `gh issue list --search det_...` finds both.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/render"
	"github.com/samma-io/alert-destination/internal/version"
)

// DefaultBaseURL is the public GitHub API root.
const DefaultBaseURL = "https://api.github.com"

// APIVersion pins the REST API's behaviour. Without it GitHub applies whatever
// its current default is, which can change under a running service.
const APIVersion = "2022-11-28"

const maxResponseBytes = 1 << 20

// Client creates issues.
type Client struct {
	// HTTP should carry the shared retrying transport. Zero means
	// http.DefaultClient, which does not retry.
	HTTP *http.Client

	// Token returns the fine-grained PAT. A function so the secret is fetched
	// lazily and never sits in a struct that might be logged.
	Token func(ctx context.Context) (string, error)

	// BaseURL overrides DefaultBaseURL. Tests and GitHub Enterprise set it.
	BaseURL string
}

// Name identifies this destination in routes and in the ledger.
func (c *Client) Name() string { return "github" }

// Deliver files one alert as an issue in target, which is "owner/repo".
func (c *Client) Deliver(ctx context.Context, a alert.Alert, target string) error {
	owner, repo, ok := splitRepo(target)
	if !ok {
		// A config mistake rather than an outage. Redelivery cannot fix it, and
		// saying so stops it burning five receives.
		return destination.Permanent(fmt.Errorf(
			"github target %q is not owner/repo", target))
	}

	token, err := c.Token(ctx)
	if err != nil {
		return fmt.Errorf("reading the github token: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"title":  render.GitHubTitle(a),
		"body":   render.GitHubBody(a),
		"labels": render.GitHubLabels(a),
	})
	if err != nil {
		return destination.Permanent(fmt.Errorf("encoding the github issue: %w", err))
	}

	url := fmt.Sprintf("%s/repos/%s/%s/issues", c.baseURL(), owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building the github request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("creating an issue in %s: %w", target, err)
	}
	defer drain(resp)

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	return classify(resp, target, reason(body, resp.StatusCode))
}

// classify turns a rejected response into the right kind of error.
//
// The hard case is 403, which GitHub uses both for "this credential may not do
// that" and for the primary rate limit. Only the headers and the message
// separate them, and getting it wrong in the permanent direction would drop a
// real detection.
func classify(resp *http.Response, target, why string) error {
	err := fmt.Errorf("github rejected an issue for %s: %s", target, why)

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusNotFound:
		// 404 is indistinguishable from a repository the credential cannot see,
		// and either way every alert routed here is undeliverable.
		return destination.AuthFailure(err)

	case http.StatusForbidden:
		if rateLimited(resp, why) {
			return err // transient: the limit resets
		}
		return destination.Permanent(err)

	case http.StatusTooManyRequests:
		return err // transient

	case http.StatusGone, // issues disabled on the repository
		http.StatusUnprocessableEntity, // validation: missing label, body too long
		http.StatusUnavailableForLegalReasons:
		return destination.Permanent(err)
	}

	if resp.StatusCode >= 500 {
		return err // transient
	}
	// An unrecognised 4xx. Prefer retrying: four wasted receives beats a
	// dropped detection.
	return err
}

// rateLimited reports whether a 403 is throttling rather than a refusal.
func rateLimited(resp *http.Response, why string) bool {
	if resp.Header.Get("Retry-After") != "" {
		return true
	}
	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		return true
	}
	return strings.Contains(strings.ToLower(why), "rate limit")
}

// reason pulls GitHub's own message out of the response, falling back to the
// status. The request is never included: its headers carry the credential and
// its body carries audit-log content.
func reason(body []byte, status int) string {
	var answer struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &answer); err == nil && answer.Message != "" {
		return fmt.Sprintf("HTTP %d: %s", status, answer.Message)
	}
	return fmt.Sprintf("HTTP %d", status)
}

func splitRepo(target string) (owner, repo string, ok bool) {
	owner, repo, ok = strings.Cut(target, "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", false
	}
	return owner, repo, true
}

func (c *Client) baseURL() string {
	if c.BaseURL != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}
	return DefaultBaseURL
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	resp.Body.Close()
}

// Compile-time check that this satisfies the registry's contract.
var _ destination.Destination = (*Client)(nil)
