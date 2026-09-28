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
	"strconv"
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

	// InvalidateToken, when set, is called on an authentication failure so the
	// next delivery re-reads the token, picking up a rotation without a restart.
	InvalidateToken func()
}

// Name identifies this destination in routes and in the ledger.
func (c *Client) Name() string { return "github" }

// Deliver files one alert as an issue in target, which is "owner/repo". The Ref
// is the new issue's number and html_url.
func (c *Client) Deliver(ctx context.Context, a alert.Alert, target string) (destination.Ref, error) {
	owner, repo, ok := splitRepo(target)
	if !ok {
		// A config mistake rather than an outage. Redelivery cannot fix it, and
		// saying so stops it burning five receives.
		return nil, destination.Permanent(destination.WithDetail(fmt.Errorf(
			"github target %q is not owner/repo", target), "invalid_target", 0))
	}

	token, err := c.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the github token: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"title":  render.GitHubTitle(a),
		"body":   render.GitHubBody(a),
		"labels": render.GitHubLabels(a),
	})
	if err != nil {
		return nil, destination.Permanent(fmt.Errorf("encoding the github issue: %w", err))
	}

	url := fmt.Sprintf("%s/repos/%s/%s/issues", c.baseURL(), owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building the github request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("creating an issue in %s: %w", target, err)
	}
	defer drain(resp)

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return issueRef(body), nil
	}
	err = classify(resp, target, reason(body, resp.StatusCode))
	if destination.IsAuthFailure(err) && c.InvalidateToken != nil {
		c.InvalidateToken()
	}
	return nil, err
}

// issueRef pulls the issue's number and url out of the 201. The issue exists
// whether or not the body parses, so a body we cannot read is an empty Ref,
// never an error: failing here would open a second issue on the retry.
func issueRef(body []byte) destination.Ref {
	var issue struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if json.Unmarshal(body, &issue) != nil || issue.Number == 0 {
		return nil
	}
	return destination.Ref{"number": strconv.Itoa(issue.Number), "html_url": issue.HTMLURL}
}

// classify turns a rejected response into the right kind of error.
//
// The hard case is 403, which GitHub uses both for "this credential may not do
// that" and for the primary rate limit. Only the headers and the message
// separate them, and getting it wrong in the permanent direction would drop a
// real detection.
func classify(resp *http.Response, target, why string) error {
	plain := fmt.Errorf("github rejected an issue for %s: %s", target, why)
	err := destination.WithDetail(plain, code(resp.StatusCode), resp.StatusCode)

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusNotFound:
		// 404 is indistinguishable from a repository the credential cannot see,
		// and either way every alert routed here is undeliverable.
		return destination.AuthFailure(err)

	case http.StatusForbidden:
		if rateLimited(resp, why) {
			// transient: the limit resets
			return destination.WithDetail(plain, "rate_limited", resp.StatusCode)
		}
		return destination.Permanent(err)

	case http.StatusTooManyRequests:
		return destination.WithDetail(plain, "rate_limited", resp.StatusCode) // transient

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

// code is the ledger's reason code for a rejected issue. GitHub's REST errors
// carry a sentence rather than a code, so the status's own name stands in:
// "unprocessable_entity" for a missing label, "not_found" for a repository the
// token cannot see.
func code(status int) string {
	text := http.StatusText(status)
	if text == "" {
		return fmt.Sprintf("http_%d", status)
	}
	return strings.ReplaceAll(strings.ToLower(text), " ", "_")
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
