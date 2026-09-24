// Package slack delivers an alert to a Slack channel.
//
// Written against the HTTP API directly rather than through slack-go. The
// decision that matters in this service is classifying a failure as permanent or
// transient, and Slack encodes that in an {"ok":false,"error":"..."} body on an
// HTTP 200 -- so the classification has to be written here either way, and a
// library in between mostly hides the response the classification needs while
// adding its own retry and transport behaviour alongside the shared one. The
// GitHub destination is hand-rolled for the same reason, so the two read alike.
package slack

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
)

// DefaultBaseURL is Slack's Web API root.
const DefaultBaseURL = "https://slack.com/api"

// maxResponseBytes caps what we read back. chat.postMessage answers with a
// handful of fields; anything larger is a proxy or an error page.
const maxResponseBytes = 1 << 20

// permanentErrors will never succeed however often the alert is redelivered.
//
// The list is deliberately explicit and everything absent from it is treated as
// transient: misclassifying a transient error as permanent risks dropping a real
// detection, while the reverse costs four redeliveries.
var permanentErrors = map[string]bool{
	"channel_not_found":                     true,
	"channel_is_archived":                   true,
	"is_archived":                           true,
	"not_in_channel":                        true,
	"restricted_action":                     true,
	"restricted_action_read_only_channel":   true,
	"restricted_action_thread_only_channel": true,
	"msg_too_long":                          true,
	"no_text":                               true,
	"invalid_blocks":                        true,
	"invalid_blocks_format":                 true,
	"messages_tab_disabled":                 true,
	"team_access_not_granted":               true,
	"no_permission":                         true,
	"ekm_access_denied":                     true,
	"invalid_arguments":                     true,
}

// authErrors are permanent and also mean every other alert is undeliverable
// right now. They get their own classification so they can have their own
// alarm: the DLQ must not be the first hint that a token was rotated.
var authErrors = map[string]bool{
	"invalid_auth":     true,
	"not_authed":       true,
	"account_inactive": true,
	"token_revoked":    true,
	"token_expired":    true,
	"missing_scope":    true,
}

// Client posts alerts to Slack.
type Client struct {
	// HTTP should carry the shared retrying transport. Zero means
	// http.DefaultClient, which does not retry.
	HTTP *http.Client

	// Token returns the bot token. A function rather than a string so the
	// secret is fetched lazily, once per execution environment, and is never
	// held in a struct that might be logged.
	Token func(ctx context.Context) (string, error)

	// BaseURL overrides DefaultBaseURL. Tests and localstack set it.
	BaseURL string
}

// Name identifies this destination in routes and in the ledger.
func (c *Client) Name() string { return "slack" }

// Deliver posts one alert to one channel.
//
// target is the channel id the route chose.
func (c *Client) Deliver(ctx context.Context, a alert.Alert, target string) error {
	token, err := c.Token(ctx)
	if err != nil {
		return fmt.Errorf("reading the slack token: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"channel": target,
		"text":    render.SlackFallbackText(a),
		"blocks":  render.SlackBlocks(a),
	})
	if err != nil {
		// Rendering produced something unencodable. Redelivery will render the
		// same bytes, so this will never succeed.
		return destination.Permanent(fmt.Errorf("encoding the slack message: %w", err))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL()+"/chat.postMessage", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building the slack request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("posting to slack channel %s: %w", target, err)
	}
	defer drain(resp)

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("reading slack's response: %w", err)
	}

	var answer struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	// A body we cannot parse is only worth reporting if the status was not
	// already telling us something.
	_ = json.Unmarshal(body, &answer)

	if answer.OK {
		return nil
	}

	reason := answer.Error
	if reason == "" {
		reason = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	// Deliberately does not include the request: the payload carries audit-log
	// content and the header carries the token.
	err = fmt.Errorf("slack rejected the message for channel %s: %s", target, reason)

	switch {
	case authErrors[answer.Error]:
		return destination.AuthFailure(err)
	case permanentErrors[answer.Error]:
		return destination.Permanent(err)
	default:
		// Includes every 5xx, ratelimited, and anything Slack adds later.
		return err
	}
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

// drain reads and closes the rest of a response so the connection is reused.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	resp.Body.Close()
}

// Compile-time check that this satisfies the registry's contract.
var _ destination.Destination = (*Client)(nil)
