// Package alert is the consumer-side view of the detection plane's message.
//
// The producing type lives in samma-io/detection-engine
// (internal/alert/alert.go). It is deliberately re-declared here rather than
// imported: the queue, not a Go package, is the contract between the two
// services, and importing the engine would couple this Lambda's build to a repo
// whose internal packages are not importable anyway.
//
// Only the fields this service reads are declared. Anything the engine adds
// later is ignored, which is what lets it add fields without a deploy here.
package alert

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SchemaVersion is the version this service was written against.
//
// A different version is reported by KnownSchema, not rejected. Rejecting would
// turn a producer-side schema bump into every alert in the queue walking to the
// DLQ, which is a far worse failure than rendering an alert whose new field we
// do not know about.
const SchemaVersion = "detection.alert.v1"

// ErrIncomplete reports an alert missing a field this service cannot work
// without. It is permanent: no number of redeliveries adds an id to a message
// that does not have one.
var ErrIncomplete = errors.New("alert is missing a required field")

// Alert is one rule firing on one event.
type Alert struct {
	SchemaVersion string    `json:"schema_version"`
	ID            string    `json:"id"`
	AlertedAt     time.Time `json:"alerted_at"`

	// LogSource is the deployment that produced this alert: aws, gcp, github,
	// workspace or slack. Not "source" -- Vector stamps a "source" field inside
	// every filtered event, and the two would be different things.
	LogSource string `json:"log_source"`

	Rule       Rule       `json:"rule"`
	Provenance Provenance `json:"provenance"`

	// Event is the matched record. Nil when Truncated is set.
	Event map[string]any `json:"event,omitempty"`

	// Truncated reports that the producer dropped Event because the alert
	// exceeded the SQS message limit. Provenance still names the object and the
	// record index, so every renderer must degrade to Rule plus Provenance
	// rather than assuming Event is there.
	Truncated bool `json:"truncated,omitempty"`

	EventSHA256 string `json:"event_sha256,omitempty"`
	EventBytes  int    `json:"event_bytes,omitempty"`
}

// Rule is the firing rule's metadata, as the engine extracted it.
type Rule struct {
	RuleID      string   `json:"id"`
	Title       string   `json:"title"`
	Level       string   `json:"level,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	References  []string `json:"references,omitempty"`
	File        string   `json:"file"`
}

// Provenance is where the event came from, in enough detail to fetch it again.
type Provenance struct {
	Bucket     string `json:"bucket"`
	Key        string `json:"key"` // decoded, not URL-encoded
	EventIndex int    `json:"event_index"`

	// SQSMessageID is the delivery that produced this alert upstream. It
	// changes on redelivery, so nothing here may key on it.
	SQSMessageID string `json:"sqs_message_id,omitempty"`
}

// Decode parses one queue message.
//
// Two fields are required and their absence is permanent: ID, because it is the
// only thing that makes delivery idempotent, and Rule.Level, because it is half
// of the routing key. Everything else can be missing and still produce a useful
// notification.
func Decode(body []byte) (Alert, error) {
	var a Alert
	if err := json.Unmarshal(body, &a); err != nil {
		return Alert{}, fmt.Errorf("decoding alert: %w", err)
	}

	var missing []string
	if a.ID == "" {
		missing = append(missing, "id")
	}
	if a.Rule.Level == "" {
		missing = append(missing, "rule.level")
	}
	if len(missing) > 0 {
		return Alert{}, fmt.Errorf("%w: %v", ErrIncomplete, missing)
	}

	return a, nil
}

// KnownSchema reports whether the alert carries the version this service was
// built against. A false answer is worth a warning and a metric; it is not
// worth refusing to deliver.
func (a Alert) KnownSchema() bool { return a.SchemaVersion == SchemaVersion }
