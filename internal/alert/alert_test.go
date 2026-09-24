package alert_test

import (
	"errors"
	"testing"
	"time"

	"github.com/samma-io/alert-destination/internal/alert"
)

const fullBody = `{
  "schema_version": "detection.alert.v1",
  "id": "det_3436971c209fbe1d",
  "alerted_at": "2026-09-02T15:07:22.118Z",
  "log_source": "aws",
  "rule": {"id":"7f8b1c42","title":"CloudTrail Logging Disabled","level":"high",
           "description":"someone turned it off","tags":["attack.defense_evasion"],
           "references":["https://example.invalid"],"file":"aws/cloudtrail_logging_disabled.yml"},
  "provenance": {"bucket":"filtered-1-us-east-1","key":"aws/date=2026-09-02/x.ndjson.gz",
                 "event_index":4,"sqs_message_id":"600eba1f"},
  "event": {"eventName":"StopLogging"},
  "event_sha256": "abc123",
  "event_bytes": 412
}`

func TestDecode_ReadsEveryFieldOfTheEnvelope(t *testing.T) {
	a, err := alert.Decode([]byte(fullBody))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if a.ID != "det_3436971c209fbe1d" {
		t.Errorf("ID = %q", a.ID)
	}
	if a.LogSource != "aws" {
		t.Errorf("LogSource = %q", a.LogSource)
	}
	if a.Rule.Level != "high" {
		t.Errorf("Rule.Level = %q", a.Rule.Level)
	}
	if a.Rule.Title != "CloudTrail Logging Disabled" {
		t.Errorf("Rule.Title = %q", a.Rule.Title)
	}
	if a.Provenance.EventIndex != 4 {
		t.Errorf("Provenance.EventIndex = %d", a.Provenance.EventIndex)
	}
	if a.Provenance.Key != "aws/date=2026-09-02/x.ndjson.gz" {
		t.Errorf("Provenance.Key = %q", a.Provenance.Key)
	}
	if got := a.Event["eventName"]; got != "StopLogging" {
		t.Errorf("Event[eventName] = %v", got)
	}
	if a.EventBytes != 412 {
		t.Errorf("EventBytes = %d", a.EventBytes)
	}
	want := time.Date(2026, 9, 2, 15, 7, 22, 118_000_000, time.UTC)
	if !a.AlertedAt.Equal(want) {
		t.Errorf("AlertedAt = %v, want %v", a.AlertedAt, want)
	}
}

// The producer drops the event body rather than the alert when it would exceed
// the SQS message limit, keeping provenance so the original is recoverable.
func TestDecode_TruncatedAlertHasNoEvent(t *testing.T) {
	body := `{"schema_version":"detection.alert.v1","id":"det_1","log_source":"aws",
	          "rule":{"id":"r","title":"t","level":"low","file":"f"},
	          "provenance":{"bucket":"b","key":"k","event_index":0},
	          "truncated":true,"event_sha256":"s","event_bytes":300000}`

	a, err := alert.Decode([]byte(body))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !a.Truncated {
		t.Error("Truncated = false, want true")
	}
	if a.Event != nil {
		t.Errorf("Event = %v, want nil", a.Event)
	}
}

// We cannot deduplicate without an id, and guessing is worse than the DLQ.
func TestDecode_MissingIDIsPermanent(t *testing.T) {
	body := `{"schema_version":"detection.alert.v1","log_source":"aws",
	          "rule":{"id":"r","title":"t","level":"low","file":"f"},
	          "provenance":{"bucket":"b","key":"k","event_index":0}}`

	_, err := alert.Decode([]byte(body))
	if err == nil {
		t.Fatal("Decode succeeded, want an error")
	}
	if !errors.Is(err, alert.ErrIncomplete) {
		t.Errorf("err = %v, want ErrIncomplete", err)
	}
}

// We cannot route without a level, for the same reason.
func TestDecode_MissingLevelIsPermanent(t *testing.T) {
	body := `{"schema_version":"detection.alert.v1","id":"det_1","log_source":"aws",
	          "rule":{"id":"r","title":"t","file":"f"},
	          "provenance":{"bucket":"b","key":"k","event_index":0}}`

	_, err := alert.Decode([]byte(body))
	if !errors.Is(err, alert.ErrIncomplete) {
		t.Errorf("err = %v, want ErrIncomplete", err)
	}
}

func TestDecode_MalformedJSONIsAnError(t *testing.T) {
	if _, err := alert.Decode([]byte(`{"id":`)); err == nil {
		t.Fatal("Decode succeeded on malformed JSON, want an error")
	}
}

// A producer-side schema bump must not DLQ every alert, so an unfamiliar
// version is reported rather than rejected.
func TestDecode_UnknownSchemaVersionIsReportedNotRejected(t *testing.T) {
	body := `{"schema_version":"detection.alert.v2","id":"det_1","log_source":"aws",
	          "rule":{"id":"r","title":"t","level":"low","file":"f"},
	          "provenance":{"bucket":"b","key":"k","event_index":0}}`

	a, err := alert.Decode([]byte(body))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if a.KnownSchema() {
		t.Error("KnownSchema() = true for detection.alert.v2, want false")
	}
}

func TestKnownSchema_TrueForTheVersionWeWereBuiltAgainst(t *testing.T) {
	a, err := alert.Decode([]byte(fullBody))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !a.KnownSchema() {
		t.Error("KnownSchema() = false, want true")
	}
}
