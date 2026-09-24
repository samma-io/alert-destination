// Package ledger records which alerts have been delivered where.
//
// It exists because every path into this service is at-least-once and the
// destinations are not all idempotent: GitHub would open a second issue and
// Slack would post a second message. The producer made that tractable by
// deriving the alert id from the finding rather than the delivery -- see the
// doc comment on alert.ID in detection-engine -- so a redelivery of the same
// finding presents the same key here.
//
// Two properties are load-bearing and are each pinned by a test:
//
//   - Only a delivered record suppresses a retry. Failures are recorded too, but
//     purely as forensics: SQS cannot annotate a message on its way to the DLQ,
//     so without this the operator who opens the DLQ sees an alert id and
//     nothing about why it is there. A failed record that gated a retry would be
//     a silent drop, which is the failure this whole service exists to prevent.
//
//   - The record is written after the destination confirms, never before.
//     Writing first would mean a crash between the two produced an alert that
//     will never be delivered and never retried -- the same mistake as deleting
//     an SQS message before the work is durable. Writing after means the
//     residual failure is a duplicate, which is noise rather than loss.
package ledger

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// DefaultTTL is how long a delivery record survives.
//
// The floor is set by the worst redrive: 14 days in the alert queue, 14 more in
// the DLQ, and an operator redriving on the last day, which is 42 days during
// which the ledger must still say "delivered" or the redrive re-notifies
// everything. 90 days clears that with margin and makes the table usable for
// incident lookback, which is the other thing anyone ever wants from it.
const DefaultTTL = 90 * 24 * time.Hour

// Status is what happened to one delivery.
type Status string

const (
	// StatusDelivered is the only value that suppresses a retry.
	StatusDelivered Status = "delivered"
	// StatusFailed is forensics. It gates nothing.
	StatusFailed Status = "failed"
)

// ErrAlreadyRecorded is returned by a Store when a conditional write finds the
// row already present.
var ErrAlreadyRecorded = errors.New("ledger: row already recorded")

// Key identifies one delivery of one alert to one address.
//
// Target is part of the identity because a destination is one client writing to
// whichever address the route chose: the same alert sent to two Slack channels
// is two deliveries, and a key of (alert, destination) alone would record the
// first and silently suppress the second.
type Key struct {
	AlertID     string
	Destination string
	Target      string
}

// PK is the partition key: every delivery of one alert shares it, so one query
// answers "where has this alert been".
func (k Key) PK() string { return "ALERT#" + k.AlertID }

// SK is the sort key within that partition.
func (k Key) SK() string { return "DEST#" + k.Destination + "#" + k.Target }

// Record is one row.
type Record struct {
	PK string
	SK string

	AlertID     string
	Destination string
	Target      string

	Status   Status
	Attempts int

	FirstAttemptAt time.Time
	LastAttemptAt  time.Time
	DeliveredAt    time.Time

	// Ref is whatever identifies the delivery at the destination -- an issue
	// number and url, a Slack channel and ts. It is what makes "which issue is
	// this alert" a lookup here instead of a search over there.
	Ref map[string]string

	// Failure detail. Meaningless unless Status is StatusFailed.
	Permanent  bool
	Code       string
	HTTPStatus int
	Message    string

	// ExpiresAt is epoch SECONDS. DynamoDB reads TTL as seconds; milliseconds
	// put the expiry in the year 51,000 and the row is never collected.
	ExpiresAt int64
}

// Failure is why one delivery did not happen.
type Failure struct {
	Permanent  bool
	Code       string
	HTTPStatus int
	Message    string
}

// Store is the persistence this package needs, in plain Go types.
//
// Declared here rather than taken as a DynamoDB client so that no test of this
// package needs AWS credentials and no business package imports the SDK -- the
// arch test enforces the second half.
type Store interface {
	// Query returns every row in one partition.
	Query(ctx context.Context, pk string) ([]Record, error)

	// PutIfAbsent writes a row only if it does not exist, returning
	// ErrAlreadyRecorded if it does.
	PutIfAbsent(ctx context.Context, r Record) error

	// Upsert writes a row, accumulating Attempts onto any existing one and
	// preserving its FirstAttemptAt.
	Upsert(ctx context.Context, r Record) error
}

// Ledger is the delivery record.
type Ledger struct {
	Store Store

	// TTL overrides DefaultTTL. Zero means DefaultTTL.
	TTL time.Duration

	// Now is injected so tests do not depend on the clock. Zero means time.Now.
	Now func() time.Time
}

// Delivered returns the sort keys already delivered for this alert.
//
// Failed rows are deliberately absent from the result: only a delivered record
// suppresses a retry.
func (l *Ledger) Delivered(ctx context.Context, alertID string) (map[string]bool, error) {
	rows, err := l.Store.Query(ctx, Key{AlertID: alertID}.PK())
	if err != nil {
		return nil, fmt.Errorf("reading delivery ledger for %s: %w", alertID, err)
	}

	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		if r.Status == StatusDelivered {
			out[r.SK] = true
		}
	}
	return out, nil
}

// RecordDelivered writes a confirmed delivery.
//
// It reports duplicate=true when the conditional write was rejected. That is not
// an error -- the outcome is the one we wanted -- but it means we delivered
// twice, because the only way to reach this call is a pre-flight read that said
// otherwise. Counting it is the only way the race is ever visible.
func (l *Ledger) RecordDelivered(ctx context.Context, k Key, ref map[string]string) (bool, error) {
	now := l.now()
	r := l.row(k, now)
	r.Status = StatusDelivered
	r.DeliveredAt = now
	r.Ref = ref

	switch err := l.Store.PutIfAbsent(ctx, r); {
	case err == nil:
		return false, nil
	case errors.Is(err, ErrAlreadyRecorded):
		return true, nil
	default:
		return false, fmt.Errorf("recording delivery of %s to %s: %w", k.AlertID, k.Destination, err)
	}
}

// RecordFailure writes why a delivery did not happen.
//
// This row gates nothing. It exists so that whoever opens the DLQ can answer
// "slack delivered at 10:02, github failed five times with 422 Validation
// Failed" from one query instead of correlating logs.
func (l *Ledger) RecordFailure(ctx context.Context, k Key, f Failure) error {
	r := l.row(k, l.now())
	r.Status = StatusFailed
	r.Permanent = f.Permanent
	r.Code = f.Code
	r.HTTPStatus = f.HTTPStatus
	r.Message = f.Message

	if err := l.Store.Upsert(ctx, r); err != nil {
		return fmt.Errorf("recording failed delivery of %s to %s: %w", k.AlertID, k.Destination, err)
	}
	return nil
}

func (l *Ledger) row(k Key, now time.Time) Record {
	return Record{
		PK:             k.PK(),
		SK:             k.SK(),
		AlertID:        k.AlertID,
		Destination:    k.Destination,
		Target:         k.Target,
		Attempts:       1,
		FirstAttemptAt: now,
		LastAttemptAt:  now,
		ExpiresAt:      now.Add(l.ttl()).Unix(),
	}
}

func (l *Ledger) ttl() time.Duration {
	if l.TTL > 0 {
		return l.TTL
	}
	return DefaultTTL
}

func (l *Ledger) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now().UTC()
}
