// Package archive keeps a copy of every alert in S3 before anything is
// delivered.
//
// The destinations are where humans read an alert; none of them is a record. A
// Slack message can be deleted, an issue closed and edited, and the ledger
// expires after 90 days. The archive is the durable answer to "what did the
// detection plane say, and when", queryable in Athena alongside the lanes.
//
// The key is a function of the alert alone, so a redelivery writes the same
// object again rather than a second one, and the ledger records the write under
// the destination name "archive" so a replay usually skips it altogether.
package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/samma-io/alert-destination/internal/alert"
)

// Destination is the name the archive write is recorded under in the ledger.
// It is not a routable destination: every alert is archived, whatever the
// routing table says.
const Destination = "archive"

// Prefix is where alerts land in the bucket. The Glue table over the archive
// reads this prefix, partitioned by log_source and date.
const Prefix = "alerts/"

// unknownLane stands in for a log_source that is missing or cannot be a
// partition value, so an odd alert is still archived rather than refused.
const unknownLane = "unknown"

// Store writes one object. Declared in plain Go types so nothing here, and no
// test of it, needs the AWS SDK; awsadapt.ObjectStore satisfies it.
type Store interface {
	// Put writes body under key, replacing whatever is there.
	Put(ctx context.Context, key string, body []byte) error
}

// Archive writes alerts to one bucket.
type Archive struct {
	Store Store

	// Bucket is recorded as the ledger target and logged. The Store already
	// knows where it writes.
	Bucket string

	// Now dates an alert with no alerted_at. Zero means time.Now.
	Now func() time.Time
}

// Put archives one alert and returns the key it was written under.
//
// The body is the alert exactly as received, on one line with a trailing
// newline, which is the shape the Glue table reads (a single `line` column).
func (ar *Archive) Put(ctx context.Context, a alert.Alert) (string, error) {
	key := Key(a, ar.now())

	body := a.Raw
	if len(body) == 0 {
		// Only an alert built in code rather than decoded from the queue has no
		// raw form. Marshalling it keeps the archive complete for those too.
		var err error
		if body, err = json.Marshal(a); err != nil {
			return key, fmt.Errorf("encoding alert %s for the archive: %w", a.ID, err)
		}
	}
	line := make([]byte, 0, len(body)+1)
	line = append(append(line, body...), '\n')

	if err := ar.Store.Put(ctx, key, line); err != nil {
		return key, fmt.Errorf("archiving alert %s to s3://%s/%s: %w", a.ID, ar.Bucket, key, err)
	}
	return key, nil
}

// Key is where an alert is archived:
//
//	alerts/log_source=<lane>/date=<YYYY-MM-DD of alerted_at, UTC>/<id>.json
//
// It depends only on the alert, so a replay overwrites the same object. now is
// used only when the alert carries no alerted_at, which the producer always
// sets; the fallback trades that one alert's replay-stability for not refusing
// it.
func Key(a alert.Alert, now time.Time) string {
	at := a.AlertedAt
	if at.IsZero() {
		at = now
	}
	return fmt.Sprintf("%slog_source=%s/date=%s/%s.json",
		Prefix, lane(a.LogSource), at.UTC().Format(time.DateOnly), segment(a.ID))
}

// lane returns log_source if it can be a partition value, else "unknown". A
// value outside [a-z0-9_-] would either split the key into extra levels or be a
// partition the Glue projection never lists.
func lane(s string) string {
	if s == "" {
		return unknownLane
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return unknownLane
		}
	}
	return s
}

// segment makes an alert id safe as one key segment. Producer ids are
// det_<hex> and pass through unchanged; anything else has its separators
// replaced so it cannot add levels to the key.
func segment(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			return r
		default:
			return '_'
		}
	}, id)
}

func (ar *Archive) now() time.Time {
	if ar.Now != nil {
		return ar.Now()
	}
	return time.Now().UTC()
}
