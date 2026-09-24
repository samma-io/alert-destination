package ledger_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/samma-io/alert-destination/internal/ledger"
)

// fakeStore is an in-memory Store with the same conditional-write semantics as
// DynamoDB: PutIfAbsent fails when the row exists, Upsert accumulates attempts.
type fakeStore struct {
	rows     map[string]map[string]ledger.Record // pk -> sk -> row
	queryErr error
	putErr   error
}

func newFake() *fakeStore {
	return &fakeStore{rows: map[string]map[string]ledger.Record{}}
}

func (f *fakeStore) Query(_ context.Context, pk string) ([]ledger.Record, error) {
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	var out []ledger.Record
	for _, r := range f.rows[pk] {
		out = append(out, r)
	}
	return out, nil
}

func (f *fakeStore) PutIfAbsent(_ context.Context, r ledger.Record) error {
	if f.putErr != nil {
		return f.putErr
	}
	if _, ok := f.rows[r.PK][r.SK]; ok {
		return ledger.ErrAlreadyRecorded
	}
	f.put(r)
	return nil
}

func (f *fakeStore) Upsert(_ context.Context, r ledger.Record) error {
	if f.putErr != nil {
		return f.putErr
	}
	if prev, ok := f.rows[r.PK][r.SK]; ok {
		r.Attempts += prev.Attempts
		r.FirstAttemptAt = prev.FirstAttemptAt
	}
	f.put(r)
	return nil
}

func (f *fakeStore) put(r ledger.Record) {
	if f.rows[r.PK] == nil {
		f.rows[r.PK] = map[string]ledger.Record{}
	}
	f.rows[r.PK][r.SK] = r
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

var now = time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

func newLedger(s ledger.Store) *ledger.Ledger {
	return &ledger.Ledger{Store: s, Now: fixedClock(now)}
}

var slackKey = ledger.Key{AlertID: "det_1", Destination: "slack", Target: "C0"}
var githubKey = ledger.Key{AlertID: "det_1", Destination: "github", Target: "o/r"}

func TestDelivered_EmptyForAnAlertNobodyHasSeen(t *testing.T) {
	got, err := newLedger(newFake()).Delivered(context.Background(), "det_1")
	if err != nil {
		t.Fatalf("Delivered: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Delivered = %v, want empty", got)
	}
}

func TestDelivered_ReportsARecordedSuccess(t *testing.T) {
	l := newLedger(newFake())
	if _, err := l.RecordDelivered(context.Background(), slackKey, nil); err != nil {
		t.Fatalf("RecordDelivered: %v", err)
	}

	got, err := l.Delivered(context.Background(), "det_1")
	if err != nil {
		t.Fatalf("Delivered: %v", err)
	}
	if !got[slackKey.SK()] {
		t.Errorf("Delivered = %v, want it to contain %q", got, slackKey.SK())
	}
}

// The invariant the whole design rests on. A recorded failure is forensics for
// whoever reads the DLQ; it must never be mistaken for "already handled".
func TestDelivered_AFailedRecordNeverSuppressesARetry(t *testing.T) {
	l := newLedger(newFake())
	err := l.RecordFailure(context.Background(), githubKey, ledger.Failure{
		Permanent: true, Code: "422", HTTPStatus: 422, Message: "Validation Failed",
	})
	if err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	got, err := l.Delivered(context.Background(), "det_1")
	if err != nil {
		t.Fatalf("Delivered: %v", err)
	}
	if got[githubKey.SK()] {
		t.Fatal("a failed record suppressed a retry; the alert would be silently dropped")
	}
}

// Two destinations of the same alert are independent deliveries.
func TestDelivered_DistinguishesDestinations(t *testing.T) {
	l := newLedger(newFake())
	if _, err := l.RecordDelivered(context.Background(), slackKey, nil); err != nil {
		t.Fatalf("RecordDelivered: %v", err)
	}

	got, _ := l.Delivered(context.Background(), "det_1")
	if !got[slackKey.SK()] {
		t.Error("slack should be delivered")
	}
	if got[githubKey.SK()] {
		t.Error("github should not be delivered")
	}
}

// The same destination at two addresses is also two deliveries; keying on the
// destination alone would record the first and silently suppress the second.
func TestKey_TargetIsPartOfTheIdentity(t *testing.T) {
	a := ledger.Key{AlertID: "det_1", Destination: "slack", Target: "C0"}
	b := ledger.Key{AlertID: "det_1", Destination: "slack", Target: "C1"}

	if a.SK() == b.SK() {
		t.Errorf("both addresses produced the same sort key %q", a.SK())
	}
}

func TestKey_PartitionsByAlert(t *testing.T) {
	if got, want := slackKey.PK(), "ALERT#det_1"; got != want {
		t.Errorf("PK = %q, want %q", got, want)
	}
}

// We only reach the write because the pre-flight read said "not delivered", so a
// rejected conditional write means we just delivered twice. That is the only
// instrument that can ever show the race is real.
func TestRecordDelivered_ReportsADoubleDelivery(t *testing.T) {
	l := newLedger(newFake())
	if _, err := l.RecordDelivered(context.Background(), slackKey, nil); err != nil {
		t.Fatalf("first RecordDelivered: %v", err)
	}

	duplicate, err := l.RecordDelivered(context.Background(), slackKey, nil)
	if err != nil {
		t.Fatalf("second RecordDelivered: %v", err)
	}
	if !duplicate {
		t.Error("duplicate = false on a second delivery, want true")
	}
}

func TestRecordDelivered_FirstWriteIsNotADuplicate(t *testing.T) {
	duplicate, err := newLedger(newFake()).RecordDelivered(context.Background(), slackKey, nil)
	if err != nil {
		t.Fatalf("RecordDelivered: %v", err)
	}
	if duplicate {
		t.Error("duplicate = true on a first delivery, want false")
	}
}

func TestRecordDelivered_KeepsTheDestinationReference(t *testing.T) {
	f := newFake()
	l := newLedger(f)
	ref := map[string]string{"issue_number": "412", "url": "https://example.invalid/412"}
	if _, err := l.RecordDelivered(context.Background(), githubKey, ref); err != nil {
		t.Fatalf("RecordDelivered: %v", err)
	}

	got := f.rows[githubKey.PK()][githubKey.SK()]
	if got.Ref["issue_number"] != "412" {
		t.Errorf("Ref = %v, want issue_number 412", got.Ref)
	}
	if got.Status != ledger.StatusDelivered {
		t.Errorf("Status = %q, want %q", got.Status, ledger.StatusDelivered)
	}
	if !got.DeliveredAt.Equal(now) {
		t.Errorf("DeliveredAt = %v, want %v", got.DeliveredAt, now)
	}
}

// Worst case is 14 days in the queue plus 14 in the DLQ plus a late redrive, so
// anything under six weeks can let a redrive re-deliver everything.
func TestRecordDelivered_ExpiresWellBeyondTheRedriveWindow(t *testing.T) {
	f := newFake()
	if _, err := newLedger(f).RecordDelivered(context.Background(), slackKey, nil); err != nil {
		t.Fatalf("RecordDelivered: %v", err)
	}

	got := f.rows[slackKey.PK()][slackKey.SK()]
	wantExpiry := now.Add(ledger.DefaultTTL).Unix()
	if got.ExpiresAt != wantExpiry {
		t.Errorf("ExpiresAt = %d, want %d", got.ExpiresAt, wantExpiry)
	}
	if min := now.Add(42 * 24 * time.Hour).Unix(); got.ExpiresAt < min {
		t.Errorf("ExpiresAt = %d expires inside the 42-day redrive window (min %d)",
			got.ExpiresAt, min)
	}
}

// DynamoDB reads TTL as epoch seconds; milliseconds expire in the year 51,000
// and the row is never collected.
func TestRecordDelivered_ExpiryIsEpochSecondsNotMillis(t *testing.T) {
	f := newFake()
	if _, err := newLedger(f).RecordDelivered(context.Background(), slackKey, nil); err != nil {
		t.Fatalf("RecordDelivered: %v", err)
	}

	got := f.rows[slackKey.PK()][slackKey.SK()].ExpiresAt
	if got > now.AddDate(100, 0, 0).Unix() {
		t.Errorf("ExpiresAt = %d is too large to be epoch seconds", got)
	}
}

func TestRecordFailure_AccumulatesAttemptsAcrossRedeliveries(t *testing.T) {
	f := newFake()
	l := newLedger(f)
	for i := 0; i < 3; i++ {
		if err := l.RecordFailure(context.Background(), githubKey, ledger.Failure{Code: "500"}); err != nil {
			t.Fatalf("RecordFailure %d: %v", i, err)
		}
	}

	if got := f.rows[githubKey.PK()][githubKey.SK()].Attempts; got != 3 {
		t.Errorf("Attempts = %d, want 3", got)
	}
}

func TestRecordFailure_KeepsTheReasonForWhoeverReadsTheDLQ(t *testing.T) {
	f := newFake()
	err := newLedger(f).RecordFailure(context.Background(), githubKey, ledger.Failure{
		Permanent: true, Code: "422", HTTPStatus: 422, Message: "Validation Failed",
	})
	if err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	got := f.rows[githubKey.PK()][githubKey.SK()]
	if got.Status != ledger.StatusFailed {
		t.Errorf("Status = %q, want %q", got.Status, ledger.StatusFailed)
	}
	if !got.Permanent || got.Code != "422" || got.HTTPStatus != 422 {
		t.Errorf("failure detail lost: %+v", got)
	}
	if got.Message != "Validation Failed" {
		t.Errorf("Message = %q", got.Message)
	}
}

func TestDelivered_PropagatesAStoreError(t *testing.T) {
	f := newFake()
	f.queryErr = errors.New("throttled")

	if _, err := newLedger(f).Delivered(context.Background(), "det_1"); err == nil {
		t.Fatal("Delivered succeeded despite a store error")
	}
}
