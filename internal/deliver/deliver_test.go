package deliver_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/archive"
	"github.com/samma-io/alert-destination/internal/deliver"
	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/ledger"
	"github.com/samma-io/alert-destination/internal/routing"
)

// --- doubles ---------------------------------------------------------------

type recorder struct {
	name  string
	calls []string // "target" per Deliver
	ref   destination.Ref
	err   error
}

func (r *recorder) Name() string { return r.name }
func (r *recorder) Deliver(_ context.Context, _ alert.Alert, target string) (destination.Ref, error) {
	r.calls = append(r.calls, target)
	if r.err != nil {
		return nil, r.err
	}
	return r.ref, nil
}

type memStore struct {
	rows      map[string]ledger.Record
	putErr    error
	upsertErr error
}

func newStore() *memStore { return &memStore{rows: map[string]ledger.Record{}} }

func (m *memStore) Query(_ context.Context, pk string) ([]ledger.Record, error) {
	var out []ledger.Record
	for _, r := range m.rows {
		if r.PK == pk {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memStore) PutIfAbsent(_ context.Context, r ledger.Record) error {
	if m.putErr != nil {
		return m.putErr
	}
	if _, ok := m.rows[r.PK+r.SK]; ok {
		return ledger.ErrAlreadyRecorded
	}
	m.rows[r.PK+r.SK] = r
	return nil
}

func (m *memStore) Upsert(_ context.Context, r ledger.Record) error {
	if m.upsertErr != nil {
		return m.upsertErr
	}
	if prev, ok := m.rows[r.PK+r.SK]; ok {
		r.Attempts += prev.Attempts
	}
	m.rows[r.PK+r.SK] = r
	return nil
}

const table = `
routes:
  - level: critical
    log_source: "*"
    deliveries:
      - {to: slack, target: "C0CRIT"}
      - {to: github, target: "example-org/detections"}
  - level: "*"
    log_source: "*"
    deliveries:
      - {to: slack, target: "C0ALL"}
default:
  deliveries:
    - {to: slack, target: "C0ALL"}
`

func testAlert(level string) alert.Alert {
	return alert.Alert{
		SchemaVersion: alert.SchemaVersion,
		ID:            "det_1",
		LogSource:     "aws",
		Rule:          alert.Rule{RuleID: "r1", Title: "Something happened", Level: level},
	}
}

type rig struct {
	handler *deliver.Handler
	slack   *recorder
	github  *recorder
	store   *memStore
}

func newRig(t *testing.T) *rig {
	t.Helper()
	tbl, err := routing.Load([]byte(table))
	if err != nil {
		t.Fatalf("routing.Load: %v", err)
	}
	sl := &recorder{name: "slack"}
	gh := &recorder{name: "github"}
	st := newStore()
	return &rig{
		slack:  sl,
		github: gh,
		store:  st,
		handler: &deliver.Handler{
			Routes:   tbl,
			Registry: destination.NewRegistry(sl, gh),
			Ledger:   &ledger.Ledger{Store: st},
			Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	}
}

// --- happy path ------------------------------------------------------------

func TestHandle_DeliversToEveryRoutedDestination(t *testing.T) {
	r := newRig(t)

	res, err := r.handler.Handle(context.Background(), testAlert("critical"))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(r.slack.calls) != 1 || r.slack.calls[0] != "C0CRIT" {
		t.Errorf("slack calls = %v, want [C0CRIT]", r.slack.calls)
	}
	if len(r.github.calls) != 1 || r.github.calls[0] != "example-org/detections" {
		t.Errorf("github calls = %v, want [example-org/detections]", r.github.calls)
	}
	if len(res.Delivered) != 2 {
		t.Errorf("Delivered = %d, want 2", len(res.Delivered))
	}
}

// The most-watched destination gets the alert before budget is spent on one
// nobody is staring at.
func TestHandle_DeliversToSlackBeforeGitHub(t *testing.T) {
	r := newRig(t)
	var order []string
	r.slack.calls, r.github.calls = nil, nil

	seq := &sequencer{order: &order}
	r.handler.Registry = destination.NewRegistry(
		&orderedRecorder{name: "slack", seq: seq},
		&orderedRecorder{name: "github", seq: seq},
	)

	if _, err := r.handler.Handle(context.Background(), testAlert("critical")); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if strings.Join(order, ",") != "slack,github" {
		t.Errorf("delivery order = %v, want slack before github", order)
	}
}

type sequencer struct{ order *[]string }
type orderedRecorder struct {
	name string
	seq  *sequencer
}

func (o *orderedRecorder) Name() string { return o.name }
func (o *orderedRecorder) Deliver(context.Context, alert.Alert, string) (destination.Ref, error) {
	*o.seq.order = append(*o.seq.order, o.name)
	return nil, nil
}

func TestHandle_RoutesByLevel(t *testing.T) {
	r := newRig(t)

	if _, err := r.handler.Handle(context.Background(), testAlert("low")); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(r.github.calls) != 0 {
		t.Errorf("github was called for a low alert: %v", r.github.calls)
	}
	if len(r.slack.calls) != 1 || r.slack.calls[0] != "C0ALL" {
		t.Errorf("slack calls = %v, want [C0ALL]", r.slack.calls)
	}
}

// --- the failure contract --------------------------------------------------

// The whole point of the service: an undelivered alert must become an alarm.
func TestHandle_FailsTheInvocationWhenADestinationFails(t *testing.T) {
	r := newRig(t)
	r.github.err = errors.New("502 bad gateway")

	if _, err := r.handler.Handle(context.Background(), testAlert("critical")); err == nil {
		t.Fatal("Handle succeeded despite an undelivered destination")
	}
}

func TestHandle_ErrorNamesTheDestinationThatFailed(t *testing.T) {
	r := newRig(t)
	r.github.err = errors.New("502 bad gateway")

	_, err := r.handler.Handle(context.Background(), testAlert("critical"))
	if err == nil {
		t.Fatal("Handle succeeded")
	}
	if !strings.Contains(err.Error(), "github") {
		t.Errorf("error does not name the failed destination: %v", err)
	}
}

// One destination failing must not stop the others from being attempted -- the
// alert should reach as many humans as it can.
func TestHandle_StillDeliversToOtherDestinationsAfterOneFails(t *testing.T) {
	r := newRig(t)
	r.slack.err = errors.New("503")

	if _, err := r.handler.Handle(context.Background(), testAlert("critical")); err == nil {
		t.Fatal("Handle succeeded despite a failed destination")
	}
	if len(r.github.calls) != 1 {
		t.Errorf("github calls = %v; a slack failure stopped the github delivery", r.github.calls)
	}
}

// The retry after a partial failure must not re-notify the destination that
// already succeeded.
func TestHandle_RetrySkipsAnAlreadyDeliveredDestination(t *testing.T) {
	r := newRig(t)
	r.github.err = errors.New("502")

	if _, err := r.handler.Handle(context.Background(), testAlert("critical")); err == nil {
		t.Fatal("first Handle succeeded, want failure")
	}
	r.github.err = nil

	res, err := r.handler.Handle(context.Background(), testAlert("critical"))
	if err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	if len(r.slack.calls) != 1 {
		t.Errorf("slack was notified %d times, want 1", len(r.slack.calls))
	}
	if len(r.github.calls) != 2 {
		t.Errorf("github calls = %d, want 2 (one failed, one retried)", len(r.github.calls))
	}
	if len(res.Skipped) != 1 {
		t.Errorf("Skipped = %d, want 1", len(res.Skipped))
	}
}

// Redelivering an alert that fully succeeded must be a no-op.
func TestHandle_ReplayOfAFullyDeliveredAlertCallsNothing(t *testing.T) {
	r := newRig(t)
	if _, err := r.handler.Handle(context.Background(), testAlert("critical")); err != nil {
		t.Fatalf("first Handle: %v", err)
	}

	res, err := r.handler.Handle(context.Background(), testAlert("critical"))
	if err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	if len(r.slack.calls) != 1 || len(r.github.calls) != 1 {
		t.Errorf("replay re-delivered: slack=%v github=%v", r.slack.calls, r.github.calls)
	}
	if len(res.Skipped) != 2 {
		t.Errorf("Skipped = %d, want 2", len(res.Skipped))
	}
}

func TestHandle_RecordsWhyADeliveryFailed(t *testing.T) {
	r := newRig(t)
	r.github.err = destination.Permanent(errors.New("422 Validation Failed"))

	if _, err := r.handler.Handle(context.Background(), testAlert("critical")); err == nil {
		t.Fatal("Handle succeeded")
	}

	k := ledger.Key{AlertID: "det_1", Destination: "github", Target: "example-org/detections"}
	row, ok := r.store.rows[k.PK()+k.SK()]
	if !ok {
		t.Fatal("no ledger row for the failed delivery; the DLQ reader learns nothing")
	}
	if row.Status != ledger.StatusFailed {
		t.Errorf("Status = %q, want failed", row.Status)
	}
	if !row.Permanent {
		t.Error("Permanent = false for a permanent failure")
	}
	if !strings.Contains(row.Message, "422") {
		t.Errorf("Message = %q, want it to mention the reason", row.Message)
	}
}

// A permanent failure is still a failed invocation: it must reach the DLQ and
// raise the alarm like any other undelivered alert.
func TestHandle_PermanentFailureStillFailsTheInvocation(t *testing.T) {
	r := newRig(t)
	r.github.err = destination.Permanent(errors.New("channel_not_found"))

	if _, err := r.handler.Handle(context.Background(), testAlert("critical")); err == nil {
		t.Fatal("Handle succeeded on a permanent failure")
	}
}

// --- the ledger must never decide the invocation's fate on its own ---------

func TestHandle_SucceedsWhenEveryDeliveryWorkedButTheLedgerWriteDidNot(t *testing.T) {
	r := newRig(t)
	r.store.putErr = errors.New("ProvisionedThroughputExceeded")

	res, err := r.handler.Handle(context.Background(), testAlert("critical"))
	if err != nil {
		t.Fatalf("Handle failed on a bookkeeping error, turning a blip into a guaranteed "+
			"duplicate on every destination: %v", err)
	}
	if res.LedgerErrors == 0 {
		t.Error("LedgerErrors = 0; the failure was swallowed without a trace")
	}
}

func TestHandle_ReportsADoubleDelivery(t *testing.T) {
	r := newRig(t)
	k := ledger.Key{AlertID: "det_1", Destination: "slack", Target: "C0ALL"}
	// A delivered row that the pre-flight read will not see, standing in for the
	// race where two receives of the same message overlap.
	r.store.rows[k.PK()+k.SK()] = ledger.Record{
		PK: k.PK(), SK: k.SK(), Status: ledger.StatusDelivered,
	}
	r.handler.Ledger = &ledger.Ledger{Store: &blindStore{memStore: r.store}}

	res, err := r.handler.Handle(context.Background(), testAlert("low"))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.Duplicates != 1 {
		t.Errorf("Duplicates = %d, want 1", res.Duplicates)
	}
}

// blindStore reads as though the partition were empty but writes normally, so a
// conditional write is rejected by a row the read never returned.
type blindStore struct{ *memStore }

func (b *blindStore) Query(context.Context, string) ([]ledger.Record, error) { return nil, nil }

// --- routing observability -------------------------------------------------

func TestHandle_ReportsAnUnknownLevelWithoutDroppingTheAlert(t *testing.T) {
	r := newRig(t)

	res, err := r.handler.Handle(context.Background(), testAlert("sev1"))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !res.Match.UnknownLevel {
		t.Error("Match.UnknownLevel = false, want true")
	}
	if len(res.Delivered) == 0 {
		t.Fatal("an unknown level delivered nowhere; the alert was dropped")
	}
}

// --- soft deadline ---------------------------------------------------------

// A hard Lambda timeout emits only "Task timed out", the worst possible DLQ
// forensics. Stopping early leaves room to write down what happened.
func TestHandle_StopsBeforeTheDeadlineAndRecordsWhatItSkipped(t *testing.T) {
	r := newRig(t)
	r.handler.Reserve = time.Hour // everything is "too close to the deadline"

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	defer cancel()

	_, err := r.handler.Handle(ctx, testAlert("critical"))
	if err == nil {
		t.Fatal("Handle succeeded despite abandoning every delivery")
	}
	if len(r.slack.calls) != 0 {
		t.Errorf("slack was called past the soft deadline: %v", r.slack.calls)
	}
	if !strings.Contains(err.Error(), "deadline") {
		t.Errorf("error does not explain the abandonment: %v", err)
	}
}

func TestHandle_UnknownDestinationInTheTableIsAnError(t *testing.T) {
	r := newRig(t)
	r.handler.Registry = destination.NewRegistry(r.slack) // github not registered

	if _, err := r.handler.Handle(context.Background(), testAlert("critical")); err == nil {
		t.Fatal("Handle succeeded with an unregistered destination in the route")
	}
}

// --- ref and failure detail ------------------------------------------------

// The destination's own reference is what turns "which issue is this alert"
// into a ledger lookup.
func TestHandle_RecordsTheRefOnTheDeliveredRow(t *testing.T) {
	r := newRig(t)
	r.github.ref = destination.Ref{"number": "412", "html_url": "https://github.invalid/o/r/issues/412"}

	if _, err := r.handler.Handle(context.Background(), testAlert("critical")); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	k := ledger.Key{AlertID: "det_1", Destination: "github", Target: "example-org/detections"}
	row := r.store.rows[k.PK()+k.SK()]
	if row.Ref["number"] != "412" || row.Ref["html_url"] == "" {
		t.Errorf("Ref = %v, want the issue number and url", row.Ref)
	}
}

func TestHandle_RecordsTheCodeAndStatusOfAFailure(t *testing.T) {
	r := newRig(t)
	r.github.err = destination.Permanent(
		destination.WithDetail(errors.New("422 Validation Failed"), "unprocessable_entity", 422))

	r.handler.Handle(context.Background(), testAlert("critical"))

	k := ledger.Key{AlertID: "det_1", Destination: "github", Target: "example-org/detections"}
	row := r.store.rows[k.PK()+k.SK()]
	if row.Code != "unprocessable_entity" || row.HTTPStatus != 422 {
		t.Errorf("failure row Code=%q HTTPStatus=%d, want unprocessable_entity/422", row.Code, row.HTTPStatus)
	}
}

func TestHandle_AnAbandonedDeliveryIsCoded(t *testing.T) {
	r := newRig(t)
	r.handler.Reserve = time.Hour
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	defer cancel()

	r.handler.Handle(ctx, testAlert("low"))

	k := ledger.Key{AlertID: "det_1", Destination: "slack", Target: "C0ALL"}
	if row := r.store.rows[k.PK()+k.SK()]; row.Code != "abandoned" {
		t.Errorf("Code = %q, want abandoned", row.Code)
	}
}

// --- archive ---------------------------------------------------------------

type objectStore struct {
	keys []string
	err  error
	// before records what had been delivered when Put was called.
	before int
	seen   *recorder
}

func (o *objectStore) Put(_ context.Context, key string, _ []byte) error {
	if o.seen != nil {
		o.before = len(o.seen.calls)
	}
	if o.err != nil {
		return o.err
	}
	o.keys = append(o.keys, key)
	return nil
}

func withArchive(r *rig, st *objectStore) {
	r.handler.Archive = &archive.Archive{Store: st, Bucket: "detections-123456789012"}
}

func TestHandle_ArchivesBeforeAnyDelivery(t *testing.T) {
	r := newRig(t)
	st := &objectStore{seen: r.slack}
	withArchive(r, st)

	res, err := r.handler.Handle(context.Background(), testAlert("critical"))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(st.keys) != 1 {
		t.Fatalf("archive writes = %d, want 1", len(st.keys))
	}
	if st.before != 0 {
		t.Error("slack was notified before the alert was archived")
	}
	if res.Archive != deliver.ArchiveWritten {
		t.Errorf("Archive = %q, want written", res.Archive)
	}

	k := ledger.Key{AlertID: "det_1", Destination: archive.Destination, Target: "detections-123456789012"}
	row := r.store.rows[k.PK()+k.SK()]
	if row.Status != ledger.StatusDelivered || row.Ref["key"] != st.keys[0] {
		t.Errorf("archive ledger row = %+v, want delivered with the object key", row)
	}
}

// The ledger is what makes a replay skip the archive, as it skips a destination.
func TestHandle_AReplaySkipsTheArchive(t *testing.T) {
	r := newRig(t)
	st := &objectStore{}
	withArchive(r, st)

	r.handler.Handle(context.Background(), testAlert("critical"))
	res, err := r.handler.Handle(context.Background(), testAlert("critical"))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(st.keys) != 1 {
		t.Errorf("archive writes = %d across a replay, want 1", len(st.keys))
	}
	if res.Archive != deliver.ArchiveSkipped {
		t.Errorf("Archive = %q, want skipped", res.Archive)
	}
}

// Like an unreadable ledger: fail, notify nobody, and let SQS bring it back.
func TestHandle_AFailedArchiveWriteFailsBeforeAnyDelivery(t *testing.T) {
	r := newRig(t)
	withArchive(r, &objectStore{err: errors.New("AccessDenied")})

	res, err := r.handler.Handle(context.Background(), testAlert("critical"))
	if err == nil {
		t.Fatal("Handle succeeded although the alert was not archived")
	}
	if len(r.slack.calls)+len(r.github.calls) != 0 {
		t.Error("a destination was notified although the archive write failed")
	}
	if res.Archive != deliver.ArchiveFailed {
		t.Errorf("Archive = %q, want failed", res.Archive)
	}

	k := ledger.Key{AlertID: "det_1", Destination: archive.Destination, Target: "detections-123456789012"}
	if row := r.store.rows[k.PK()+k.SK()]; row.Status != ledger.StatusFailed {
		t.Errorf("archive failure row status = %q, want failed", row.Status)
	}
}

// A failed-archive row is forensics like any other failure: the next receive
// must try again.
func TestHandle_AFailedArchiveIsRetriedOnTheNextReceive(t *testing.T) {
	r := newRig(t)
	st := &objectStore{err: errors.New("SlowDown")}
	withArchive(r, st)

	r.handler.Handle(context.Background(), testAlert("low"))
	st.err = nil
	if _, err := r.handler.Handle(context.Background(), testAlert("low")); err != nil {
		t.Fatalf("second receive: %v", err)
	}
	if len(st.keys) != 1 || len(r.slack.calls) != 1 {
		t.Errorf("archive writes=%d slack=%d, want 1 and 1", len(st.keys), len(r.slack.calls))
	}
}

func TestHandle_ArchiveOffByDefault(t *testing.T) {
	r := newRig(t)
	res, err := r.handler.Handle(context.Background(), testAlert("low"))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.Archive != deliver.ArchiveOff {
		t.Errorf("Archive = %q with no archive configured", res.Archive)
	}
}
