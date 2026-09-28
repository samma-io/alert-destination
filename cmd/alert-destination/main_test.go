package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/deliver"
	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/ledger"
	"github.com/samma-io/alert-destination/internal/routing"
)

type okSlack struct{ calls int }

func (s *okSlack) Name() string { return "slack" }
func (s *okSlack) Deliver(context.Context, alert.Alert, string) (destination.Ref, error) {
	s.calls++
	return nil, nil
}

type memStore struct{ rows map[string]ledger.Record }

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
	if _, ok := m.rows[r.PK+r.SK]; ok {
		return ledger.ErrAlreadyRecorded
	}
	m.rows[r.PK+r.SK] = r
	return nil
}
func (m *memStore) Upsert(_ context.Context, r ledger.Record) error {
	m.rows[r.PK+r.SK] = r
	return nil
}

func testHandler(t *testing.T, sl *okSlack) *deliver.Handler {
	t.Helper()
	routes, err := routing.Load([]byte(`
routes:
  - {level: "*", log_source: "*", deliveries: [{to: slack, target: "C0ALL"}]}
default:
  deliveries: [{to: slack, target: "C0ALL"}]
`))
	if err != nil {
		t.Fatalf("routing.Load: %v", err)
	}
	return &deliver.Handler{
		Routes:   routes,
		Registry: destination.NewRegistry(sl),
		Ledger:   &ledger.Ledger{Store: &memStore{rows: map[string]ledger.Record{}}},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

const good = `{"schema_version":"detection.alert.v1","id":"det_1","log_source":"aws","rule":{"level":"high"}}`

func TestFromLambda_KeepsIDAndBody(t *testing.T) {
	msgs := fromLambda(events.SQSEvent{Records: []events.SQSMessage{{MessageId: "m1", Body: good}}})
	if len(msgs) != 1 || msgs[0].ID != "m1" || msgs[0].Body != good {
		t.Errorf("fromLambda = %+v", msgs)
	}
}

// The same function runs both modes, so these hold for the Lambda invocation
// and for each daemon message alike.
func TestHandle_SucceedsWhenTheAlertIsDelivered(t *testing.T) {
	sl := &okSlack{}
	if err := handle(context.Background(), testHandler(t, sl), quiet(), []message{{ID: "m1", Body: good}}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if sl.calls != 1 {
		t.Errorf("slack calls = %d, want 1", sl.calls)
	}
}

func TestHandle_AnUndecodableMessageFails(t *testing.T) {
	err := handle(context.Background(), testHandler(t, &okSlack{}), quiet(), []message{{ID: "m1", Body: "{"}})
	if err == nil {
		t.Fatal("handle succeeded on a message it could not read; it would be deleted unseen")
	}
}

func TestHandle_OneBadRecordFailsTheBatch(t *testing.T) {
	err := handle(context.Background(), testHandler(t, &okSlack{}), quiet(),
		[]message{{ID: "m1", Body: good}, {ID: "m2", Body: `{"id":"det_2"}`}})
	if !errors.Is(err, alert.ErrIncomplete) {
		t.Errorf("handle = %v, want the incomplete record to fail the batch", err)
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
