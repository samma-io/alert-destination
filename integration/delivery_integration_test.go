//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/archive"
	"github.com/samma-io/alert-destination/internal/deliver"
	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/destination/github"
	"github.com/samma-io/alert-destination/internal/destination/slack"
	"github.com/samma-io/alert-destination/internal/ledger"
	"github.com/samma-io/alert-destination/internal/routing"
)

// maxReceiveCount matches the redrive policy aws-siem puts on the alert queue:
// after this many receives SQS moves the message to the dead-letter queue.
const maxReceiveCount = 5

type fakeSlack struct {
	*httptest.Server
	posts []map[string]any
}

func newFakeSlack(t *testing.T) *fakeSlack {
	f := &fakeSlack{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		f.posts = append(f.posts, body)
		io.WriteString(w, `{"ok":true,"ts":"1700000000.000100"}`)
	}))
	t.Cleanup(f.Close)
	return f
}

type fakeGitHub struct {
	*httptest.Server
	created    []map[string]any
	rejectWith int
	rejectBody string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)

		if f.rejectWith != 0 {
			w.WriteHeader(f.rejectWith)
			io.WriteString(w, f.rejectBody)
			return
		}
		f.created = append(f.created, body)
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"number":412,"html_url":"https://github.invalid/o/r/issues/412"}`)
	}))
	t.Cleanup(f.Close)
	return f
}

// criticalRoutes sends a critical alert to both destinations, which is the only
// configuration in which a partial failure is possible.
const criticalRoutes = `
routes:
  - level: critical
    log_source: "*"
    deliveries:
      - {to: slack, target: "C0CRIT"}
      - {to: github, target: "example-org/detections"}
default:
  deliveries:
    - {to: slack, target: "C0CRIT"}
`

func criticalAlert() alert.Alert {
	return alert.Alert{
		SchemaVersion: alert.SchemaVersion,
		ID:            "det_e2e",
		LogSource:     "aws",
		Rule: alert.Rule{
			RuleID: "7f8b1c42", Title: "CloudTrail Logging Disabled", Level: "critical",
		},
		Provenance: alert.Provenance{Bucket: "filtered-1", Key: "aws/date=x/y.gz", EventIndex: 0},
		Event:      map[string]any{"eventName": "StopLogging"},
	}
}

func newHandler(t *testing.T, sl *fakeSlack, gh *fakeGitHub) *deliver.Handler {
	t.Helper()
	routes, err := routing.Load([]byte(criticalRoutes))
	if err != nil {
		t.Fatalf("routing.Load: %v", err)
	}
	token := func(context.Context) (string, error) { return "test-token", nil }

	return &deliver.Handler{
		Routes: routes,
		Registry: destination.NewRegistry(
			&slack.Client{HTTP: sl.Client(), Token: token, BaseURL: sl.URL},
			&github.Client{HTTP: gh.Client(), Token: token, BaseURL: gh.URL},
		),
		Ledger: &ledger.Ledger{Store: newTable(t)},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// The test the whole design exists to make pass.
//
// GitHub permanently rejects the issue. SQS redelivers the message five times
// and then parks it in the dead-letter queue. Across all five attempts Slack must
// be notified exactly once, every attempt must fail the invocation, and the
// ledger must end up telling the operator who opens the DLQ precisely what
// happened.
func TestDeliveryContract_PartialFailureAcrossEveryRedeliveryUntilTheDLQ(t *testing.T) {
	sl, gh := newFakeSlack(t), newFakeGitHub(t)
	gh.rejectWith, gh.rejectBody = http.StatusUnprocessableEntity, `{"message":"Validation Failed"}`
	h := newHandler(t, sl, gh)
	ctx := context.Background()

	for receive := 1; receive <= maxReceiveCount; receive++ {
		if _, err := h.Handle(ctx, criticalAlert()); err == nil {
			t.Fatalf("receive %d succeeded; the alert never reached GitHub and the message "+
				"would have been deleted from the queue", receive)
		}
	}

	if len(sl.posts) != 1 {
		t.Errorf("slack was notified %d times across %d redeliveries, want exactly 1",
			len(sl.posts), maxReceiveCount)
	}

	rows, err := h.Ledger.Store.Query(ctx, ledger.Key{AlertID: "det_e2e"}.PK())
	if err != nil {
		t.Fatalf("reading the ledger: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("ledger rows = %d, want one per destination", len(rows))
	}

	byDestination := map[string]ledger.Record{}
	for _, r := range rows {
		byDestination[r.Destination] = r
	}

	if got := byDestination["slack"]; got.Status != ledger.StatusDelivered {
		t.Errorf("slack row status = %q, want delivered", got.Status)
	} else if got.Ref["ts"] != "1700000000.000100" {
		t.Errorf("slack row ref = %v, want the ts Slack answered with", got.Ref)
	}

	failed := byDestination["github"]
	if failed.Status != ledger.StatusFailed {
		t.Errorf("github row status = %q, want failed", failed.Status)
	}
	if failed.Attempts != maxReceiveCount {
		t.Errorf("github attempts = %d, want %d", failed.Attempts, maxReceiveCount)
	}
	if !failed.Permanent {
		t.Error("a 422 was not recorded as permanent")
	}
	if !strings.Contains(failed.Message, "Validation Failed") {
		t.Errorf("the reason did not reach the ledger: %q", failed.Message)
	}
	if failed.Code != "unprocessable_entity" || failed.HTTPStatus != 422 {
		t.Errorf("github failure code/status = %q/%d, want unprocessable_entity/422",
			failed.Code, failed.HTTPStatus)
	}
}

// The issue's number and url survive the round trip through DynamoDB, so
// "which issue is this alert" is answered by the ledger.
func TestDeliveryContract_TheLedgerRecordsTheIssue(t *testing.T) {
	sl, gh := newFakeSlack(t), newFakeGitHub(t)
	h := newHandler(t, sl, gh)
	ctx := context.Background()

	if _, err := h.Handle(ctx, criticalAlert()); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	rows, err := h.Ledger.Store.Query(ctx, ledger.Key{AlertID: "det_e2e"}.PK())
	if err != nil {
		t.Fatalf("reading the ledger: %v", err)
	}
	for _, r := range rows {
		if r.Destination == "github" {
			if r.Ref["number"] != "412" || r.Ref["html_url"] != "https://github.invalid/o/r/issues/412" {
				t.Errorf("github ref = %v", r.Ref)
			}
			return
		}
	}
	t.Error("no github row")
}

type memObjects struct{ puts map[string]int }

func (m *memObjects) Put(_ context.Context, key string, _ []byte) error {
	m.puts[key]++
	return nil
}

// The archive is written once and recorded in the real ledger, so a redelivery
// -- here, after GitHub failed the first receive -- skips it like a delivered
// destination.
func TestDeliveryContract_ArchiveIsWrittenOnceAcrossRedeliveries(t *testing.T) {
	sl, gh := newFakeSlack(t), newFakeGitHub(t)
	gh.rejectWith, gh.rejectBody = http.StatusServiceUnavailable, `{"message":"unavailable"}`
	h := newHandler(t, sl, gh)
	objects := &memObjects{puts: map[string]int{}}
	h.Archive = &archive.Archive{Store: objects, Bucket: "detections-123456789012"}
	ctx := context.Background()

	if _, err := h.Handle(ctx, criticalAlert()); err == nil {
		t.Fatal("the first receive succeeded despite GitHub being down")
	}
	gh.rejectWith = 0
	res, err := h.Handle(ctx, criticalAlert())
	if err != nil {
		t.Fatalf("the redelivery failed: %v", err)
	}

	if len(objects.puts) != 1 {
		t.Fatalf("archive keys = %v, want one", objects.puts)
	}
	for key, n := range objects.puts {
		if n != 1 {
			t.Errorf("%s written %d times, want 1", key, n)
		}
	}
	if res.Archive != deliver.ArchiveSkipped {
		t.Errorf("redelivery archive outcome = %q, want skipped", res.Archive)
	}
}

// Recovery: once the destination is fixed, the very next redelivery completes
// the alert without re-notifying anyone who already heard about it.
func TestDeliveryContract_RecoveryDeliversOnlyWhatWasMissing(t *testing.T) {
	sl, gh := newFakeSlack(t), newFakeGitHub(t)
	gh.rejectWith, gh.rejectBody = http.StatusServiceUnavailable, `{"message":"Bad gateway"}`
	h := newHandler(t, sl, gh)
	ctx := context.Background()

	if _, err := h.Handle(ctx, criticalAlert()); err == nil {
		t.Fatal("the first attempt succeeded despite GitHub being down")
	}

	gh.rejectWith = 0 // somebody fixed it

	if _, err := h.Handle(ctx, criticalAlert()); err != nil {
		t.Fatalf("the retry failed after GitHub recovered: %v", err)
	}
	if len(sl.posts) != 1 {
		t.Errorf("slack was notified %d times, want 1", len(sl.posts))
	}
	if len(gh.created) != 1 {
		t.Errorf("github issues created = %d, want 1", len(gh.created))
	}
}

// A replay of an alert that fully succeeded must touch nothing. The producer
// guarantees the same finding always presents the same id, so this is the
// ordinary case rather than an edge one.
func TestDeliveryContract_ReplayOfADeliveredAlertIsANoOp(t *testing.T) {
	sl, gh := newFakeSlack(t), newFakeGitHub(t)
	h := newHandler(t, sl, gh)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := h.Handle(ctx, criticalAlert()); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}

	if len(sl.posts) != 1 {
		t.Errorf("slack messages = %d, want 1", len(sl.posts))
	}
	if len(gh.created) != 1 {
		t.Errorf("github issues = %d, want 1", len(gh.created))
	}
}

// The id has to survive into the issue, because it is the only way a human can
// spot a duplicate created in the crash window between delivery and the ledger
// write.
func TestDeliveryContract_TheIssueCarriesTheAlertID(t *testing.T) {
	sl, gh := newFakeSlack(t), newFakeGitHub(t)
	h := newHandler(t, sl, gh)

	if _, err := h.Handle(context.Background(), criticalAlert()); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(gh.created) != 1 {
		t.Fatalf("issues created = %d", len(gh.created))
	}
	if title, _ := gh.created[0]["title"].(string); !strings.Contains(title, "det_e2e") {
		t.Errorf("issue title = %q, want it to carry the alert id", title)
	}
}
