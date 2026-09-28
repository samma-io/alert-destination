package archive_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/archive"
)

type memStore struct {
	objects map[string][]byte
	err     error
}

func (m *memStore) Put(_ context.Context, key string, body []byte) error {
	if m.err != nil {
		return m.err
	}
	if m.objects == nil {
		m.objects = map[string][]byte{}
	}
	m.objects[key] = body
	return nil
}

func testAlert() alert.Alert {
	a, err := alert.Decode([]byte(`{"schema_version":"detection.alert.v1","id":"det_3436971c",` +
		`"alerted_at":"2026-09-02T23:59:59.5-02:00","log_source":"cloudflare",` +
		`"rule":{"id":"r1","level":"high"},"added_later":true}`))
	if err != nil {
		panic(err)
	}
	return a
}

var epoch = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

// The key is the contract with the Glue table: prefix, partition names, and a
// date taken from alerted_at in UTC (here the next day, because of the offset).
func TestKey_IsPartitionedByLaneAndUTCDate(t *testing.T) {
	got := archive.Key(testAlert(), epoch)
	want := "alerts/log_source=cloudflare/date=2026-09-03/det_3436971c.json"
	if got != want {
		t.Errorf("Key = %q, want %q", got, want)
	}
}

// A replay must overwrite the same object, so nothing about the moment of the
// write may reach the key.
func TestKey_DoesNotDependOnWhenItIsWritten(t *testing.T) {
	a := testAlert()
	if archive.Key(a, epoch) != archive.Key(a, epoch.Add(48*time.Hour)) {
		t.Error("the key changed with the clock; a replay would archive the alert twice")
	}
}

func TestKey_FallsBackWhenAFieldCannotBeAPartition(t *testing.T) {
	a := alert.Alert{ID: "det/../x", LogSource: "AWS/prod"}
	got := archive.Key(a, epoch)
	want := "alerts/log_source=unknown/date=2030-01-01/det_.._x.json"
	if got != want {
		t.Errorf("Key = %q, want %q", got, want)
	}
}

func TestPut_WritesTheMessageAsReceivedOnOneLine(t *testing.T) {
	st := &memStore{}
	ar := &archive.Archive{Store: st, Bucket: "detections-123456789012"}

	key, err := ar.Put(context.Background(), testAlert())
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	body := string(st.objects[key])
	if !strings.HasSuffix(body, "}\n") || strings.Count(body, "\n") != 1 {
		t.Errorf("body is not one line: %q", body)
	}
	if !strings.Contains(body, `"added_later":true`) {
		t.Errorf("the archive dropped a field the producer sent: %s", body)
	}
}

func TestPut_EncodesAnAlertThatWasNotDecoded(t *testing.T) {
	st := &memStore{}
	ar := &archive.Archive{Store: st, Bucket: "b", Now: func() time.Time { return epoch }}

	key, err := ar.Put(context.Background(), alert.Alert{ID: "det_1", LogSource: "aws"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !strings.Contains(string(st.objects[key]), `"id":"det_1"`) {
		t.Errorf("body = %s", st.objects[key])
	}
}

func TestPut_ReportsTheStoreError(t *testing.T) {
	boom := errors.New("AccessDenied")
	ar := &archive.Archive{Store: &memStore{err: boom}, Bucket: "b"}

	_, err := ar.Put(context.Background(), testAlert())
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want it to wrap the store's", err)
	}
	if !strings.Contains(err.Error(), "s3://b/alerts/") {
		t.Errorf("the error does not say where it was writing: %v", err)
	}
}
