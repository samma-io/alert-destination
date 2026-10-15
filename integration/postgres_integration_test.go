//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/ledger"
	"github.com/samma-io/alert-destination/internal/pgadapt"
)

// postgresDSN finds the Postgres from hack/local/docker-compose.yml, probing
// the same hosts as endpoint() for the same reason.
func postgresDSN() string {
	if v := os.Getenv("ALERTDEST_POSTGRES_DSN"); v != "" {
		return v
	}
	for _, host := range []string{"127.0.0.1", "host.docker.internal", "172.17.0.1"} {
		addr := net.JoinHostPort(host, "5433")
		if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			conn.Close()
			return "postgres://alertdest:alertdest@" + addr + "/alertdest?sslmode=disable"
		}
	}
	return "postgres://alertdest:alertdest@127.0.0.1:5433/alertdest?sslmode=disable"
}

func openDB(t *testing.T) *pgadapt.DB {
	t.Helper()
	db, err := pgadapt.Open(context.Background(), postgresDSN())
	if err != nil {
		t.Fatalf("pgadapt.Open: %v", err)
	}
	t.Cleanup(db.Close)
	// Opening twice is what every restart does; the schema must take it.
	again, err := pgadapt.Open(context.Background(), postgresDSN())
	if err != nil {
		t.Fatalf("second pgadapt.Open: %v", err)
	}
	again.Close()
	return db
}

func TestPostgres_InsertAlertIsIdempotentByID(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	id := fmt.Sprintf("alert-%d", time.Now().UnixNano())
	a := alert.Alert{
		SchemaVersion: "detection.alert.v1", ID: id, AlertedAt: time.Now().UTC(), LogSource: "workspace",
		Rule:       alert.Rule{RuleID: "r1", Title: "Admin role granted", Level: "high"},
		Provenance: alert.Provenance{Bucket: "nats:SIEM_LOGS", Key: "samma.logs.workspace/7"},
		Raw:        []byte(`{"id":"` + id + `"}`),
	}
	for i := 0; i < 2; i++ {
		if err := db.InsertAlert(ctx, "siem_alerts", a); err != nil {
			t.Fatalf("InsertAlert #%d: %v", i+1, err)
		}
	}
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM siem_alerts WHERE id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
}

func TestPostgres_LedgerMatchesTheDynamoSemantics(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	l := &ledger.Ledger{Store: &pgadapt.Ledger{DB: db}}
	k := ledger.Key{AlertID: fmt.Sprintf("a-%d", time.Now().UnixNano()), Destination: "postgres", Target: "siem_alerts"}

	// Two failures accumulate attempts and gate nothing.
	for i := 0; i < 2; i++ {
		if err := l.RecordFailure(ctx, k, ledger.Failure{Code: "x", Message: "boom"}); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}
	got, err := l.Delivered(ctx, k.AlertID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a failed row suppressed a retry: %v", got)
	}

	// The delivery replaces the failure; a second delivery is a duplicate.
	dup, err := l.RecordDelivered(ctx, k, map[string]string{"id": k.AlertID})
	if err != nil || dup {
		t.Fatalf("first RecordDelivered: dup=%v err=%v", dup, err)
	}
	dup, err = l.RecordDelivered(ctx, k, nil)
	if err != nil || !dup {
		t.Fatalf("second RecordDelivered: dup=%v err=%v, want a duplicate", dup, err)
	}
	got, err = l.Delivered(ctx, k.AlertID)
	if err != nil {
		t.Fatal(err)
	}
	if !got[k.SK()] {
		t.Errorf("delivered = %v, want %s", got, k.SK())
	}

	rows, err := (&pgadapt.Ledger{DB: db}).Query(ctx, k.PK())
	if err != nil || len(rows) != 1 {
		t.Fatalf("Query = %d rows, %v", len(rows), err)
	}
	if rows[0].Attempts != 3 || rows[0].Ref["id"] != k.AlertID {
		t.Errorf("row = attempts %d ref %v, want 3 attempts and the ref", rows[0].Attempts, rows[0].Ref)
	}
}
