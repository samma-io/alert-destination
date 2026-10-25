package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/destination/postgres"
)

type fakeDB struct {
	table string
	ids   []string
	err   error
}

func (f *fakeDB) InsertAlert(_ context.Context, table string, a alert.Alert) error {
	f.table = table
	f.ids = append(f.ids, a.ID)
	return f.err
}

func TestDeliver_InsertsIntoTheTargetTable(t *testing.T) {
	db := &fakeDB{}
	c := &postgres.Client{DB: db}
	ref, err := c.Deliver(context.Background(), alert.Alert{ID: "abc"}, "siem_alerts")
	if err != nil {
		t.Fatal(err)
	}
	if db.table != "siem_alerts" || len(db.ids) != 1 || ref["id"] != "abc" {
		t.Errorf("table=%q ids=%v ref=%v", db.table, db.ids, ref)
	}
}

func TestDeliver_ABadTableNameIsPermanent(t *testing.T) {
	c := &postgres.Client{DB: &fakeDB{}}
	_, err := c.Deliver(context.Background(), alert.Alert{ID: "abc"}, `alerts"; drop table x; --`)
	if err == nil || !destination.IsPermanent(err) {
		t.Fatalf("err = %v, want a permanent error", err)
	}
}

func TestDeliver_ADatabaseErrorIsTransient(t *testing.T) {
	c := &postgres.Client{DB: &fakeDB{err: errors.New("connection refused")}}
	_, err := c.Deliver(context.Background(), alert.Alert{ID: "abc"}, "siem_alerts")
	if err == nil || destination.IsPermanent(err) {
		t.Fatalf("err = %v, want a transient error", err)
	}
}
