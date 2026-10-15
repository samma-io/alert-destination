package natsadapt_test

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/samma-io/alert-destination/internal/natsadapt"
)

func TestQueue_ReceiveThenDeleteAcknowledges(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server did not start")
	}
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "SIEM_ALERTS", Subjects: []string{"samma.alerts.>"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, "samma.alerts.workspace", []byte(`{"id":"abc"}`)); err != nil {
		t.Fatal(err)
	}
	cons, err := js.CreateConsumer(ctx, "SIEM_ALERTS", jetstream.ConsumerConfig{
		Durable: "alert-destination", AckPolicy: jetstream.AckExplicitPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}

	q := &natsadapt.Queue{Consumer: cons}
	msgs, err := q.Receive(ctx, 1, time.Second)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("Receive = %d, %v", len(msgs), err)
	}
	if msgs[0].Body != `{"id":"abc"}` || msgs[0].ID != "samma.alerts.workspace/1" {
		t.Errorf("message = %+v", msgs[0])
	}
	if err := q.Delete(ctx, msgs[0].ReceiptHandle); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	info, err := cons.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.NumAckPending != 0 {
		t.Errorf("ack pending = %d, want 0", info.NumAckPending)
	}
	if err := q.Delete(ctx, msgs[0].ReceiptHandle); err == nil {
		t.Error("a second Delete of the same handle should fail")
	}
}
