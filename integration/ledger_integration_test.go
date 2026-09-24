//go:build integration

// Package integration exercises the parts that only a real DynamoDB can prove:
// that the conditional write maps to ConditionalCheckFailedException, and that
// the attempt counter accumulates across redeliveries rather than resetting.
//
// Run with: make test-integration (starts DynamoDB Local via docker compose).
package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamotypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/samma-io/alert-destination/internal/awsadapt"
	"github.com/samma-io/alert-destination/internal/ledger"
)

// endpoint finds DynamoDB Local.
//
// The candidates exist because the published port is not always on this
// process's loopback: on a normal dev machine it is, but when the tests
// themselves run inside a container the host is reachable only as
// host.docker.internal or on the bridge gateway. Probing beats hard-coding,
// and "localhost" is deliberately not tried first -- the Go resolver prefers
// ::1, which the published port does not answer on.
func endpoint() string {
	if v := os.Getenv("ALERTDEST_DYNAMODB_ENDPOINT_URL"); v != "" {
		return v
	}
	for _, host := range []string{"127.0.0.1", "host.docker.internal", "172.17.0.1"} {
		addr := net.JoinHostPort(host, "8000")
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return "http://" + addr
		}
	}
	return "http://127.0.0.1:8000"
}

// newTable creates a table shaped like the ledger table aws-siem creates for
// this function: string pk and sk, on-demand billing.
func newTable(t *testing.T) *awsadapt.LedgerStore {
	t.Helper()
	ctx := context.Background()

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		t.Fatalf("aws config: %v", err)
	}

	ep := endpoint()
	api := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) { o.BaseEndpoint = &ep })

	name := fmt.Sprintf("ledger-%d", time.Now().UnixNano())
	_, err = api.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   aws.String(name),
		BillingMode: dynamotypes.BillingModePayPerRequest,
		AttributeDefinitions: []dynamotypes.AttributeDefinition{
			{AttributeName: aws.String(awsadapt.PartitionKey), AttributeType: dynamotypes.ScalarAttributeTypeS},
			{AttributeName: aws.String(awsadapt.SortKey), AttributeType: dynamotypes.ScalarAttributeTypeS},
		},
		KeySchema: []dynamotypes.KeySchemaElement{
			{AttributeName: aws.String(awsadapt.PartitionKey), KeyType: dynamotypes.KeyTypeHash},
			{AttributeName: aws.String(awsadapt.SortKey), KeyType: dynamotypes.KeyTypeRange},
		},
	})
	if err != nil {
		t.Fatalf("create table (is DynamoDB Local up? make local-up): %v", err)
	}
	t.Cleanup(func() {
		api.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(name)})
	})

	return &awsadapt.LedgerStore{API: api, Table: name}
}

var slackKey = ledger.Key{AlertID: "det_int", Destination: "slack", Target: "C0"}
var githubKey = ledger.Key{AlertID: "det_int", Destination: "github", Target: "o/r"}

func TestLedger_RecordsAndReadsBackADelivery(t *testing.T) {
	l := &ledger.Ledger{Store: newTable(t)}
	ctx := context.Background()

	duplicate, err := l.RecordDelivered(ctx, slackKey, map[string]string{"ts": "1700.1"})
	if err != nil {
		t.Fatalf("RecordDelivered: %v", err)
	}
	if duplicate {
		t.Error("duplicate = true on a first delivery")
	}

	got, err := l.Delivered(ctx, "det_int")
	if err != nil {
		t.Fatalf("Delivered: %v", err)
	}
	if !got[slackKey.SK()] {
		t.Errorf("Delivered = %v, want it to contain %q", got, slackKey.SK())
	}
}

// The behaviour a fake cannot prove: DynamoDB rejects the second conditional
// write with a typed exception, and awsadapt maps exactly that to
// ErrAlreadyRecorded rather than to a generic failure.
func TestLedger_ConditionalWriteDetectsADoubleDelivery(t *testing.T) {
	store := newTable(t)
	l := &ledger.Ledger{Store: store}
	ctx := context.Background()

	if _, err := l.RecordDelivered(ctx, slackKey, nil); err != nil {
		t.Fatalf("first RecordDelivered: %v", err)
	}

	duplicate, err := l.RecordDelivered(ctx, slackKey, nil)
	if err != nil {
		t.Fatalf("second RecordDelivered returned an error rather than reporting a duplicate: %v", err)
	}
	if !duplicate {
		t.Fatal("duplicate = false; the conditional write did not detect the second delivery")
	}
}

func TestLedgerStore_MapsTheConditionFailureToErrAlreadyRecorded(t *testing.T) {
	store := newTable(t)
	ctx := context.Background()

	row := ledger.Record{
		PK: slackKey.PK(), SK: slackKey.SK(),
		Status: ledger.StatusDelivered, ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	if err := store.PutIfAbsent(ctx, row); err != nil {
		t.Fatalf("first PutIfAbsent: %v", err)
	}

	err := store.PutIfAbsent(ctx, row)
	if !errors.Is(err, ledger.ErrAlreadyRecorded) {
		t.Fatalf("PutIfAbsent returned %v, want ErrAlreadyRecorded", err)
	}
}

// Across five redeliveries the DLQ reader must be able to see that this failed
// five times, so the counter has to accumulate rather than be overwritten.
func TestLedger_FailureAttemptsAccumulateAcrossRedeliveries(t *testing.T) {
	l := &ledger.Ledger{Store: newTable(t)}
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		err := l.RecordFailure(ctx, githubKey, ledger.Failure{
			Permanent: true, Code: "422", HTTPStatus: 422, Message: "Validation Failed",
		})
		if err != nil {
			t.Fatalf("RecordFailure %d: %v", i, err)
		}
	}

	rows, err := l.Store.Query(ctx, githubKey.PK())
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].Attempts != 5 {
		t.Errorf("Attempts = %d, want 5; the DLQ reader cannot see how often this failed",
			rows[0].Attempts)
	}
	if !rows[0].Permanent || rows[0].Code != "422" {
		t.Errorf("failure detail lost: %+v", rows[0])
	}
}

// The invariant, against real storage: five recorded failures must still leave
// the destination eligible for delivery.
func TestLedger_FiveRecordedFailuresDoNotSuppressARetry(t *testing.T) {
	l := &ledger.Ledger{Store: newTable(t)}
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := l.RecordFailure(ctx, githubKey, ledger.Failure{Code: "500"}); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}

	delivered, err := l.Delivered(ctx, "det_int")
	if err != nil {
		t.Fatalf("Delivered: %v", err)
	}
	if delivered[githubKey.SK()] {
		t.Fatal("a failed row suppressed a retry; the alert would be silently dropped")
	}
}

// A partial success and its retry, against real storage.
func TestLedger_RetryAfterAPartialSuccessSkipsOnlyTheDeliveredDestination(t *testing.T) {
	l := &ledger.Ledger{Store: newTable(t)}
	ctx := context.Background()

	if _, err := l.RecordDelivered(ctx, slackKey, nil); err != nil {
		t.Fatalf("RecordDelivered: %v", err)
	}
	if err := l.RecordFailure(ctx, githubKey, ledger.Failure{Code: "502"}); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	delivered, err := l.Delivered(ctx, "det_int")
	if err != nil {
		t.Fatalf("Delivered: %v", err)
	}
	if !delivered[slackKey.SK()] {
		t.Error("slack would be re-notified on the retry")
	}
	if delivered[githubKey.SK()] {
		t.Error("github would be skipped despite never having been delivered")
	}
}

// TTL is only honoured on a Number attribute; a String is accepted and the row
// then never expires.
func TestLedger_ExpiryIsStoredAsANumber(t *testing.T) {
	store := newTable(t)
	l := &ledger.Ledger{Store: store}
	ctx := context.Background()

	if _, err := l.RecordDelivered(ctx, slackKey, nil); err != nil {
		t.Fatalf("RecordDelivered: %v", err)
	}

	rows, err := store.Query(ctx, slackKey.PK())
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if rows[0].ExpiresAt <= time.Now().Unix() {
		t.Errorf("ExpiresAt = %d, already in the past", rows[0].ExpiresAt)
	}
	if min := time.Now().Add(42 * 24 * time.Hour).Unix(); rows[0].ExpiresAt < min {
		t.Errorf("ExpiresAt = %d expires inside the 42-day redrive window", rows[0].ExpiresAt)
	}
}
