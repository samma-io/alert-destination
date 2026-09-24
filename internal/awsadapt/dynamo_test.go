package awsadapt_test

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/samma-io/alert-destination/internal/awsadapt"
	"github.com/samma-io/alert-destination/internal/ledger"
)

func sampleRecord() ledger.Record {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	return ledger.Record{
		PK: "ALERT#det_1", SK: "DEST#github#o/r",
		AlertID: "det_1", Destination: "github", Target: "o/r",
		Status: ledger.StatusDelivered, Attempts: 1,
		FirstAttemptAt: now, LastAttemptAt: now, DeliveredAt: now,
		Ref:       map[string]string{"issue_number": "412"},
		ExpiresAt: now.Add(ledger.DefaultTTL).Unix(),
	}
}

func TestItem_RoundTripsARecord(t *testing.T) {
	want := sampleRecord()

	item, err := awsadapt.Item(want)
	if err != nil {
		t.Fatalf("Item: %v", err)
	}
	got, err := awsadapt.RecordFrom(item)
	if err != nil {
		t.Fatalf("RecordFrom: %v", err)
	}

	if got.PK != want.PK || got.SK != want.SK {
		t.Errorf("keys did not survive: %q/%q", got.PK, got.SK)
	}
	if got.Status != want.Status {
		t.Errorf("Status = %q, want %q", got.Status, want.Status)
	}
	if got.Attempts != want.Attempts {
		t.Errorf("Attempts = %d, want %d", got.Attempts, want.Attempts)
	}
	if got.Ref["issue_number"] != "412" {
		t.Errorf("Ref = %v", got.Ref)
	}
	if got.ExpiresAt != want.ExpiresAt {
		t.Errorf("ExpiresAt = %d, want %d", got.ExpiresAt, want.ExpiresAt)
	}
}

// DynamoDB reads the TTL attribute only when it is a Number. A String is
// accepted by PutItem and then silently never expires, so the table grows
// forever and nobody finds out.
func TestItem_StoresTheExpiryAsANumber(t *testing.T) {
	item, err := awsadapt.Item(sampleRecord())
	if err != nil {
		t.Fatalf("Item: %v", err)
	}

	attr, ok := item[awsadapt.TTLAttribute]
	if !ok {
		t.Fatalf("no %q attribute; the row would never expire", awsadapt.TTLAttribute)
	}
	if _, isNumber := attr.(*types.AttributeValueMemberN); !isNumber {
		t.Errorf("%s is %T, want a Number", awsadapt.TTLAttribute, attr)
	}
}

func TestItem_UsesThePartitionAndSortKeyNamesTheTableDeclares(t *testing.T) {
	item, err := awsadapt.Item(sampleRecord())
	if err != nil {
		t.Fatalf("Item: %v", err)
	}

	for _, name := range []string{awsadapt.PartitionKey, awsadapt.SortKey} {
		if _, ok := item[name]; !ok {
			t.Errorf("item has no %q attribute", name)
		}
	}
}

func TestRecordFrom_ToleratesAnItemWithoutOptionalFields(t *testing.T) {
	item := map[string]types.AttributeValue{
		awsadapt.PartitionKey: &types.AttributeValueMemberS{Value: "ALERT#det_1"},
		awsadapt.SortKey:      &types.AttributeValueMemberS{Value: "DEST#slack#C0"},
		"status":              &types.AttributeValueMemberS{Value: "delivered"},
	}

	got, err := awsadapt.RecordFrom(item)
	if err != nil {
		t.Fatalf("RecordFrom: %v", err)
	}
	if got.Status != ledger.StatusDelivered {
		t.Errorf("Status = %q", got.Status)
	}
}

func TestRecordFrom_RejectsAnItemItCannotRead(t *testing.T) {
	item := map[string]types.AttributeValue{
		"attempts": &types.AttributeValueMemberS{Value: "not-a-number"},
	}

	if _, err := awsadapt.RecordFrom(item); err == nil {
		t.Fatal("RecordFrom accepted an item with a mistyped attribute")
	}
}

// Guards against a rename on one side only: what Item writes and what the
// conditional-write expression names have to stay in agreement.
func TestPartitionKeyName_MatchesWhatItemEmits(t *testing.T) {
	item, err := awsadapt.Item(sampleRecord())
	if err != nil {
		t.Fatalf("Item: %v", err)
	}
	got, ok := item[awsadapt.PartitionKey].(*types.AttributeValueMemberS)
	if !ok {
		t.Fatalf("%s is %T, want a String", awsadapt.PartitionKey, item[awsadapt.PartitionKey])
	}
	if got.Value != "ALERT#det_1" {
		t.Errorf("%s = %q", awsadapt.PartitionKey, got.Value)
	}
	if !strings.Contains(awsadapt.NotAlreadyRecorded, awsadapt.PartitionKey) {
		t.Errorf("the conditional-write expression %q does not name %q",
			awsadapt.NotAlreadyRecorded, awsadapt.PartitionKey)
	}
}
