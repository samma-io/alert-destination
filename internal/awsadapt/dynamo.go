// Package awsadapt is the only package that imports the AWS SDK.
//
// Everything else in this service takes a narrow interface in plain Go types --
// ledger.Store, secrets.Getter -- and this package is where those are satisfied.
// The arrangement is copied from detection-engine, and its payoff is that no
// unit test anywhere else needs AWS credentials or a mocked SDK client.
// internal/arch enforces it.
package awsadapt

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/samma-io/alert-destination/internal/ledger"
)

// Attribute names. These are the contract with deployment/terraform/dynamodb.tf:
// the table declares pk as its hash key, sk as its range key, and expires_at as
// its TTL attribute. Changing one without the other is caught by a test here
// and by nothing in AWS.
const (
	PartitionKey = "pk"
	SortKey      = "sk"
	TTLAttribute = "expires_at"
)

// NotAlreadyRecorded is the conditional-write expression that turns a blind
// overwrite into a detectable double delivery.
//
// We only ever reach a delivered write because the pre-flight read said the row
// was absent, so a rejection means two receives of the same message overlapped
// and the destination got the alert twice. Without the condition that race is
// invisible forever.
const NotAlreadyRecorded = "attribute_not_exists(" + PartitionKey + ")"

// item is the stored shape.
//
// Declared here rather than by tagging ledger.Record so that the domain type
// stays free of persistence concerns and the package holding it stays free of
// this one's dependencies.
type item struct {
	PK string `dynamodbav:"pk"`
	SK string `dynamodbav:"sk"`

	AlertID     string `dynamodbav:"alert_id,omitempty"`
	Destination string `dynamodbav:"destination,omitempty"`
	Target      string `dynamodbav:"target,omitempty"`

	Status   string `dynamodbav:"status"`
	Attempts int    `dynamodbav:"attempts"`

	FirstAttemptAt int64 `dynamodbav:"first_attempt_at,omitempty"`
	LastAttemptAt  int64 `dynamodbav:"last_attempt_at,omitempty"`
	DeliveredAt    int64 `dynamodbav:"delivered_at,omitempty"`

	Ref map[string]string `dynamodbav:"ref,omitempty"`

	Permanent  bool   `dynamodbav:"permanent,omitempty"`
	Code       string `dynamodbav:"error_code,omitempty"`
	HTTPStatus int    `dynamodbav:"http_status,omitempty"`
	Message    string `dynamodbav:"error_message,omitempty"`

	// ExpiresAt must marshal as a Number. DynamoDB ignores a TTL attribute of
	// any other type -- PutItem succeeds and the row simply never expires.
	ExpiresAt int64 `dynamodbav:"expires_at"`
}

// Item marshals a ledger record for storage.
func Item(r ledger.Record) (map[string]types.AttributeValue, error) {
	out, err := attributevalue.MarshalMap(item{
		PK: r.PK, SK: r.SK,
		AlertID: r.AlertID, Destination: r.Destination, Target: r.Target,
		Status: string(r.Status), Attempts: r.Attempts,
		FirstAttemptAt: unix(r.FirstAttemptAt),
		LastAttemptAt:  unix(r.LastAttemptAt),
		DeliveredAt:    unix(r.DeliveredAt),
		Ref:            r.Ref,
		Permanent:      r.Permanent, Code: r.Code, HTTPStatus: r.HTTPStatus, Message: r.Message,
		ExpiresAt: r.ExpiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling ledger record %s: %w", r.SK, err)
	}
	return out, nil
}

// RecordFrom unmarshals a stored item.
func RecordFrom(raw map[string]types.AttributeValue) (ledger.Record, error) {
	var i item
	if err := attributevalue.UnmarshalMap(raw, &i); err != nil {
		return ledger.Record{}, fmt.Errorf("unmarshalling ledger item: %w", err)
	}
	return ledger.Record{
		PK: i.PK, SK: i.SK,
		AlertID: i.AlertID, Destination: i.Destination, Target: i.Target,
		Status: ledger.Status(i.Status), Attempts: i.Attempts,
		FirstAttemptAt: fromUnix(i.FirstAttemptAt),
		LastAttemptAt:  fromUnix(i.LastAttemptAt),
		DeliveredAt:    fromUnix(i.DeliveredAt),
		Ref:            i.Ref,
		Permanent:      i.Permanent, Code: i.Code, HTTPStatus: i.HTTPStatus, Message: i.Message,
		ExpiresAt: i.ExpiresAt,
	}, nil
}

// DynamoAPI is the slice of DynamoDB this package uses.
type DynamoAPI interface {
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// LedgerStore implements ledger.Store over DynamoDB.
type LedgerStore struct {
	API   DynamoAPI
	Table string
}

// Query returns every delivery recorded for one alert.
//
// Strongly consistent on purpose: this is an idempotency check, and an
// eventually-consistent read of one can return "not delivered" for something
// that was, which is the duplicate the ledger exists to prevent.
func (s *LedgerStore) Query(ctx context.Context, pk string) ([]ledger.Record, error) {
	out, err := s.API.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.Table),
		KeyConditionExpression: aws.String("#pk = :pk"),
		ExpressionAttributeNames: map[string]string{
			"#pk": PartitionKey,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: pk},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("querying the ledger for %s: %w", pk, err)
	}

	records := make([]ledger.Record, 0, len(out.Items))
	for _, raw := range out.Items {
		r, err := RecordFrom(raw)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}

// PutIfAbsent writes a row only if it is not already there.
func (s *LedgerStore) PutIfAbsent(ctx context.Context, r ledger.Record) error {
	attrs, err := Item(r)
	if err != nil {
		return err
	}

	_, err = s.API.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.Table),
		Item:                attrs,
		ConditionExpression: aws.String(NotAlreadyRecorded),
	})

	var failed *types.ConditionalCheckFailedException
	if errors.As(err, &failed) {
		return ledger.ErrAlreadyRecorded
	}
	if err != nil {
		return fmt.Errorf("writing ledger row %s: %w", r.SK, err)
	}
	return nil
}

// Upsert writes a row, accumulating attempts onto any existing one.
//
// UpdateItem rather than PutItem because the attempt count has to survive the
// previous delivery's row: a PutItem would reset it to one on every redelivery
// and the DLQ reader would never see that this failed five times.
func (s *LedgerStore) Upsert(ctx context.Context, r ledger.Record) error {
	_, err := s.API.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.Table),
		Key: map[string]types.AttributeValue{
			PartitionKey: &types.AttributeValueMemberS{Value: r.PK},
			SortKey:      &types.AttributeValueMemberS{Value: r.SK},
		},
		UpdateExpression: aws.String(
			"SET #status = :status, #alert_id = :alert_id, #destination = :destination, " +
				"#target = :target, #last = :last, #permanent = :permanent, #code = :code, " +
				"#http_status = :http_status, #message = :message, #expires = :expires, " +
				"#first = if_not_exists(#first, :first) " +
				"ADD #attempts :attempts"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status", "#alert_id": "alert_id", "#destination": "destination",
			"#target": "target", "#last": "last_attempt_at", "#first": "first_attempt_at",
			"#permanent": "permanent", "#code": "error_code", "#http_status": "http_status",
			"#message": "error_message", "#expires": TTLAttribute, "#attempts": "attempts",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status":      &types.AttributeValueMemberS{Value: string(r.Status)},
			":alert_id":    &types.AttributeValueMemberS{Value: r.AlertID},
			":destination": &types.AttributeValueMemberS{Value: r.Destination},
			":target":      &types.AttributeValueMemberS{Value: r.Target},
			":last":        number(unix(r.LastAttemptAt)),
			":first":       number(unix(r.FirstAttemptAt)),
			":permanent":   &types.AttributeValueMemberBOOL{Value: r.Permanent},
			":code":        &types.AttributeValueMemberS{Value: r.Code},
			":http_status": number(int64(r.HTTPStatus)),
			":message":     &types.AttributeValueMemberS{Value: r.Message},
			":expires":     number(r.ExpiresAt),
			":attempts":    number(int64(r.Attempts)),
		},
	})
	if err != nil {
		return fmt.Errorf("updating ledger row %s: %w", r.SK, err)
	}
	return nil
}

func number(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", v)}
}

var _ ledger.Store = (*LedgerStore)(nil)
