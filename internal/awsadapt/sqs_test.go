package awsadapt_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/samma-io/alert-destination/internal/awsadapt"
)

type fakeSQS struct {
	receive *sqs.ReceiveMessageInput
	deleted *sqs.DeleteMessageInput
	msgs    []sqstypes.Message
	err     error
}

func (f *fakeSQS) ReceiveMessage(_ context.Context, in *sqs.ReceiveMessageInput,
	_ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {

	f.receive = in
	if f.err != nil {
		return nil, f.err
	}
	return &sqs.ReceiveMessageOutput{Messages: f.msgs}, nil
}

func (f *fakeSQS) DeleteMessage(_ context.Context, in *sqs.DeleteMessageInput,
	_ ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error) {

	f.deleted = in
	return &sqs.DeleteMessageOutput{}, f.err
}

const queueURL = "https://sqs.us-east-1.amazonaws.com/123456789012/alerts"

func TestQueue_LongPollsAndMapsMessages(t *testing.T) {
	f := &fakeSQS{msgs: []sqstypes.Message{{
		MessageId: aws.String("m1"), Body: aws.String(`{"id":"det_1"}`), ReceiptHandle: aws.String("rh1"),
	}}}
	q := &awsadapt.Queue{API: f, URL: queueURL}

	msgs, err := q.Receive(context.Background(), 3, 20*time.Second)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if aws.ToString(f.receive.QueueUrl) != queueURL || f.receive.MaxNumberOfMessages != 3 ||
		f.receive.WaitTimeSeconds != 20 {
		t.Errorf("receive input = %+v", f.receive)
	}
	if len(msgs) != 1 || msgs[0].ID != "m1" || msgs[0].Body != `{"id":"det_1"}` || msgs[0].ReceiptHandle != "rh1" {
		t.Errorf("messages = %+v", msgs)
	}
}

func TestQueue_DeletesByReceiptHandle(t *testing.T) {
	f := &fakeSQS{}
	q := &awsadapt.Queue{API: f, URL: queueURL}

	if err := q.Delete(context.Background(), "rh1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if aws.ToString(f.deleted.ReceiptHandle) != "rh1" || aws.ToString(f.deleted.QueueUrl) != queueURL {
		t.Errorf("delete input = %+v", f.deleted)
	}
}

func TestQueue_ReportsErrors(t *testing.T) {
	boom := errors.New("AccessDenied")
	q := &awsadapt.Queue{API: &fakeSQS{err: boom}, URL: queueURL}

	if _, err := q.Receive(context.Background(), 1, time.Second); !errors.Is(err, boom) {
		t.Errorf("Receive = %v", err)
	}
	if err := q.Delete(context.Background(), "rh"); !errors.Is(err, boom) {
		t.Errorf("Delete = %v", err)
	}
}
