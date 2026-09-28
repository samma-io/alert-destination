package awsadapt

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"github.com/samma-io/alert-destination/internal/daemon"
)

// SQSAPI is the slice of SQS this package uses.
type SQSAPI interface {
	ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessage(context.Context, *sqs.DeleteMessageInput, ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error)
}

// Queue implements daemon.Queue over one SQS queue. Only the daemon uses it;
// in Lambda the event source mapping receives and deletes.
type Queue struct {
	API SQSAPI
	URL string
}

// Receive long-polls for up to max messages.
func (q *Queue) Receive(ctx context.Context, max int, wait time.Duration) ([]daemon.Message, error) {
	out, err := q.API.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(q.URL),
		MaxNumberOfMessages: int32(max),
		WaitTimeSeconds:     int32(wait / time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("receiving from %s: %w", q.URL, err)
	}

	msgs := make([]daemon.Message, 0, len(out.Messages))
	for _, m := range out.Messages {
		msgs = append(msgs, daemon.Message{
			ID:            aws.ToString(m.MessageId),
			Body:          aws.ToString(m.Body),
			ReceiptHandle: aws.ToString(m.ReceiptHandle),
		})
	}
	return msgs, nil
}

// Delete removes one message after it was handled.
func (q *Queue) Delete(ctx context.Context, receiptHandle string) error {
	_, err := q.API.DeleteMessage(ctx, &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(q.URL),
		ReceiptHandle: aws.String(receiptHandle),
	})
	if err != nil {
		return fmt.Errorf("deleting from %s: %w", q.URL, err)
	}
	return nil
}

var _ daemon.Queue = (*Queue)(nil)
