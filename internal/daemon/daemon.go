// Package daemon drains the alert queue from a long-running process, for
// running the service outside Lambda.
//
// In Lambda the event source mapping polls SQS, hands over a batch, and deletes
// it when the invocation succeeds. This package is that mapping, reduced to
// what the service relies on:
//
//   - each message is handled with its own deadline, the equivalent of the
//     function timeout, so the handler's soft deadline behaves the same;
//   - a message is deleted only after its handler succeeded, and left alone
//     otherwise, so SQS redelivers it and the redrive policy moves it to the
//     DLQ after five receives -- the same per-message outcome as the Lambda's
//     failure path;
//   - a stop signal ends polling, lets the message in hand finish within its
//     deadline, and leaves the rest of the batch for SQS to redeliver.
//
// The queue is an interface in plain Go types, so neither this package nor its
// tests know about the AWS SDK; awsadapt.Queue satisfies it.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Defaults applied when a Loop field is left zero.
const (
	// DefaultWait is SQS's maximum long-poll wait.
	DefaultWait = 20 * time.Second
	// DefaultMessageTimeout matches the Lambda's timeout.
	DefaultMessageTimeout = 60 * time.Second
	// DefaultBackoff is the first pause after a failed receive. It doubles on
	// each consecutive failure, up to maxBackoff.
	DefaultBackoff = time.Second

	maxBackoff = time.Minute
	// deleteTimeout bounds the delete after a success. It runs on a context
	// detached from the stop signal, so a message that was delivered is not
	// left to be redelivered just because the process is shutting down.
	deleteTimeout = 10 * time.Second
)

// Message is one received queue message.
type Message struct {
	ID            string
	Body          string
	ReceiptHandle string
}

// Queue is the slice of SQS the loop needs.
type Queue interface {
	// Receive long-polls for up to max messages, waiting at most wait.
	Receive(ctx context.Context, max int, wait time.Duration) ([]Message, error)
	// Delete removes one received message.
	Delete(ctx context.Context, receiptHandle string) error
}

// Loop polls a queue and hands each message to Handle.
type Loop struct {
	Queue Queue

	// Handle processes one message. Nil means success and the message is
	// deleted; an error leaves it for redelivery.
	Handle func(ctx context.Context, m Message) error

	// Batch is the most messages one receive asks for. Zero means 1.
	Batch int
	// Wait is the long-poll wait. Zero means DefaultWait.
	Wait time.Duration
	// MessageTimeout is each message's deadline. Zero means
	// DefaultMessageTimeout.
	MessageTimeout time.Duration
	// Backoff is the first pause after a failed receive. Zero means
	// DefaultBackoff.
	Backoff time.Duration

	Log *slog.Logger

	// Sleep is injected so tests do not wait. Zero means a context-aware sleep.
	Sleep func(context.Context, time.Duration) error
}

// Run polls until ctx is cancelled, then returns nil.
//
// A failed receive is logged and retried with backoff rather than returned:
// an expired credential or a throttle clears, and a process that exits on the
// first one turns a blip into a restart loop.
func (l *Loop) Run(ctx context.Context) error {
	failures := 0
	for ctx.Err() == nil {
		msgs, err := l.Queue.Receive(ctx, l.batch(), l.wait())
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			wait := l.backoff(failures)
			failures++
			l.Log.Error("receiving from the queue failed; retrying",
				"error", err, "retry_in", wait.String(), "consecutive_failures", failures)
			if l.sleep(ctx, wait) != nil {
				break
			}
			continue
		}
		failures = 0

		for _, m := range msgs {
			if ctx.Err() != nil {
				// Not started, so not failed: SQS makes it visible again when
				// the visibility timeout lapses.
				break
			}
			l.process(ctx, m)
		}
	}
	l.Log.Info("stopping: polling ended")
	return nil
}

// process handles one message and deletes it on success.
//
// The handler's context is detached from the stop signal and carries only the
// message deadline. Cancelling mid-delivery would abandon a message that is
// about to succeed and guarantee a redelivery, for the sake of stopping a few
// seconds sooner.
func (l *Loop) process(ctx context.Context, m Message) {
	msgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), l.messageTimeout())
	defer cancel()

	if err := l.Handle(msgCtx, m); err != nil {
		// The handler has already logged why. Leaving the message is the whole
		// failure path: SQS redelivers it, and the redrive policy applies.
		l.Log.Warn("message left on the queue for redelivery", "sqs_message_id", m.ID)
		return
	}

	delCtx, cancelDel := context.WithTimeout(context.WithoutCancel(ctx), deleteTimeout)
	defer cancelDel()
	if err := l.Queue.Delete(delCtx, m.ReceiptHandle); err != nil {
		// Delivered but still on the queue. The redelivery finds every
		// destination in the ledger and does nothing, so this is noise.
		l.Log.Error("could not delete a handled message; it will be redelivered and skipped",
			"sqs_message_id", m.ID, "error", err)
	}
}

func (l *Loop) backoff(failures int) time.Duration {
	d := l.Backoff
	if d <= 0 {
		d = DefaultBackoff
	}
	for i := 0; i < failures && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}

func (l *Loop) batch() int {
	if l.Batch > 0 {
		return l.Batch
	}
	return 1
}

func (l *Loop) wait() time.Duration {
	if l.Wait > 0 {
		return l.Wait
	}
	return DefaultWait
}

func (l *Loop) messageTimeout() time.Duration {
	if l.MessageTimeout > 0 {
		return l.MessageTimeout
	}
	return DefaultMessageTimeout
}

func (l *Loop) sleep(ctx context.Context, d time.Duration) error {
	if l.Sleep != nil {
		return l.Sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ErrNoQueue is returned by main when the process is neither a Lambda nor
// given a queue to poll. Declared here so the message lives next to the mode
// it is about.
var ErrNoQueue = errors.New("not running in Lambda (AWS_LAMBDA_RUNTIME_API is unset) and " +
	"ALERTDEST_QUEUE_URL is not set; set it to run as a daemon that polls the alert queue")
