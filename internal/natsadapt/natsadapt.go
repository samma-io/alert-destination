// Package natsadapt holds the only code in the service that imports the NATS
// client. Queue is the JetStream counterpart of awsadapt.Queue: the daemon
// loop drains a durable pull consumer on samma.alerts.> instead of SQS.
//
// The transport contract is in samma-io/aws-siem
// docs/contracts/detection-alert-v1.md, section "NATS transport".
package natsadapt

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/samma-io/alert-destination/internal/daemon"
)

// MaxWait caps one fetch. JetStream fetches cannot be cancelled by a context,
// so this is also the longest the loop takes to notice shutdown.
const MaxWait = 5 * time.Second

// Fetcher is the slice of a JetStream consumer the queue needs.
type Fetcher interface {
	Fetch(batch int, opts ...jetstream.FetchOpt) (jetstream.MessageBatch, error)
}

// Queue implements daemon.Queue. The receipt handle is the stream sequence; a
// message left unacknowledged is redelivered after the consumer's AckWait and
// parked after MaxDeliver, which is the DLQ of this transport.
type Queue struct {
	Consumer Fetcher

	mu      sync.Mutex
	pending map[string]jetstream.Msg
}

var _ daemon.Queue = (*Queue)(nil)

// Receive fetches up to max messages.
func (q *Queue) Receive(ctx context.Context, max int, wait time.Duration) ([]daemon.Message, error) {
	if wait <= 0 || wait > MaxWait {
		wait = MaxWait
	}
	batch, err := q.Consumer.Fetch(max, jetstream.FetchMaxWait(wait))
	if err != nil {
		return nil, fmt.Errorf("fetching alerts: %w", err)
	}

	var out []daemon.Message
	for m := range batch.Messages() {
		md, err := m.Metadata()
		if err != nil {
			continue // redelivered after AckWait
		}
		handle := strconv.FormatUint(md.Sequence.Stream, 10)
		q.mu.Lock()
		if q.pending == nil {
			q.pending = make(map[string]jetstream.Msg)
		}
		q.pending[handle] = m
		q.mu.Unlock()
		out = append(out, daemon.Message{
			ID:            m.Subject() + "/" + handle,
			Body:          string(m.Data()),
			ReceiptHandle: handle,
		})
	}
	if err := batch.Error(); err != nil && !errors.Is(err, jetstream.ErrNoMessages) &&
		!errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		return out, fmt.Errorf("fetching alerts: %w", err)
	}
	return out, nil
}

// Delete acknowledges a handled message and waits for the server to confirm.
func (q *Queue) Delete(ctx context.Context, receiptHandle string) error {
	q.mu.Lock()
	m, ok := q.pending[receiptHandle]
	delete(q.pending, receiptHandle)
	q.mu.Unlock()
	if !ok {
		return fmt.Errorf("no alert in flight for sequence %s", receiptHandle)
	}
	return m.DoubleAck(ctx)
}
