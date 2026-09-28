package daemon_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/samma-io/alert-destination/internal/daemon"
)

// fakeQueue hands out scripted receives, then blocks like an empty long poll
// until the context is cancelled.
type fakeQueue struct {
	mu       sync.Mutex
	script   []receive
	deleted  []string
	maxes    []int
	waits    []time.Duration
	drained  chan struct{}
	onceDone sync.Once
}

type receive struct {
	msgs []daemon.Message
	err  error
}

func newQueue(script ...receive) *fakeQueue {
	return &fakeQueue{script: script, drained: make(chan struct{})}
}

func (q *fakeQueue) Receive(ctx context.Context, max int, wait time.Duration) ([]daemon.Message, error) {
	q.mu.Lock()
	q.maxes = append(q.maxes, max)
	q.waits = append(q.waits, wait)
	if len(q.script) > 0 {
		r := q.script[0]
		q.script = q.script[1:]
		q.mu.Unlock()
		return r.msgs, r.err
	}
	q.mu.Unlock()
	q.onceDone.Do(func() { close(q.drained) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (q *fakeQueue) Delete(_ context.Context, receipt string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.deleted = append(q.deleted, receipt)
	return nil
}

func msg(id string) daemon.Message {
	return daemon.Message{ID: id, Body: `{"id":"` + id + `"}`, ReceiptHandle: "rh-" + id}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// run starts the loop, waits until the script is used up, stops it, and
// returns what Run returned.
func run(t *testing.T, l *daemon.Loop, q *fakeQueue) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()

	select {
	case <-q.drained:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop never finished its script")
	}
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
		return nil
	}
}

// The contract with SQS, as the Lambda event source mapping keeps it: delete
// what succeeded, leave what failed for redelivery and the DLQ.
func TestRun_DeletesOnlyWhatWasHandled(t *testing.T) {
	q := newQueue(receive{msgs: []daemon.Message{msg("ok"), msg("bad"), msg("ok2")}})
	l := &daemon.Loop{
		Queue: q, Log: quiet(), Batch: 3,
		Handle: func(_ context.Context, m daemon.Message) error {
			if m.ID == "bad" {
				return errors.New("github: 502")
			}
			return nil
		},
	}

	if err := run(t, l, q); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(q.deleted) != 2 || q.deleted[0] != "rh-ok" || q.deleted[1] != "rh-ok2" {
		t.Errorf("deleted = %v, want [rh-ok rh-ok2]", q.deleted)
	}
}

func TestRun_AsksForTheBatchSizeWithTheLongestPoll(t *testing.T) {
	q := newQueue()
	l := &daemon.Loop{Queue: q, Log: quiet(), Batch: 4,
		Handle: func(context.Context, daemon.Message) error { return nil }}

	run(t, l, q)
	if q.maxes[0] != 4 || q.waits[0] != 20*time.Second {
		t.Errorf("receive(max=%d, wait=%s), want (4, 20s)", q.maxes[0], q.waits[0])
	}
}

// The per-message deadline is what the handler's soft deadline measures
// against, as the Lambda timeout is in Lambda.
func TestRun_GivesEachMessageItsOwnDeadline(t *testing.T) {
	q := newQueue(receive{msgs: []daemon.Message{msg("a")}})
	var remaining time.Duration
	l := &daemon.Loop{
		Queue: q, Log: quiet(), MessageTimeout: 42 * time.Second,
		Handle: func(ctx context.Context, _ daemon.Message) error {
			d, ok := ctx.Deadline()
			if ok {
				remaining = time.Until(d)
			}
			return nil
		},
	}

	run(t, l, q)
	if remaining <= 40*time.Second || remaining > 42*time.Second {
		t.Errorf("message deadline in %s, want about 42s", remaining)
	}
}

// A stop signal mid-delivery must not abandon a message that is about to
// succeed; it finishes, is deleted, and the rest of the batch is left for SQS.
func TestRun_FinishesTheMessageInHandOnStopAndLeavesTheRest(t *testing.T) {
	q := newQueue(receive{msgs: []daemon.Message{msg("first"), msg("second")}})
	ctx, cancel := context.WithCancel(context.Background())
	var handled []string
	l := &daemon.Loop{
		Queue: q, Log: quiet(), Batch: 2,
		Handle: func(hctx context.Context, m daemon.Message) error {
			handled = append(handled, m.ID)
			cancel() // SIGTERM arrives while this message is being delivered
			if hctx.Err() != nil {
				t.Error("the handler's context was cancelled by the stop signal")
			}
			return nil
		},
	}

	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the stop signal")
	}

	if len(handled) != 1 {
		t.Errorf("handled = %v, want only the message in hand", handled)
	}
	if len(q.deleted) != 1 || q.deleted[0] != "rh-first" {
		t.Errorf("deleted = %v, want [rh-first]", q.deleted)
	}
}

// A throttle or an expiring credential clears; exiting on the first one would
// turn it into a restart loop.
func TestRun_BacksOffAndRetriesAFailedReceive(t *testing.T) {
	q := newQueue(
		receive{err: errors.New("ThrottlingException")},
		receive{err: errors.New("ThrottlingException")},
		receive{msgs: []daemon.Message{msg("a")}},
	)
	var slept []time.Duration
	l := &daemon.Loop{
		Queue: q, Log: quiet(), Backoff: time.Second,
		Sleep:  func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil },
		Handle: func(context.Context, daemon.Message) error { return nil },
	}

	if err := run(t, l, q); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(slept) != 2 || slept[0] != time.Second || slept[1] != 2*time.Second {
		t.Errorf("backoff = %v, want [1s 2s]", slept)
	}
	if len(q.deleted) != 1 {
		t.Errorf("deleted = %v; the loop did not recover after the errors", q.deleted)
	}
}

func TestRun_ReturnsNilWhenStopped(t *testing.T) {
	q := newQueue()
	l := &daemon.Loop{Queue: q, Log: quiet(),
		Handle: func(context.Context, daemon.Message) error { return nil }}

	if err := run(t, l, q); err != nil {
		t.Errorf("Run = %v, want nil on a clean stop", err)
	}
}
