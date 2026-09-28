// Package deliver is the orchestrator: it turns one alert into zero or more
// deliveries and decides whether the invocation succeeded.
//
// The decision is concentrated here, in one place, for the reason
// detection-engine gives for concentrating its delete decision in Run: an
// invariant re-derived at a dozen early returns is an invariant that will
// eventually be got wrong at one of them. The invariant is:
//
//	the invocation succeeds only if every routed destination has been delivered
//
// with one deliberate exception, called out at its site: a failure to write the
// ledger row after every destination already accepted does not fail the
// invocation, because failing there would convert a bookkeeping blip into a
// guaranteed duplicate on every destination on the retry.
//
// When an archive is configured, the alert is written there before any
// delivery, and a failed archive write fails the invocation before anyone is
// notified -- the same treatment as an unreadable ledger.
package deliver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/archive"
	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/ledger"
	"github.com/samma-io/alert-destination/internal/routing"
)

// DefaultReserve is how much of the invocation's time is held back from
// delivery so that, when the budget runs out, there is room to record why.
const DefaultReserve = 5 * time.Second

// slackFirst is the destination delivered before any other.
//
// Ordering matters because the budget can run out mid-alert: whoever is watching
// a channel should hear about it before time is spent on a destination nobody
// watches in real time.
const slackFirst = "slack"

// Result is what happened, for logging and metrics. It is returned even when
// Handle errors, because the failure detail is the interesting part.
type Result struct {
	Delivered []ledger.Key
	Skipped   []ledger.Key
	Failed    []Failure

	// Duplicates counts deliveries whose ledger write was rejected as already
	// present, which means we delivered something twice.
	Duplicates int

	// LedgerErrors counts bookkeeping writes that did not land. Non-zero means
	// a future retry may re-notify a destination that already succeeded.
	LedgerErrors int

	// Archive is what happened to the archive write. ArchiveOff when no
	// archive is configured.
	Archive ArchiveOutcome

	Match routing.Match
}

// ArchiveOutcome is what happened to one alert's archive write.
type ArchiveOutcome string

// The archive outcomes.
const (
	ArchiveOff     ArchiveOutcome = ""
	ArchiveWritten ArchiveOutcome = "written"
	ArchiveSkipped ArchiveOutcome = "skipped" // the ledger says an earlier receive wrote it
	ArchiveFailed  ArchiveOutcome = "failed"
)

// Failure is one destination that did not receive the alert.
type Failure struct {
	Key       ledger.Key
	Err       error
	Permanent bool
}

// Handler delivers one alert.
type Handler struct {
	Routes   *routing.Table
	Registry *destination.Registry
	Ledger   *ledger.Ledger
	Log      *slog.Logger

	// Archive, when set, receives every alert before any delivery. Nil means
	// archiving is off.
	Archive *archive.Archive

	// Reserve is time held back from delivery for recording the outcome. Zero
	// means DefaultReserve.
	Reserve time.Duration
}

// Handle routes one alert and delivers it.
//
// An error means at least one routed destination did not receive the alert, and
// the caller must let SQS redeliver. Returning nil when something was
// undelivered would make the queue depth fall while detections went nowhere,
// which is the one failure mode this service exists to prevent.
func (h *Handler) Handle(ctx context.Context, a alert.Alert) (Result, error) {
	deliveries, match := h.Routes.Resolve(a.Rule.Level, a.LogSource)
	res := Result{Match: match}

	log := h.Log.With(
		"alert_id", a.ID,
		"rule_id", a.Rule.RuleID,
		"level", a.Rule.Level,
		"log_source", a.LogSource,
	)

	// Should be unreachable: Load rejects an empty default and every route must
	// name at least one destination. If it ever happens, a DLQ entry beats a
	// silent drop.
	if len(deliveries) == 0 {
		return res, fmt.Errorf("alert %s routed to no destination", a.ID)
	}

	log.Info("routing decided",
		"destinations", names(deliveries),
		"used_default", match.UsedDefault,
		"unknown_level", match.UnknownLevel,
		"unknown_log_source", match.UnknownLogSource,
	)

	already, err := h.Ledger.Delivered(ctx, a.ID)
	if err != nil {
		// Without the ledger we cannot tell a first delivery from a replay.
		// Delivering anyway would duplicate; the honest answer is to fail and
		// let SQS bring the alert back when DynamoDB is healthy.
		return res, err
	}

	if h.Archive != nil {
		if err := h.archive(ctx, &res, log, a, already); err != nil {
			return res, err
		}
	}

	for _, d := range order(deliveries) {
		key := ledger.Key{AlertID: a.ID, Destination: d.To, Target: d.Target}

		if already[key.SK()] {
			res.Skipped = append(res.Skipped, key)
			log.Info("delivery skipped, already recorded", "destination", d.To, "target", d.Target)
			continue
		}

		if err := h.budgetLeft(ctx); err != nil {
			res.Failed = append(res.Failed, Failure{Key: key, Err: err})
			h.recordFailure(ctx, &res, log, key, err, false)
			continue
		}

		dest, err := h.Registry.Lookup(d.To)
		if err != nil {
			// A route naming a destination this binary does not have is a
			// deploy-time mistake, but it reaches us as one undelivered alert.
			err = destination.WithDetail(err, "unknown_destination", 0)
			res.Failed = append(res.Failed, Failure{Key: key, Err: err, Permanent: true})
			h.recordFailure(ctx, &res, log, key, err, true)
			continue
		}

		ref, err := dest.Deliver(ctx, a, d.Target)
		if err != nil {
			permanent := destination.IsPermanent(err)
			res.Failed = append(res.Failed, Failure{Key: key, Err: err, Permanent: permanent})
			h.recordFailure(ctx, &res, log, key, err, permanent)
			continue
		}

		res.Delivered = append(res.Delivered, key)

		duplicate, err := h.Ledger.RecordDelivered(ctx, key, ref)
		switch {
		case err != nil:
			// Deliberately not fatal on its own. The destination has the alert;
			// failing here would guarantee a duplicate everywhere on the retry
			// in exchange for correcting a row nobody has read yet.
			res.LedgerErrors++
			log.Error("delivered but could not record it; a retry may duplicate",
				"destination", d.To, "target", d.Target, "error", err)
		case duplicate:
			// The pre-flight read said this was undelivered, so being rejected
			// as already present means two receives of this message overlapped
			// and the destination got it twice.
			res.Duplicates++
			log.Warn("double delivery detected", "destination", d.To, "target", d.Target)
		}
	}

	if len(res.Failed) > 0 {
		return res, undelivered(a.ID, res.Failed)
	}
	return res, nil
}

// archive writes the alert to the archive unless the ledger says an earlier
// receive already did, and records the write so the next replay skips it.
//
// Its error fails the invocation before anything is delivered. That is the
// price of "every notified alert is archived": an S3 outage holds notifications
// back until it clears, exactly as a DynamoDB outage does.
func (h *Handler) archive(ctx context.Context, res *Result, log *slog.Logger,
	a alert.Alert, already map[string]bool) error {

	key := ledger.Key{AlertID: a.ID, Destination: archive.Destination, Target: h.Archive.Bucket}
	if already[key.SK()] {
		res.Archive = ArchiveSkipped
		log.Debug("archive skipped, already recorded", "bucket", h.Archive.Bucket)
		return nil
	}

	objectKey, err := h.Archive.Put(ctx, a)
	if err != nil {
		res.Archive = ArchiveFailed
		h.recordFailure(ctx, res, log, key, err, false)
		return err
	}
	res.Archive = ArchiveWritten

	// A lost ledger row here costs one rewrite of the same object on a replay,
	// so it is counted and logged but never fails anything. A duplicate means
	// two receives overlapped and both wrote the same bytes, which is harmless.
	ref := destination.Ref{"bucket": h.Archive.Bucket, "key": objectKey}
	if _, err := h.Ledger.RecordDelivered(ctx, key, ref); err != nil {
		res.LedgerErrors++
		log.Error("archived but could not record it; a retry will rewrite the object",
			"bucket", h.Archive.Bucket, "error", err)
	}
	return nil
}

// recordFailure writes the forensics row. Its own failure is logged and
// otherwise ignored: the invocation is already failing, and a missing row costs
// the DLQ reader some detail, not correctness.
func (h *Handler) recordFailure(ctx context.Context, res *Result, log *slog.Logger,
	key ledger.Key, cause error, permanent bool) {

	code, status := destination.Detail(cause)
	log.Error("delivery failed",
		"destination", key.Destination, "target", key.Target,
		"permanent", permanent, "auth_failure", destination.IsAuthFailure(cause),
		"code", code, "http_status", status,
		"error", cause)

	f := ledger.Failure{
		Permanent:  permanent,
		Code:       code,
		HTTPStatus: status,
		Message:    truncate(cause.Error(), 512),
	}
	if err := h.Ledger.RecordFailure(ctx, key, f); err != nil {
		res.LedgerErrors++
		log.Error("could not record the failed delivery", "error", err)
	}
}

// budgetLeft reports whether there is enough time to start another delivery.
//
// Stopping short of the deadline is what buys the ledger writes and the error
// log. A hard timeout emits "Task timed out" and nothing else, which is the
// worst possible thing to find attached to a DLQ message.
func (h *Handler) budgetLeft(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	if remaining := time.Until(deadline); remaining <= h.reserve() {
		return destination.WithDetail(
			fmt.Errorf("abandoned: %s left before the deadline, under the %s reserve",
				remaining.Round(time.Millisecond), h.reserve()),
			"abandoned", 0)
	}
	return nil
}

func (h *Handler) reserve() time.Duration {
	if h.Reserve > 0 {
		return h.Reserve
	}
	return DefaultReserve
}

// order puts slack first and otherwise preserves the table's order, so the
// sequence is a property of the code rather than of how somebody happened to
// list the deliveries.
func order(ds []routing.Delivery) []routing.Delivery {
	out := make([]routing.Delivery, 0, len(ds))
	for _, d := range ds {
		if d.To == slackFirst {
			out = append(out, d)
		}
	}
	for _, d := range ds {
		if d.To != slackFirst {
			out = append(out, d)
		}
	}
	return out
}

func names(ds []routing.Delivery) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.To+":"+d.Target)
	}
	return out
}

func undelivered(alertID string, failures []Failure) error {
	parts := make([]string, 0, len(failures))
	errs := make([]error, 0, len(failures))
	for _, f := range failures {
		parts = append(parts, f.Key.Destination)
		errs = append(errs, fmt.Errorf("%s: %w", f.Key.Destination, f.Err))
	}
	return fmt.Errorf("alert %s undelivered to %s: %w",
		alertID, strings.Join(parts, ", "), errors.Join(errs...))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
