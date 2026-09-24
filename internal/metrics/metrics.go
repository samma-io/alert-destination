// Package metrics reports what one invocation did, as CloudWatch Embedded
// Metric Format.
//
// EMF rather than Prometheus because a Lambda cannot be scraped: the sibling
// detection-engine exposes /metrics to an ADOT sidecar, and there is nothing
// here to scrape between invocations. An EMF line is a structured log line that
// CloudWatch turns into metrics on ingestion, so it needs no dependency, no
// extra network call inside the invocation's budget, and no IAM.
//
// Two rules are carried over from detection-engine, and the tests enforce both.
//
// First, every declared metric is emitted on every invocation, even as zero, and
// every declared metric has an increment site. A metric that is declared and
// never written renders as a flat zero, and a flat zero is indistinguishable
// from a healthy quiet period -- which is the one thing a detection pipeline
// cannot afford to say by accident.
//
// Second, nothing unbounded becomes a dimension. The destination is a closed set
// of two; the alert id, the rule id and the target are not.
package metrics

import (
	"encoding/json"
	"io"
	"time"
)

// Namespace is where these land in CloudWatch.
const Namespace = "AlertDestination"

// Metric names. Every one of these has an increment site below, which
// TestEveryDeclaredMetricHasAnIncrementSite checks.
const (
	Delivered         = "AlertsDelivered"
	Skipped           = "DeliveriesSkipped"
	Duplicates        = "DuplicateDeliveries"
	PermanentFailures = "PermanentDeliveryFailures"
	TransientFailures = "TransientDeliveryFailures"
	AuthFailures      = "AuthFailures"
	LedgerErrors      = "LedgerWriteErrors"
	UnknownLevel      = "AlertsWithUnknownLevel"
	UnknownLogSource  = "AlertsWithUnknownLogSource"
	DefaultRoute      = "AlertsRoutedByDefault"
)

// Names returns every declared metric.
func Names() []string {
	return []string{
		Delivered, Skipped, Duplicates,
		PermanentFailures, TransientFailures, AuthFailures,
		LedgerErrors, UnknownLevel, UnknownLogSource, DefaultRoute,
	}
}

// Batch accumulates one invocation's counts.
type Batch struct {
	counts map[string]float64

	// destinations records which destinations appeared, for the log line. It is
	// deliberately not a metric dimension.
	destinations map[string]bool
}

// New returns an empty batch with every metric at zero.
func New() *Batch {
	b := &Batch{counts: map[string]float64{}, destinations: map[string]bool{}}
	for _, name := range Names() {
		b.counts[name] = 0
	}
	return b
}

// Delivered counts alerts that reached a destination.
func (b *Batch) Delivered(dest string, n int) { b.add(Delivered, dest, float64(n)) }

// Skipped counts deliveries the ledger said had already happened.
func (b *Batch) Skipped(dest string) { b.add(Skipped, dest, 1) }

// Duplicate counts deliveries whose ledger write was rejected as already
// present, meaning the destination received the alert twice.
func (b *Batch) Duplicate(dest string) { b.add(Duplicates, dest, 1) }

// Failed counts one failed delivery, split by whether retrying can help and
// whether the credential is the problem.
//
// Auth failures are counted separately because they mean every alert is
// undeliverable, not just this one, and that deserves its own alarm rather than
// being lost among ordinary permanent failures.
func (b *Batch) Failed(dest string, permanent, auth bool) {
	if permanent {
		b.add(PermanentFailures, dest, 1)
	} else {
		b.add(TransientFailures, dest, 1)
	}
	if auth {
		b.add(AuthFailures, dest, 1)
	}
}

// LedgerError counts a bookkeeping write that did not land.
func (b *Batch) LedgerError() { b.counts[LedgerErrors]++ }

// UnknownLevel counts an alert whose severity is outside Sigma's closed set.
func (b *Batch) UnknownLevel() { b.counts[UnknownLevel]++ }

// UnknownLogSource counts an alert from a source added upstream since this
// binary was built.
func (b *Batch) UnknownLogSource() { b.counts[UnknownLogSource]++ }

// UsedDefaultRoute counts an alert no route matched.
func (b *Batch) UsedDefaultRoute() { b.counts[DefaultRoute]++ }

func (b *Batch) add(metric, dest string, n float64) {
	b.counts[metric] += n
	if dest != "" {
		b.destinations[dest] = true
	}
}

// Emit writes the batch as one EMF line.
func (b *Batch) Emit(w io.Writer) error {
	definitions := make([]map[string]string, 0, len(b.counts))
	for _, name := range Names() {
		definitions = append(definitions, map[string]string{"Name": name, "Unit": "Count"})
	}

	doc := map[string]any{
		"_aws": map[string]any{
			"Timestamp": time.Now().UnixMilli(),
			"CloudWatchMetrics": []map[string]any{{
				"Namespace": Namespace,
				// No dimensions: every value here is a count for the function as
				// a whole, and the function is already a CloudWatch dimension.
				// Splitting by destination would be useful and is deliberately
				// left to the log line, which carries it without creating a
				// metric per value.
				"Dimensions": [][]string{{}},
				"Metrics":    definitions,
			}},
		},
	}
	for name, value := range b.counts {
		doc[name] = value
	}

	line, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = w.Write(append(line, '\n'))
	return err
}
