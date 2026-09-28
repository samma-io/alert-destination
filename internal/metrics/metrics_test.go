package metrics_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/samma-io/alert-destination/internal/metrics"
)

// emit renders one batch and returns it parsed.
func emit(t *testing.T, mutate func(*metrics.Batch)) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	b := metrics.New()
	mutate(b)
	if err := b.Emit(&buf); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("emitted line is not JSON: %v\n%s", err, buf.String())
	}
	return doc
}

// CloudWatch only turns a log line into metrics when it carries the _aws
// envelope; without it this is an expensive way to write a log.
func TestEmit_CarriesTheEmbeddedMetricEnvelope(t *testing.T) {
	doc := emit(t, func(b *metrics.Batch) { b.Delivered("slack", 1) })

	aws, ok := doc["_aws"].(map[string]any)
	if !ok {
		t.Fatal("no _aws envelope; CloudWatch will not extract any metric")
	}
	if aws["Timestamp"] == nil {
		t.Error("no Timestamp in the envelope")
	}
	directives, ok := aws["CloudWatchMetrics"].([]any)
	if !ok || len(directives) == 0 {
		t.Fatal("no CloudWatchMetrics directives")
	}
	d := directives[0].(map[string]any)
	if d["Namespace"] != metrics.Namespace {
		t.Errorf("Namespace = %v, want %s", d["Namespace"], metrics.Namespace)
	}
}

func TestEmit_ReportsDeliveredCounts(t *testing.T) {
	doc := emit(t, func(b *metrics.Batch) { b.Delivered("slack", 2) })

	if doc[metrics.Delivered] != float64(2) {
		t.Errorf("%s = %v, want 2", metrics.Delivered, doc[metrics.Delivered])
	}
}

func TestEmit_ReportsEveryDeclaredMetricSoAZeroIsDistinguishable(t *testing.T) {
	doc := emit(t, func(b *metrics.Batch) {})

	for _, name := range metrics.Names() {
		if _, ok := doc[name]; !ok {
			t.Errorf("%s is absent from an empty batch; an absent metric and a zero one are "+
				"different things on a dashboard", name)
		}
	}
}

// A metric declared and never incremented renders as a flat zero, and a flat
// zero reads as "nothing is wrong" -- the one thing a detection pipeline cannot
// afford to say by accident.
//
// Asserted by exercising every way the batch can be written to and checking that
// between them they reach every declared metric. A metric added to Names()
// without a method that moves it fails here.
func TestEveryDeclaredMetricHasAnIncrementSite(t *testing.T) {
	doc := emit(t, func(b *metrics.Batch) {
		b.Delivered("slack", 1)
		b.Skipped("slack")
		b.Duplicate("slack")
		b.Failed("github", true, true)
		b.Failed("github", false, false)
		b.LedgerError()
		b.UnknownLevel()
		b.UnknownLogSource()
		b.UsedDefaultRoute()
		b.Archive(false)
		b.Archive(true)
	})

	for _, name := range metrics.Names() {
		value, ok := doc[name].(float64)
		if !ok {
			t.Errorf("metric %q is not emitted at all", name)
			continue
		}
		if value == 0 {
			t.Errorf("metric %q is declared but nothing increments it; it would render as a "+
				"flat zero, which is indistinguishable from a quiet week", name)
		}
	}
}

func TestEmit_ReportsPermanentAndAuthFailuresSeparately(t *testing.T) {
	doc := emit(t, func(b *metrics.Batch) {
		b.Failed("github", true, false)
		b.Failed("slack", true, true)
	})

	if doc[metrics.PermanentFailures] != float64(2) {
		t.Errorf("%s = %v, want 2", metrics.PermanentFailures, doc[metrics.PermanentFailures])
	}
	if doc[metrics.AuthFailures] != float64(1) {
		t.Errorf("%s = %v, want 1; a rotated token needs its own alarm",
			metrics.AuthFailures, doc[metrics.AuthFailures])
	}
}

func TestEmit_ReportsTransientFailures(t *testing.T) {
	doc := emit(t, func(b *metrics.Batch) { b.Failed("github", false, false) })

	if doc[metrics.TransientFailures] != float64(1) {
		t.Errorf("%s = %v, want 1", metrics.TransientFailures, doc[metrics.TransientFailures])
	}
	if doc[metrics.PermanentFailures] != float64(0) {
		t.Errorf("a transient failure was counted as permanent")
	}
}

func TestEmit_ReportsDuplicatesAndSkips(t *testing.T) {
	doc := emit(t, func(b *metrics.Batch) {
		b.Duplicate("slack")
		b.Skipped("github")
		b.Skipped("slack")
	})

	if doc[metrics.Duplicates] != float64(1) {
		t.Errorf("%s = %v, want 1", metrics.Duplicates, doc[metrics.Duplicates])
	}
	if doc[metrics.Skipped] != float64(2) {
		t.Errorf("%s = %v, want 2", metrics.Skipped, doc[metrics.Skipped])
	}
}

func TestEmit_ReportsRoutingAnomalies(t *testing.T) {
	doc := emit(t, func(b *metrics.Batch) {
		b.UnknownLevel()
		b.UnknownLogSource()
		b.UsedDefaultRoute()
	})

	for _, name := range []string{metrics.UnknownLevel, metrics.UnknownLogSource, metrics.DefaultRoute} {
		if doc[name] != float64(1) {
			t.Errorf("%s = %v, want 1", name, doc[name])
		}
	}
}

func TestEmit_ReportsLedgerErrors(t *testing.T) {
	doc := emit(t, func(b *metrics.Batch) { b.LedgerError() })

	if doc[metrics.LedgerErrors] != float64(1) {
		t.Errorf("%s = %v, want 1", metrics.LedgerErrors, doc[metrics.LedgerErrors])
	}
}

// Cardinality: the destination is a closed set of two, the alert id is not.
func TestEmit_DoesNotDimensionByAnythingUnbounded(t *testing.T) {
	var buf bytes.Buffer
	b := metrics.New()
	b.Delivered("slack", 1)
	if err := b.Emit(&buf); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	var doc struct {
		AWS struct {
			CloudWatchMetrics []struct {
				Dimensions [][]string `json:"Dimensions"`
			} `json:"CloudWatchMetrics"`
		} `json:"_aws"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, set := range doc.AWS.CloudWatchMetrics[0].Dimensions {
		for _, d := range set {
			if d == "alert_id" || d == "rule_id" || d == "target" {
				t.Errorf("%q is a metric dimension; its cardinality is unbounded", d)
			}
		}
	}
}
