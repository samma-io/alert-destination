// Command alert-destination drains the detection plane's alert queue and
// delivers each alert to the destinations its severity and log source route it
// to.
//
// It is the consumer of the detection-engine's alert queue in the aws-siem
// stack. Notifying is all it does: the evidence trail (archiving the matched
// records) is deliberately somebody else's job.
//
// The contract with SQS is the whole point: an invocation fails whenever any
// routed destination did not receive the alert. Redelivery then retries, the
// message reaches the dead-letter queue after five receives, and the alarms on
// Lambda errors and DLQ depth fire. Returning success while an alert went
// nowhere would make queue depth fall and every dashboard look healthy, which is
// the failure this service exists to prevent.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	awslambda "github.com/aws/aws-lambda-go/lambda"
	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/awsadapt"
	"github.com/samma-io/alert-destination/internal/config"
	"github.com/samma-io/alert-destination/internal/deliver"
	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/destination/github"
	"github.com/samma-io/alert-destination/internal/destination/slack"
	"github.com/samma-io/alert-destination/internal/httpx"
	"github.com/samma-io/alert-destination/internal/ledger"
	"github.com/samma-io/alert-destination/internal/metrics"
	"github.com/samma-io/alert-destination/internal/routing"
	"github.com/samma-io/alert-destination/internal/secrets"
)

// httpTimeout bounds one request to a destination.
//
// Sized from the invocation budget rather than from what a destination usually
// needs: the Lambda gets 60s against the queue's 120s visibility timeout, the
// two destinations run in sequence with two retries each, and the soft deadline
// reserves the last few seconds for recording the outcome.
const httpTimeout = 5 * time.Second

func main() {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		// Nothing structured yet, and nothing worth starting without.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)

	handler, err := build(context.Background(), cfg, log)
	if err != nil {
		log.Error("cannot start", "error", err)
		os.Exit(1)
	}

	awslambda.Start(func(ctx context.Context, event events.SQSEvent) error {
		return handle(ctx, handler, log, event)
	})
}

// build wires everything together.
//
// Deliberately not in init(): an init() failure produces Runtime.ExitError with
// no structured log, and it re-runs on every cold start of a container that will
// keep failing the same way.
func build(ctx context.Context, cfg config.Config, log *slog.Logger) (*deliver.Handler, error) {
	aws, err := awsadapt.New(ctx, awsadapt.Options{
		LedgerTable:         cfg.LedgerTable,
		DynamoDBEndpointURL: cfg.DynamoDBEndpointURL, // local runs and tests only
		SSMEndpointURL:      cfg.SSMEndpointURL,      // local runs and tests only
	})
	if err != nil {
		return nil, err
	}

	// The routing table is loaded and validated here, at start, so a table that
	// would send an alert nowhere fails the deploy rather than one alert. A
	// configured source (SSM parameter, then file) is authoritative: if it cannot
	// be read or does not validate this returns an error rather than falling
	// back to the embedded table, because routing with a table the operator did
	// not choose is exactly the kind of fail-open this service exists to prevent.
	routes, origin, err := routing.Select(ctx, routing.Sources{
		Param:      cfg.RoutesParam,
		Path:       cfg.RoutesPath,
		Parameters: aws.Parameters,
	})
	if err != nil {
		return nil, fmt.Errorf("loading the routing table: %w", err)
	}

	// Secrets resolve lazily, so an alert routed only to Slack is not blocked by
	// an unreadable GitHub credential.
	tokens := secrets.NewCache(aws.Parameters)

	client := &http.Client{
		Timeout: httpTimeout,
		Transport: &httpx.RetryTransport{
			// The ceiling is what stops a GitHub secondary-rate-limit
			// Retry-After of 60s from sleeping through the whole invocation.
			MaxWait:    httpx.DefaultMaxWait,
			MaxRetries: 2,
		},
	}

	registry := destination.NewRegistry(
		&slack.Client{HTTP: client, Token: tokens.TokenFunc(cfg.SlackTokenParam), BaseURL: cfg.SlackBaseURL},
		&github.Client{HTTP: client, Token: tokens.TokenFunc(cfg.GitHubTokenParam), BaseURL: cfg.GitHubBaseURL},
	)

	log.Info("starting",
		"ledger_table", cfg.LedgerTable,
		"destinations", registry.Names(),
		"routes", len(routes.Routes),
		"routes_origin", string(origin),
		"soft_deadline", cfg.SoftDeadline.String(),
	)

	return &deliver.Handler{
		Routes:   routes,
		Registry: registry,
		Ledger:   &ledger.Ledger{Store: aws.Ledger},
		Log:      log,
		Reserve:  cfg.SoftDeadline,
	}, nil
}

// handle processes one SQS delivery.
//
// The event source is configured with batch_size = 1, so this is one alert in
// practice. The loop is still written to handle a batch, and to fail if any
// record fails, because the alternative -- assuming one record and silently
// ignoring the rest -- would drop alerts if the batch size were ever raised
// without anyone reading this function.
func handle(ctx context.Context, h *deliver.Handler, log *slog.Logger, event events.SQSEvent) error {
	batch := metrics.New()
	defer func() {
		if err := batch.Emit(os.Stdout); err != nil {
			log.Error("could not emit metrics", "error", err)
		}
	}()

	var failures []error

	for _, msg := range event.Records {
		a, err := alert.Decode([]byte(msg.Body))
		if err != nil {
			// A message we cannot read will not become readable on redelivery.
			// It still fails the invocation so it reaches the DLQ, where it is
			// its own evidence.
			log.Error("undecodable alert", "sqs_message_id", msg.MessageId, "error", err)
			failures = append(failures, err)
			continue
		}
		if !a.KnownSchema() {
			// Reported, not rejected: refusing an unfamiliar version would send
			// every alert to the DLQ the moment the producer bumps its schema.
			log.Warn("alert carries an unfamiliar schema version",
				"alert_id", a.ID, "schema_version", a.SchemaVersion,
				"built_for", alert.SchemaVersion)
		}

		res, err := h.Handle(ctx, a)
		count(batch, res)
		if err != nil {
			failures = append(failures, err)
		}
	}

	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	return nil
}

// count folds one alert's outcome into the invocation's metrics.
func count(batch *metrics.Batch, res deliver.Result) {
	for _, k := range res.Delivered {
		batch.Delivered(k.Destination, 1)
	}
	for _, k := range res.Skipped {
		batch.Skipped(k.Destination)
	}
	for _, f := range res.Failed {
		batch.Failed(f.Key.Destination, f.Permanent, destination.IsAuthFailure(f.Err))
	}
	for i := 0; i < res.Duplicates; i++ {
		batch.Duplicate("")
	}
	for i := 0; i < res.LedgerErrors; i++ {
		batch.LedgerError()
	}
	if res.Match.UnknownLevel {
		batch.UnknownLevel()
	}
	if res.Match.UnknownLogSource {
		batch.UnknownLogSource()
	}
	if res.Match.UsedDefault {
		batch.UsedDefaultRoute()
	}
}
