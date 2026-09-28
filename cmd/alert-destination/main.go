// Command alert-destination drains the detection plane's alert queue and
// delivers each alert to the destinations its severity and log source route it
// to.
//
// It is the consumer of the detection-engine's alert queue in the aws-siem
// stack. With ALERTDEST_ARCHIVE_BUCKET set it also writes every alert to S3
// before delivering it; the matched records themselves stay where provenance
// says they are.
//
// One binary, two ways to run. With AWS_LAMBDA_RUNTIME_API set it is a Lambda
// fed by an SQS event source mapping. Without it, it is a daemon that long-polls
// ALERTDEST_QUEUE_URL itself (internal/daemon). Both feed every message through
// the same handle function below.
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
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-lambda-go/events"
	awslambda "github.com/aws/aws-lambda-go/lambda"
	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/archive"
	"github.com/samma-io/alert-destination/internal/awsadapt"
	"github.com/samma-io/alert-destination/internal/config"
	"github.com/samma-io/alert-destination/internal/daemon"
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
// needs: the Lambda (or one daemon message) gets 60s, the two destinations run
// in sequence with two retries each, and the soft deadline reserves the last few
// seconds for recording the outcome.
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

	// The Lambda runtime sets this; nothing else does.
	inLambda := os.Getenv("AWS_LAMBDA_RUNTIME_API") != ""
	if !inLambda && cfg.QueueURL == "" {
		log.Error("cannot start", "error", daemon.ErrNoQueue.Error())
		os.Exit(1)
	}
	if inLambda {
		// The event source mapping owns the queue. Building an SQS client from
		// a stray variable would only be a second, unused poller-in-waiting.
		cfg.QueueURL = ""
	}

	handler, aws, err := build(context.Background(), cfg, log)
	if err != nil {
		log.Error("cannot start", "error", err)
		os.Exit(1)
	}

	if inLambda {
		awslambda.Start(func(ctx context.Context, event events.SQSEvent) error {
			return handle(ctx, handler, log, fromLambda(event))
		})
		return
	}

	// Outside Lambda: poll until SIGTERM (ECS, Kubernetes, docker stop) or
	// SIGINT (a terminal), then exit 0.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	log.Info("polling the alert queue",
		"queue_url", cfg.QueueURL,
		"batch", cfg.DaemonBatch,
		"message_timeout", cfg.DaemonMessageTimeout.String(),
	)
	loop := &daemon.Loop{
		Queue:          aws.Queue,
		Batch:          cfg.DaemonBatch,
		MessageTimeout: cfg.DaemonMessageTimeout,
		Log:            log,
		Handle: func(ctx context.Context, m daemon.Message) error {
			return handle(ctx, handler, log, []message{{ID: m.ID, Body: m.Body}})
		},
	}
	if err := loop.Run(ctx); err != nil {
		log.Error("daemon stopped", "error", err)
		os.Exit(1)
	}
	log.Info("stopped")
}

// message is one queue message, whichever way it arrived.
type message struct {
	ID   string
	Body string
}

// fromLambda is the only place that reads the Lambda event type, so handle is
// the same function in both modes.
func fromLambda(event events.SQSEvent) []message {
	out := make([]message, 0, len(event.Records))
	for _, r := range event.Records {
		out = append(out, message{ID: r.MessageId, Body: r.Body})
	}
	return out
}

// build wires everything together.
//
// Deliberately not in init(): an init() failure produces Runtime.ExitError with
// no structured log, and it re-runs on every cold start of a container that will
// keep failing the same way.
func build(ctx context.Context, cfg config.Config, log *slog.Logger) (*deliver.Handler, *awsadapt.Clients, error) {
	aws, err := awsadapt.New(ctx, awsadapt.Options{
		LedgerTable:         cfg.LedgerTable,
		ArchiveBucket:       cfg.ArchiveBucket,
		QueueURL:            cfg.QueueURL,
		DynamoDBEndpointURL: cfg.DynamoDBEndpointURL, // local runs and tests only
		SSMEndpointURL:      cfg.SSMEndpointURL,      // local runs and tests only
		S3EndpointURL:       cfg.S3EndpointURL,       // local runs and tests only
		SQSEndpointURL:      cfg.SQSEndpointURL,      // local runs and tests only
	})
	if err != nil {
		return nil, nil, err
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
		return nil, nil, fmt.Errorf("loading the routing table: %w", err)
	}

	// Secrets resolve lazily, so an alert routed only to Slack is not blocked by
	// an unreadable GitHub credential.
	tokens := secrets.NewCache(aws.Parameters)

	// One client per destination, because the retry policy is per API: Slack
	// reports throttling in the body of an HTTP 200, GitHub in its status and
	// headers. The ceiling on both is what stops a GitHub secondary-rate-limit
	// Retry-After of 60s from sleeping through the whole invocation.
	client := func(policy httpx.Policy) *http.Client {
		return &http.Client{
			Timeout: httpTimeout,
			Transport: &httpx.RetryTransport{
				Policy:     policy,
				MaxWait:    httpx.DefaultMaxWait,
				MaxRetries: 2,
			},
		}
	}

	registry := destination.NewRegistry(
		&slack.Client{
			HTTP:            client(slack.RetryPolicy),
			Token:           tokens.TokenFunc(cfg.SlackTokenParam),
			InvalidateToken: func() { tokens.Invalidate(cfg.SlackTokenParam) },
			BaseURL:         cfg.SlackBaseURL,
		},
		&github.Client{
			HTTP:            client(nil),
			Token:           tokens.TokenFunc(cfg.GitHubTokenParam),
			InvalidateToken: func() { tokens.Invalidate(cfg.GitHubTokenParam) },
			BaseURL:         cfg.GitHubBaseURL,
		},
	)

	var arch *archive.Archive
	if aws.Archive != nil {
		arch = &archive.Archive{Store: aws.Archive, Bucket: cfg.ArchiveBucket}
	}

	log.Info("starting",
		"ledger_table", cfg.LedgerTable,
		"archive_bucket", cfg.ArchiveBucket,
		"destinations", registry.Names(),
		"routes", len(routes.Routes),
		"routes_origin", string(origin),
		"soft_deadline", cfg.SoftDeadline.String(),
	)

	return &deliver.Handler{
		Routes:   routes,
		Registry: registry,
		Ledger:   &ledger.Ledger{Store: aws.Ledger},
		Archive:  arch,
		Log:      log,
		Reserve:  cfg.SoftDeadline,
	}, aws, nil
}

// handle processes one SQS delivery: a Lambda invocation's batch, or one
// message in daemon mode.
//
// The event source is configured with batch_size = 1, so this is one alert in
// practice. The loop is still written to handle a batch, and to fail if any
// record fails, because the alternative -- assuming one record and silently
// ignoring the rest -- would drop alerts if the batch size were ever raised
// without anyone reading this function.
func handle(ctx context.Context, h *deliver.Handler, log *slog.Logger, msgs []message) error {
	batch := metrics.New()
	defer func() {
		if err := batch.Emit(os.Stdout); err != nil {
			log.Error("could not emit metrics", "error", err)
		}
	}()

	var failures []error

	for _, msg := range msgs {
		a, err := alert.Decode([]byte(msg.Body))
		if err != nil {
			// A message we cannot read will not become readable on redelivery.
			// It still fails the invocation so it reaches the DLQ, where it is
			// its own evidence.
			log.Error("undecodable alert", "sqs_message_id", msg.ID, "error", err)
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
	switch res.Archive {
	case deliver.ArchiveWritten:
		batch.Archive(false)
	case deliver.ArchiveFailed:
		batch.Archive(true)
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
