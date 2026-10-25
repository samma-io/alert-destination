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
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-lambda-go/events"
	awslambda "github.com/aws/aws-lambda-go/lambda"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/archive"
	"github.com/samma-io/alert-destination/internal/awsadapt"
	"github.com/samma-io/alert-destination/internal/config"
	"github.com/samma-io/alert-destination/internal/daemon"
	"github.com/samma-io/alert-destination/internal/deliver"
	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/destination/github"
	"github.com/samma-io/alert-destination/internal/destination/postgres"
	"github.com/samma-io/alert-destination/internal/destination/slack"
	"github.com/samma-io/alert-destination/internal/httpx"
	"github.com/samma-io/alert-destination/internal/ledger"
	"github.com/samma-io/alert-destination/internal/metrics"
	"github.com/samma-io/alert-destination/internal/natsadapt"
	"github.com/samma-io/alert-destination/internal/pgadapt"
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
	if inLambda && cfg.Transport != config.TransportSQS {
		log.Error("cannot start", "error", "a Lambda is fed by SQS; ALERTDEST_TRANSPORT must be sqs")
		os.Exit(1)
	}
	if !inLambda && cfg.Transport == config.TransportSQS && cfg.QueueURL == "" {
		log.Error("cannot start", "error", daemon.ErrNoQueue.Error())
		os.Exit(1)
	}
	if inLambda {
		// The event source mapping owns the queue. Building an SQS client from
		// a stray variable would only be a second, unused poller-in-waiting.
		cfg.QueueURL = ""
	}

	handler, queue, closeAll, err := build(context.Background(), cfg, log)
	if err != nil {
		log.Error("cannot start", "error", err)
		os.Exit(1)
	}
	defer closeAll()

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
		"transport", cfg.Transport,
		"queue_url", cfg.QueueURL,
		"nats_consumer", cfg.NATSStream+"/"+cfg.NATSConsumer,
		"batch", cfg.DaemonBatch,
		"message_timeout", cfg.DaemonMessageTimeout.String(),
	)
	loop := &daemon.Loop{
		Queue:          queue,
		Batch:          cfg.DaemonBatch,
		MessageTimeout: cfg.DaemonMessageTimeout,
		Log:            log,
		Handle: func(ctx context.Context, m daemon.Message) error {
			return handle(ctx, handler, log, []message{{ID: m.ID, Body: m.Body}})
		},
	}
	if err := loop.Run(ctx); err != nil {
		log.Error("daemon stopped", "error", err)
		closeAll()
		os.Exit(1) //nolint:gocritic // closeAll already ran
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
//
// The transport picks the backing services: SQS, DynamoDB, SSM and S3 on AWS;
// JetStream and Postgres in Kubernetes. Everything after the wiring -- routing,
// the ledger rules, delivery -- is the same code either way.
func build(ctx context.Context, cfg config.Config, log *slog.Logger) (*deliver.Handler, daemon.Queue, func(), error) {
	if cfg.Transport == config.TransportNATS {
		return buildNATS(ctx, cfg, log)
	}

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
		return nil, nil, nil, err
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
		return nil, nil, nil, fmt.Errorf("loading the routing table: %w", err)
	}

	// Secrets resolve lazily, so an alert routed only to Slack is not blocked by
	// an unreadable GitHub credential.
	tokens := secrets.NewCache(aws.Parameters)

	registry := destination.NewRegistry(
		&slack.Client{
			HTTP:            httpClient(slack.RetryPolicy),
			Token:           tokens.TokenFunc(cfg.SlackTokenParam),
			InvalidateToken: func() { tokens.Invalidate(cfg.SlackTokenParam) },
			BaseURL:         cfg.SlackBaseURL,
		},
		&github.Client{
			HTTP:            httpClient(nil),
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
		"transport", cfg.Transport,
		"ledger_table", cfg.LedgerTable,
		"archive_bucket", cfg.ArchiveBucket,
		"destinations", registry.Names(),
		"routes", len(routes.Routes),
		"routes_origin", string(origin),
		"soft_deadline", cfg.SoftDeadline.String(),
	)

	var queue daemon.Queue
	if aws.Queue != nil {
		queue = aws.Queue
	}
	return &deliver.Handler{
		Routes:   routes,
		Registry: registry,
		Ledger:   &ledger.Ledger{Store: aws.Ledger},
		Archive:  arch,
		Log:      log,
		Reserve:  cfg.SoftDeadline,
	}, queue, func() {}, nil
}

// buildNATS wires the Kubernetes deployment: alerts from a JetStream consumer,
// the ledger and the postgres destination in one database, and Slack and
// GitHub when the routing table names them. No AWS client is built, so nothing
// here can reach for credentials that do not exist.
func buildNATS(ctx context.Context, cfg config.Config, log *slog.Logger) (*deliver.Handler, daemon.Queue, func(), error) {
	dsn := cfg.PostgresDSN
	if cfg.PostgresDSNFile != "" {
		raw, err := os.ReadFile(cfg.PostgresDSNFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reading the postgres DSN file: %w", err)
		}
		dsn = strings.TrimSpace(string(raw))
	}
	db, err := pgadapt.Open(ctx, dsn)
	if err != nil {
		return nil, nil, nil, err
	}

	nc, err := nats.Connect(cfg.NATSURL, nats.Name("alert-destination"), nats.MaxReconnects(-1))
	if err != nil {
		db.Close()
		return nil, nil, nil, fmt.Errorf("nats connect: %w", err)
	}
	closeAll := func() {
		_ = nc.Drain()
		db.Close()
	}
	js, err := jetstream.New(nc)
	if err != nil {
		closeAll()
		return nil, nil, nil, fmt.Errorf("jetstream: %w", err)
	}
	// The consumer is created by the deployment, not here: its AckWait and
	// MaxDeliver are the redelivery policy, and that belongs with the stream.
	consumer, err := js.Consumer(ctx, cfg.NATSStream, cfg.NATSConsumer)
	if err != nil {
		closeAll()
		return nil, nil, nil, fmt.Errorf("jetstream consumer %s/%s: %w", cfg.NATSStream, cfg.NATSConsumer, err)
	}

	// Only a file: there is no SSM here, and the embedded table routes to
	// placeholders.
	if cfg.RoutesPath == "" {
		closeAll()
		return nil, nil, nil, errors.New("ALERTDEST_ROUTES_PATH is required with the nats transport")
	}
	routes, origin, err := routing.Select(ctx, routing.Sources{Path: cfg.RoutesPath})
	if err != nil {
		closeAll()
		return nil, nil, nil, fmt.Errorf("loading the routing table: %w", err)
	}

	registry, err := natsRegistry(ctx, cfg, routes, &postgres.Client{DB: db}, log)
	if err != nil {
		closeAll()
		return nil, nil, nil, err
	}

	log.Info("starting",
		"transport", cfg.Transport,
		"nats_consumer", cfg.NATSStream+"/"+cfg.NATSConsumer,
		"destinations", registry.Names(),
		"routes", len(routes.Routes),
		"routes_origin", string(origin),
		"soft_deadline", cfg.SoftDeadline.String(),
	)

	return &deliver.Handler{
		Routes:   routes,
		Registry: registry,
		Ledger:   &ledger.Ledger{Store: &pgadapt.Ledger{DB: db}},
		Log:      log,
		Reserve:  cfg.SoftDeadline,
	}, &natsadapt.Queue{Consumer: consumer}, closeAll, nil
}

// natsRegistry builds the destinations of a nats deployment: postgres always,
// Slack and GitHub only when the routing table names them, with their tokens
// read from files (a mounted Secret) instead of SSM.
//
// A routed destination's token is read here, once, so a missing key in the
// Secret fails the rollout rather than every alert routed there. After that
// the cache behaves as on AWS: an authentication failure invalidates the
// token and the next delivery re-reads the file, which picks up a rotated
// Secret with no restart. The token is held only by the cache and sent only
// in the destination's Authorization header; no error or log line carries it.
func natsRegistry(ctx context.Context, cfg config.Config, routes *routing.Table, pg destination.Destination, log *slog.Logger) (*destination.Registry, error) {
	routed := routedDestinations(routes)
	tokens := secrets.NewCache(secrets.Files{})
	dests := []destination.Destination{pg}

	var problems []error
	token := func(name, env, path string) bool {
		switch {
		case !routed[name] && path != "":
			log.Info("token file configured for a destination no route reaches; not building it",
				"destination", name, "env", env)
			return false
		case !routed[name]:
			return false
		case path == "":
			problems = append(problems, fmt.Errorf("the routing table names %s; set %s to the file holding its token", name, env))
			return false
		}
		if _, err := tokens.Get(ctx, path); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", env, err))
			return false
		}
		return true
	}

	if token("slack", "ALERTDEST_SLACK_TOKEN_FILE", cfg.SlackTokenFile) {
		dests = append(dests, &slack.Client{
			HTTP:            httpClient(slack.RetryPolicy),
			Token:           tokens.TokenFunc(cfg.SlackTokenFile),
			InvalidateToken: func() { tokens.Invalidate(cfg.SlackTokenFile) },
			BaseURL:         cfg.SlackBaseURL,
		})
	}
	if token("github", "ALERTDEST_GITHUB_TOKEN_FILE", cfg.GitHubTokenFile) {
		dests = append(dests, &github.Client{
			HTTP:            httpClient(nil),
			Token:           tokens.TokenFunc(cfg.GitHubTokenFile),
			InvalidateToken: func() { tokens.Invalidate(cfg.GitHubTokenFile) },
			BaseURL:         cfg.GitHubBaseURL,
		})
	}
	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}

	registry := destination.NewRegistry(dests...)
	if err := checkRegistered(routes, registry); err != nil {
		return nil, err
	}
	return registry, nil
}

// routedDestinations is every destination name the table can deliver to.
func routedDestinations(t *routing.Table) map[string]bool {
	out := map[string]bool{}
	for _, rt := range t.Routes {
		for _, d := range rt.Deliveries {
			out[d.To] = true
		}
	}
	for _, d := range t.Default.Deliveries {
		out[d.To] = true
	}
	return out
}

// checkRegistered refuses a routing table that names a destination this
// process has not built. Without it the first alert routed there fails at
// delivery time, one alert at a time.
func checkRegistered(t *routing.Table, r *destination.Registry) error {
	var missing []string
	for name := range routedDestinations(t) {
		if _, err := r.Lookup(name); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("the routing table names destinations this deployment has not configured: %s; registered: %s",
			strings.Join(missing, ", "), strings.Join(r.Names(), ", "))
	}
	return nil
}

// httpClient is one client per destination, because the retry policy is per
// API: Slack reports throttling in the body of an HTTP 200, GitHub in its
// status and headers. The ceiling on both is what stops a GitHub
// secondary-rate-limit Retry-After of 60s from sleeping through the whole
// invocation.
func httpClient(policy httpx.Policy) *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		Transport: &httpx.RetryTransport{
			Policy:     policy,
			MaxWait:    httpx.DefaultMaxWait,
			MaxRetries: 2,
		},
	}
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
