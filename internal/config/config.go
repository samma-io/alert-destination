// Package config loads the service's wiring from the environment.
//
// Everything here is something that differs between a deployment, a local run
// and a test. The routing table itself is not configured here, only where it is
// loaded from (ALERTDEST_ROUTES_PARAM, ALERTDEST_ROUTES_PATH); the table is
// validated at start and a bad one refuses to run.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// DefaultSoftDeadline is how much of the invocation's budget is held back so
// that, when time runs out, there is room to record why.
const DefaultSoftDeadline = 5 * time.Second

// Daemon defaults, used only outside Lambda.
const (
	// DefaultDaemonBatch is one message per receive, the same as the event
	// source mapping's batch_size.
	DefaultDaemonBatch = 1
	// MaxDaemonBatch is SQS's own ceiling on MaxNumberOfMessages.
	MaxDaemonBatch = 10
	// DefaultDaemonMessageTimeout is the per-message budget, matching the
	// Lambda's 60s timeout so the soft deadline behaves the same in both.
	DefaultDaemonMessageTimeout = 60 * time.Second
)

// Transports. The default is SQS, the AWS deployment.
const (
	TransportSQS  = "sqs"
	TransportNATS = "nats"

	DefaultNATSStream   = "SIEM_ALERTS"
	DefaultNATSConsumer = "alert-destination"
)

// Config is the resolved environment.
type Config struct {
	// Transport is "sqs" (Lambda or daemon on SQS, DynamoDB ledger, SSM
	// secrets) or "nats" (daemon on JetStream, Postgres ledger, Kubernetes).
	Transport string

	// NATS transport only.
	NATSURL      string
	NATSStream   string
	NATSConsumer string

	// PostgresDSN or PostgresDSNFile (a mounted Secret) is the database
	// holding the ledger and the postgres destination's tables. Required with
	// the NATS transport.
	PostgresDSN     string
	PostgresDSNFile string

	// LedgerTable is the DynamoDB table recording what has been delivered.
	LedgerTable string

	// SlackTokenParam and GitHubTokenParam are SSM parameter NAMES. The values
	// are read at runtime and never appear in the function's environment.
	SlackTokenParam  string
	GitHubTokenParam string

	// SlackTokenFile and GitHubTokenFile are the NATS transport's equivalent:
	// paths to files holding the tokens (keys of a mounted Secret). Each is
	// required only when the routing table names that destination, which is
	// checked at start once the table is loaded. Ignored with the sqs
	// transport, which reads SSM.
	SlackTokenFile  string
	GitHubTokenFile string

	// RoutesParam and RoutesPath say where the routing table is loaded from:
	// RoutesParam is an SSM parameter NAME holding the YAML, RoutesPath a file.
	// Precedence is parameter, then file, then the table embedded in the
	// binary. Both are optional; a configured one that fails validation stops
	// the service from starting.
	RoutesParam string
	RoutesPath  string

	// ArchiveBucket, when set, is the S3 bucket every alert is written to
	// before any delivery. Empty turns archiving off.
	ArchiveBucket string

	SoftDeadline time.Duration
	LogLevel     slog.Leveler

	// QueueURL is the SQS queue to long-poll when not running in Lambda. In
	// Lambda the event source mapping does the polling and this is ignored.
	QueueURL string
	// DaemonBatch is how many messages one receive asks for (1-10).
	DaemonBatch int
	// DaemonMessageTimeout is the per-message deadline in daemon mode, the
	// equivalent of the Lambda timeout. It must exceed SoftDeadline.
	DaemonMessageTimeout time.Duration

	// Endpoint overrides. Localstack and tests only; empty in the account.
	DynamoDBEndpointURL string
	SSMEndpointURL      string
	S3EndpointURL       string
	SQSEndpointURL      string
	SlackBaseURL        string
	GitHubBaseURL       string
}

// FromEnv reads and validates the environment.
//
// getenv is a parameter rather than a call to os.Getenv so that tests never
// mutate process state, which would leak between them.
//
// Every required value is an error rather than a default, and every problem is
// reported at once. A service that starts with half its wiring drains its queue
// and delivers nothing, and queue depth going down is indistinguishable from a
// quiet week -- so refusing to start is the only cheap defence.
func FromEnv(getenv func(string) string) (Config, error) {
	get := func(key string) string { return strings.TrimSpace(getenv(key)) }

	cfg := Config{
		Transport:       get("ALERTDEST_TRANSPORT"),
		NATSURL:         get("ALERTDEST_NATS_URL"),
		NATSStream:      get("ALERTDEST_NATS_STREAM"),
		NATSConsumer:    get("ALERTDEST_NATS_CONSUMER"),
		PostgresDSN:     get("ALERTDEST_POSTGRES_DSN"),
		PostgresDSNFile: get("ALERTDEST_POSTGRES_DSN_FILE"),

		LedgerTable:      get("ALERTDEST_LEDGER_TABLE"),
		SlackTokenParam:  get("ALERTDEST_SLACK_TOKEN_PARAM"),
		GitHubTokenParam: get("ALERTDEST_GITHUB_TOKEN_PARAM"),
		SlackTokenFile:   get("ALERTDEST_SLACK_TOKEN_FILE"),
		GitHubTokenFile:  get("ALERTDEST_GITHUB_TOKEN_FILE"),
		RoutesParam:      get("ALERTDEST_ROUTES_PARAM"),
		RoutesPath:       get("ALERTDEST_ROUTES_PATH"),
		ArchiveBucket:    get("ALERTDEST_ARCHIVE_BUCKET"),
		QueueURL:         get("ALERTDEST_QUEUE_URL"),

		DynamoDBEndpointURL: get("ALERTDEST_DYNAMODB_ENDPOINT_URL"),
		SSMEndpointURL:      get("ALERTDEST_SSM_ENDPOINT_URL"),
		S3EndpointURL:       get("ALERTDEST_S3_ENDPOINT_URL"),
		SQSEndpointURL:      get("ALERTDEST_SQS_ENDPOINT_URL"),
		SlackBaseURL:        get("ALERTDEST_SLACK_BASE_URL"),
		GitHubBaseURL:       get("ALERTDEST_GITHUB_BASE_URL"),

		// A typo in the level should reduce detail, never silence the service,
		// so this cannot fail.
		LogLevel: parseLevel(get("ALERTDEST_LOG_LEVEL")),
	}

	if cfg.Transport == "" {
		cfg.Transport = TransportSQS
	}
	if cfg.NATSStream == "" {
		cfg.NATSStream = DefaultNATSStream
	}
	if cfg.NATSConsumer == "" {
		cfg.NATSConsumer = DefaultNATSConsumer
	}

	var (
		problems []string
		required []struct{ key, value string }
	)
	switch cfg.Transport {
	case TransportSQS:
		required = []struct{ key, value string }{
			{"ALERTDEST_LEDGER_TABLE", cfg.LedgerTable},
			{"ALERTDEST_SLACK_TOKEN_PARAM", cfg.SlackTokenParam},
			{"ALERTDEST_GITHUB_TOKEN_PARAM", cfg.GitHubTokenParam},
		}
	case TransportNATS:
		// Slack and GitHub are optional here: whether their token files are
		// required depends on the routing table, which is not loaded yet.
		// A table that names one without its ALERTDEST_*_TOKEN_FILE, or with
		// a file that cannot be read, refuses to start.
		required = []struct{ key, value string }{
			{"ALERTDEST_NATS_URL", cfg.NATSURL},
		}
		if cfg.PostgresDSN == "" && cfg.PostgresDSNFile == "" {
			problems = append(problems, "ALERTDEST_POSTGRES_DSN or ALERTDEST_POSTGRES_DSN_FILE is required with the nats transport")
		}
	default:
		problems = append(problems, fmt.Sprintf("ALERTDEST_TRANSPORT must be %q or %q, got %q",
			TransportSQS, TransportNATS, cfg.Transport))
	}
	for _, required := range required {
		if required.value == "" {
			problems = append(problems, required.key+" is required")
		}
	}

	deadline, err := duration(get("ALERTDEST_SOFT_DEADLINE_SECONDS"), DefaultSoftDeadline)
	switch {
	case err != nil:
		problems = append(problems, "ALERTDEST_SOFT_DEADLINE_SECONDS: "+err.Error())
	case deadline <= 0:
		problems = append(problems, "ALERTDEST_SOFT_DEADLINE_SECONDS must be positive")
	default:
		cfg.SoftDeadline = deadline
	}

	batch, err := count(get("ALERTDEST_DAEMON_BATCH"), DefaultDaemonBatch)
	switch {
	case err != nil:
		problems = append(problems, "ALERTDEST_DAEMON_BATCH: "+err.Error())
	case batch < 1 || batch > MaxDaemonBatch:
		problems = append(problems, fmt.Sprintf("ALERTDEST_DAEMON_BATCH must be between 1 and %d", MaxDaemonBatch))
	default:
		cfg.DaemonBatch = batch
	}

	timeout, err := goDuration(get("ALERTDEST_DAEMON_MESSAGE_TIMEOUT"), DefaultDaemonMessageTimeout)
	switch {
	case err != nil:
		problems = append(problems, "ALERTDEST_DAEMON_MESSAGE_TIMEOUT: "+err.Error())
	case cfg.SoftDeadline > 0 && timeout <= cfg.SoftDeadline:
		// Otherwise every delivery is abandoned before it starts.
		problems = append(problems, fmt.Sprintf(
			"ALERTDEST_DAEMON_MESSAGE_TIMEOUT (%s) must exceed the soft deadline (%s)", timeout, cfg.SoftDeadline))
	default:
		cfg.DaemonMessageTimeout = timeout
	}

	if len(problems) > 0 {
		return Config{}, errors.New("invalid configuration:\n  " + strings.Join(problems, "\n  "))
	}
	return cfg, nil
}

func duration(raw string, fallback time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	secs, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%q is not a whole number of seconds", raw)
	}
	return time.Duration(secs) * time.Second, nil
}

func count(raw string, fallback int) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%q is not a whole number", raw)
	}
	return n, nil
}

// goDuration reads a Go duration ("60s", "2m"), or a bare number as seconds so
// the value can be written the same way as ALERTDEST_SOFT_DEADLINE_SECONDS.
func goDuration(raw string, fallback time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		raw = strconv.Itoa(secs) + "s"
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration such as 60s", raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%q must be positive", raw)
	}
	return d, nil
}

func parseLevel(raw string) slog.Leveler {
	switch strings.ToLower(raw) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
