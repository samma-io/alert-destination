// Package config loads the Lambda's wiring from the environment.
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

// Config is the resolved environment.
type Config struct {
	// LedgerTable is the DynamoDB table recording what has been delivered.
	LedgerTable string

	// SlackTokenParam and GitHubTokenParam are SSM parameter NAMES. The values
	// are read at runtime and never appear in the function's environment.
	SlackTokenParam  string
	GitHubTokenParam string

	// RoutesParam and RoutesPath say where the routing table is loaded from:
	// RoutesParam is an SSM parameter NAME holding the YAML, RoutesPath a file.
	// Precedence is parameter, then file, then the table embedded in the
	// binary. Both are optional; a configured one that fails validation stops
	// the service from starting.
	RoutesParam string
	RoutesPath  string

	SoftDeadline time.Duration
	LogLevel     slog.Leveler

	// Endpoint overrides. Localstack and tests only; empty in the account.
	DynamoDBEndpointURL string
	SSMEndpointURL      string
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
		LedgerTable:      get("ALERTDEST_LEDGER_TABLE"),
		SlackTokenParam:  get("ALERTDEST_SLACK_TOKEN_PARAM"),
		GitHubTokenParam: get("ALERTDEST_GITHUB_TOKEN_PARAM"),
		RoutesParam:      get("ALERTDEST_ROUTES_PARAM"),
		RoutesPath:       get("ALERTDEST_ROUTES_PATH"),

		DynamoDBEndpointURL: get("ALERTDEST_DYNAMODB_ENDPOINT_URL"),
		SSMEndpointURL:      get("ALERTDEST_SSM_ENDPOINT_URL"),
		SlackBaseURL:        get("ALERTDEST_SLACK_BASE_URL"),
		GitHubBaseURL:       get("ALERTDEST_GITHUB_BASE_URL"),

		// A typo in the level should reduce detail, never silence the service,
		// so this cannot fail.
		LogLevel: parseLevel(get("ALERTDEST_LOG_LEVEL")),
	}

	var problems []string
	for _, required := range []struct{ key, value string }{
		{"ALERTDEST_LEDGER_TABLE", cfg.LedgerTable},
		{"ALERTDEST_SLACK_TOKEN_PARAM", cfg.SlackTokenParam},
		{"ALERTDEST_GITHUB_TOKEN_PARAM", cfg.GitHubTokenParam},
	} {
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
