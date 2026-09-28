package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/samma-io/alert-destination/internal/config"
)

func env(pairs map[string]string) func(string) string {
	return func(k string) string { return pairs[k] }
}

func complete() map[string]string {
	return map[string]string{
		"ALERTDEST_LEDGER_TABLE":       "alert-destination-ledger-1-us-east-1",
		"ALERTDEST_SLACK_TOKEN_PARAM":  "/applications/alert-destination/SLACK_BOT_TOKEN",
		"ALERTDEST_GITHUB_TOKEN_PARAM": "/applications/alert-destination/GITHUB_TOKEN",
	}
}

func TestFromEnv_ReadsTheWiring(t *testing.T) {
	cfg, err := config.FromEnv(env(complete()))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}

	if cfg.LedgerTable != "alert-destination-ledger-1-us-east-1" {
		t.Errorf("LedgerTable = %q", cfg.LedgerTable)
	}
	if cfg.SlackTokenParam == "" || cfg.GitHubTokenParam == "" {
		t.Errorf("token parameter names not read: %+v", cfg)
	}
}

// A service that starts with half its wiring and drains the queue delivering
// nothing looks healthy on every dashboard, so every required value is an error
// rather than a default.
func TestFromEnv_RequiresTheLedgerTable(t *testing.T) {
	vars := complete()
	delete(vars, "ALERTDEST_LEDGER_TABLE")

	if _, err := config.FromEnv(env(vars)); err == nil {
		t.Fatal("FromEnv succeeded with no ledger table")
	}
}

func TestFromEnv_RequiresBothTokenParameters(t *testing.T) {
	for _, key := range []string{"ALERTDEST_SLACK_TOKEN_PARAM", "ALERTDEST_GITHUB_TOKEN_PARAM"} {
		vars := complete()
		delete(vars, key)

		if _, err := config.FromEnv(env(vars)); err == nil {
			t.Errorf("FromEnv succeeded with no %s", key)
		}
	}
}

// One deploy, one list of everything wrong, rather than a fix-and-redeploy loop.
func TestFromEnv_ReportsEveryProblemAtOnce(t *testing.T) {
	_, err := config.FromEnv(env(map[string]string{}))
	if err == nil {
		t.Fatal("FromEnv succeeded with an empty environment")
	}

	for _, want := range []string{
		"ALERTDEST_LEDGER_TABLE",
		"ALERTDEST_SLACK_TOKEN_PARAM",
		"ALERTDEST_GITHUB_TOKEN_PARAM",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestFromEnv_SoftDeadlineDefaults(t *testing.T) {
	cfg, err := config.FromEnv(env(complete()))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.SoftDeadline <= 0 {
		t.Errorf("SoftDeadline = %v, want a non-zero default", cfg.SoftDeadline)
	}
}

func TestFromEnv_SoftDeadlineIsTunable(t *testing.T) {
	vars := complete()
	vars["ALERTDEST_SOFT_DEADLINE_SECONDS"] = "8"

	cfg, err := config.FromEnv(env(vars))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.SoftDeadline != 8*time.Second {
		t.Errorf("SoftDeadline = %v, want 8s", cfg.SoftDeadline)
	}
}

func TestFromEnv_RejectsANonNumericSoftDeadline(t *testing.T) {
	vars := complete()
	vars["ALERTDEST_SOFT_DEADLINE_SECONDS"] = "soon"

	if _, err := config.FromEnv(env(vars)); err == nil {
		t.Fatal("FromEnv accepted a non-numeric soft deadline")
	}
}

func TestFromEnv_RejectsANegativeSoftDeadline(t *testing.T) {
	vars := complete()
	vars["ALERTDEST_SOFT_DEADLINE_SECONDS"] = "-1"

	if _, err := config.FromEnv(env(vars)); err == nil {
		t.Fatal("FromEnv accepted a negative soft deadline")
	}
}

// A typo should reduce detail, never silence the service.
func TestFromEnv_AnUnparseableLogLevelFallsBackToInfo(t *testing.T) {
	vars := complete()
	vars["ALERTDEST_LOG_LEVEL"] = "verbose-ish"

	cfg, err := config.FromEnv(env(vars))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.LogLevel.Level().String() != "INFO" {
		t.Errorf("LogLevel = %v, want INFO", cfg.LogLevel)
	}
}

func TestFromEnv_LogLevelIsCaseInsensitive(t *testing.T) {
	vars := complete()
	vars["ALERTDEST_LOG_LEVEL"] = "debug"

	cfg, err := config.FromEnv(env(vars))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.LogLevel.Level().String() != "DEBUG" {
		t.Errorf("LogLevel = %v, want DEBUG", cfg.LogLevel)
	}
}

// Localstack needs these; the account must never set them.
func TestFromEnv_EndpointOverridesAreOptional(t *testing.T) {
	cfg, err := config.FromEnv(env(complete()))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.DynamoDBEndpointURL != "" || cfg.SSMEndpointURL != "" ||
		cfg.SlackBaseURL != "" || cfg.GitHubBaseURL != "" {
		t.Errorf("endpoint overrides default to non-empty: %+v", cfg)
	}
}

func TestFromEnv_EndpointOverridesAreRead(t *testing.T) {
	vars := complete()
	vars["ALERTDEST_DYNAMODB_ENDPOINT_URL"] = "http://localhost:4566"
	vars["ALERTDEST_SLACK_BASE_URL"] = "http://localhost:9001"

	cfg, err := config.FromEnv(env(vars))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.DynamoDBEndpointURL != "http://localhost:4566" {
		t.Errorf("DynamoDBEndpointURL = %q", cfg.DynamoDBEndpointURL)
	}
	if cfg.SlackBaseURL != "http://localhost:9001" {
		t.Errorf("SlackBaseURL = %q", cfg.SlackBaseURL)
	}
}

// Without either, the embedded table is used; the keys must not be required.
func TestFromEnv_RoutesSourcesAreOptional(t *testing.T) {
	cfg, err := config.FromEnv(env(complete()))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.RoutesParam != "" || cfg.RoutesPath != "" {
		t.Errorf("routes sources default to non-empty: %+v", cfg)
	}
}

func TestFromEnv_RoutesSourcesAreRead(t *testing.T) {
	vars := complete()
	vars["ALERTDEST_ROUTES_PARAM"] = "/siem/alert-destination/routes"
	vars["ALERTDEST_ROUTES_PATH"] = "/etc/alert-destination/routes.yaml"

	cfg, err := config.FromEnv(env(vars))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.RoutesParam != "/siem/alert-destination/routes" {
		t.Errorf("RoutesParam = %q", cfg.RoutesParam)
	}
	if cfg.RoutesPath != "/etc/alert-destination/routes.yaml" {
		t.Errorf("RoutesPath = %q", cfg.RoutesPath)
	}
}

func TestFromEnv_ArchiveIsOffUnlessABucketIsSet(t *testing.T) {
	cfg, err := config.FromEnv(env(complete()))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.ArchiveBucket != "" {
		t.Errorf("ArchiveBucket = %q, want empty", cfg.ArchiveBucket)
	}

	vars := complete()
	vars["ALERTDEST_ARCHIVE_BUCKET"] = "siem-detections-123456789012"
	if cfg, _ = config.FromEnv(env(vars)); cfg.ArchiveBucket != "siem-detections-123456789012" {
		t.Errorf("ArchiveBucket = %q", cfg.ArchiveBucket)
	}
}

func TestFromEnv_DaemonDefaults(t *testing.T) {
	cfg, err := config.FromEnv(env(complete()))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.QueueURL != "" || cfg.DaemonBatch != 1 || cfg.DaemonMessageTimeout != 60*time.Second {
		t.Errorf("daemon defaults = %q/%d/%s, want empty/1/60s",
			cfg.QueueURL, cfg.DaemonBatch, cfg.DaemonMessageTimeout)
	}
}

func TestFromEnv_DaemonSettingsAreRead(t *testing.T) {
	vars := complete()
	vars["ALERTDEST_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123456789012/alerts"
	vars["ALERTDEST_SQS_ENDPOINT_URL"] = "http://localhost:4566"
	vars["ALERTDEST_DAEMON_BATCH"] = "10"
	vars["ALERTDEST_DAEMON_MESSAGE_TIMEOUT"] = "2m"

	cfg, err := config.FromEnv(env(vars))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.QueueURL == "" || cfg.SQSEndpointURL != "http://localhost:4566" {
		t.Errorf("queue wiring not read: %+v", cfg)
	}
	if cfg.DaemonBatch != 10 || cfg.DaemonMessageTimeout != 2*time.Minute {
		t.Errorf("batch/timeout = %d/%s, want 10/2m", cfg.DaemonBatch, cfg.DaemonMessageTimeout)
	}
}

func TestFromEnv_DaemonTimeoutAcceptsBareSeconds(t *testing.T) {
	vars := complete()
	vars["ALERTDEST_DAEMON_MESSAGE_TIMEOUT"] = "90"

	cfg, err := config.FromEnv(env(vars))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.DaemonMessageTimeout != 90*time.Second {
		t.Errorf("DaemonMessageTimeout = %s, want 90s", cfg.DaemonMessageTimeout)
	}
}

func TestFromEnv_RejectsBadDaemonSettings(t *testing.T) {
	for name, pair := range map[string][2]string{
		"batch zero":           {"ALERTDEST_DAEMON_BATCH", "0"},
		"batch over SQS limit": {"ALERTDEST_DAEMON_BATCH", "11"},
		"batch not a number":   {"ALERTDEST_DAEMON_BATCH", "many"},
		"timeout garbage":      {"ALERTDEST_DAEMON_MESSAGE_TIMEOUT", "soon"},
		"timeout negative":     {"ALERTDEST_DAEMON_MESSAGE_TIMEOUT", "-5s"},
		// Under the 5s soft deadline, every delivery would be abandoned.
		"timeout under reserve": {"ALERTDEST_DAEMON_MESSAGE_TIMEOUT", "5s"},
	} {
		vars := complete()
		vars[pair[0]] = pair[1]
		if _, err := config.FromEnv(env(vars)); err == nil {
			t.Errorf("%s: FromEnv accepted %s=%s", name, pair[0], pair[1])
		}
	}
}
