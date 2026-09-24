# alert-destination

The alert router of [`samma-io/aws-siem`](https://github.com/samma-io/aws-siem): a Go Lambda
that drains the detection queue and delivers each `detection.alert.v1` message to the places
humans read, exactly once per destination.

```
detection-engine ──► SQS detections-alerts ──► alert-destination ──┬──► Slack   chat.postMessage
 (one queue, every lane)   visibility 120s        (Lambda, batch_size=1) └──► GitHub  POST /repos/{owner}/{repo}/issues
                           DLQ after 5 receives              │
                                                             ▼
                                             DynamoDB delivery ledger (what reached where, and why not)

                      any routed destination undelivered ──► invocation fails ──► SQS redelivers ──► DLQ ──► alarm
```

## Where it sits in the flow

`aws-siem` lands logs in S3, parses them with Vector into per-lane filtered objects, and runs
Sigma rules over each lane in `detection-engine`. Every match becomes one
`detection.alert.v1` message on a single SQS queue. This function is that queue's only
consumer. It routes by `(level, log_source)` to Slack and/or GitHub, records every delivery in
a DynamoDB ledger so a redelivered message never notifies anyone twice, and fails the
invocation whenever an alert did not reach every destination it was routed to. Archiving the
matched record is deliberately not its job; the alert's `provenance` names the object in S3.

The Terraform that deploys it (function, ledger table, queue wiring, SSM parameters, alarms)
is the `alert-destination` module in `aws-siem`. This repository holds only the code and
publishes the deployment package.

## The one rule

**An alert that did not reach every destination it was routed to fails the invocation.**

Returning success while an alert went nowhere would make queue depth fall, errors stay at
zero, and every dashboard look healthy while detections reached no one. So a failed delivery
errors, SQS redelivers, the message lands in the dead-letter queue after five receives, and
the alarms fire.

## Run standalone

Everything runs in Docker; no Go toolchain is needed on the host.

```bash
make                    # gofmt check, go vet, go test -race
make test-integration   # starts DynamoDB Local, runs the delivery-contract suite, leaves it up
make local-down         # stops DynamoDB Local
make build              # bin/bootstrap (linux/amd64, static)
make package            # dist/alert-destination-<version>.zip + .zip.sha256
```

The integration suite (`integration/`, build tag `integration`) is the standalone run of the
service: it wires the real `deliver.Handler`, the real Slack and GitHub clients and the real
DynamoDB adapter, against DynamoDB Local (`hack/local/docker-compose.yml`) and in-process
`httptest` fakes of Slack and GitHub. Its centrepiece,
`TestDeliveryContract_PartialFailureAcrossEveryRedeliveryUntilTheDLQ`, drives a permanently
failing GitHub through all five receives and asserts that Slack was notified exactly once,
that every invocation failed, and that the ledger ends up saying `slack: delivered` and
`github: failed, permanent, attempts=5`.

There is no `docker compose up` that runs the handler itself. It is an SQS-triggered Lambda:
running it outside Lambda would need the Runtime Interface Emulator, an SQS event source, an
SSM emulator for the tokens and either real destinations or the same fakes the suite already
has. The suite exercises the same code path with less machinery, so it is the supported way
to run the service on a laptop. To hit real destinations once, use the smoke tests below.

**Smoke tests** (`make smoke`, build tag `smoke`) post one clearly-marked test message to a
real Slack channel and open one clearly-marked issue in a real repository. They take their
inputs from the environment and have no defaults:

| Variable | Meaning |
|---|---|
| `ALERTDEST_SMOKE_SLACK_CHANNEL` | channel id (`C…`) the bot has been invited to |
| `ALERTDEST_SMOKE_SLACK_TOKEN` | bot token (`xoxb-…`) with `chat:write` |
| `ALERTDEST_SMOKE_GITHUB_REPO` | `owner/repo` the token may open issues in |
| `ALERTDEST_SMOKE_GITHUB_TOKEN` | fine-grained PAT with Issues: read and write |

They catch what nothing else can: a bot never invited to the channel (`not_in_channel`), a
PAT never granted the repository (GitHub answers 404, not 403), and a label the renderer
applies that the repository does not have (422). All three are permanent delivery failures
in production.

## Configuration

Every setting is an `ALERTDEST_*` environment variable, read once at cold start by
`internal/config`. Required values have no defaults, and every problem is reported in one
error, so a half-wired function refuses to start instead of draining the queue.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ALERTDEST_LEDGER_TABLE` | yes | | DynamoDB table holding the delivery ledger (`pk`/`sk` string keys, TTL on `expires_at`). |
| `ALERTDEST_SLACK_TOKEN_PARAM` | yes | | SSM parameter **name** holding the Slack bot token. The value is read at runtime and never appears in the environment. |
| `ALERTDEST_GITHUB_TOKEN_PARAM` | yes | | SSM parameter **name** holding the GitHub fine-grained PAT. |
| `ALERTDEST_ROUTES_PARAM` | no | | SSM parameter **name** whose value is the routing table YAML. Highest precedence. |
| `ALERTDEST_ROUTES_PATH` | no | | Path to a routing table YAML file. Used when `ALERTDEST_ROUTES_PARAM` is unset. |
| `ALERTDEST_SOFT_DEADLINE_SECONDS` | no | `5` | Time held back from the invocation so the outcome can be recorded when the budget runs out. Must be a positive integer. |
| `ALERTDEST_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error`. An unknown value falls back to `info` rather than silencing the service. |
| `ALERTDEST_DYNAMODB_ENDPOINT_URL` | no | | Endpoint override for DynamoDB. Local runs and tests only. |
| `ALERTDEST_SSM_ENDPOINT_URL` | no | | Endpoint override for SSM. Local runs and tests only. |
| `ALERTDEST_SLACK_BASE_URL` | no | `https://slack.com/api` | Slack API root. Tests only. |
| `ALERTDEST_GITHUB_BASE_URL` | no | `https://api.github.com` | GitHub API root. GitHub Enterprise or tests. |

Reading a `SecureString` needs `kms:Decrypt` on its key as well as `ssm:GetParameters`;
without it the failure looks like a bad token downstream. Tokens are cached for the life of
the execution environment and dropped on an authentication failure, so a rotated credential
is picked up within one container lifetime with no redeploy.

## Routing table

Routing decides whether a detection reaches a human, so the table is validated at start and
a broken one stops the function from starting. It is loaded from the first of these that is
configured, and **a configured source is authoritative**: if it cannot be read or fails
validation the function exits rather than falling through to the next source, because
routing with a table the operator did not choose is a fail-open.

1. `ALERTDEST_ROUTES_PARAM`: an SSM parameter (String or SecureString) holding the YAML.
   Changing the table is then a parameter update and a cold start; nothing is rebuilt.
2. `ALERTDEST_ROUTES_PATH`: a file, for images or layers that ship their own table.
3. The table embedded in the binary (`internal/routing/routes.yaml`). It is a placeholder
   that names a channel and repository that do not exist; a real deployment always sets one
   of the two above. The startup log records `routes_origin` so you can see which won.

Matching is most-specific-wins over `(level, log_source)`: an exact pair beats an exact level
with a wildcard source, which beats a wildcard level with an exact source, which beats the
all-wildcard rule. Wildcards are always written `"*"`; a missing field is a validation error,
never an implied wildcard. Levels are Sigma's `informational`, `low`, `medium`, `high`,
`critical`; log sources are the `aws-siem` lane names (`aws`, `github`, `dns`, `alb`, `slack`,
`onepassword`, `workspace`, `gcp`). An unknown level or source is counted in metrics and
still delivered; every lookup is total, so no alert can resolve to nowhere.

```yaml
routes:
  # Critical alerts from any lane: Slack and a GitHub issue.
  - level: critical
    log_source: "*"
    deliveries:
      - {to: slack,  target: "C0EXAMPLE1"}                  # channel id, not name
      - {to: github, target: "example-org/security-alerts"}  # owner/repo

  # High alerts from the aws lane go to a dedicated channel.
  - level: high
    log_source: aws
    deliveries:
      - {to: slack, target: "C0EXAMPLE1"}

  # Everything else.
  - level: "*"
    log_source: "*"
    deliveries:
      - {to: slack, target: "C0EXAMPLE1"}

# Mandatory. Unreachable while an all-wildcard route exists, and what makes
# "no route matched" impossible by construction.
default:
  deliveries:
    - {to: slack, target: "C0EXAMPLE1"}
```

Validation rules, all reported at once:

- `routes[].level` and `routes[].log_source` are non-empty (`"*"` for any).
- Every `deliveries` list is non-empty, names only `slack` or `github`, and has a non-empty
  `target`.
- **Every route, and the default, includes `slack`.** GitHub failing while Slack succeeded is
  survivable because a human sees it; the reverse is not, because nobody watches an issue
  tracker in real time.
- `default.deliveries` is present and non-empty.

**GitHub gets `critical` only in the shipped example, deliberately.** Alert ids are derived
per matched *record*, so a rule firing on 500 records in one object is 500 alerts and would
be 500 issues. A per-`(rule_id, log_source)` suppression window is the fix and is not built.

**Labels must already exist in the repository.** The renderer applies `detection`,
`severity:<level>` and `source:<log_source>`; GitHub answers 422 for an unknown label, which
this service treats as permanent, so the alert is never delivered.

## The alert

The consumed message is `detection.alert.v1` as produced by `detection-engine`. Only the
fields this service reads are declared, and unknown fields are ignored, so the producer can
add fields without a deploy here. An unfamiliar `schema_version` is logged, not rejected.

```json
{
  "schema_version": "detection.alert.v1",
  "id": "det_9f2c…",
  "alerted_at": "2026-01-01T00:00:00Z",
  "log_source": "aws",
  "rule": {"id": "7f8b1c42", "title": "CloudTrail Logging Disabled", "level": "critical", "file": "aws/cloudtrail_disabled.yml"},
  "provenance": {"bucket": "filtered-123456789012", "key": "aws/date=2026-01-01/part-0001.gz", "event_index": 17},
  "event": {"eventName": "StopLogging"},
  "event_sha256": "…",
  "event_bytes": 1432
}
```

`id` is derived by the producer from the rule and the event's location, so the same finding
always presents the same id. That is what makes the ledger below work.

## Idempotency and the ledger

The ledger is one DynamoDB table: `pk = ALERT#<alert id>`, `sk = DEST#<destination>#<target>`,
one row per `(alert, destination, target)`, with `status`, `attempts`, the failure detail,
and a TTL (`expires_at`) comfortably longer than SQS's maximum redrive window. On each
receive the handler reads the alert's rows, skips every destination already `delivered`,
attempts the rest, and writes the outcome. The delivered row is written with a conditional
put (`attribute_not_exists`), so a race between two invocations of the same alert is settled
by DynamoDB and surfaces as a counted duplicate, not a second notification.

Rules that hold the design together:

1. **A failed ledger row never suppresses a retry.** Only `status == "delivered"` does.
   Failures are recorded purely so whoever opens the dead-letter queue can see why. Making a
   failed row gate a retry turns an undelivered alert into a silent drop.
   `TestOnlyADeliveredRecordSuppressesARetry` and
   `TestDelivered_AFailedRecordNeverSuppressesARetry` guard it.
2. **The ledger row is written after the destination confirms, never before.** Writing first
   means a crash between the two produces an alert that is never delivered and never retried.
   Writing after means the residual failure is a duplicate, which is noise.
3. **A ledger write failure does not, on its own, fail the invocation.** If every destination
   accepted and only the bookkeeping failed, failing would convert a DynamoDB blip into a
   guaranteed duplicate on every destination at the retry.
4. **Every route includes Slack** and **every routing lookup is total**, as above.
5. **The AWS SDK stays in `internal/awsadapt`.** `TestPackages_DoNotImportTheAWSSDK` enforces
   it, so no unit test anywhere needs credentials.
6. **Rendering is deterministic.** A retry must produce byte-identical output, or "the same
   alert produces the same issue" stops being true. Every map is walked through sorted keys.

Things that look wrong but are deliberate:

- **No GitHub issue search before creating.** GitHub's search index lags seconds to minutes
  and the retry interval is 120s, so the check misses in exactly the window it exists for,
  and at 30 requests a minute it starts refusing during any burst. The ledger is strongly
  consistent. The alert id is in the issue *title* instead, so a duplicate from the crash
  window is obvious and findable.
- **`batch_size = 1` and no partial batch failures.** With `ReportBatchItemFailures` an empty
  failure list on an error deletes the whole batch. One alert per invocation makes the
  failure contract trivial. The handler still loops over the batch and fails if any record
  fails, so raising the batch size cannot silently drop alerts.
- **`maximum_concurrency` on the event source, not reserved concurrency.** Reserved
  concurrency throttles *after* the receive has incremented `ApproximateReceiveCount`, so
  sustained throttling walks messages to the DLQ without ever attempting delivery.
- **A permanent failure still fails the invocation.** `channel_not_found` will not fix itself
  on a retry, but it does fix itself when somebody creates the channel, and five receives is
  about eight minutes in which that can happen. Permanence only suppresses the in-process
  HTTP retry.
- **`Retry-After` is capped.** GitHub's secondary-rate-limit `Retry-After` is routinely 60s,
  which would sleep through the function's entire budget and end in `Task timed out` with
  nothing recorded. SQS's redelivery is the long backoff.
- **Slack is hand-rolled rather than a library.** The decision that matters is permanent vs
  transient, and Slack encodes it as `{"ok":false,"error":…}` on an HTTP 200, so the
  classification has to be written here regardless.

## Data handling

Alert bodies leave AWS: they are posted to Slack and written into GitHub issues. The renderers
ship rule metadata, provenance and a byte-budgeted excerpt of the matched event rather than
the whole record; the full record stays in S3 and the provenance names it exactly. Logs carry
the alert id, rule id, severity, log source and the event's SHA-256, never event content and
never a token. Do not feed this pipeline log sources whose content may not leave your
account.

## Layout

```
cmd/alert-destination/   entrypoint: config, wiring, the SQS handler
internal/config/         env -> Config, every problem in one error, no defaults for wiring
internal/alert/          the consumed detection.alert.v1 envelope
internal/routing/        (level, log_source) -> destinations; table loading and validation
internal/deliver/        the orchestrator and the one rule above
internal/destination/    the Destination contract, the registry, permanent vs transient
internal/destination/slack/    chat.postMessage
internal/destination/github/   POST /repos/{owner}/{repo}/issues
internal/ledger/         what has been delivered where, and why anything failed
internal/render/         alert -> Slack blocks / GitHub issue, with byte budgets
internal/httpx/          the retrying transport
internal/secrets/        SSM reader with a warm-container cache
internal/awsadapt/       the only package that imports the AWS SDK
internal/version/        the build version, set at link time
internal/arch/           tests about the shape of the codebase, not its behaviour
integration/             the delivery-contract suite (build tag `integration`)
hack/                    DynamoDB Local compose file, scrub gate
```

## Artifact and deployment

Every tag `v*` publishes a GitHub Release with two assets:

- `alert-destination-<tag>.zip`: a Lambda deployment package for `provided.al2023` on
  `x86_64`, containing one static binary named `bootstrap` built with
  `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 -trimpath -ldflags '-s -w'` and the tag baked in as
  the version (it appears in the `User-Agent` sent to GitHub as
  `samma-io-alert-destination/<tag>`).
- `alert-destination-<tag>.zip.sha256`: its checksum in `sha256sum` format.

The `aws-siem` module fetches the zip by tag, verifies it against the `.sha256`, and passes
it to `aws_lambda_function` as `filename` plus `source_code_hash`. `make package` produces the
same two files locally under `dist/`.

The function needs: `sqs:ReceiveMessage/DeleteMessage/GetQueueAttributes` on the alert queue;
`dynamodb:PutItem/UpdateItem/Query` on the ledger table; `ssm:GetParameters` on the token
parameters (and the routes parameter, if used) plus `kms:Decrypt` on their key. The event
source mapping uses `batch_size = 1` and a `maximum_concurrency`; the queue's visibility
timeout should be at least twice the function timeout, with a redrive policy of five
receives to a dead-letter queue that has an alarm on it.

Before the first alerts flow: create a Slack app with the `chat:write` bot scope, install it,
**invite the bot to every channel in the table**, and store the `xoxb-…` token in the Slack
parameter; create a fine-grained PAT scoped to the target repository with Issues: read and
write, create the labels, and store it in the GitHub parameter. Until a parameter is set the
service reports "the secret has not been set" rather than a confusing 401. Then put the
routing table in the routes parameter and send one synthetic alert; one message and one issue
should appear, and sending it again should produce nothing new.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
