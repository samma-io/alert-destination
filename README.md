# alert-destination

The alert router of [`samma-io/aws-siem`](https://github.com/samma-io/aws-siem): a Go service
that drains the detection queue and delivers each `detection.alert.v1` message to the places
humans read, exactly once per destination. It runs as a Lambda, or as a daemon anywhere else
(see [Running outside Lambda](#running-outside-lambda)).

```
detection-engine ──► SQS detections-alerts ──► alert-destination ──┬──► S3 archive  alerts/log_source=…/date=…/<id>.json  (first, optional)
 (one queue, every lane)  visibility ≥ 6×timeout  (Lambda/daemon)  ├──► Slack       chat.postMessage
                          DLQ after 5 receives           │         └──► GitHub      POST /repos/{owner}/{repo}/issues
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
invocation whenever an alert did not reach every destination it was routed to.

With `ALERTDEST_ARCHIVE_BUCKET` set, every alert is first written to S3 (see
[The archive](#the-archive)), so there is a durable, Athena-queryable record of what the
detection plane said. The matched record itself is not copied; the alert's `provenance` names
the object it came from.

The Terraform that deploys it (function, ledger table, queue wiring, SSM parameters, archive
grant) is the `alert-destination` module in `aws-siem`. This repository holds the code and the
`Dockerfile`; images are built and pushed by us (see
[Image and deployment](#image-and-deployment)).

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
make image              # ghcr.io/samma-io/alert-destination:<short sha>
make lambda-zip         # dist/alert-destination.zip, bootstrap copied out of the image
```

The integration suite (`integration/`, build tag `integration`) is the standalone run of the
service: it wires the real `deliver.Handler`, the real Slack and GitHub clients and the real
DynamoDB adapter, against DynamoDB Local (`hack/local/docker-compose.yml`) and in-process
`httptest` fakes of Slack and GitHub. Its centrepiece,
`TestDeliveryContract_PartialFailureAcrossEveryRedeliveryUntilTheDLQ`, drives a permanently
failing GitHub through all five receives and asserts that Slack was notified exactly once,
that every invocation failed, and that the ledger ends up saying `slack: delivered` and
`github: failed, permanent, attempts=5`.

The suite is still the quickest way to exercise the handler on a laptop. To run the real
image against a queue, see [Running outside Lambda](#running-outside-lambda); to hit real
destinations once, use the smoke tests below.

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
| `ALERTDEST_ARCHIVE_BUCKET` | no | | S3 bucket every alert is written to before any delivery. Unset turns archiving off. See [The archive](#the-archive). |
| `ALERTDEST_QUEUE_URL` | daemon only | | SQS queue to long-poll when not running in Lambda. Ignored in Lambda. |
| `ALERTDEST_DAEMON_BATCH` | no | `1` | Daemon only: messages per receive, 1 to 10. Each is still handled and deleted on its own. |
| `ALERTDEST_DAEMON_MESSAGE_TIMEOUT` | no | `60s` | Daemon only: each message's deadline, the equivalent of the Lambda timeout. A Go duration or whole seconds; must exceed the soft deadline. |
| `ALERTDEST_SOFT_DEADLINE_SECONDS` | no | `5` | Time held back from the invocation so the outcome can be recorded when the budget runs out. Must be a positive integer. |
| `ALERTDEST_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error`. An unknown value falls back to `info` rather than silencing the service. |
| `ALERTDEST_DYNAMODB_ENDPOINT_URL` | no | | Endpoint override for DynamoDB. Local runs and tests only. |
| `ALERTDEST_SSM_ENDPOINT_URL` | no | | Endpoint override for SSM. Local runs and tests only. |
| `ALERTDEST_S3_ENDPOINT_URL` | no | | Endpoint override for S3 (path-style). Local runs and tests only. |
| `ALERTDEST_SQS_ENDPOINT_URL` | no | | Endpoint override for SQS. Local runs only. |
| `ALERTDEST_SLACK_BASE_URL` | no | `https://slack.com/api` | Slack API root. Tests only. |
| `ALERTDEST_GITHUB_BASE_URL` | no | `https://api.github.com` | GitHub API root. GitHub Enterprise or tests. |

Reading a `SecureString` needs `kms:Decrypt` on its key as well as `ssm:GetParameters`;
without it the failure looks like a bad token downstream. Tokens are cached for the life of
the process and dropped when a destination reports an authentication failure (Slack
`invalid_auth`, `token_revoked`, …; GitHub 401 or 404), so the next delivery re-reads the
parameter and a rotated credential is picked up with no redeploy and no cold start.

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
`onepassword`, `workspace`, `gcp`, `cloudflare`). An unknown level or source is counted in metrics and
still delivered; every lookup is total, so no alert can resolve to nowhere.

```yaml
routes:
  # Critical alerts from any lane: Slack and a GitHub issue.
  - level: critical
    log_source: "*"
    deliveries:
      - {to: slack,  target: "C0EXAMPLE1"}                  # channel id, not name
      - {to: github, target: "example-org/security-alerts"}  # owner/repo

  # High alerts from the aws lane go to a dedicated channel. This exact
  # (level, log_source) pair beats the wildcard route below.
  - level: high
    log_source: aws
    deliveries:
      - {to: slack, target: "C0EXAMPLEAWS"}

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
one row per `(alert, destination, target)`, with `status`, `attempts`, and a TTL
(`expires_at`) comfortably longer than SQS's maximum redrive window. A delivered row carries
`ref`, what the destination assigned: `channel` and `ts` for Slack, `number` and `html_url`
for GitHub, `bucket` and `key` for the archive. A failed row carries `error_code` (Slack's
error string, GitHub's status name such as `unprocessable_entity`, `rate_limited`,
`abandoned` for the soft deadline), `http_status`, `permanent` and `error_message`. On each
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
  and the retry interval is the queue's visibility timeout, so the check misses in exactly the window it exists for,
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
- **Slack's `ratelimited` is retried in-process although it arrives as HTTP 200.** Slack's
  transport has a policy that reads the body; a rate-limited call posted nothing, so retrying
  it cannot duplicate. It honours `Retry-After` up to the same cap.
- **Slack is hand-rolled rather than a library.** The decision that matters is permanent vs
  transient, and Slack encodes it as `{"ok":false,"error":…}` on an HTTP 200, so the
  classification has to be written here regardless.

## The archive

With `ALERTDEST_ARCHIVE_BUCKET` set, every alert is written, before any destination is
attempted, to

```
s3://<bucket>/alerts/log_source=<lane>/date=<YYYY-MM-DD of alerted_at, UTC>/<alert id>.json
```

The object is the queue message exactly as received, compacted onto one line with a trailing
newline: one alert per object, one JSON document per line, which is what the `detections`
Glue table in `aws-siem` reads (a single `line string` column, partitions projected on
`log_source` and `date`). A `log_source` that cannot be a partition value is filed under
`unknown`.

- **Idempotent.** The key depends only on the alert, so a replay rewrites the same object.
  The write is also recorded in the ledger as destination `archive` (target: the bucket), so a
  redelivery normally skips it altogether.
- **It gates delivery.** A failed archive write fails the invocation before anyone is notified,
  the same as an unreadable ledger, and SQS redelivers. The failure is recorded as a failed
  `archive` row and counted in `ArchiveWriteFailures`. The trade is deliberate: every alert a
  human saw is in the archive.
- **Permissions:** `s3:PutObject` on `<bucket>/alerts/*` only. Nothing reads the bucket, so
  there is no `s3:GetObject`. With SSE-KMS under a customer key, add `kms:GenerateDataKey`.

## Running outside Lambda

The same image runs as a long-lived process. With `AWS_LAMBDA_RUNTIME_API` unset (the Lambda
runtime sets it; nothing else does) and `ALERTDEST_QUEUE_URL` set, it long-polls that queue
itself, 20 s per receive, `ALERTDEST_DAEMON_BATCH` messages at a time (default 1). Each message
goes through the same handler as a Lambda invocation, with its own deadline of
`ALERTDEST_DAEMON_MESSAGE_TIMEOUT` (default 60s) so the soft deadline behaves the same:

- handled successfully: the message is deleted;
- anything undelivered: the message is left alone, SQS makes it visible again after the
  visibility timeout, and the redrive policy moves it to the DLQ after five receives, exactly
  as in Lambda;
- `SIGTERM` or `SIGINT`: polling stops, the message in hand finishes within its deadline and
  is deleted if it succeeded, the rest of the batch is left for redelivery, and the process
  exits 0.

With neither a Lambda runtime nor a queue URL it exits 1 with an error saying so. A receive
error (throttling, an expiring credential) is logged and retried with backoff up to a minute
rather than ending the process.

The queue's visibility timeout must be longer than the message timeout, as it must be longer
than the Lambda timeout. The daemon needs `sqs:ReceiveMessage` and `sqs:DeleteMessage` on the
queue in addition to the Lambda's permissions below. Metrics are the same EMF lines on
stdout; outside Lambda they become CloudWatch metrics only if the log shipper understands
EMF (the CloudWatch agent does, the `awslogs` driver does not).

Locally, against localstack or ElasticMQ:

```bash
make image
docker run --rm \
  -e AWS_REGION=us-east-1 -e AWS_ACCESS_KEY_ID=test -e AWS_SECRET_ACCESS_KEY=test \
  -e ALERTDEST_QUEUE_URL=http://localstack:4566/000000000000/alerts \
  -e ALERTDEST_SQS_ENDPOINT_URL=http://localstack:4566 \
  -e ALERTDEST_DYNAMODB_ENDPOINT_URL=http://localstack:4566 \
  -e ALERTDEST_SSM_ENDPOINT_URL=http://localstack:4566 \
  -e ALERTDEST_LEDGER_TABLE=ledger \
  -e ALERTDEST_SLACK_TOKEN_PARAM=/alert-destination/slack \
  -e ALERTDEST_GITHUB_TOKEN_PARAM=/alert-destination/github \
  ghcr.io/samma-io/alert-destination:$(git rev-parse --short HEAD)
```

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
internal/archive/        the S3 copy of every alert, and its key
internal/routing/        (level, log_source) -> destinations; table loading and validation
internal/deliver/        the orchestrator and the one rule above
internal/destination/    the Destination contract, the registry, permanent vs transient
internal/destination/slack/    chat.postMessage
internal/destination/github/   POST /repos/{owner}/{repo}/issues
internal/ledger/         what has been delivered where, and why anything failed
internal/render/         alert -> Slack blocks / GitHub issue, with byte budgets
internal/httpx/          the retrying transport
internal/secrets/        SSM reader with a warm-container cache
internal/daemon/         the SQS poll loop for running outside Lambda
internal/awsadapt/       the only package that imports the AWS SDK
internal/version/        the build version, set at link time
internal/arch/           tests about the shape of the codebase, not its behaviour
integration/             the delivery-contract suite (build tag `integration`)
hack/                    DynamoDB Local compose file, scrub gate
Dockerfile               static build, /app/bootstrap on distroless/static
```

## Image and deployment

There are no GitHub Releases. We build and push the image ourselves:

```bash
make image push IMAGE=ghcr.io/samma-io/alert-destination TAG=$(git rev-parse --short HEAD)
make lambda-zip          # dist/alert-destination.zip
```

`IMAGE` defaults to `ghcr.io/samma-io/alert-destination` and `TAG` to the short git sha,
which is the recommended tag (no `v` prefix). `PLATFORM` defaults to `linux/amd64`, because
the Lambda is `x86_64`. The image is a static binary built with
`CGO_ENABLED=0 -trimpath -ldflags '-s -w'` and the tag baked in as the version (it appears in
the `User-Agent` sent to GitHub as `samma-io-alert-destination/<tag>`), at `/app/bootstrap`
on `gcr.io/distroless/static-debian12:nonroot`, running as uid 65532.

`make lambda-zip` copies `/app/bootstrap` out of the image and zips it as a single file
named `bootstrap` at the root: the deployment package for `provided.al2023`. The file's
timestamp is pinned, so the same image gives the same zip and the same `source_code_hash`.
`aws-siem/hack/build-images.sh` does the same for every repository, then the
`alert-destination` module takes the zip as `zip_path`. CI builds the image (never pushes
it), checks the zip, and scans the image with Trivy.

The function needs: `sqs:ReceiveMessage/DeleteMessage/GetQueueAttributes` on the alert queue;
`dynamodb:PutItem/UpdateItem/Query` on the ledger table; `ssm:GetParameters` on the token
parameters (and the routes parameter, if used) plus `kms:Decrypt` on their key; and, with an
archive, `s3:PutObject` on `<bucket>/alerts/*`. The event source mapping uses
`batch_size = 1` and a `maximum_concurrency`; the queue's visibility timeout should be at
least six times the function timeout, with a redrive policy of five receives to a
dead-letter queue that has an alarm on it.

Before the first alerts flow: create a Slack app with the `chat:write` bot scope, install it,
**invite the bot to every channel in the table**, and store the `xoxb-…` token in the Slack
parameter; create a fine-grained PAT scoped to the target repository with Issues: read and
write, create the labels, and store it in the GitHub parameter. Until a parameter is set the
service reports "the secret has not been set" rather than a confusing 401. Then put the
routing table in the routes parameter and send one synthetic alert; one message and one issue
should appear, and sending it again should produce nothing new.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
