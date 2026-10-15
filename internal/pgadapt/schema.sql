-- Applied at start, idempotently. Additive changes only: a column dropped or
-- retyped here would need a real migration, and this is not one.

-- siem_alerts is the alert store the Kubernetes deployment forwards to. One row
-- per alert id; a redelivery of the same finding is the same row.
CREATE TABLE IF NOT EXISTS siem_alerts (
    id             text        PRIMARY KEY,
    schema_version text        NOT NULL,
    alerted_at     timestamptz NOT NULL,
    stored_at      timestamptz NOT NULL DEFAULT now(),
    log_source     text        NOT NULL,
    rule_id        text        NOT NULL,
    rule_title     text        NOT NULL,
    level          text        NOT NULL,
    provenance     jsonb       NOT NULL,
    alert          jsonb       NOT NULL
);
CREATE INDEX IF NOT EXISTS siem_alerts_alerted_at ON siem_alerts (alerted_at DESC);
CREATE INDEX IF NOT EXISTS siem_alerts_rule ON siem_alerts (log_source, rule_id);

-- alert_ledger is the delivery record, the Postgres twin of the DynamoDB
-- ledger table. Expired rows are deleted at start; nothing reads them.
CREATE TABLE IF NOT EXISTS alert_ledger (
    pk               text        NOT NULL,
    sk               text        NOT NULL,
    alert_id         text        NOT NULL,
    destination      text        NOT NULL,
    target           text        NOT NULL,
    status           text        NOT NULL,
    attempts         integer     NOT NULL,
    first_attempt_at timestamptz NOT NULL,
    last_attempt_at  timestamptz NOT NULL,
    delivered_at     timestamptz,
    ref              jsonb,
    permanent        boolean     NOT NULL DEFAULT false,
    error_code       text        NOT NULL DEFAULT '',
    http_status      integer     NOT NULL DEFAULT 0,
    error_message    text        NOT NULL DEFAULT '',
    expires_at       timestamptz NOT NULL,
    PRIMARY KEY (pk, sk)
);
