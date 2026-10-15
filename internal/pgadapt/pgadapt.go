// Package pgadapt holds the only code in the service that imports the Postgres
// driver. It backs the delivery ledger and the postgres destination in the
// Kubernetes deployment, where there is no DynamoDB.
package pgadapt

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/ledger"
)

//go:embed schema.sql
var schema string

// DB is a connection pool with the schema applied.
type DB struct {
	Pool *pgxpool.Pool
}

// Open connects and applies the schema. A database that cannot take the schema
// stops the service at start rather than at the first alert.
func Open(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: applying schema: %w", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM alert_ledger WHERE expires_at < now()`); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: expiring ledger rows: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Close releases the pool.
func (db *DB) Close() { db.Pool.Close() }

// InsertAlert stores one alert in table. A row with the same id is left as it
// is: the id is derived from the finding, so it is the same alert.
func (db *DB) InsertAlert(ctx context.Context, table string, a alert.Alert) error {
	prov, err := json.Marshal(a.Provenance)
	if err != nil {
		return err
	}
	body := a.Raw
	if len(body) == 0 {
		if body, err = json.Marshal(a); err != nil {
			return err
		}
	}
	sql := `INSERT INTO ` + pgx.Identifier{table}.Sanitize() + `
	    (id, schema_version, alerted_at, log_source, rule_id, rule_title, level, provenance, alert)
	    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	    ON CONFLICT (id) DO NOTHING`
	_, err = db.Pool.Exec(ctx, sql, a.ID, a.SchemaVersion, a.AlertedAt, a.LogSource,
		a.Rule.RuleID, a.Rule.Title, a.Rule.Level, prov, body)
	return err
}

// Ledger implements ledger.Store on table alert_ledger.
type Ledger struct {
	DB *DB
}

var _ ledger.Store = (*Ledger)(nil)

const ledgerColumns = `pk, sk, alert_id, destination, target, status, attempts,
	first_attempt_at, last_attempt_at, delivered_at, ref, permanent, error_code,
	http_status, error_message, expires_at`

// Query returns every row in one partition.
func (l *Ledger) Query(ctx context.Context, pk string) ([]ledger.Record, error) {
	rows, err := l.DB.Pool.Query(ctx, `SELECT `+ledgerColumns+` FROM alert_ledger WHERE pk = $1`, pk)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ledger.Record
	for rows.Next() {
		var (
			r         ledger.Record
			status    string
			delivered *time.Time
			ref       []byte
			expires   time.Time
		)
		if err := rows.Scan(&r.PK, &r.SK, &r.AlertID, &r.Destination, &r.Target, &status, &r.Attempts,
			&r.FirstAttemptAt, &r.LastAttemptAt, &delivered, &ref, &r.Permanent, &r.Code,
			&r.HTTPStatus, &r.Message, &expires); err != nil {
			return nil, err
		}
		r.Status = ledger.Status(status)
		if delivered != nil {
			r.DeliveredAt = *delivered
		}
		if len(ref) > 0 {
			if err := json.Unmarshal(ref, &r.Ref); err != nil {
				return nil, fmt.Errorf("ledger row %s %s: ref: %w", r.PK, r.SK, err)
			}
		}
		r.ExpiresAt = expires.Unix()
		out = append(out, r)
	}
	return out, rows.Err()
}

// PutIfAbsent writes a delivered row unless one exists.
//
// A failed row for the same key is replaced: it gates nothing, and the
// delivered row is the one that must win. Only an existing delivered row makes
// this ErrAlreadyRecorded -- the same outcome as the DynamoDB condition.
func (l *Ledger) PutIfAbsent(ctx context.Context, r ledger.Record) error {
	ref, err := json.Marshal(r.Ref)
	if err != nil {
		return err
	}
	tag, err := l.DB.Pool.Exec(ctx, `INSERT INTO alert_ledger (`+ledgerColumns+`)
	    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	    ON CONFLICT (pk, sk) DO UPDATE SET
	        status = EXCLUDED.status,
	        attempts = alert_ledger.attempts + EXCLUDED.attempts,
	        last_attempt_at = EXCLUDED.last_attempt_at,
	        delivered_at = EXCLUDED.delivered_at,
	        ref = EXCLUDED.ref,
	        expires_at = EXCLUDED.expires_at
	    WHERE alert_ledger.status <> $6`,
		r.PK, r.SK, r.AlertID, r.Destination, r.Target, string(r.Status), r.Attempts,
		r.FirstAttemptAt, r.LastAttemptAt, nullTime(r.DeliveredAt), ref, r.Permanent, r.Code,
		r.HTTPStatus, r.Message, time.Unix(r.ExpiresAt, 0))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ledger.ErrAlreadyRecorded
	}
	return nil
}

// Upsert writes a row, accumulating attempts and keeping first_attempt_at.
func (l *Ledger) Upsert(ctx context.Context, r ledger.Record) error {
	_, err := l.DB.Pool.Exec(ctx, `INSERT INTO alert_ledger (`+ledgerColumns+`)
	    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, NULL, $10, $11, $12, $13, $14)
	    ON CONFLICT (pk, sk) DO UPDATE SET
	        status = EXCLUDED.status,
	        attempts = alert_ledger.attempts + EXCLUDED.attempts,
	        last_attempt_at = EXCLUDED.last_attempt_at,
	        permanent = EXCLUDED.permanent,
	        error_code = EXCLUDED.error_code,
	        http_status = EXCLUDED.http_status,
	        error_message = EXCLUDED.error_message,
	        expires_at = EXCLUDED.expires_at`,
		r.PK, r.SK, r.AlertID, r.Destination, r.Target, string(r.Status), r.Attempts,
		r.FirstAttemptAt, r.LastAttemptAt, r.Permanent, r.Code, r.HTTPStatus, r.Message,
		time.Unix(r.ExpiresAt, 0))
	return err
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
