// Package postgres delivers alerts into a Postgres table, the alert store of
// the Kubernetes deployment. The route's target is the table name.
//
// The SQL lives in internal/pgadapt; this package is the Destination contract
// around it, so it can be tested without a database.
package postgres

import (
	"context"
	"fmt"
	"regexp"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/destination"
)

// Name is the destination name routes use.
const Name = "postgres"

// tableName is deliberately narrow. The name comes from a routing table, and
// although pgadapt quotes it, a table called anything else is a typo.
var tableName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Inserter stores one alert in one table, idempotently by alert id.
type Inserter interface {
	InsertAlert(ctx context.Context, table string, a alert.Alert) error
}

// Client is the postgres destination.
type Client struct {
	DB Inserter
}

// Name implements destination.Destination.
func (c *Client) Name() string { return Name }

// Deliver inserts the alert. A database error is transient: the message stays
// on the stream and is redelivered.
func (c *Client) Deliver(ctx context.Context, a alert.Alert, target string) (destination.Ref, error) {
	if !tableName.MatchString(target) {
		return nil, destination.Permanent(fmt.Errorf("postgres: %q is not a valid table name", target))
	}
	if c.DB == nil {
		return nil, destination.Permanent(fmt.Errorf("postgres: no database configured"))
	}
	if err := c.DB.InsertAlert(ctx, target, a); err != nil {
		return nil, fmt.Errorf("postgres: inserting alert %s: %w", a.ID, err)
	}
	return destination.Ref{"table": target, "id": a.ID}, nil
}
