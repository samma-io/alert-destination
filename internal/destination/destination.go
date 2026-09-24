// Package destination is the contract every delivery target implements, and the
// vocabulary for why a delivery failed.
//
// The permanent/transient split is borrowed from the producer's
// publisher.Rejection.SenderFault (detection-engine/internal/publisher): true
// means the message will never be accepted however often it is retried, false
// means throttling or a server error. Using the same distinction on both halves
// of the pipeline means an operator only has to learn it once.
package destination

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/samma-io/alert-destination/internal/alert"
)

// Destination delivers one alert to one address.
//
// Target is the channel id or "owner/repo" the route chose. It is a parameter
// rather than client state because there is one client per destination type and
// the address is a routing decision.
type Destination interface {
	Name() string
	Deliver(ctx context.Context, a alert.Alert, target string) error
}

// permanentError marks a failure no retry can fix.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }
func (e permanentError) permanent()    {}

// authError is a permanent failure that also means every other alert is
// undeliverable right now -- a revoked token, a repository the credential can no
// longer see. It is separated from an ordinary permanent failure so it can have
// its own alarm: the DLQ must not be the first hint that a token was rotated.
type authError struct{ permanentError }

func (e authError) auth() {}

// Permanent marks err as unfixable by retrying.
func Permanent(err error) error { return permanentError{err} }

// AuthFailure marks err as a credential problem affecting every delivery.
func AuthFailure(err error) error { return authError{permanentError{err}} }

// IsPermanent reports whether err, or anything it wraps, is permanent.
//
// Permanence suppresses the in-process HTTP retry only. It never short-circuits
// to the DLQ: "permanent" is a guess about the outside world, and
// channel_not_found stops being permanent the moment somebody creates the
// channel. Over five redeliveries a human fixing config mid-incident still gets
// the alert delivered.
func IsPermanent(err error) bool {
	var p interface{ permanent() }
	return errors.As(err, &p)
}

// IsAuthFailure reports whether err, or anything it wraps, is a credential
// problem.
func IsAuthFailure(err error) bool {
	var a interface{ auth() }
	return errors.As(err, &a)
}

// Registry is the set of destinations this process can deliver to.
//
// A map rather than a switch, for the reason detection-engine's source registry
// gives: a name present in config but missing from a switch falls through to a
// default, and the service then drains the queue delivering nothing.
type Registry struct {
	byName map[string]Destination
}

// NewRegistry indexes destinations by name.
func NewRegistry(ds ...Destination) *Registry {
	byName := make(map[string]Destination, len(ds))
	for _, d := range ds {
		byName[d.Name()] = d
	}
	return &Registry{byName: byName}
}

// Lookup returns the destination with this name.
//
// The error lists every registered name because the name it was given came from
// a config file, and an operator reading "unknown destination" without the
// alternatives has to go and read the source.
func (r *Registry) Lookup(name string) (Destination, error) {
	if d, ok := r.byName[name]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("unknown destination %q; registered: %s",
		name, strings.Join(r.Names(), ", "))
}

// Names returns every registered name, sorted so logs and errors are stable.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.byName))
	for name := range r.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
