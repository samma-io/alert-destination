package destination_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/samma-io/alert-destination/internal/alert"
	"github.com/samma-io/alert-destination/internal/destination"
)

type stub struct{ name string }

func (s stub) Name() string                                       { return s.name }
func (s stub) Deliver(context.Context, alert.Alert, string) error { return nil }

func TestPermanent_IsDetectedThroughWrapping(t *testing.T) {
	err := fmt.Errorf("posting to slack: %w", destination.Permanent(errors.New("channel_not_found")))

	if !destination.IsPermanent(err) {
		t.Error("IsPermanent = false for a wrapped permanent error, want true")
	}
	if !strings.Contains(err.Error(), "channel_not_found") {
		t.Errorf("wrapping lost the reason: %v", err)
	}
}

func TestIsPermanent_FalseForAnOrdinaryError(t *testing.T) {
	if destination.IsPermanent(errors.New("connection reset")) {
		t.Error("IsPermanent = true for a transient error, want false")
	}
}

func TestIsPermanent_FalseForNil(t *testing.T) {
	if destination.IsPermanent(nil) {
		t.Error("IsPermanent(nil) = true, want false")
	}
}

// Auth failures stop every alert, not just this one, so they are distinguishable
// from an ordinary permanent failure and get their own alarm.
func TestAuthFailure_IsPermanentAndIdentifiable(t *testing.T) {
	err := fmt.Errorf("slack: %w", destination.AuthFailure(errors.New("token_revoked")))

	if !destination.IsAuthFailure(err) {
		t.Error("IsAuthFailure = false, want true")
	}
	if !destination.IsPermanent(err) {
		t.Error("an auth failure must also be permanent")
	}
}

func TestRegistry_LooksUpByName(t *testing.T) {
	r := destination.NewRegistry(stub{"slack"}, stub{"github"})

	d, err := r.Lookup("github")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if d.Name() != "github" {
		t.Errorf("Name = %q, want github", d.Name())
	}
}

// The name comes from a config file, so the error has to say what would have
// worked -- otherwise the operator is guessing.
func TestRegistry_UnknownNameErrorListsEveryValidName(t *testing.T) {
	r := destination.NewRegistry(stub{"slack"}, stub{"github"})

	_, err := r.Lookup("pagerduty")
	if err == nil {
		t.Fatal("Lookup succeeded for an unregistered name")
	}
	for _, want := range []string{"pagerduty", "github", "slack"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is missing %q: %v", want, err)
		}
	}
}

func TestRegistry_NamesAreSortedSoLogsAreStable(t *testing.T) {
	r := destination.NewRegistry(stub{"slack"}, stub{"github"})

	if got := strings.Join(r.Names(), ","); got != "github,slack" {
		t.Errorf("Names = %s, want github,slack", got)
	}
}
