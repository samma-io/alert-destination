package routing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ParameterReader reads SSM parameters by name. It has the same shape as
// secrets.Getter and is declared here so this package depends on neither the
// AWS SDK nor the secrets package; awsadapt.ParameterStore satisfies both.
type ParameterReader interface {
	Get(ctx context.Context, names ...string) (map[string]string, error)
}

// Sources says where the routing table may come from.
//
// Precedence is Param, then Path, then the table embedded in the binary. A
// source that is configured is authoritative: if it cannot be read or does not
// validate, Select fails rather than falling through to the next one, because
// routing with a different table than the operator configured is a fail-open.
type Sources struct {
	// Param is the name of an SSM parameter whose value is the YAML table.
	Param string
	// Path is a file holding the YAML table. Consulted only when Param is empty.
	Path string
	// Parameters reads Param. Required when Param is set.
	Parameters ParameterReader
}

// Origin names which source answered, for the startup log.
type Origin string

// The possible origins of a routing table.
const (
	OriginParameter Origin = "parameter"
	OriginFile      Origin = "file"
	OriginEmbedded  Origin = "embedded"
)

// Select loads and validates the routing table from the highest-precedence
// source that is configured. It fails closed: a configured source that cannot
// be read or does not validate is an error, never a fall-through.
func Select(ctx context.Context, s Sources) (*Table, Origin, error) {
	switch {
	case s.Param != "":
		t, err := fromParameter(ctx, s)
		return t, OriginParameter, err
	case s.Path != "":
		t, err := fromFile(s.Path)
		return t, OriginFile, err
	default:
		t, err := Embedded()
		return t, OriginEmbedded, err
	}
}

func fromParameter(ctx context.Context, s Sources) (*Table, error) {
	if s.Parameters == nil {
		return nil, errors.New("routing table parameter " + s.Param + " is configured but no parameter reader was supplied")
	}
	values, err := s.Parameters.Get(ctx, s.Param)
	if err != nil {
		return nil, fmt.Errorf("reading routing table parameter %s: %w", s.Param, err)
	}
	raw, ok := values[s.Param]
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("routing table parameter %s is empty or absent; the table has not been set", s.Param)
	}
	t, err := Load([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("routing table parameter %s: %w", s.Param, err)
	}
	return t, nil
}

func fromFile(path string) (*Table, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading routing table file: %w", err)
	}
	t, err := Load(raw)
	if err != nil {
		return nil, fmt.Errorf("routing table file %s: %w", path, err)
	}
	return t, nil
}
