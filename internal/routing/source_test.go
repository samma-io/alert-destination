package routing_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samma-io/alert-destination/internal/routing"
)

// tableFor is a minimal valid table that sends everything to one channel, so a
// test can tell which source answered by the target it resolves to.
func tableFor(channel string) string {
	return `
routes: []
default:
  deliveries:
    - {to: slack, target: "` + channel + `"}
`
}

// githubOnly fails validation: every route must include slack.
const githubOnly = `
routes: []
default:
  deliveries:
    - {to: github, target: "example-org/detections"}
`

type fakeParams struct {
	values map[string]string
	err    error
	calls  int
}

func (f *fakeParams) Get(_ context.Context, names ...string) (map[string]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]string{}
	for _, n := range names {
		if v, ok := f.values[n]; ok {
			out[n] = v
		}
	}
	return out, nil
}

func writeTable(t *testing.T, src string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "routes.yaml")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("writing the table: %v", err)
	}
	return path
}

func defaultTarget(t *testing.T, tbl *routing.Table) string {
	t.Helper()
	got, _ := tbl.Resolve("medium", "aws")
	return targets(got)
}

func TestSelect_ParameterOutranksFileAndEmbedded(t *testing.T) {
	params := &fakeParams{values: map[string]string{"/siem/routes": tableFor("C0PARAM")}}

	// The file path deliberately does not exist: if precedence were wrong,
	// Select would fail trying to read it instead of succeeding from SSM.
	tbl, origin, err := routing.Select(context.Background(), routing.Sources{
		Param:      "/siem/routes",
		Path:       filepath.Join(t.TempDir(), "does-not-exist.yaml"),
		Parameters: params,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if origin != routing.OriginParameter {
		t.Errorf("origin = %q, want parameter", origin)
	}
	if got := defaultTarget(t, tbl); got != "slack:C0PARAM" {
		t.Errorf("resolved %s, want the parameter's table", got)
	}
	if params.calls != 1 {
		t.Errorf("parameter reads = %d, want 1", params.calls)
	}
}

func TestSelect_FileOutranksEmbedded(t *testing.T) {
	tbl, origin, err := routing.Select(context.Background(), routing.Sources{
		Path: writeTable(t, tableFor("C0FILE")),
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if origin != routing.OriginFile {
		t.Errorf("origin = %q, want file", origin)
	}
	if got := defaultTarget(t, tbl); got != "slack:C0FILE" {
		t.Errorf("resolved %s, want the file's table", got)
	}
}

func TestSelect_NothingConfiguredUsesTheEmbeddedTable(t *testing.T) {
	tbl, origin, err := routing.Select(context.Background(), routing.Sources{})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if origin != routing.OriginEmbedded {
		t.Errorf("origin = %q, want embedded", origin)
	}
	embedded, err := routing.Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	if defaultTarget(t, tbl) != defaultTarget(t, embedded) {
		t.Error("Select without sources did not return the embedded table")
	}
}

// A configured source is authoritative. Falling through to the embedded table
// would route alerts with a table the operator did not choose, silently.
func TestSelect_AnInvalidParameterTableFailsClosed(t *testing.T) {
	params := &fakeParams{values: map[string]string{"/siem/routes": githubOnly}}

	tbl, _, err := routing.Select(context.Background(), routing.Sources{
		Param: "/siem/routes", Parameters: params,
	})
	if err == nil {
		t.Fatal("Select succeeded with an invalid parameter table; want an error")
	}
	if tbl != nil {
		t.Error("Select returned a table alongside the error")
	}
	if !strings.Contains(err.Error(), "/siem/routes") || !strings.Contains(err.Error(), "slack") {
		t.Errorf("error names neither the parameter nor the problem: %v", err)
	}
}

func TestSelect_AnAbsentParameterFailsClosed(t *testing.T) {
	_, _, err := routing.Select(context.Background(), routing.Sources{
		Param: "/siem/routes", Parameters: &fakeParams{values: map[string]string{}},
	})
	if err == nil {
		t.Fatal("Select succeeded with a parameter SSM does not have; want an error")
	}
}

func TestSelect_AParameterReadErrorFailsClosed(t *testing.T) {
	_, _, err := routing.Select(context.Background(), routing.Sources{
		Param: "/siem/routes", Parameters: &fakeParams{err: errors.New("AccessDeniedException")},
	})
	if err == nil {
		t.Fatal("Select succeeded despite an SSM error; want an error")
	}
	if !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Errorf("the SSM error was not preserved: %v", err)
	}
}

func TestSelect_AParameterWithoutAReaderIsAnError(t *testing.T) {
	_, _, err := routing.Select(context.Background(), routing.Sources{Param: "/siem/routes"})
	if err == nil {
		t.Fatal("Select succeeded with a parameter name and no reader; want an error")
	}
}

func TestSelect_AMissingFileFailsClosed(t *testing.T) {
	_, _, err := routing.Select(context.Background(), routing.Sources{
		Path: filepath.Join(t.TempDir(), "does-not-exist.yaml"),
	})
	if err == nil {
		t.Fatal("Select succeeded with a missing file; want an error")
	}
}

func TestSelect_AnInvalidFileFailsClosed(t *testing.T) {
	path := writeTable(t, githubOnly)

	tbl, _, err := routing.Select(context.Background(), routing.Sources{Path: path})
	if err == nil {
		t.Fatal("Select succeeded with an invalid file table; want an error")
	}
	if tbl != nil {
		t.Error("Select returned a table alongside the error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error does not name the file: %v", err)
	}
}
