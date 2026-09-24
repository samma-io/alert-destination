// Package arch holds tests about the shape of the codebase rather than its
// behaviour. Each one guards a property that is easy to state, easy to break by
// accident, and invisible in review once broken.
package arch_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samma-io/alert-destination/internal/destination"
	"github.com/samma-io/alert-destination/internal/destination/github"
	"github.com/samma-io/alert-destination/internal/destination/slack"
	"github.com/samma-io/alert-destination/internal/routing"
)

// repoRoot walks up from this package to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root")
	return ""
}

// packageImports maps each package directory to the import paths it uses.
func packageImports(t *testing.T, root string, includeTests bool) map[string][]string {
	t.Helper()
	out := map[string][]string{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "vendor" || name == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if !includeTests && strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		for _, imp := range file.Imports {
			out[rel] = append(out[rel], strings.Trim(imp.Path.Value, `"`))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	return out
}

// The payoff is that no unit test anywhere else needs AWS credentials, a mocked
// SDK client, or a localstack. Business packages take narrow interfaces in plain
// Go types and awsadapt is the only thing that satisfies them.
func TestPackages_DoNotImportTheAWSSDK(t *testing.T) {
	const allowed = "internal/awsadapt"

	for pkg, imports := range packageImports(t, repoRoot(t), false) {
		if pkg == allowed {
			continue
		}
		for _, imp := range imports {
			if strings.Contains(imp, "aws-sdk-go") {
				t.Errorf("%s imports %s; only %s may touch the AWS SDK", pkg, imp, allowed)
			}
		}
	}
}

// Keeping the Lambda event types in cmd is what lets the orchestrator be tested
// with a plain alert.Alert and no AWS type in sight.
func TestOnlyTheEntrypointImportsTheLambdaRuntime(t *testing.T) {
	const allowed = "cmd/alert-destination"

	for pkg, imports := range packageImports(t, repoRoot(t), false) {
		if pkg == allowed {
			continue
		}
		for _, imp := range imports {
			if strings.Contains(imp, "aws-lambda-go") {
				t.Errorf("%s imports %s; only %s may know it is a Lambda", pkg, imp, allowed)
			}
		}
	}
}

// A destination named in the shipped routing table but absent from the registry
// would be a route that delivers nowhere, discovered one undelivered alert at a
// time.
func TestEveryRoutedDestinationIsRegistered(t *testing.T) {
	table, err := routing.Embedded()
	if err != nil {
		t.Fatalf("routing.Embedded: %v", err)
	}
	registry := destination.NewRegistry(&slack.Client{}, &github.Client{})

	seen := map[string]bool{}
	for _, r := range table.Routes {
		for _, d := range r.Deliveries {
			seen[d.To] = true
		}
	}
	for _, d := range table.Default.Deliveries {
		seen[d.To] = true
	}

	for name := range seen {
		if _, err := registry.Lookup(name); err != nil {
			t.Errorf("the routing table sends alerts to %q, which nothing implements: %v", name, err)
		}
	}
}

// The reverse: a destination this binary can deliver to but no route ever
// chooses is dead weight at best and a forgotten wiring step at worst.
func TestEveryRegisteredDestinationIsReachable(t *testing.T) {
	table, err := routing.Embedded()
	if err != nil {
		t.Fatalf("routing.Embedded: %v", err)
	}

	routed := map[string]bool{}
	for _, r := range table.Routes {
		for _, d := range r.Deliveries {
			routed[d.To] = true
		}
	}
	for _, d := range table.Default.Deliveries {
		routed[d.To] = true
	}

	for _, name := range destination.NewRegistry(&slack.Client{}, &github.Client{}).Names() {
		if !routed[name] {
			t.Errorf("destination %q is registered but no route reaches it", name)
		}
	}
}

// The whole service rests on this: a failed delivery is forensics for the DLQ
// reader, never a reason to skip a retry. It is exactly the line a later
// refactor "simplifies" into a silent drop, so it is asserted in the one place
// that reads like a rule rather than a case.
func TestOnlyADeliveredRecordSuppressesARetry(t *testing.T) {
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "internal", "ledger", "ledger.go"))
	if err != nil {
		t.Fatalf("reading the ledger: %v", err)
	}

	if !strings.Contains(string(src), "if r.Status == StatusDelivered {") {
		t.Error("ledger.Delivered no longer filters on StatusDelivered; a failed row may now " +
			"suppress a retry, which turns an undelivered alert into a silent drop")
	}
}
