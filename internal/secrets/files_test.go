package secrets_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samma-io/alert-destination/internal/secrets"
)

func TestFiles_ReadsAndTrimsAMountedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slack-token")
	if err := os.WriteFile(path, []byte("value-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := secrets.NewCache(secrets.Files{})
	got, err := c.Get(context.Background(), path)
	if err != nil || got != "value-one" {
		t.Fatalf("Get = %q, %v; want value-one", got, err)
	}
}

// The kubelet rewrites a mounted Secret in place; Invalidate is what makes the
// cache see it.
func TestFiles_InvalidateRereadsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	write := func(v string) {
		if err := os.WriteFile(path, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("old-value")
	c := secrets.NewCache(secrets.Files{})
	if v, _ := c.Get(context.Background(), path); v != "old-value" {
		t.Fatalf("Get = %q", v)
	}
	write("new-value")
	if v, _ := c.Get(context.Background(), path); v != "old-value" {
		t.Fatalf("Get = %q before Invalidate, want the cached value", v)
	}
	c.Invalidate(path)
	if v, _ := c.Get(context.Background(), path); v != "new-value" {
		t.Fatalf("Get = %q after Invalidate, want new-value", v)
	}
}

func TestFiles_MissingEmptyAndOversizedFilesAreErrorsNamingThePath(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, []byte(strings.Repeat("x", 65<<10)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "absent"), empty, big} {
		_, err := secrets.NewCache(secrets.Files{}).Get(context.Background(), path)
		if err == nil {
			t.Errorf("Get(%s) succeeded", path)
			continue
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("error does not name %s: %v", path, err)
		}
		if strings.Contains(err.Error(), "xxxx") {
			t.Errorf("error carries the file's content: %.80s", err)
		}
	}
}
