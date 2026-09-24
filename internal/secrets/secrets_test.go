package secrets_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/samma-io/alert-destination/internal/secrets"
)

type fakeGetter struct {
	mu     sync.Mutex
	values map[string]string
	calls  [][]string
	err    error
}

func (f *fakeGetter) Get(_ context.Context, names ...string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string(nil), names...))
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

func newFake(values map[string]string) *fakeGetter {
	return &fakeGetter{values: values}
}

func TestGet_ReadsTheValue(t *testing.T) {
	c := secrets.NewCache(newFake(map[string]string{"/a/TOKEN": "xoxb-real"}))

	got, err := c.Get(context.Background(), "/a/TOKEN")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "xoxb-real" {
		t.Errorf("Get = %q, want xoxb-real", got)
	}
}

// A warm execution environment should spend one read per cold start, not one
// per invocation.
func TestGet_ReadsOnlyOncePerName(t *testing.T) {
	f := newFake(map[string]string{"/a/TOKEN": "v"})
	c := secrets.NewCache(f)

	for i := 0; i < 5; i++ {
		if _, err := c.Get(context.Background(), "/a/TOKEN"); err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
	}
	if len(f.calls) != 1 {
		t.Errorf("reads = %d, want 1", len(f.calls))
	}
}

// A sync.Once would cache a throttle or a moment's IAM propagation for the whole
// life of the container, so every later invocation keeps failing with an error
// that has already gone away.
func TestGet_DoesNotCacheAFailure(t *testing.T) {
	f := newFake(map[string]string{"/a/TOKEN": "v"})
	f.err = errors.New("ThrottlingException")
	c := secrets.NewCache(f)

	if _, err := c.Get(context.Background(), "/a/TOKEN"); err == nil {
		t.Fatal("Get succeeded despite a getter error")
	}

	f.err = nil
	got, err := c.Get(context.Background(), "/a/TOKEN")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if got != "v" {
		t.Errorf("Get = %q after recovery, want v", got)
	}
}

// Terraform declares each parameter with a placeholder and ignores later changes
// to its value, so an empty one means nobody set the real secret. Saying that
// beats a 401 from the destination.
func TestGet_AnEmptyValueIsAnExplicitError(t *testing.T) {
	c := secrets.NewCache(newFake(map[string]string{"/a/TOKEN": "   "}))

	_, err := c.Get(context.Background(), "/a/TOKEN")
	if err == nil {
		t.Fatal("Get succeeded on an unset parameter")
	}
	if !strings.Contains(err.Error(), "/a/TOKEN") {
		t.Errorf("error does not name the parameter: %v", err)
	}
}

func TestGet_AMissingParameterIsAnError(t *testing.T) {
	c := secrets.NewCache(newFake(map[string]string{}))

	if _, err := c.Get(context.Background(), "/a/NOPE"); err == nil {
		t.Fatal("Get succeeded for a parameter the store does not have")
	}
}

func TestGet_TrimsSurroundingWhitespace(t *testing.T) {
	c := secrets.NewCache(newFake(map[string]string{"/a/TOKEN": "  v\n"}))

	got, err := c.Get(context.Background(), "/a/TOKEN")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "v" {
		t.Errorf("Get = %q, want the value trimmed", got)
	}
}

// Without this, a rotated credential keeps failing for the whole life of a warm
// container -- potentially hours of undelivered alerts.
func TestInvalidate_ForcesARereadAfterARotation(t *testing.T) {
	f := newFake(map[string]string{"/a/TOKEN": "old"})
	c := secrets.NewCache(f)

	if _, err := c.Get(context.Background(), "/a/TOKEN"); err != nil {
		t.Fatalf("Get: %v", err)
	}

	f.mu.Lock()
	f.values["/a/TOKEN"] = "rotated"
	f.mu.Unlock()
	c.Invalidate("/a/TOKEN")

	got, err := c.Get(context.Background(), "/a/TOKEN")
	if err != nil {
		t.Fatalf("Get after Invalidate: %v", err)
	}
	if got != "rotated" {
		t.Errorf("Get = %q after invalidation, want rotated", got)
	}
}

// SSM's throughput is account-wide, so a burst of cold starts each doing one
// call per secret is how you produce ThrottlingException for everyone.
func TestPrime_FetchesEveryNameInOneCall(t *testing.T) {
	f := newFake(map[string]string{"/a/SLACK": "s", "/a/GITHUB": "g"})
	c := secrets.NewCache(f)

	if err := c.Prime(context.Background(), "/a/SLACK", "/a/GITHUB"); err != nil {
		t.Fatalf("Prime: %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(f.calls))
	}
	if len(f.calls[0]) != 2 {
		t.Errorf("first call asked for %v, want both names", f.calls[0])
	}

	for _, name := range []string{"/a/SLACK", "/a/GITHUB"} {
		if _, err := c.Get(context.Background(), name); err != nil {
			t.Errorf("Get(%s) after Prime: %v", name, err)
		}
	}
	if len(f.calls) != 1 {
		t.Errorf("Prime did not populate the cache; calls = %d", len(f.calls))
	}
}

func TestTokenFunc_ResolvesLazily(t *testing.T) {
	f := newFake(map[string]string{"/a/TOKEN": "v"})
	c := secrets.NewCache(f)

	token := c.TokenFunc("/a/TOKEN")
	if len(f.calls) != 0 {
		t.Fatal("TokenFunc read the secret eagerly")
	}

	got, err := token(context.Background())
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got != "v" {
		t.Errorf("token = %q, want v", got)
	}
}

func TestGet_IsSafeForConcurrentUse(t *testing.T) {
	c := secrets.NewCache(newFake(map[string]string{"/a/TOKEN": "v"}))

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background(), "/a/TOKEN"); err != nil {
				t.Errorf("Get: %v", err)
			}
		}()
	}
	wg.Wait()
}
