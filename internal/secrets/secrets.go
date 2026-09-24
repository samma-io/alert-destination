// Package secrets reads the destination credentials at runtime.
//
// The Lambda's environment holds parameter names, never values. A token in an
// environment variable is visible in the console, in the API, and in every
// terraform plan that touches the function; these are a Slack bot token and a
// GitHub PAT that can open issues, so the indirection is worth one API call per
// cold start.
//
// Two choices here are deliberate: values are fetched in one batched call
// rather than one per name, because SSM's throughput is account-wide and a
// burst of cold starts each making two calls is how a service throttles itself;
// and a cached value can be invalidated, because a cache that lives for the
// whole container would keep presenting a rotated credential for hours.
package secrets

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Getter reads parameters by name. Declared in plain Go types so nothing here,
// and no test of it, needs the AWS SDK.
type Getter interface {
	Get(ctx context.Context, names ...string) (map[string]string, error)
}

// Cache memoises secrets for the life of the execution environment.
//
// Only successes are remembered. Caching a failure would preserve a throttle, or
// a moment's IAM propagation, for the whole life of a warm container, so every
// later invocation would keep failing with an error that had already cleared.
type Cache struct {
	getter Getter

	mu     sync.Mutex
	values map[string]string
}

// NewCache returns a cache over getter.
func NewCache(getter Getter) *Cache {
	return &Cache{getter: getter, values: map[string]string{}}
}

// Prime fetches several parameters in one call.
//
// Call it once per cold start with every name the invocation might need, so the
// service costs one round trip rather than one per secret.
func (c *Cache) Prime(ctx context.Context, names ...string) error {
	missing := c.missing(names)
	if len(missing) == 0 {
		return nil
	}

	fetched, err := c.getter.Get(ctx, missing...)
	if err != nil {
		return fmt.Errorf("reading parameters %s: %w", strings.Join(missing, ", "), err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for name, value := range fetched {
		if v := strings.TrimSpace(value); v != "" {
			c.values[name] = v
		}
	}
	return nil
}

// Get returns one parameter's value, reading it if it is not already cached.
func (c *Cache) Get(ctx context.Context, name string) (string, error) {
	if v, ok := c.cached(name); ok {
		return v, nil
	}

	if err := c.Prime(ctx, name); err != nil {
		return "", err
	}

	if v, ok := c.cached(name); ok {
		return v, nil
	}
	// Terraform declares each parameter with a placeholder and ignores later
	// changes to its value, so an unset one is the expected first-deploy state.
	// Naming it beats a 401 from the destination, which looks like a bad token
	// rather than an absent one.
	return "", fmt.Errorf("parameter %s is empty or absent; the secret has not been set", name)
}

// Invalidate drops a cached value so the next Get re-reads it.
//
// Called when a destination reports an authentication failure: the credential
// may have been rotated since this container started, and without this the
// container keeps presenting the stale one until it is recycled.
func (c *Cache) Invalidate(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.values, name)
}

// TokenFunc returns a resolver for one parameter, suitable for a destination's
// Token field. Nothing is read until it is called, so a Slack-only alert is not
// blocked by an unreadable GitHub credential.
func (c *Cache) TokenFunc(name string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) { return c.Get(ctx, name) }
}

func (c *Cache) cached(name string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.values[name]
	return v, ok
}

func (c *Cache) missing(names []string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []string
	for _, n := range names {
		if _, ok := c.values[n]; !ok {
			out = append(out, n)
		}
	}
	return out
}
