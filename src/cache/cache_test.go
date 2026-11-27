package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/config"
)

func TestNewMemoryModeProvidesTTLCache(t *testing.T) {
	client, err := New(config.CacheConfig{Type: "memory", Prefix: "test:"}, t.TempDir())
	if err != nil || client == nil {
		t.Fatalf("New(memory) = %v, %v", client, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	count, err := client.Increment(t.Context(), "count", time.Minute)
	if err != nil || count != 1 {
		t.Fatalf("first increment = %d, %v", count, err)
	}
	count, err = client.Increment(t.Context(), "count", time.Minute)
	if err != nil || count != 2 {
		t.Fatalf("second increment = %d, %v", count, err)
	}
	if err := client.Set(t.Context(), "value", "cached", time.Minute); err != nil {
		t.Fatal(err)
	}
	if value, err := client.Get(t.Context(), "value"); err != nil || value != "cached" {
		t.Fatalf("Get() = %q, %v", value, err)
	}
	subscription, err := client.Subscribe(t.Context(), "events")
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if err := client.Publish(t.Context(), "events", "updated"); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-subscription.Messages():
		if message != "updated" {
			t.Fatalf("pub/sub message = %q", message)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cache pub/sub message")
	}
	if _, err := New(config.CacheConfig{Type: "none"}, t.TempDir()); err != nil {
		t.Fatalf("New(none): %v", err)
	}
}

func TestMemorySlidingWindowRateLimit(t *testing.T) {
	client, err := New(config.CacheConfig{Type: "memory"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	for attempt := 0; attempt < 2; attempt++ {
		allowed, _, err := client.Allow(t.Context(), "requests", 2, time.Minute)
		if err != nil || !allowed {
			t.Fatalf("attempt %d allowed=%t err=%v", attempt+1, allowed, err)
		}
	}
	if allowed, _, err := client.Allow(t.Context(), "requests", 2, time.Minute); err != nil || allowed {
		t.Fatalf("over-limit request allowed=%t err=%v", allowed, err)
	}
}

func TestRedisOptionsParsesValkeyURLAndTLS(t *testing.T) {
	options, cluster, err := redisOptions(config.CacheConfig{Type: "valkey", URL: "valkeys://user:secret@cache.example:6380/2", TLSSkipVerify: false, Prefix: "app:"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cluster != nil || options == nil {
		t.Fatal("standalone URL unexpectedly configured a cluster client")
	}
	if options.Addr != "cache.example:6380" || options.Username != "user" || options.Password != "secret" || options.DB != 2 {
		t.Fatalf("parsed URL options = %#v", options)
	}
	if options.TLSConfig == nil || options.TLSConfig.InsecureSkipVerify {
		t.Fatal("valkeys URL did not enable verified TLS")
	}
}

func TestRedisOptionsClusterUsesConfiguredNodes(t *testing.T) {
	_, cluster, err := redisOptions(config.CacheConfig{Type: "redis", URL: "redis://cache.example:6379/0", Cluster: true, ClusterNodes: []string{"cache-a:6379", "cache-b:6379"}, PoolSize: 8, MinIdle: 1, Timeout: "2s"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cluster == nil || len(cluster.Addrs) != 2 || cluster.PoolSize != 8 || cluster.MinIdleConns != 1 || cluster.DialTimeout != 2*time.Second {
		t.Fatalf("cluster options = %#v", cluster)
	}
}

func TestMemoryCacheExpirationDeletionCountersAndValidation(t *testing.T) {
	client := newMemoryClient("prefix:")
	ctx := context.Background()
	if err := client.Set(ctx, "expire", "old", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := client.Get(ctx, "expire"); !errors.Is(err, ErrMiss) {
		t.Fatalf("expired value error = %v", err)
	}
	if err := client.Set(ctx, "counter", "3", time.Minute); err != nil {
		t.Fatal(err)
	}
	if count, err := client.Decrement(ctx, "counter"); err != nil || count != 2 {
		t.Fatalf("decrement = %d, %v", count, err)
	}
	if err := client.Set(ctx, "counter", "1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if count, err := client.Decrement(ctx, "counter"); err != nil || count != 0 {
		t.Fatalf("final decrement = %d, %v", count, err)
	}
	if _, err := client.Decrement(ctx, "missing"); !errors.Is(err, ErrMiss) {
		t.Fatalf("missing decrement error = %v", err)
	}
	if err := client.Set(ctx, "counter", "not-a-number", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Increment(ctx, "counter", 0); err == nil {
		t.Fatal("increment accepted a malformed stored counter")
	}
	if _, err := client.Decrement(ctx, "counter"); err == nil {
		t.Fatal("decrement accepted a malformed stored counter")
	}
	if err := client.Delete(ctx, "counter"); err != nil {
		t.Fatal(err)
	}
	for _, check := range []func() error{
		func() error { _, _, err := client.Allow(ctx, "x", 0, time.Minute); return err },
		func() error { _, _, err := client.Allow(ctx, "x", 1, 0); return err },
		func() error { _, err := client.Count(ctx, "x", 0); return err },
		func() error { _, err := client.RetryAfter(ctx, "x", 0); return err },
	} {
		if err := check(); err == nil {
			t.Fatal("invalid rate-limit parameters were accepted")
		}
	}
	if retry, err := client.RetryAfter(ctx, "unused", time.Minute); err != nil || retry != 1 {
		t.Fatalf("empty RetryAfter = %d, %v", retry, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := client.Get(canceled, "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Get error = %v", err)
	}
	if _, _, err := client.Allow(canceled, "x", 1, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Allow error = %v", err)
	}
}

func TestMemoryCacheCloseAndSubscriptionLifecycle(t *testing.T) {
	client := newMemoryClient("")
	subscription, err := client.Subscribe(context.Background(), "events")
	if err != nil {
		t.Fatal(err)
	}
	if err := subscription.Close(); err != nil {
		t.Fatal(err)
	}
	if err := subscription.Close(); err != nil {
		t.Fatalf("repeated subscription close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(context.Background()); err == nil {
		t.Fatal("closed cache client passed Ping")
	}
	if _, err := client.Get(context.Background(), "x"); err == nil {
		t.Fatal("closed cache client returned a value")
	}
	if err := client.Set(context.Background(), "x", "y", 0); err == nil {
		t.Fatal("closed cache client accepted Set")
	}
	if err := client.Delete(context.Background(), "x"); err == nil {
		t.Fatal("closed cache client accepted Delete")
	}
	if _, err := client.Increment(context.Background(), "x", 0); err == nil {
		t.Fatal("closed cache client accepted Increment")
	}
	if _, _, err := client.Allow(context.Background(), "x", 1, time.Minute); err == nil {
		t.Fatal("closed cache client accepted Allow")
	}
	if _, err := client.Count(context.Background(), "x", time.Minute); err == nil {
		t.Fatal("closed cache client accepted Count")
	}
	if _, err := client.RetryAfter(context.Background(), "x", time.Minute); err == nil {
		t.Fatal("closed cache client accepted RetryAfter")
	}
	if _, err := client.Decrement(context.Background(), "x"); err == nil {
		t.Fatal("closed cache client accepted Decrement")
	}
	if err := client.Publish(context.Background(), "events", "message"); err == nil {
		t.Fatal("closed cache client accepted Publish")
	}
	if _, err := client.Subscribe(context.Background(), "events"); err == nil {
		t.Fatal("closed cache client accepted Subscribe")
	}
}

func TestCacheRejectsUnsupportedModeAndInvalidRedisSettings(t *testing.T) {
	if _, err := New(config.CacheConfig{Type: "other"}, t.TempDir()); err == nil {
		t.Fatal("unsupported cache type was accepted")
	}
	if _, _, err := redisOptions(config.CacheConfig{Type: "redis", URL: "redis://%"}, t.TempDir()); err == nil {
		t.Fatal("malformed cache URL was accepted")
	}
	if _, _, err := redisOptions(config.CacheConfig{Type: "redis", Host: "cache.example", Port: 6379, TLS: true, TLSCert: "client.crt"}, t.TempDir()); err == nil {
		t.Fatal("unpaired TLS client certificate was accepted")
	}
	if _, _, err := redisOptions(config.CacheConfig{Type: "redis", URL: "redis://cache.example:6379/2", Cluster: true}, t.TempDir()); err == nil {
		t.Fatal("cluster mode with a nonzero database was accepted")
	}
}
