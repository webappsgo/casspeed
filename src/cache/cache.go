package cache

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/metrics"
	redis "github.com/redis/go-redis/v9"
)

// Client is the shared cache contract used by single-node and clustered servers.
type Client interface {
	Ping(context.Context) error
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string, time.Duration) error
	Delete(context.Context, string) error
	Increment(context.Context, string, time.Duration) (int64, error)
	Allow(context.Context, string, int, time.Duration) (bool, int, error)
	Count(context.Context, string, time.Duration) (int, error)
	RetryAfter(context.Context, string, time.Duration) (int, error)
	Decrement(context.Context, string) (int64, error)
	Publish(context.Context, string, string) error
	Subscribe(context.Context, string) (Subscription, error)
	Close() error
}

// Subscription owns one cache pub/sub stream.
type Subscription interface {
	Messages() <-chan string
	Close() error
}

type redisClient struct {
	client redis.UniversalClient
	prefix string
	name   string
}

var rateLimitMemberSequence atomic.Uint64

// New constructs the configured in-process or Valkey/Redis cache client.
func New(cfg config.CacheConfig, configDir string) (Client, error) {
	if cfg.Type == "" || cfg.Type == "none" || cfg.Type == "memory" {
		if cfg.Type == "none" {
			return nil, nil
		}
		return newMemoryClient(cfg.Prefix), nil
	}
	if cfg.Type != "valkey" && cfg.Type != "redis" {
		return nil, fmt.Errorf("unsupported cache type %q", cfg.Type)
	}
	tlsDir := filepath.Join(configDir, "ssl")
	options, clusterOptions, err := redisOptions(cfg, tlsDir)
	if err != nil {
		return nil, err
	}
	var client redis.UniversalClient
	if clusterOptions != nil {
		client = redis.NewClusterClient(clusterOptions)
	} else {
		client = redis.NewClient(options)
	}
	return &redisClient{client: client, prefix: cfg.Prefix, name: cfg.Type}, nil
}

func redisOptions(cfg config.CacheConfig, tlsDir string) (*redis.Options, *redis.ClusterOptions, error) {
	var options *redis.Options
	var parsed *url.URL
	if cfg.URL != "" {
		normalized := cfg.URL
		normalized = strings.TrimPrefix(normalized, "valkeys://")
		if normalized != cfg.URL {
			normalized = "rediss://" + normalized
		} else {
			normalized = strings.TrimPrefix(normalized, "valkey://")
			if normalized != cfg.URL {
				normalized = "redis://" + normalized
			}
		}
		var err error
		options, err = redis.ParseURL(normalized)
		if err != nil {
			return nil, nil, fmt.Errorf("parse cache URL: %w", err)
		}
		parsed, _ = url.Parse(normalized)
	} else {
		addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
		options = &redis.Options{Addr: addr, Username: cfg.Username, Password: cfg.Password, DB: cfg.DB}
	}
	if options == nil {
		return nil, nil, errors.New("cache options are unavailable")
	}
	if cfg.PoolSize > 0 {
		options.PoolSize = cfg.PoolSize
	}
	if cfg.MinIdle > 0 {
		options.MinIdleConns = cfg.MinIdle
	}
	if timeout, err := time.ParseDuration(cfg.Timeout); err == nil && timeout > 0 {
		options.ReadTimeout, options.WriteTimeout, options.DialTimeout = timeout, timeout, timeout
	}
	if cfg.TLS || options.TLSConfig != nil {
		// TLS verification behavior follows the explicit server.cache setting.
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.TLSSkipVerify}
		if options.TLSConfig != nil {
			tlsConfig = options.TLSConfig.Clone()
			tlsConfig.InsecureSkipVerify = cfg.TLSSkipVerify
		}
		if cfg.TLSCA != "" {
			pem, err := os.ReadFile(tlsFile(tlsDir, cfg.TLSCA))
			if err != nil {
				return nil, nil, fmt.Errorf("read cache TLS CA: %w", err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, nil, errors.New("cache TLS CA contains no certificates")
			}
			tlsConfig.RootCAs = pool
		}
		if cfg.TLSCert != "" || cfg.TLSKey != "" {
			if cfg.TLSCert == "" || cfg.TLSKey == "" {
				return nil, nil, errors.New("cache TLS client certificate and key must be configured together")
			}
			cert, err := tls.LoadX509KeyPair(tlsFile(tlsDir, cfg.TLSCert), tlsFile(tlsDir, cfg.TLSKey))
			if err != nil {
				return nil, nil, fmt.Errorf("load cache TLS client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		options.TLSConfig = tlsConfig
	}
	if cfg.Cluster {
		if options.DB != 0 {
			return nil, nil, errors.New("cache database must be zero in cluster mode")
		}
		addresses := append([]string(nil), cfg.ClusterNodes...)
		if len(addresses) == 0 && parsed != nil {
			addresses = []string{parsed.Host}
		}
		if len(addresses) == 0 {
			addresses = []string{options.Addr}
		}
		cluster := &redis.ClusterOptions{Addrs: addresses, Username: options.Username, Password: options.Password, PoolSize: options.PoolSize, MinIdleConns: options.MinIdleConns, DialTimeout: options.DialTimeout, ReadTimeout: options.ReadTimeout, WriteTimeout: options.WriteTimeout, TLSConfig: options.TLSConfig}
		return nil, cluster, nil
	}
	return options, nil, nil
}

func tlsFile(tlsDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(tlsDir, path)
}

func (c *redisClient) key(key string) string          { return c.prefix + key }
func (c *redisClient) Ping(ctx context.Context) error { return c.client.Ping(ctx).Err() }
func (c *redisClient) Get(ctx context.Context, key string) (string, error) {
	value, err := c.client.Get(ctx, c.key(key)).Result()
	metrics.RecordCacheAccess(c.name, err == nil)
	return value, err
}
func (c *redisClient) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return c.client.Set(ctx, c.key(key), value, ttl).Err()
}
func (c *redisClient) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, c.key(key)).Err()
}

func (c *redisClient) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	const script = `local count = redis.call('INCR', KEYS[1]); if count == 1 and tonumber(ARGV[1]) > 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); end; return count`
	return c.client.Eval(ctx, script, []string{c.key(key)}, ttl.Milliseconds()).Int64()
}

func (c *redisClient) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	const script = `local key = KEYS[1]; local now = tonumber(ARGV[1]); local duration = tonumber(ARGV[2]); local cutoff = now - duration; redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff); local count = redis.call('ZCARD', key); if count >= tonumber(ARGV[3]) then local first = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES'); local wait = math.max(1, math.ceil((tonumber(first[2]) + duration - now) / 1000)); return {0, wait} end; redis.call('ZADD', key, now, ARGV[4]); redis.call('PEXPIRE', key, duration); return {1, 0}`
	now := time.Now()
	member := strconv.FormatInt(now.UnixNano(), 10) + ":" + strconv.FormatUint(rateLimitMemberSequence.Add(1), 10)
	result, err := c.client.Eval(ctx, script, []string{c.key(key)}, now.UnixMilli(), window.Milliseconds(), limit, member).Int64Slice()
	if err != nil {
		return false, 0, err
	}
	if len(result) != 2 {
		return false, 0, errors.New("invalid cache rate-limit response")
	}
	return result[0] == 1, int(result[1]), nil
}

func (c *redisClient) Count(ctx context.Context, key string, window time.Duration) (int, error) {
	const script = `local key = KEYS[1]; local cutoff = tonumber(ARGV[1]) - tonumber(ARGV[2]); redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff); return redis.call('ZCARD', key)`
	count, err := c.client.Eval(ctx, script, []string{c.key(key)}, time.Now().UnixMilli(), window.Milliseconds()).Int()
	return count, err
}

func (c *redisClient) RetryAfter(ctx context.Context, key string, window time.Duration) (int, error) {
	const script = `local key = KEYS[1]; local now = tonumber(ARGV[1]); local duration = tonumber(ARGV[2]); local cutoff = now - duration; redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff); local first = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES'); if #first == 0 then return 1 end; return math.max(1, math.ceil((tonumber(first[2]) + duration - now) / 1000))`
	seconds, err := c.client.Eval(ctx, script, []string{c.key(key)}, time.Now().UnixMilli(), window.Milliseconds()).Int()
	return seconds, err
}

func (c *redisClient) Decrement(ctx context.Context, key string) (int64, error) {
	const script = `local count = redis.call('DECR', KEYS[1]); if count <= 0 then redis.call('DEL', KEYS[1]); return 0; end; return count`
	return c.client.Eval(ctx, script, []string{c.key(key)}).Int64()
}

func (c *redisClient) Publish(ctx context.Context, channel, message string) error {
	return c.client.Publish(ctx, c.key("channel:"+channel), message).Err()
}

type redisSubscription struct {
	pubsub   *redis.PubSub
	cancel   context.CancelFunc
	messages chan string
}

func (c *redisClient) Subscribe(ctx context.Context, channel string) (Subscription, error) {
	clientCtx, cancel := context.WithCancel(ctx)
	pubsub := c.client.Subscribe(clientCtx, c.key("channel:"+channel))
	if _, err := pubsub.Receive(clientCtx); err != nil {
		cancel()
		_ = pubsub.Close()
		return nil, err
	}
	result := &redisSubscription{pubsub: pubsub, cancel: cancel, messages: make(chan string)}
	go func() {
		defer close(result.messages)
		defer pubsub.Close()
		for message := range pubsub.Channel() {
			select {
			case result.messages <- message.Payload:
			case <-clientCtx.Done():
				return
			}
		}
	}()
	return result, nil
}

func (s *redisSubscription) Messages() <-chan string { return s.messages }
func (s *redisSubscription) Close() error            { s.cancel(); return s.pubsub.Close() }

func (c *redisClient) Close() error { return c.client.Close() }
