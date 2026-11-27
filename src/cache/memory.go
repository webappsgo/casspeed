package cache

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/casapps/casspeed/src/metrics"
)

var ErrMiss = errors.New("cache key not found")

type memoryEntry struct {
	value   string
	expires time.Time
}

type memoryClient struct {
	mu          sync.Mutex
	entries     map[string]memoryEntry
	windows     map[string][]time.Time
	subscribers map[string]map[*memorySubscription]struct{}
	prefix      string
	closed      bool
}

type memorySubscription struct {
	client   *memoryClient
	channel  string
	messages chan string
	closed   bool
}

func newMemoryClient(prefix string) *memoryClient {
	return &memoryClient{entries: make(map[string]memoryEntry), windows: make(map[string][]time.Time), subscribers: make(map[string]map[*memorySubscription]struct{}), prefix: prefix}
}

func (c *memoryClient) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	if limit < 1 || window <= 0 {
		return false, 0, errors.New("rate limit must have a positive limit and window")
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false, 0, errors.New("cache client is closed")
	}
	key = c.prefix + key
	cutoff := now.Add(-window)
	prior := c.windows[key]
	active := prior[:0]
	for _, stamped := range prior {
		if stamped.After(cutoff) {
			active = append(active, stamped)
		}
	}
	if len(active) >= limit {
		c.windows[key] = active
		retry := int(time.Until(active[0].Add(window)).Seconds())
		if retry < 1 {
			retry = 1
		}
		return false, retry, nil
	}
	c.windows[key] = append(active, now)
	return true, 0, nil
}

func (c *memoryClient) Count(ctx context.Context, key string, window time.Duration) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if window <= 0 {
		return 0, errors.New("rate-limit window must be positive")
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("cache client is closed")
	}
	key = c.prefix + key
	cutoff := now.Add(-window)
	prior := c.windows[key]
	active := prior[:0]
	for _, stamped := range prior {
		if stamped.After(cutoff) {
			active = append(active, stamped)
		}
	}
	c.windows[key] = active
	return len(active), nil
}

func (c *memoryClient) RetryAfter(ctx context.Context, key string, window time.Duration) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if window <= 0 {
		return 0, errors.New("rate-limit window must be positive")
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("cache client is closed")
	}
	key = c.prefix + key
	cutoff := now.Add(-window)
	prior := c.windows[key]
	active := prior[:0]
	for _, stamped := range prior {
		if stamped.After(cutoff) {
			active = append(active, stamped)
		}
	}
	c.windows[key] = active
	if len(active) == 0 {
		return 1, nil
	}
	seconds := int(time.Until(active[0].Add(window)).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return seconds, nil
}

func (c *memoryClient) Ping(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("cache client is closed")
	}
	return nil
}

func (c *memoryClient) Get(ctx context.Context, key string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return "", errors.New("cache client is closed")
	}
	key = c.prefix + key
	entry, ok := c.entries[key]
	if !ok {
		metrics.RecordCacheAccess("memory", false)
		return "", ErrMiss
	}
	if !entry.expires.IsZero() && !time.Now().Before(entry.expires) {
		delete(c.entries, key)
		metrics.RecordCacheEviction("memory")
		metrics.RecordCacheAccess("memory", false)
		return "", ErrMiss
	}
	metrics.RecordCacheAccess("memory", true)
	return entry.value, nil
}

func (c *memoryClient) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("cache client is closed")
	}
	entry := memoryEntry{value: value}
	if ttl > 0 {
		entry.expires = time.Now().Add(ttl)
	}
	c.entries[c.prefix+key] = entry
	return nil
}

func (c *memoryClient) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("cache client is closed")
	}
	delete(c.entries, c.prefix+key)
	return nil
}

func (c *memoryClient) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("cache client is closed")
	}
	key = c.prefix + key
	entry := c.entries[key]
	if !entry.expires.IsZero() && !time.Now().Before(entry.expires) {
		entry = memoryEntry{}
	}
	count := int64(0)
	if entry.value != "" {
		parsed, err := strconv.ParseInt(entry.value, 10, 64)
		if err != nil {
			return 0, err
		}
		count = parsed
	}
	count++
	entry.value = strconv.FormatInt(count, 10)
	if entry.expires.IsZero() && ttl > 0 {
		entry.expires = time.Now().Add(ttl)
	}
	c.entries[key] = entry
	return count, nil
}

func (c *memoryClient) Decrement(ctx context.Context, key string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("cache client is closed")
	}
	key = c.prefix + key
	entry, ok := c.entries[key]
	if !ok {
		return 0, ErrMiss
	}
	count, err := strconv.ParseInt(entry.value, 10, 64)
	if err != nil {
		return 0, err
	}
	count--
	if count <= 0 {
		delete(c.entries, key)
		return 0, nil
	}
	entry.value = strconv.FormatInt(count, 10)
	c.entries[key] = entry
	return count, nil
}

func (c *memoryClient) Subscribe(ctx context.Context, channel string) (Subscription, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("cache client is closed")
	}
	name := c.prefix + "channel:" + channel
	subscription := &memorySubscription{client: c, channel: name, messages: make(chan string, 32)}
	if c.subscribers[name] == nil {
		c.subscribers[name] = make(map[*memorySubscription]struct{})
	}
	c.subscribers[name][subscription] = struct{}{}
	c.mu.Unlock()
	go func() { <-ctx.Done(); _ = subscription.Close() }()
	return subscription, nil
}

func (c *memoryClient) Publish(ctx context.Context, channel, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("cache client is closed")
	}
	for subscription := range c.subscribers[c.prefix+"channel:"+channel] {
		select {
		case subscription.messages <- message:
		default:
		}
	}
	return nil
}

func (s *memorySubscription) Messages() <-chan string { return s.messages }

func (s *memorySubscription) Close() error {
	s.client.mu.Lock()
	defer s.client.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if subscribers := s.client.subscribers[s.channel]; subscribers != nil {
		delete(subscribers, s)
		if len(subscribers) == 0 {
			delete(s.client.subscribers, s.channel)
		}
	}
	close(s.messages)
	return nil
}

func (c *memoryClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.entries = nil
	c.windows = nil
	for _, subscriptions := range c.subscribers {
		for subscription := range subscriptions {
			if !subscription.closed {
				subscription.closed = true
				close(subscription.messages)
			}
		}
	}
	c.subscribers = nil
	return nil
}
