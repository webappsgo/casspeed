package metrics

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds metrics configuration
type Config struct {
	Enabled    bool
	Retention  time.Duration
	SampleRate int
}

// Counter represents a monotonically increasing counter
type Counter struct {
	value uint64
}

// Gauge represents a value that can go up or down
type Gauge struct {
	value int64
}

// Histogram tracks distribution of values
type Histogram struct {
	samples []float64
	mu      sync.RWMutex
}

// Metrics holds all application metrics
type Metrics struct {
	// HTTP metrics
	RequestsTotal     *Counter
	RequestsActive    *Gauge
	ResponseTime      *Histogram
	ErrorsTotal       *Counter

	// Speed test metrics
	TestsTotal        *Counter
	TestsActive       *Gauge
	DownloadSpeed     *Histogram
	UploadSpeed       *Histogram
	PingLatency       *Histogram

	// System metrics
	MemoryUsage       *Gauge
	GoroutineCount    *Gauge
	CPUUsage          *Gauge

	mu     sync.RWMutex
	config *Config
}

var (
	instance *Metrics
	once     sync.Once
)

// GetMetrics returns singleton metrics instance
func GetMetrics() *Metrics {
	once.Do(func() {
		instance = &Metrics{
			RequestsTotal:  &Counter{},
			RequestsActive: &Gauge{},
			ResponseTime:   NewHistogram(),
			ErrorsTotal:    &Counter{},
			TestsTotal:     &Counter{},
			TestsActive:    &Gauge{},
			DownloadSpeed:  NewHistogram(),
			UploadSpeed:    NewHistogram(),
			PingLatency:    NewHistogram(),
			MemoryUsage:    &Gauge{},
			GoroutineCount: &Gauge{},
			CPUUsage:       &Gauge{},
		}
	})
	return instance
}

// Initialize sets up metrics with configuration
func (m *Metrics) Initialize(cfg *Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg

	if cfg.Enabled {
		// Start background metric collector
		go m.collectSystemMetrics()
	}
}

// IsEnabled returns whether metrics collection is enabled
func (m *Metrics) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config != nil && m.config.Enabled
}

// Inc increments a counter by 1
func (c *Counter) Inc() {
	atomic.AddUint64(&c.value, 1)
}

// Add adds delta to counter
func (c *Counter) Add(delta uint64) {
	atomic.AddUint64(&c.value, delta)
}

// Value returns current counter value
func (c *Counter) Value() uint64 {
	return atomic.LoadUint64(&c.value)
}

// Set sets gauge to value
func (g *Gauge) Set(value int64) {
	atomic.StoreInt64(&g.value, value)
}

// Inc increments gauge by 1
func (g *Gauge) Inc() {
	atomic.AddInt64(&g.value, 1)
}

// Dec decrements gauge by 1
func (g *Gauge) Dec() {
	atomic.AddInt64(&g.value, -1)
}

// Value returns current gauge value
func (g *Gauge) Value() int64 {
	return atomic.LoadInt64(&g.value)
}

// NewHistogram creates a new histogram
func NewHistogram() *Histogram {
	return &Histogram{
		samples: make([]float64, 0, 1000),
	}
}

// Observe adds a sample to histogram
func (h *Histogram) Observe(value float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.samples = append(h.samples, value)

	// Keep only recent samples (last 1000)
	if len(h.samples) > 1000 {
		h.samples = h.samples[len(h.samples)-1000:]
	}
}

// Percentile returns the Pth percentile value
func (h *Histogram) Percentile(p float64) float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.samples) == 0 {
		return 0
	}

	// Simplified percentile calculation
	idx := int(float64(len(h.samples)) * p / 100.0)
	if idx >= len(h.samples) {
		idx = len(h.samples) - 1
	}

	return h.samples[idx]
}

// Mean returns average value
func (h *Histogram) Mean() float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.samples) == 0 {
		return 0
	}

	sum := 0.0
	for _, v := range h.samples {
		sum += v
	}

	return sum / float64(len(h.samples))
}

// collectSystemMetrics collects system metrics in background
func (m *Metrics) collectSystemMetrics() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !m.IsEnabled() {
			continue
		}

		// Memory usage
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		m.MemoryUsage.Set(int64(memStats.Alloc))

		// Goroutine count
		m.GoroutineCount.Set(int64(runtime.NumGoroutine()))
	}
}

// Summary returns a summary of all metrics
func (m *Metrics) Summary() map[string]interface{} {
	return map[string]interface{}{
		"http": map[string]interface{}{
			"requests_total":  m.RequestsTotal.Value(),
			"requests_active": m.RequestsActive.Value(),
			"response_time_avg": m.ResponseTime.Mean(),
			"response_time_p95": m.ResponseTime.Percentile(95),
			"errors_total":    m.ErrorsTotal.Value(),
		},
		"speedtest": map[string]interface{}{
			"tests_total":     m.TestsTotal.Value(),
			"tests_active":    m.TestsActive.Value(),
			"download_avg":    m.DownloadSpeed.Mean(),
			"upload_avg":      m.UploadSpeed.Mean(),
			"ping_avg":        m.PingLatency.Mean(),
		},
		"system": map[string]interface{}{
			"memory_bytes":     m.MemoryUsage.Value(),
			"goroutines":       m.GoroutineCount.Value(),
			"cpu_usage_percent": m.CPUUsage.Value(),
		},
	}
}

// RecordRequest records an HTTP request
func (m *Metrics) RecordRequest(duration time.Duration) {
	if !m.IsEnabled() {
		return
	}
	m.RequestsTotal.Inc()
	m.ResponseTime.Observe(float64(duration.Milliseconds()))
}

// RecordError records an error
func (m *Metrics) RecordError() {
	if !m.IsEnabled() {
		return
	}
	m.ErrorsTotal.Inc()
}

// RecordSpeedTest records a speed test result
func (m *Metrics) RecordSpeedTest(downloadMbps, uploadMbps, pingMs float64) {
	if !m.IsEnabled() {
		return
	}
	m.TestsTotal.Inc()
	m.DownloadSpeed.Observe(downloadMbps)
	m.UploadSpeed.Observe(uploadMbps)
	m.PingLatency.Observe(pingMs)
}

// TotalRequests returns the total number of HTTP requests (lifetime)
func (m *Metrics) TotalRequests() int64 {
	return int64(m.RequestsTotal.Value())
}

// Requests24h returns requests in the last 24 hours (approximated from total for now)
func (m *Metrics) Requests24h() int64 {
	return int64(m.RequestsTotal.Value())
}

// ActiveConnections returns the current number of active HTTP connections
func (m *Metrics) ActiveConnections() int {
	return int(m.RequestsActive.Value())
}

// Reset resets all metrics
func (m *Metrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.RequestsTotal = &Counter{}
	m.RequestsActive = &Gauge{}
	m.ResponseTime = NewHistogram()
	m.ErrorsTotal = &Counter{}
	m.TestsTotal = &Counter{}
	m.TestsActive = &Gauge{}
	m.DownloadSpeed = NewHistogram()
	m.UploadSpeed = NewHistogram()
	m.PingLatency = NewHistogram()
	m.MemoryUsage = &Gauge{}
	m.GoroutineCount = &Gauge{}
	m.CPUUsage = &Gauge{}
}

// Export exports metrics in Prometheus format
func (m *Metrics) Export() string {
	summary := m.Summary()
	output := ""

	// HTTP metrics
	http := summary["http"].(map[string]interface{})
	output += fmt.Sprintf("http_requests_total %v\n", http["requests_total"])
	output += fmt.Sprintf("http_requests_active %v\n", http["requests_active"])
	output += fmt.Sprintf("http_response_time_avg %v\n", http["response_time_avg"])
	output += fmt.Sprintf("http_errors_total %v\n", http["errors_total"])

	// Speed test metrics
	st := summary["speedtest"].(map[string]interface{})
	output += fmt.Sprintf("speedtest_tests_total %v\n", st["tests_total"])
	output += fmt.Sprintf("speedtest_download_mbps_avg %v\n", st["download_avg"])
	output += fmt.Sprintf("speedtest_upload_mbps_avg %v\n", st["upload_avg"])
	output += fmt.Sprintf("speedtest_ping_ms_avg %v\n", st["ping_avg"])

	// System metrics
	sys := summary["system"].(map[string]interface{})
	output += fmt.Sprintf("system_memory_bytes %v\n", sys["memory_bytes"])
	output += fmt.Sprintf("system_goroutines %v\n", sys["goroutines"])

	return output
}
