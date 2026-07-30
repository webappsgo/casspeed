package metrics

import (
	"strings"
	"testing"
	"time"
)

// newMetrics returns a fresh Metrics instance for each test (bypasses the singleton).
func newMetrics() *Metrics {
	return &Metrics{
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
}

// ---- Counter tests -------------------------------------------------------

func TestCounter_StartsAtZero(t *testing.T) {
	c := &Counter{}
	if c.Value() != 0 {
		t.Errorf("initial value = %d, want 0", c.Value())
	}
}

func TestCounter_Inc(t *testing.T) {
	c := &Counter{}
	c.Inc()
	c.Inc()
	if c.Value() != 2 {
		t.Errorf("value after 2 Inc() = %d, want 2", c.Value())
	}
}

func TestCounter_Add(t *testing.T) {
	c := &Counter{}
	c.Add(10)
	if c.Value() != 10 {
		t.Errorf("value after Add(10) = %d, want 10", c.Value())
	}
}

func TestCounter_AddZero(t *testing.T) {
	c := &Counter{}
	c.Add(0)
	if c.Value() != 0 {
		t.Errorf("value after Add(0) = %d, want 0", c.Value())
	}
}

// ---- Gauge tests ---------------------------------------------------------

func TestGauge_StartsAtZero(t *testing.T) {
	g := &Gauge{}
	if g.Value() != 0 {
		t.Errorf("initial value = %d, want 0", g.Value())
	}
}

func TestGauge_SetAndGet(t *testing.T) {
	g := &Gauge{}
	g.Set(42)
	if g.Value() != 42 {
		t.Errorf("value after Set(42) = %d, want 42", g.Value())
	}
}

func TestGauge_IncDec(t *testing.T) {
	g := &Gauge{}
	g.Inc()
	g.Inc()
	g.Inc()
	g.Dec()
	if g.Value() != 2 {
		t.Errorf("value after 3 Inc + 1 Dec = %d, want 2", g.Value())
	}
}

func TestGauge_NegativeValue(t *testing.T) {
	g := &Gauge{}
	g.Set(-5)
	if g.Value() != -5 {
		t.Errorf("value = %d, want -5", g.Value())
	}
}

// ---- Histogram tests -----------------------------------------------------

func TestHistogram_EmptyMeanIsZero(t *testing.T) {
	h := NewHistogram()
	if h.Mean() != 0 {
		t.Errorf("Mean() of empty histogram = %f, want 0", h.Mean())
	}
}

func TestHistogram_EmptyPercentileIsZero(t *testing.T) {
	h := NewHistogram()
	if h.Percentile(50) != 0 {
		t.Errorf("Percentile(50) of empty histogram = %f, want 0", h.Percentile(50))
	}
}

func TestHistogram_Mean(t *testing.T) {
	h := NewHistogram()
	h.Observe(10)
	h.Observe(20)
	h.Observe(30)
	if h.Mean() != 20 {
		t.Errorf("Mean() = %f, want 20", h.Mean())
	}
}

func TestHistogram_SingleSample(t *testing.T) {
	h := NewHistogram()
	h.Observe(7)
	if h.Mean() != 7 {
		t.Errorf("Mean() = %f, want 7", h.Mean())
	}
}

func TestHistogram_Percentile(t *testing.T) {
	h := NewHistogram()
	// Add 100 samples 1..100
	for i := 1; i <= 100; i++ {
		h.Observe(float64(i))
	}
	// P0 should be the first sample
	p0 := h.Percentile(0)
	if p0 < 1 {
		t.Errorf("Percentile(0) = %f, want >= 1", p0)
	}
}

func TestHistogram_CapAt1000Samples(t *testing.T) {
	h := NewHistogram()
	for i := 0; i < 1500; i++ {
		h.Observe(float64(i))
	}
	h.mu.RLock()
	n := len(h.samples)
	h.mu.RUnlock()
	if n > 1000 {
		t.Errorf("histogram kept %d samples, want <= 1000", n)
	}
}

// ---- Metrics IsEnabled / Initialize tests --------------------------------

func TestMetrics_NotEnabledByDefault(t *testing.T) {
	m := newMetrics()
	if m.IsEnabled() {
		t.Error("fresh Metrics should not be enabled")
	}
}

func TestMetrics_EnabledAfterInitialize(t *testing.T) {
	m := newMetrics()
	m.Initialize(&Config{Enabled: true, Retention: time.Hour, SampleRate: 1})
	if !m.IsEnabled() {
		t.Error("Metrics should be enabled after Initialize(Enabled=true)")
	}
}

// ---- RecordRequest / RecordError / RecordSpeedTest tests ----------------

func TestRecordRequest_WhenEnabled(t *testing.T) {
	m := newMetrics()
	m.Initialize(&Config{Enabled: true})
	before := m.RequestsTotal.Value()
	m.RecordRequest(10 * time.Millisecond)
	after := m.RequestsTotal.Value()
	if after-before != 1 {
		t.Errorf("RequestsTotal delta = %d, want 1", after-before)
	}
}

func TestRecordRequest_WhenDisabled(t *testing.T) {
	m := newMetrics()
	m.RecordRequest(10 * time.Millisecond)
	if m.RequestsTotal.Value() != 0 {
		t.Error("RecordRequest should no-op when disabled")
	}
}

func TestRecordError_WhenEnabled(t *testing.T) {
	m := newMetrics()
	m.Initialize(&Config{Enabled: true})
	m.RecordError()
	m.RecordError()
	if m.ErrorsTotal.Value() != 2 {
		t.Errorf("ErrorsTotal = %d, want 2", m.ErrorsTotal.Value())
	}
}

func TestRecordError_WhenDisabled(t *testing.T) {
	m := newMetrics()
	m.RecordError()
	if m.ErrorsTotal.Value() != 0 {
		t.Error("RecordError should no-op when disabled")
	}
}

func TestRecordSpeedTest_WhenEnabled(t *testing.T) {
	m := newMetrics()
	m.Initialize(&Config{Enabled: true})
	m.RecordSpeedTest(100, 50, 10)
	if m.TestsTotal.Value() != 1 {
		t.Errorf("TestsTotal = %d, want 1", m.TestsTotal.Value())
	}
	if m.DownloadSpeed.Mean() != 100 {
		t.Errorf("DownloadSpeed.Mean() = %f, want 100", m.DownloadSpeed.Mean())
	}
}

func TestRecordSpeedTest_WhenDisabled(t *testing.T) {
	m := newMetrics()
	m.RecordSpeedTest(100, 50, 10)
	if m.TestsTotal.Value() != 0 {
		t.Error("RecordSpeedTest should no-op when disabled")
	}
}

// ---- TotalRequests / Requests24h / ActiveConnections tests --------------

func TestTotalRequests(t *testing.T) {
	m := newMetrics()
	m.RequestsTotal.Add(7)
	if m.TotalRequests() != 7 {
		t.Errorf("TotalRequests() = %d, want 7", m.TotalRequests())
	}
}

func TestRequests24h(t *testing.T) {
	m := newMetrics()
	m.RequestsTotal.Add(5)
	if m.Requests24h() != 5 {
		t.Errorf("Requests24h() = %d, want 5", m.Requests24h())
	}
}

func TestActiveConnections(t *testing.T) {
	m := newMetrics()
	m.RequestsActive.Set(3)
	if m.ActiveConnections() != 3 {
		t.Errorf("ActiveConnections() = %d, want 3", m.ActiveConnections())
	}
}

// ---- Summary / Export tests ----------------------------------------------

func TestSummary_ReturnsExpectedKeys(t *testing.T) {
	m := newMetrics()
	summary := m.Summary()

	for _, top := range []string{"http", "speedtest", "system"} {
		if _, ok := summary[top]; !ok {
			t.Errorf("Summary() missing key %q", top)
		}
	}
}

func TestExport_ContainsPrometheusLines(t *testing.T) {
	m := newMetrics()
	output := m.Export()

	expectedPrefixes := []string{
		"http_requests_total",
		"speedtest_tests_total",
		"system_memory_bytes",
		"system_goroutines",
	}
	for _, prefix := range expectedPrefixes {
		if !strings.Contains(output, prefix) {
			t.Errorf("Export() missing line with prefix %q", prefix)
		}
	}
}

// ---- Reset test ----------------------------------------------------------

func TestReset_ClearsAllMetrics(t *testing.T) {
	m := newMetrics()
	m.Initialize(&Config{Enabled: true})
	m.RequestsTotal.Add(100)
	m.ErrorsTotal.Add(10)
	m.Reset()

	if m.RequestsTotal.Value() != 0 {
		t.Errorf("RequestsTotal after Reset = %d, want 0", m.RequestsTotal.Value())
	}
	if m.ErrorsTotal.Value() != 0 {
		t.Errorf("ErrorsTotal after Reset = %d, want 0", m.ErrorsTotal.Value())
	}
}

// ---- Concurrency smoke test ---------------------------------------------

func TestCounter_ConcurrentInc(t *testing.T) {
	c := &Counter{}
	done := make(chan struct{})
	const goroutines = 50
	const incsEach = 100

	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < incsEach; j++ {
				c.Inc()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
	want := uint64(goroutines * incsEach)
	if c.Value() != want {
		t.Errorf("concurrent Inc: value = %d, want %d", c.Value(), want)
	}
}
