package metrics

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

// PrometheusConfig controls optional metric families and histogram boundaries.
type PrometheusConfig struct {
	IncludeSystem   bool
	IncludeRuntime  bool
	DurationBuckets []float64
	SizeBuckets     []float64
}

type prometheusSet struct {
	registry                                                        *prometheus.Registry
	httpRequests                                                    *prometheus.CounterVec
	httpDuration                                                    *prometheus.HistogramVec
	httpRequestSize                                                 *prometheus.HistogramVec
	httpResponseSize                                                *prometheus.HistogramVec
	httpActive                                                      prometheus.Gauge
	dbQueries                                                       *prometheus.CounterVec
	dbDuration                                                      *prometheus.HistogramVec
	dbOpen, dbInUse                                                 prometheus.Gauge
	dbErrors                                                        *prometheus.CounterVec
	dbBusy                                                          prometheus.Counter
	dbWriteWait                                                     prometheus.Histogram
	cacheHits, cacheMisses, cacheEvictions                          *prometheus.CounterVec
	cacheSize, cacheBytes                                           *prometheus.GaugeVec
	schedulerTotal                                                  *prometheus.CounterVec
	schedulerDuration                                               *prometheus.HistogramVec
	schedulerRunning, schedulerLastRun                              *prometheus.GaugeVec
	authAttempts                                                    *prometheus.CounterVec
	authSessions, usersTotal, usersActive, apiTokensActive          prometheus.Gauge
	appInfo                                                         *prometheus.GaugeVec
	appUptime, appStart                                             prometheus.Gauge
	speedTests                                                      prometheus.Counter
	speedDownload, speedUpload, speedPing                           prometheus.Histogram
	systemCPU, systemMemoryPct, systemMemoryUsed, systemMemoryTotal prometheus.Gauge
	systemDiskPct, systemDiskUsed, systemDiskTotal                  *prometheus.GaugeVec
	runtimeGoroutines, runtimeAlloc, runtimeSys                     prometheus.Gauge
	runtimeGCRuns, runtimeGCPause                                   prometheus.Counter
	started                                                         time.Time
}

var prometheusMetrics = struct {
	sync.RWMutex
	set *prometheusSet
	cfg PrometheusConfig
}{cfg: PrometheusConfig{IncludeSystem: true, IncludeRuntime: true}}

var (
	metricUUID   = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	metricNumber = regexp.MustCompile(`/\d+(/|$)`)
)

// NormalizePath replaces likely identifiers in URL paths to bound label cardinality.
func NormalizePath(path string) string {
	path = metricUUID.ReplaceAllString(path, ":id")
	return metricNumber.ReplaceAllString(path, "/:id$1")
}

// ConfigurePrometheus installs the application registry and its histogram
// buckets. Call it during startup, before recording metrics or serving scrapes.
func ConfigurePrometheus(cfg PrometheusConfig) {
	prometheusMetrics.Lock()
	defer prometheusMetrics.Unlock()
	if prometheusMetrics.set != nil && reflect.DeepEqual(prometheusMetrics.cfg, cfg) {
		return
	}
	prometheusMetrics.cfg = cfg
	prometheusMetrics.set = newPrometheusSet(cfg)
}

func newPrometheusSet(cfg PrometheusConfig) *prometheusSet {
	duration := validFloatBuckets(cfg.DurationBuckets, []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10})
	sizes := validFloatBuckets(cfg.SizeBuckets, []float64{100, 1000, 10000, 100000, 1000000, 10000000})
	r := prometheus.NewRegistry()
	register := func(c prometheus.Collector) { r.MustRegister(c) }
	m := &prometheusSet{registry: r, started: time.Now()}
	m.httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "casspeed_http_requests_total", Help: "Total HTTP requests."}, []string{"method", "path", "status"})
	m.httpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "casspeed_http_request_duration_seconds", Help: "HTTP request duration in seconds.", Buckets: duration}, []string{"method", "path"})
	m.httpRequestSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "casspeed_http_request_size_bytes", Help: "HTTP request size in bytes.", Buckets: sizes}, []string{"method", "path"})
	m.httpResponseSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "casspeed_http_response_size_bytes", Help: "HTTP response size in bytes.", Buckets: sizes}, []string{"method", "path"})
	m.httpActive = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_http_active_requests", Help: "Requests currently being processed."})
	m.dbQueries = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "casspeed_db_queries_total", Help: "Database queries."}, []string{"operation", "table"})
	m.dbDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "casspeed_db_query_duration_seconds", Help: "Database query duration in seconds.", Buckets: []float64{.0001, .0005, .001, .005, .01, .05, .1, .5, 1}}, []string{"operation", "table"})
	m.dbOpen = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_db_connections_open", Help: "Open database connections."})
	m.dbInUse = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_db_connections_in_use", Help: "Database connections in use."})
	m.dbErrors = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "casspeed_db_errors_total", Help: "Database errors."}, []string{"operation", "error_type"})
	m.dbBusy = prometheus.NewCounter(prometheus.CounterOpts{Name: "casspeed_db_busy_total", Help: "SQLite write busy or locked errors retried."})
	m.dbWriteWait = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "casspeed_db_write_wait_seconds", Help: "Time waiting for SQLite write access.", Buckets: duration})
	m.cacheHits = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "casspeed_cache_hits_total", Help: "Cache hits."}, []string{"cache"})
	m.cacheMisses = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "casspeed_cache_misses_total", Help: "Cache misses."}, []string{"cache"})
	m.cacheEvictions = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "casspeed_cache_evictions_total", Help: "Cache evictions."}, []string{"cache"})
	m.cacheSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "casspeed_cache_size", Help: "Cache item count."}, []string{"cache"})
	m.cacheBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "casspeed_cache_bytes", Help: "Cache bytes."}, []string{"cache"})
	m.schedulerTotal = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "casspeed_scheduler_tasks_total", Help: "Scheduled task executions."}, []string{"task", "status"})
	m.schedulerDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "casspeed_scheduler_task_duration_seconds", Help: "Scheduled task duration.", Buckets: []float64{.1, .5, 1, 5, 10, 30, 60, 300, 600}}, []string{"task"})
	m.schedulerRunning = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "casspeed_scheduler_tasks_running", Help: "Scheduled tasks running."}, []string{"task"})
	m.schedulerLastRun = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "casspeed_scheduler_last_run_timestamp", Help: "Unix timestamp of last task run."}, []string{"task"})
	m.authAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "casspeed_auth_attempts_total", Help: "Authentication attempts."}, []string{"method", "status"})
	m.authSessions = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_auth_sessions_active", Help: "Active authentication sessions."})
	m.usersTotal = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_users_total", Help: "Registered users."})
	m.usersActive = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_users_active", Help: "Users active in the last 24 hours."})
	m.apiTokensActive = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_api_tokens_active", Help: "Active API tokens."})
	m.appInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "casspeed_app_info", Help: "Application build information."}, []string{"version", "commit", "build_date", "go_version"})
	m.appUptime = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_app_uptime_seconds", Help: "Application uptime in seconds."})
	m.appStart = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_app_start_timestamp", Help: "Unix timestamp when the application started."})
	m.speedTests = prometheus.NewCounter(prometheus.CounterOpts{Name: "casspeed_speedtest_tests_total", Help: "Completed speed tests."})
	m.speedDownload = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "casspeed_speedtest_download_mbps", Help: "Speed test download throughput in Mbps."})
	m.speedUpload = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "casspeed_speedtest_upload_mbps", Help: "Speed test upload throughput in Mbps."})
	m.speedPing = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "casspeed_speedtest_ping_milliseconds", Help: "Speed test ping latency in milliseconds."})
	m.systemCPU = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_system_cpu_usage_percent", Help: "CPU usage percentage."})
	m.systemMemoryPct = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_system_memory_usage_percent", Help: "Memory usage percentage."})
	m.systemMemoryUsed = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_system_memory_used_bytes", Help: "Memory used in bytes."})
	m.systemMemoryTotal = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_system_memory_total_bytes", Help: "Total memory in bytes."})
	m.systemDiskPct = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "casspeed_system_disk_usage_percent", Help: "Disk usage percentage."}, []string{"path"})
	m.systemDiskUsed = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "casspeed_system_disk_used_bytes", Help: "Disk used in bytes."}, []string{"path"})
	m.systemDiskTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "casspeed_system_disk_total_bytes", Help: "Total disk bytes."}, []string{"path"})
	m.runtimeGoroutines = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_go_goroutines", Help: "Current goroutine count."})
	m.runtimeAlloc = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_go_mem_alloc_bytes", Help: "Allocated heap bytes."})
	m.runtimeSys = prometheus.NewGauge(prometheus.GaugeOpts{Name: "casspeed_go_mem_sys_bytes", Help: "Bytes obtained from system."})
	m.runtimeGCRuns = prometheus.NewCounter(prometheus.CounterOpts{Name: "casspeed_go_gc_runs_total", Help: "Garbage collection runs."})
	m.runtimeGCPause = prometheus.NewCounter(prometheus.CounterOpts{Name: "casspeed_go_gc_pause_total_seconds", Help: "Time spent in garbage collection pauses."})
	for _, c := range []prometheus.Collector{m.httpRequests, m.httpDuration, m.httpRequestSize, m.httpResponseSize, m.httpActive, m.dbQueries, m.dbDuration, m.dbOpen, m.dbInUse, m.dbErrors, m.dbBusy, m.dbWriteWait, m.cacheHits, m.cacheMisses, m.cacheEvictions, m.cacheSize, m.cacheBytes, m.schedulerTotal, m.schedulerDuration, m.schedulerRunning, m.schedulerLastRun, m.authAttempts, m.authSessions, m.usersTotal, m.usersActive, m.apiTokensActive, m.appInfo, m.appUptime, m.appStart, m.speedTests, m.speedDownload, m.speedUpload, m.speedPing, m.systemCPU, m.systemMemoryPct, m.systemMemoryUsed, m.systemMemoryTotal, m.systemDiskPct, m.systemDiskUsed, m.systemDiskTotal, m.runtimeGoroutines, m.runtimeAlloc, m.runtimeSys, m.runtimeGCRuns, m.runtimeGCPause} {
		register(c)
	}
	m.appStart.Set(float64(m.started.Unix()))
	m.appInfo.WithLabelValues("unknown", "unknown", "unknown", runtime.Version()).Set(1)
	m.httpRequests.WithLabelValues("GET", "/", "200")
	m.httpDuration.WithLabelValues("GET", "/")
	m.httpRequestSize.WithLabelValues("GET", "/")
	m.httpResponseSize.WithLabelValues("GET", "/")
	m.dbQueries.WithLabelValues("unknown", "unknown")
	m.dbDuration.WithLabelValues("unknown", "unknown")
	m.dbErrors.WithLabelValues("unknown", "other")
	m.cacheHits.WithLabelValues("default")
	m.cacheMisses.WithLabelValues("default")
	m.cacheEvictions.WithLabelValues("default")
	m.cacheSize.WithLabelValues("default")
	m.cacheBytes.WithLabelValues("default")
	m.schedulerTotal.WithLabelValues("unknown", "success")
	m.schedulerDuration.WithLabelValues("unknown")
	m.schedulerRunning.WithLabelValues("unknown")
	m.schedulerLastRun.WithLabelValues("unknown")
	m.authAttempts.WithLabelValues("unknown", "failed")
	return m
}

func validFloatBuckets(values, fallback []float64) []float64 {
	if len(values) == 0 {
		return fallback
	}
	out := append([]float64(nil), values...)
	sort.Float64s(out)
	for i, v := range out {
		if v <= 0 || (i > 0 && out[i-1] == v) {
			return fallback
		}
	}
	return out
}
func currentPrometheusSet() *prometheusSet {
	prometheusMetrics.RLock()
	m := prometheusMetrics.set
	prometheusMetrics.RUnlock()
	if m != nil {
		return m
	}
	prometheusMetrics.Lock()
	defer prometheusMetrics.Unlock()
	if prometheusMetrics.set == nil {
		prometheusMetrics.set = newPrometheusSet(prometheusMetrics.cfg)
	}
	return prometheusMetrics.set
}

// RecordHTTP records a completed request using normalized, bounded label values.
func RecordHTTP(method, path, status string, durationSeconds, requestBytes, responseBytes float64) {
	m := currentPrometheusSet()
	m.httpRequests.WithLabelValues(method, NormalizePath(path), status).Inc()
	m.httpDuration.WithLabelValues(method, NormalizePath(path)).Observe(durationSeconds)
	m.httpRequestSize.WithLabelValues(method, NormalizePath(path)).Observe(requestBytes)
	m.httpResponseSize.WithLabelValues(method, NormalizePath(path)).Observe(responseBytes)
}

// HTTPRequestStarted and HTTPRequestFinished track in-flight requests.
func HTTPRequestStarted()  { currentPrometheusSet().httpActive.Inc() }
func HTTPRequestFinished() { currentPrometheusSet().httpActive.Dec() }

// RecordDatabase records a database operation and its outcome.
func RecordDatabase(operation, table, errorType string, duration float64) {
	m := currentPrometheusSet()
	m.dbQueries.WithLabelValues(operation, table).Inc()
	m.dbDuration.WithLabelValues(operation, table).Observe(duration)
	if errorType != "" {
		m.dbErrors.WithLabelValues(operation, errorType).Inc()
	}
}

// SetDatabaseConnections updates connection pool gauges.
func SetDatabaseConnections(open, inUse float64) {
	m := currentPrometheusSet()
	m.dbOpen.Set(open)
	m.dbInUse.Set(inUse)
}

// RecordDatabaseBusy records an SQLite busy or locked write that was retried.
func RecordDatabaseBusy() { currentPrometheusSet().dbBusy.Inc() }

// RecordDatabaseWriteWait observes time spent waiting for SQLite write access.
func RecordDatabaseWriteWait(seconds float64) { currentPrometheusSet().dbWriteWait.Observe(seconds) }

// SetBusinessMetrics updates aggregate user and token gauges.
func SetBusinessMetrics(users, activeUsers, activeTokens, activeSessions float64) {
	m := currentPrometheusSet()
	m.usersTotal.Set(users)
	m.usersActive.Set(activeUsers)
	m.apiTokensActive.Set(activeTokens)
	m.authSessions.Set(activeSessions)
}

// RecordCacheAccess records a cache hit or miss.
func RecordCacheAccess(name string, hit bool) {
	m := currentPrometheusSet()
	if hit {
		m.cacheHits.WithLabelValues(name).Inc()
	} else {
		m.cacheMisses.WithLabelValues(name).Inc()
	}
}

// RecordCacheEviction records a cache eviction.
func RecordCacheEviction(name string) {
	currentPrometheusSet().cacheEvictions.WithLabelValues(name).Inc()
}

// RecordScheduler records one scheduled task execution.
func RecordScheduler(task, status string, duration float64) {
	m := currentPrometheusSet()
	m.schedulerTotal.WithLabelValues(task, status).Inc()
	m.schedulerDuration.WithLabelValues(task).Observe(duration)
	m.schedulerLastRun.WithLabelValues(task).Set(float64(time.Now().Unix()))
}

// SchedulerTaskStarted and SchedulerTaskFinished track active scheduled tasks.
func SchedulerTaskStarted(task string) {
	currentPrometheusSet().schedulerRunning.WithLabelValues(task).Inc()
}
func SchedulerTaskFinished(task string) {
	currentPrometheusSet().schedulerRunning.WithLabelValues(task).Dec()
}

// RecordAuthentication records an authentication attempt.
func RecordAuthentication(method, status string) {
	currentPrometheusSet().authAttempts.WithLabelValues(method, status).Inc()
}

// RecordSpeedTestMetrics records completed speed test measurements.
func RecordSpeedTestMetrics(downloadMbps, uploadMbps, pingMilliseconds float64) {
	m := currentPrometheusSet()
	m.speedTests.Inc()
	m.speedDownload.Observe(downloadMbps)
	m.speedUpload.Observe(uploadMbps)
	m.speedPing.Observe(pingMilliseconds)
}

// InitPrometheusAppInfo sets build labels on the application info metric.
func InitPrometheusAppInfo(version, commit, buildDate string) {
	currentPrometheusSet().appInfo.Reset()
	currentPrometheusSet().appInfo.WithLabelValues(version, commit, buildDate, runtime.Version()).Set(1)
}

// SetSystemMetrics updates system resource gauges, when enabled.
func SetSystemMetrics(cpuPercent, memoryPercent, memoryUsed, memoryTotal, diskPercent, diskUsed, diskTotal float64, dataPath string) {
	prometheusMetrics.RLock()
	enabled := prometheusMetrics.cfg.IncludeSystem
	prometheusMetrics.RUnlock()
	if !enabled {
		return
	}
	m := currentPrometheusSet()
	m.systemCPU.Set(cpuPercent)
	m.systemMemoryPct.Set(memoryPercent)
	m.systemMemoryUsed.Set(memoryUsed)
	m.systemMemoryTotal.Set(memoryTotal)
	m.systemDiskPct.WithLabelValues(dataPath).Set(diskPercent)
	m.systemDiskUsed.WithLabelValues(dataPath).Set(diskUsed)
	m.systemDiskTotal.WithLabelValues(dataPath).Set(diskTotal)
}

// ExportPrometheus returns the configured registry in Prometheus text format.
func ExportPrometheus() (string, error) {
	m := currentPrometheusSet()
	prometheusMetrics.RLock()
	cfg := prometheusMetrics.cfg
	prometheusMetrics.RUnlock()
	m.appUptime.Set(time.Since(m.started).Seconds())
	if cfg.IncludeRuntime {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		m.runtimeGoroutines.Set(float64(runtime.NumGoroutine()))
		m.runtimeAlloc.Set(float64(mem.Alloc))
		m.runtimeSys.Set(float64(mem.Sys))
	}
	families, err := m.registry.Gather()
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	enc := expfmt.NewEncoder(&b, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, family := range families {
		name := family.GetName()
		if !cfg.IncludeSystem && strings.HasPrefix(name, "casspeed_system_") {
			continue
		}
		if !cfg.IncludeRuntime && strings.HasPrefix(name, "casspeed_go_") {
			continue
		}
		if err := enc.Encode(family); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// PrometheusHandler exposes the registry using the official client handler.
func PrometheusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ExportPrometheus()
		if err != nil {
			http.Error(w, fmt.Sprintf("metrics collection failed: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", string(expfmt.NewFormat(expfmt.TypeTextPlain)))
		_, _ = io.WriteString(w, body)
	})
}
