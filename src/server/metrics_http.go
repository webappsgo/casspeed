package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/metrics"
)

var (
	metricCredentialPattern = regexp.MustCompile(`(?i)\b(adm_|usr_|org_|mtr_)[A-Za-z0-9]{32}\b`)
	metricBearerPattern     = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*`)
	metricSecretField       = regexp.MustCompile(`(?i)("(?:token|password|secret|api[_-]?key|encryption[_-]?key)"\s*:\s*")[^"]*(")`)
	metricSecretAssignment  = regexp.MustCompile(`(?i)(\b(?:token|password|passwd|secret|api[_-]?key|encryption[_-]?key)\s*[:=]\s*)[^\s,;]+`)
	metricCredentialURL     = regexp.MustCompile(`([a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@/\s]+(@)`)
	metricLogTimestamp      = regexp.MustCompile(`^\[[^]]+\]\s+(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})`)
)

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

type lokiPushPayload struct {
	Streams []lokiStream `json:"streams"`
}

type metricsDashboard struct {
	Annotations   map[string]any `json:"annotations"`
	Editable      bool           `json:"editable"`
	Panels        []any          `json:"panels"`
	SchemaVersion int            `json:"schemaVersion"`
	Templating    map[string]any `json:"templating"`
	Title         string         `json:"title"`
	Timezone      string         `json:"timezone"`
	Version       int            `json:"version"`
}

func (s *Server) serveMetricsService(w http.ResponseWriter, r *http.Request, serviceName string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if serviceName != "prometheus" && serviceName != "grafana" && serviceName != "loki" {
		http.NotFound(w, r)
		return
	}
	if !s.Config.Server.Metrics.Auth.AllowUnauthenticated && !s.validMetricsBearer(serviceName, r.Header.Get("Authorization")) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="casspeed metrics"`)
		http.Error(w, "Metrics authentication required", http.StatusUnauthorized)
		return
	}
	switch serviceName {
	case "prometheus":
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(s.prometheusMetrics(r.Context())))
	case "grafana":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(s.grafanaDashboard())
	case "loki":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(s.lokiLogs(time.Now().UTC()))
	}
}

func (s *Server) validMetricsBearer(serviceName, authorization string) bool {
	if !strings.HasPrefix(authorization, "Bearer ") {
		return false
	}
	value := strings.TrimPrefix(authorization, "Bearer ")
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	expected, ok := s.metricsTokenHashes[serviceName]
	if !ok {
		return false
	}
	actual := sha256.Sum256([]byte(value))
	return subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
}

func (s *Server) prometheusMetrics(ctx context.Context) string {
	var output strings.Builder
	metrics.CollectSystemMetrics(s.DataDir)
	if database, ok := s.Store.(dbStatter); ok {
		stats := database.DBStats()
		metrics.SetDatabaseConnections(float64(stats.OpenConnections), float64(stats.InUse))
	}
	if s.Store != nil {
		countCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		userCount, userErr := s.Store.CountUsers(countCtx)
		testCount, testErr := s.Store.CountSpeedTests(countCtx)
		cancel()
		if userErr == nil {
			metrics.SetBusinessMetrics(float64(userCount), 0, 0, 0)
		}
		if testErr == nil {
			fmt.Fprintf(&output, "# TYPE casspeed_business_speed_tests_total gauge\ncasspeed_business_speed_tests_total %d\n", testCount)
		}
	}
	s.cacheHealthMu.Lock()
	cacheStatus := s.cacheHealthStatus
	s.cacheHealthMu.Unlock()
	cacheAvailable := 1
	if cacheStatus == "degraded" {
		cacheAvailable = 0
	}
	fmt.Fprintf(&output, "# TYPE casspeed_cache_available gauge\ncasspeed_cache_available %d\n", cacheAvailable)
	if s.Scheduler != nil {
		status := s.Scheduler.GetStatus()
		tasks, _ := status["tasks"].([]map[string]any)
		var taskCount, failures int
		for _, task := range tasks {
			if enabled, _ := task["enabled"].(bool); enabled {
				taskCount++
			}
			if count, ok := task["fail_count"].(int); ok {
				failures += count
			}
		}
		fmt.Fprintf(&output, "# TYPE casspeed_scheduler_tasks_enabled gauge\ncasspeed_scheduler_tasks_enabled %d\n# TYPE casspeed_scheduler_task_failures_total counter\ncasspeed_scheduler_task_failures_total %d\n", taskCount, failures)
	}
	if text, err := metrics.ExportPrometheus(); err == nil {
		output.WriteString(text)
	}
	return output.String()
}

func (s *Server) grafanaDashboard() metricsDashboard {
	promQL := []struct {
		title string
		expr  string
	}{
		{"HTTP requests", "sum by (method, status) (rate(casspeed_http_requests_total[5m]))"},
		{"HTTP latency p95", "histogram_quantile(0.95, sum by (le, method, path) (rate(casspeed_http_request_duration_seconds_bucket[5m])))"},
		{"HTTP body sizes", "sum by (le) (rate(casspeed_http_request_size_bytes_bucket[5m]))"},
		{"Database queries", "sum by (operation) (rate(casspeed_db_queries_total[5m]))"},
		{"Database connections", "casspeed_db_connections_open"},
		{"Database errors", "sum by (error_type) (rate(casspeed_db_errors_total[5m]))"},
		{"Cache hits and misses", "sum by (cache) (rate(casspeed_cache_hits_total[5m])) + sum by (cache) (rate(casspeed_cache_misses_total[5m]))"},
		{"Scheduler task executions", "sum by (task, status) (rate(casspeed_scheduler_tasks_total[5m]))"},
		{"Scheduler duration p95", "histogram_quantile(0.95, sum by (le, task) (rate(casspeed_scheduler_task_duration_seconds_bucket[5m])))"},
		{"System CPU", "casspeed_system_cpu_usage_percent"},
		{"System memory", "casspeed_system_memory_usage_percent"},
		{"System disk", "casspeed_system_disk_usage_percent"},
		{"Go runtime goroutines", "casspeed_go_goroutines"},
		{"Go runtime heap", "casspeed_go_mem_alloc_bytes"},
		{"Authentication attempts", "sum by (method, status) (rate(casspeed_auth_attempts_total[5m]))"},
		{"Business users", "casspeed_users_total"},
		{"Speed tests", "rate(casspeed_speedtest_tests_total[5m])"},
		{"Speed test throughput", "histogram_quantile(0.95, sum by (le) (rate(casspeed_speedtest_download_mbps_bucket[5m])))"},
		{"Cache availability", "casspeed_cache_available"},
	}
	panels := make([]any, 0, len(promQL))
	for index, query := range promQL {
		panels = append(panels, map[string]any{
			"datasource":  map[string]string{"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
			"fieldConfig": map[string]any{"defaults": map[string]any{}, "overrides": []any{}},
			"gridPos":     map[string]int{"h": 8, "w": 12, "x": (index % 2) * 12, "y": (index / 2) * 8},
			"id":          index + 1,
			"targets":     []any{map[string]any{"expr": query.expr, "refId": "A"}},
			"title":       query.title,
			"type":        "timeseries",
		})
	}
	return metricsDashboard{
		Annotations:   map[string]any{"list": []any{}},
		Editable:      true,
		Panels:        panels,
		SchemaVersion: 41,
		Templating: map[string]any{"list": []any{map[string]any{
			"current": map[string]any{"selected": false, "text": "Prometheus", "value": "prometheus"},
			"name":    "DS_PROMETHEUS", "query": "prometheus", "type": "datasource",
		}}},
		Title:    "CasSpeed metrics",
		Timezone: "browser",
		Version:  1,
	}
}

func (s *Server) lokiLogs(now time.Time) lokiPushPayload {
	limit := s.Config.Server.Metrics.Loki.MaxEntries
	if limit <= 0 {
		limit = 1000
	}
	if limit > 10000 {
		limit = 10000
	}
	maxAge, err := time.ParseDuration(s.Config.Server.Metrics.Loki.MaxAge)
	if err != nil || maxAge <= 0 {
		maxAge = time.Hour
	}
	files := []string{"access.log", "server.log", "error.log", "security.log", "audit.log"}
	entries := make([]lokiLogEntry, 0, limit)
	for _, file := range files {
		entries = append(entries, readRecentMetricLogs(filepath.Join(s.metricsLogDir, file), file, now.Add(-maxAge), limit-len(entries))...)
		if len(entries) >= limit {
			break
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].timestamp.Before(entries[j].timestamp) })
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	streamsBySource := make(map[string]*lokiStream)
	for _, entry := range entries {
		stream := streamsBySource[entry.source]
		if stream == nil {
			stream = &lokiStream{Stream: map[string]string{"job": "casspeed", "source": entry.source}, Values: make([][2]string, 0)}
			streamsBySource[entry.source] = stream
		}
		stream.Values = append(stream.Values, [2]string{fmt.Sprintf("%d", entry.timestamp.UnixNano()), entry.line})
	}
	sources := make([]string, 0, len(streamsBySource))
	for source := range streamsBySource {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	streams := make([]lokiStream, 0, len(sources))
	for _, source := range sources {
		streams = append(streams, *streamsBySource[source])
	}
	return lokiPushPayload{Streams: streams}
}

type lokiLogEntry struct {
	timestamp time.Time
	source    string
	line      string
}

func readRecentMetricLogs(path, source string, cutoff time.Time, remaining int) []lokiLogEntry {
	if remaining <= 0 {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil
	}
	const maximumReadBytes int64 = 4 << 20
	start := info.Size() - maximumReadBytes
	if start < 0 {
		start = 0
	}
	reader := bufio.NewReader(file)
	if start > 0 {
		if _, err := file.Seek(start, 0); err != nil {
			return nil
		}
		reader = bufio.NewReader(file)
		_, _ = reader.ReadString('\n')
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	entries := make([]lokiLogEntry, 0, remaining)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		timestamp := info.ModTime().UTC()
		if match := metricLogTimestamp.FindStringSubmatch(line); len(match) == 2 {
			if parsed, parseErr := time.ParseInLocation("2006/01/02 15:04:05", match[1], time.Local); parseErr == nil {
				timestamp = parsed.UTC()
			}
		}
		if timestamp.Before(cutoff) {
			continue
		}
		line = redactMetricLogLine(line)
		entries = append(entries, lokiLogEntry{timestamp: timestamp, source: strings.TrimSuffix(source, ".log"), line: line})
	}
	if len(entries) > remaining {
		entries = entries[len(entries)-remaining:]
	}
	return entries
}

func redactMetricLogLine(line string) string {
	line = metricBearerPattern.ReplaceAllString(line, `${1}[REDACTED]`)
	line = metricCredentialPattern.ReplaceAllString(line, "[REDACTED]")
	line = metricSecretField.ReplaceAllString(line, `${1}[REDACTED]${2}`)
	line = metricSecretAssignment.ReplaceAllString(line, `${1}[REDACTED]`)
	return metricCredentialURL.ReplaceAllString(line, `${1}[REDACTED]${2}`)
}
