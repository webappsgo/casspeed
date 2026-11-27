package server

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/config"
)

func TestMetricsServiceTokensAreIndependentAndHeaderOnly(t *testing.T) {
	cfg := config.Default()
	tokens := map[string]string{
		"prometheus": "mtr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"grafana":    "mtr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"loki":       "mtr_cccccccccccccccccccccccccccccccc",
	}
	s := &Server{Config: cfg, metricsTokenHashes: make(map[string][32]byte), metricsLogDir: t.TempDir()}
	for name, token := range tokens {
		s.metricsTokenHashes[name] = sha256.Sum256([]byte(token))
	}
	for serviceName, token := range tokens {
		t.Run(serviceName, func(t *testing.T) {
			wrongToken := tokens["prometheus"]
			if serviceName == "prometheus" {
				wrongToken = tokens["grafana"]
			}
			wrong := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/server/metrics/"+serviceName, nil)
			request.Header.Set("Authorization", "Bearer "+wrongToken)
			s.serveMetricsService(wrong, request, serviceName)
			if wrong.Code != http.StatusUnauthorized {
				t.Fatalf("other service token status = %d, want 401", wrong.Code)
			}
			queryToken := httptest.NewRecorder()
			request = httptest.NewRequest(http.MethodGet, "/server/metrics/"+serviceName+"?token="+token, nil)
			s.serveMetricsService(queryToken, request, serviceName)
			if queryToken.Code != http.StatusUnauthorized {
				t.Fatalf("query-string token status = %d, want 401", queryToken.Code)
			}
			accepted := httptest.NewRecorder()
			request = httptest.NewRequest(http.MethodGet, "/server/metrics/"+serviceName, nil)
			request.Header.Set("Authorization", "Bearer "+token)
			s.serveMetricsService(accepted, request, serviceName)
			if accepted.Code != http.StatusOK {
				t.Fatalf("correct service token status = %d body=%s", accepted.Code, accepted.Body.String())
			}
		})
	}
}

func TestMetricsServicesReturnPrometheusAndGrafanaDocuments(t *testing.T) {
	s := &Server{Config: config.Default(), metricsTokenHashes: map[string][32]byte{}, metricsLogDir: t.TempDir()}
	s.Config.Server.Metrics.Auth.AllowUnauthenticated = true
	response := httptest.NewRecorder()
	s.serveMetricsService(response, httptest.NewRequest(http.MethodGet, "/server/metrics", nil), "prometheus")
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "text/plain; version=0.0.4") || !strings.Contains(response.Body.String(), "# TYPE casspeed_http_requests_total") {
		t.Fatalf("Prometheus response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	response = httptest.NewRecorder()
	s.serveMetricsService(response, httptest.NewRequest(http.MethodGet, "/server/metrics/grafana", nil), "grafana")
	var dashboard map[string]any
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &dashboard) != nil {
		t.Fatalf("Grafana response is not JSON: %d %s", response.Code, response.Body.String())
	}
	if dashboard["title"] != "CasSpeed metrics" || dashboard["schemaVersion"] == nil || len(dashboard["panels"].([]any)) < 6 {
		t.Fatalf("Grafana dashboard is incomplete: %#v", dashboard)
	}
}

func TestSwaggerSpecUsesConfiguredAPIVersion(t *testing.T) {
	cfg := config.Default()
	cfg.Server.APIVersion = "v2"
	s := &Server{Config: cfg}
	response := httptest.NewRecorder()
	s.handleSwaggerSpec(response, httptest.NewRequest(http.MethodGet, "/api/swagger", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"url":"http://example.com/api/v2"`) {
		t.Fatalf("Swagger server URL did not use configured API version: %d %s", response.Code, response.Body.String())
	}
}

func TestLokiMetricsAreBoundedAndRedactCredentials(t *testing.T) {
	logDir := t.TempDir()
	logPath := filepath.Join(logDir, "server.log")
	contents := strings.Join([]string{
		"[SERVER] " + time.Now().Add(-2*time.Hour).Format("2006/01/02 15:04:05") + " old record",
		"[SERVER] " + time.Now().Format("2006/01/02 15:04:05") + " Authorization: Bearer mtr_dddddddddddddddddddddddddddddddd",
		"[SERVER] " + time.Now().Format("2006/01/02 15:04:05") + ` {"password":"unsafe"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{Config: config.Default(), metricsLogDir: logDir}
	s.Config.Server.Metrics.Loki.MaxEntries = 1
	s.Config.Server.Metrics.Loki.MaxAge = "1h"
	payload := s.lokiLogs(time.Now().UTC())
	if len(payload.Streams) != 1 || len(payload.Streams[0].Values) != 1 {
		t.Fatalf("Loki payload is not bounded: %#v", payload)
	}
	line := payload.Streams[0].Values[0][1]
	if strings.Contains(line, "mtr_dddddddddddddddddddddddddddddddd") || strings.Contains(line, "unsafe") || !strings.Contains(line, "[REDACTED]") {
		t.Fatalf("Loki response leaked a credential: %s", line)
	}
}

func TestLoadOrCreateSecretsGeneratesAndPersistsMetricsTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.yml")
	first, err := config.LoadOrCreateSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, serviceName := range []string{"prometheus", "grafana", "loki"} {
		token := first.MetricsTokens[serviceName]
		if len(token) != 36 || !strings.HasPrefix(token, "mtr_") {
			t.Errorf("%s token = %q; expected mtr_ plus 32 characters", serviceName, token)
		}
	}
	second, err := config.LoadOrCreateSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	for serviceName, token := range first.MetricsTokens {
		if second.MetricsTokens[serviceName] != token {
			t.Errorf("%s token changed across reload", serviceName)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("secrets file mode = %o, want 600", info.Mode().Perm())
	}
}
