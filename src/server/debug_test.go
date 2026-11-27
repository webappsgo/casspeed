package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/mode"
	"github.com/go-chi/chi/v5"
)

func TestDebugHandlersReturnSanitizedDiagnostics(t *testing.T) {
	s := minimalServer()
	s.Mode = &mode.State{Mode: mode.Production, Debug: true}
	s.Router = chi.NewRouter()
	s.Router.Get("/health", s.handleHealth)

	tests := []struct {
		name        string
		handler     http.HandlerFunc
		status      int
		contentType string
		contains    string
	}{
		{"config", s.handleDebugConfig, http.StatusOK, "application/json", `"debug": true`},
		{"routes", s.handleDebugRoutes, http.StatusOK, "application/json", `"route": "/health"`},
		{"memory", s.handleDebugMemory, http.StatusOK, "application/json", `"goroutines"`},
		{"goroutines", s.handleDebugGoroutines, http.StatusOK, "text/plain; charset=utf-8", "goroutine"},
		{"cache", s.handleDebugCache, http.StatusOK, "application/json", `"enabled": false`},
		{"database", s.handleDebugDB, http.StatusOK, "application/json", "store does not expose db stats"},
		{"scheduler", s.handleDebugScheduler, http.StatusServiceUnavailable, "application/json", "Scheduler is unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			test.handler(recorder, httptest.NewRequest(http.MethodGet, "/debug/"+test.name, nil))
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, test.status, recorder.Body.String())
			}
			if got := recorder.Header().Get("Content-Type"); got != test.contentType {
				t.Errorf("Content-Type = %q, want %q", got, test.contentType)
			}
			if !strings.Contains(recorder.Body.String(), test.contains) {
				t.Errorf("response does not contain %q: %s", test.contains, recorder.Body.String())
			}
			if strings.HasSuffix(test.contentType, "json") && !json.Valid(recorder.Body.Bytes()) {
				t.Errorf("response is not valid JSON: %s", recorder.Body.String())
			}
		})
	}
}

func TestDebugRouteRegistrationRequiresDebugMode(t *testing.T) {
	for _, debug := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[debug], func(t *testing.T) {
			cfg := minimalServer()
			cfg.Mode = &mode.State{Mode: mode.Production, Debug: debug}
			router := chi.NewRouter()
			cfg.registerDebugRoutes(router)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/debug/config", nil))
			want := http.StatusNotFound
			if debug {
				want = http.StatusUnauthorized
			}
			if response.Code != want {
				t.Fatalf("debug=%t status = %d, want %d", debug, response.Code, want)
			}
		})
	}
}
