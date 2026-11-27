package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/config"
)

func TestValidCORSOriginRejectsNonOrigins(t *testing.T) {
	for _, test := range []struct {
		origin string
		valid  bool
	}{
		{"https://example.test", true},
		{"http://localhost:3000", true},
		{"//example.test", false},
		{"https://user@example.test", false},
		{"https://example.test/path", false},
		{"https://example.test?query=1", false},
		{"https://example.test#fragment", false},
		{"ftp://example.test", false},
		{"", false},
	} {
		t.Run(test.origin, func(t *testing.T) {
			if got := validCORSOrigin(test.origin); got != test.valid {
				t.Errorf("validCORSOrigin(%q) = %t, want %t", test.origin, got, test.valid)
			}
		})
	}
}

func TestCORSPreflightUsesConfiguredOriginPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.Web.CORS = "https://allowed.example.test"
	s := &Server{Config: cfg}
	handler := s.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, test := range []struct {
		origin string
		status int
		allow  string
	}{
		{"https://allowed.example.test", http.StatusNoContent, "https://allowed.example.test"},
		{"https://blocked.example.test", http.StatusForbidden, ""},
	} {
		t.Run(test.origin, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodOptions, "/api/v1/users", nil)
			request.Header.Set("Origin", test.origin)
			request.Header.Set("Access-Control-Request-Method", http.MethodPost)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || response.Header().Get("Access-Control-Allow-Origin") != test.allow {
				t.Fatalf("preflight response = %d allow-origin=%q body=%s", response.Code, response.Header().Get("Access-Control-Allow-Origin"), response.Body.String())
			}
			if test.allow != "" && (response.Header().Get("Access-Control-Allow-Credentials") != "true" || !strings.Contains(response.Header().Get("Vary"), "Origin")) {
				t.Errorf("explicit origin response omitted credential or Vary headers: %v", response.Header())
			}
		})
	}
}

func TestWriteRateLimitedSetsRetryAndJSON(t *testing.T) {
	response := httptest.NewRecorder()
	writeRateLimited(response, 0)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("rate limit response = %d Retry-After=%q", response.Code, response.Header().Get("Retry-After"))
	}
	if response.Header().Get("Content-Type") != "application/json; charset=utf-8" || !strings.Contains(response.Body.String(), `"RATE_LIMITED"`) {
		t.Fatalf("unexpected rate limit response headers/body: %v %s", response.Header(), response.Body.String())
	}
}
