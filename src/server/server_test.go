package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/mode"
)

// minimalServer builds a Server with just enough state for handler tests.
func minimalServer() *Server {
	cfg := config.Default()
	return &Server{
		Config:      cfg,
		Mode:        &mode.State{Mode: mode.Production},
		ipTestCount: make(map[string]*ipRateLimit),
		startTime:   time.Now(),
	}
}

func TestHandleIndex(t *testing.T) {
	s := minimalServer()
	rec := httptest.NewRecorder()
	s.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("handleIndex status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want HTML", got)
	}
	if rec.Body.Len() == 0 {
		t.Error("embedded index response should not be empty")
	}
}

func TestHandleHealthNegotiatesRepresentation(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		accept      string
		contentType string
		contains    string
	}{
		{name: "JSON path suffix", path: "/healthz.json", contentType: "application/json", contains: `"status": "healthy"`},
		{name: "text path suffix", path: "/healthz.txt", contentType: "text/plain; charset=utf-8", contains: "status: healthy"},
		{name: "JSON API default", path: "/api/v1/server/healthz", contentType: "application/json", contains: `"status": "healthy"`},
		{name: "text accept", path: "/server/healthz", accept: "text/plain", contentType: "text/plain; charset=utf-8", contains: "database: ok"},
		{name: "browser default", path: "/server/healthz", accept: "text/html", contentType: "text/html; charset=utf-8", contains: "Health Status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := minimalServer()
			s.version = "1.2.3"
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Header.Set("Accept", tt.accept)
			rec := httptest.NewRecorder()
			s.handleHealth(rec, req)

			if got := rec.Header().Get("Content-Type"); got != tt.contentType {
				t.Errorf("Content-Type = %q, want %q", got, tt.contentType)
			}
			if !strings.Contains(rec.Body.String(), tt.contains) {
				t.Errorf("response body does not contain %q", tt.contains)
			}
			if tt.contentType == "application/json" {
				var body healthResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("decode health response: %v", err)
				}
				if body.Status != "healthy" || body.Version != "1.2.3" {
					t.Errorf("health response = status %q, version %q", body.Status, body.Version)
				}
			}
		})
	}
}

func TestHandleAPIRootResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	minimalServer().handleAPIRoot(rec, httptest.NewRequest(http.MethodGet, "/api/v1", nil))

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode API root response: %v", err)
	}
	if body["version"] != "v1" || body["status"] != "ok" {
		t.Errorf("API root response = %#v", body)
	}
}

func TestRateLimitMiddlewareRejectsConcurrentTest(t *testing.T) {
	s := minimalServer()
	s.Config.Test.MaxConcurrent = 1
	entered := make(chan struct{})
	release := make(chan struct{})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})
	wrapped := s.rateLimitMiddleware(next)

	firstRec := httptest.NewRecorder()
	firstReq := httptest.NewRequest(http.MethodGet, "/api/v1/speedtest/start", nil)
	firstDone := make(chan struct{})
	go func() {
		wrapped.ServeHTTP(firstRec, firstReq)
		close(firstDone)
	}()
	<-entered

	secondRec := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodGet, "/api/v1/speedtest/start", nil)
	wrapped.ServeHTTP(secondRec, secondReq)
	if secondRec.Code != http.StatusTooManyRequests {
		t.Errorf("second request status = %d, want 429", secondRec.Code)
	}
	if secondRec.Header().Get("Retry-After") != "60" {
		t.Errorf("Retry-After = %q, want 60", secondRec.Header().Get("Retry-After"))
	}

	close(release)
	<-firstDone
	if firstRec.Code != http.StatusNoContent {
		t.Errorf("first request status = %d, want 204", firstRec.Code)
	}
}

func TestRateLimitMiddlewareMinIntervalAndPassThrough(t *testing.T) {
	s := minimalServer()
	s.Config.Test.MaxConcurrent = 1
	s.Config.Test.MinInterval = 60
	called := 0
	wrapped := s.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRecorder()
	wrapped.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/v1/speedtest/start", nil))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first target request status = %d, want 204", first.Code)
	}
	second := httptest.NewRecorder()
	wrapped.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/api/v1/speedtest/start", nil))
	if second.Code != http.StatusTooManyRequests || !strings.Contains(second.Body.String(), "Test interval too short") {
		t.Errorf("second target response = %d %q, want interval rejection", second.Code, second.Body.String())
	}
	if second.Header().Get("Retry-After") == "" {
		t.Error("interval rejection should include Retry-After")
	}

	other := httptest.NewRecorder()
	wrapped.ServeHTTP(other, httptest.NewRequest(http.MethodGet, "/api/v1/server/healthz", nil))
	if other.Code != http.StatusNoContent || called != 2 {
		t.Errorf("non-target pass-through status=%d, next calls=%d; want 204 and 2", other.Code, called)
	}
}

func TestSecurityHeaders(t *testing.T) {
	for _, tt := range []struct {
		name      string
		ssl       bool
		wantHSTS  bool
	}{
		{name: "HTTP", ssl: false, wantHSTS: false},
		{name: "HTTPS", ssl: true, wantHSTS: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			rec := httptest.NewRecorder()
			securityHeaders(tt.ssl)(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			for header, want := range map[string]string{
				"X-Content-Type-Options": "nosniff",
				"X-Frame-Options":        "SAMEORIGIN",
				"Referrer-Policy":        "strict-origin-when-cross-origin",
			} {
				if got := rec.Header().Get(header); got != want {
					t.Errorf("%s = %q, want %q", header, got, want)
				}
			}
			if got := rec.Header().Get("Strict-Transport-Security"); (got != "") != tt.wantHSTS {
				t.Errorf("HSTS = %q, want present %t", got, tt.wantHSTS)
			}
		})
	}
}

// ---- formatUptime tests --------------------------------------------------

func TestFormatUptime(t *testing.T) {
	cases := []struct {
		input time.Duration
		want  string
	}{
		{30 * time.Minute, "30m"},
		{90 * time.Minute, "1h 30m"},
		{25 * time.Hour, "1d 1h 0m"},
		{48*time.Hour + 30*time.Minute, "2d 0h 30m"},
		{0, "0m"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			got := formatUptime(tc.input)
			if got != tc.want {
				t.Errorf("formatUptime(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---- padAddr tests -------------------------------------------------------

func TestPadAddr(t *testing.T) {
	got := padAddr("127.0.0.1:8080")
	if got == "" {
		t.Error("padAddr should not return empty string")
	}
}

// ---- padTime tests -------------------------------------------------------

func TestPadTime(t *testing.T) {
	got := padTime()
	if got == "" {
		t.Error("padTime should not return empty string")
	}
}

// ---- handleRobotsTxt tests -----------------------------------------------

func TestHandleRobotsTxt(t *testing.T) {
	s := minimalServer()
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rr := httptest.NewRecorder()
	s.handleRobotsTxt(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleRobotsTxt status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "User-agent: *") {
		t.Error("robots.txt should contain User-agent: *")
	}
	// Admin path should be disallowed.
	if !strings.Contains(body, "admin") {
		t.Error("robots.txt should disallow admin path")
	}
}

func TestHandleRobotsTxt_CustomAdminPath(t *testing.T) {
	s := minimalServer()
	s.Config.Server.AdminPath = "manage"

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rr := httptest.NewRecorder()
	s.handleRobotsTxt(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "manage") {
		t.Error("robots.txt should contain custom admin path 'manage'")
	}
}

// ---- handleSecurityTxt tests ---------------------------------------------

func TestHandleSecurityTxt(t *testing.T) {
	s := minimalServer()
	s.Config.Server.FQDN = "speedtest.example.com"

	req := httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil)
	rr := httptest.NewRecorder()
	s.handleSecurityTxt(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleSecurityTxt status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Contact:") {
		t.Error("security.txt should contain Contact field")
	}
	if !strings.Contains(body, "speedtest.example.com") {
		t.Error("security.txt should contain FQDN")
	}
}

// ---- handleChangePassword tests ------------------------------------------

func TestHandleChangePassword(t *testing.T) {
	s := minimalServer()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/change-password", nil)
	rr := httptest.NewRecorder()
	s.handleChangePassword(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("handleChangePassword status = %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "reset") {
		t.Errorf("Location = %q, expected redirect to password reset", loc)
	}
}

// ---- handleAPIRoot tests ------------------------------------------------

func TestHandleAPIRoot(t *testing.T) {
	s := minimalServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1", nil)
	rr := httptest.NewRecorder()
	s.handleAPIRoot(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleAPIRoot status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "v1") {
		t.Error("API root response should contain version info")
	}
}

// ---- handleMetrics tests ------------------------------------------------

func TestHandleMetrics(t *testing.T) {
	s := minimalServer()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleMetrics status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}
