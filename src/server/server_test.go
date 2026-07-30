package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/config"
)

// minimalServer builds a Server with just enough state for handler tests.
func minimalServer() *Server {
	cfg := config.Default()
	return &Server{
		Config:      cfg,
		ipTestCount: make(map[string]*ipRateLimit),
		startTime:   time.Now(),
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
