package swagger

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- GetThemeCSS tests ---------------------------------------------------

func TestGetThemeCSS_Light(t *testing.T) {
	css := GetThemeCSS("light")
	if !strings.Contains(css, "#ffffff") {
		t.Error("light CSS should contain white background")
	}
}

func TestGetThemeCSS_Dark(t *testing.T) {
	css := GetThemeCSS("dark")
	if !strings.Contains(css, "#1a1a1a") {
		t.Error("dark CSS should contain dark background")
	}
}

func TestGetThemeCSS_Auto(t *testing.T) {
	css := GetThemeCSS("auto")
	if !strings.Contains(css, "prefers-color-scheme") {
		t.Error("auto CSS should contain media queries")
	}
}

func TestGetThemeCSS_Unknown(t *testing.T) {
	css := GetThemeCSS("unknown")
	if css != "" {
		t.Errorf("unknown theme should return empty string, got %q", css)
	}
}

// ---- Handler tests -------------------------------------------------------

func TestHandler_ReturnsHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Handler status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "swagger-ui") {
		t.Error("response body should contain swagger-ui")
	}
}

func TestHandler_ThemeFromQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/docs?theme=light", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "#ffffff") {
		t.Error("light theme CSS should be included in response")
	}
}

// ---- SpecHandler tests ---------------------------------------------------

func TestSpecHandler_ReturnsJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rr := httptest.NewRecorder()
	SpecHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("SpecHandler status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "openapi") {
		t.Error("spec should contain 'openapi' field")
	}
}
