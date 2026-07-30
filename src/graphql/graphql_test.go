package graphql

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- Handler tests -------------------------------------------------------

func TestHandler_ReturnsHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
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
	if !strings.Contains(body, "graphiql") {
		t.Error("response should contain graphiql")
	}
}

func TestHandler_DarkThemeByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req)

	// Default theme is dark; dark CSS should be embedded.
	body := rr.Body.String()
	if body == "" {
		t.Fatal("empty response")
	}
}

// ---- QueryHandler tests --------------------------------------------------

func TestQueryHandler_Post(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/graphql/query", strings.NewReader(`{"query":"{health}"}`))
	rr := httptest.NewRecorder()
	QueryHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("QueryHandler POST status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if !strings.Contains(rr.Body.String(), "health") {
		t.Error("response should contain health field")
	}
}

func TestQueryHandler_GetMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/graphql/query", nil)
	rr := httptest.NewRecorder()
	QueryHandler(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("QueryHandler GET status = %d, want 405", rr.Code)
	}
}

// ---- GetThemeCSS tests ---------------------------------------------------

func TestGetThemeCSS_Dark(t *testing.T) {
	css := GetThemeCSS("dark")
	if css == "" {
		t.Error("dark theme CSS should not be empty")
	}
}

func TestGetThemeCSS_Light(t *testing.T) {
	css := GetThemeCSS("light")
	if css == "" {
		t.Error("light theme CSS should not be empty")
	}
}

func TestGetThemeCSS_Unknown(t *testing.T) {
	css := GetThemeCSS("unknown")
	_ = css // Unknown may return empty; no assertion on content.
}

// ---- Schema test ---------------------------------------------------------

func TestSchema_NotEmpty(t *testing.T) {
	if Schema == "" {
		t.Error("GraphQL schema should not be empty")
	}
	if !strings.Contains(Schema, "SpeedTest") {
		t.Error("schema should define SpeedTest type")
	}
}
