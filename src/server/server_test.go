package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/mode"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
)

func TestConfiguredRateLimitUsesSlidingWindowFallback(t *testing.T) {
	cfg := config.Default()
	cfg.Server.RateLimit.Read = config.RateWindowLimit{Requests: 1, Window: 60}
	cfg.Server.RateLimit.GlobalBurst = 10
	s := &Server{Config: cfg}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	r.RemoteAddr = "192.0.2.50:1234"
	if allowed, _ := s.allowConfiguredRequest(r); !allowed {
		t.Fatal("first read request was unexpectedly limited")
	}
	if allowed, retry := s.allowConfiguredRequest(r); allowed || retry < 1 {
		t.Fatalf("second read request allowed=%t retry=%d", allowed, retry)
	}
}

func TestFailedAuthenticationLocksOutIPUntilSlidingWindowExpires(t *testing.T) {
	cfg := config.Default()
	cfg.Server.RateLimit.AuthFailures = config.RateWindowLimit{Requests: 1, Window: 900}
	s := &Server{Config: cfg}
	r := httptest.NewRequest(http.MethodPost, "/server/auth/login", nil)
	r.RemoteAddr = "192.0.2.51:1234"
	s.recordFailedAuthentication(r)
	if locked, retry := s.authFailureLockedOut(r); !locked || retry < 899 || retry > 900 {
		t.Fatalf("lockout = %t, retry=%d; want true, approximately 900", locked, retry)
	}
}

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
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request = request.WithContext(contextWithLanguage(request, "ar"))
	s.handleIndex(rec, request)

	if rec.Code != http.StatusOK {
		t.Fatalf("handleIndex status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want HTML", got)
	}
	if rec.Body.Len() == 0 {
		t.Error("embedded index response should not be empty")
	}
	if !strings.Contains(rec.Body.String(), `lang="ar" dir="rtl"`) || !strings.Contains(rec.Body.String(), "اختبر سرعتك") {
		t.Error("index response should render Arabic text with right-to-left document direction")
	}
	if !strings.Contains(rec.Body.String(), "/server/preferences#language") {
		t.Error("index response should link to language preferences")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("ETag"); got == "" {
		t.Error("index response should include a build-stamp ETag")
	}
}

func TestPublicPageHandlers(t *testing.T) {
	s := minimalServer()
	for _, name := range []string{"about", "privacy", "help", "help/mcp", "terms", "dpo", "security", "security/policy", "security/thanks"} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.handlePublicPage(rec, httptest.NewRequest(http.MethodGet, "/server/"+name, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("page status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q, want HTML", got)
			}
			for _, required := range []string{"<header class=\"site-header\">", "<main id=\"main-content\"", "<footer class=\"site-footer\">", "<h1 class=\"page-title\">"} {
				if !strings.Contains(rec.Body.String(), required) {
					t.Errorf("page does not contain required shell element %q", required)
				}
			}
			body := rec.Body.String()
			if strings.Count(body, "<main ") != 1 || strings.Count(body, "<h1 ") != 1 {
				t.Errorf("page shell has main=%d h1=%d", strings.Count(body, "<main "), strings.Count(body, "<h1 "))
			}
			if strings.Contains(body, " style=") || strings.Contains(body, "<style") || strings.Contains(body, "<script>") || strings.Contains(body, "onload=") {
				t.Errorf("page contains inline executable content")
			}
			if strings.Contains(body, `<section class="section-card" aria-label=`) {
				t.Errorf("page card is missing a heading relationship")
			}
			if cards, headings := strings.Count(body, `<section class="section-card"`), strings.Count(body, "<h2 "); cards != headings {
				t.Errorf("page has %d content cards and %d card headings", cards, headings)
			}
		})
	}
}

func TestPublicPagePrivacyUsesConfiguredRetention(t *testing.T) {
	s := minimalServer()
	s.Config.Server.Privacy.Retention.Period = "Test results are retained for 45 days."
	recorder := httptest.NewRecorder()
	s.handlePublicPage(recorder, httptest.NewRequest(http.MethodGet, "/server/privacy", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Test results are retained for 45 days.") {
		t.Fatalf("privacy page did not render configured retention: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestMCPRejectsInvalidOriginBeforeAuthentication(t *testing.T) {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Origin", "https://attacker.example")
	minimalServer().handleMCP(recorder, req)
	if recorder.Code != http.StatusForbidden || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("invalid origin response = %d %q %s", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
	}
}

func TestMCPRequiresBearerToken(t *testing.T) {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	minimalServer().handleMCP(recorder, req)
	if recorder.Code != http.StatusUnauthorized || recorder.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("missing token response = %d %q %s", recorder.Code, recorder.Header().Get("WWW-Authenticate"), recorder.Body.String())
	}
}

func TestAdminSetupTokenAuthenticatesAdminAPI(t *testing.T) {
	db, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	credential := "adm_" + strings.Repeat("A", 32)
	digest := sha256.Sum256([]byte(credential))
	account := &model.Admin{Username: "operator", Password: "not-used", Role: "primary", Enabled: true, APITokenHash: hex.EncodeToString(digest[:])}
	if err := db.CreateAdmin(t.Context(), account); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = db
	handler := s.apiTokenMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := r.Context().Value(apiTokenContextKey{}).(apiTokenIdentity)
		if !ok || !identity.Admin {
			t.Error("admin token identity was not added to request context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/server/administration/settings", nil)
	request.Header.Set("Authorization", "Bearer "+credential)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("admin API status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestDebugEndpointsRequireOperatorToken(t *testing.T) {
	s := minimalServer()
	token := "adm_" + strings.Repeat("B", 32)
	s.operatorTokenHash = sha256.Sum256([]byte(token))
	handler := s.requireOperatorDebug(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/debug/memory", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("missing debug token status = %d, want 401", unauthorized.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/debug/memory", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusNoContent {
		t.Fatalf("valid operator token status = %d, want 204", authorized.Code)
	}
}

func TestCORSMiddlewareHonorsOriginPolicyAndPreflight(t *testing.T) {
	t.Setenv("DOMAIN", "")
	s := minimalServer()
	endpoint := s.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	s.Config.Web.CORS = "https://client.example"
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/server/healthz", nil)
	req.Header.Set("Origin", "https://client.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	endpoint.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "https://client.example" || rec.Header().Get("Access-Control-Allow-Credentials") != "true" || rec.Header().Get("Access-Control-Max-Age") != "86400" {
		t.Fatalf("explicit-origin preflight = %d %#v", rec.Code, rec.Header())
	}
	req = httptest.NewRequest(http.MethodOptions, "/api/v1/server/healthz", nil)
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec = httptest.NewRecorder()
	endpoint.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unlisted-origin preflight = %d %#v", rec.Code, rec.Header())
	}
	s.Config.Web.CORS = "*"
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://any.example")
	rec = httptest.NewRecorder()
	endpoint.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" || rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("wildcard CORS must not allow credentials: %#v", rec.Header())
	}
}

func TestCORSOriginResolutionUsesDomainAndHonorsDisabledPolicy(t *testing.T) {
	s := minimalServer()
	s.Config.Web.CORS = "*"
	t.Setenv("DOMAIN", "api.example,web.example")
	if allowed, wildcard := s.corsOriginAllowed("https://api.example"); !allowed || wildcard {
		t.Fatalf("DOMAIN origin resolution = %t, wildcard=%t", allowed, wildcard)
	}
	if allowed, _ := s.corsOriginAllowed("https://attacker.example"); allowed {
		t.Fatal("unlisted origin was allowed when DOMAIN entries resolved")
	}
	s.Config.Web.CORS = ""
	if allowed, _ := s.corsOriginAllowed("https://api.example"); allowed {
		t.Fatal("empty CORS configuration must disable CORS even with DOMAIN set")
	}
}

func TestCORSAndCSPUseLearnedTrustedProxyOrigins(t *testing.T) {
	t.Setenv("DOMAIN", "")
	s := minimalServer()
	s.Config.Web.CORS = "*"
	s.learnedOrigins = map[string]struct{}{"https://learned.example": {}}
	if allowed, wildcard := s.corsOriginAllowed("https://learned.example"); !allowed || wildcard {
		t.Fatalf("learned origin resolution = %t, wildcard=%t", allowed, wildcard)
	}
	if allowed, _ := s.corsOriginAllowed("https://other.example"); allowed {
		t.Fatal("wildcard fallback should not override learned origins")
	}
	endpoint := securityHeaders(s)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	recorder := httptest.NewRecorder()
	endpoint.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://casspeed.example/", nil))
	policy := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "https://learned.example") || !strings.Contains(policy, "wss://learned.example") {
		t.Fatalf("CSP omitted trusted proxy origin: %q", policy)
	}
}

func TestTrustedProxyOriginsAreLearnedForCORSAndCSP(t *testing.T) {
	s := minimalServer()
	s.Config.Server.TrustedProxies.Additional = []string{"203.0.113.10"}
	request := httptest.NewRequest(http.MethodGet, "http://backend/", nil)
	request.RemoteAddr = "203.0.113.10:12345"
	request.Header.Set("X-Forwarded-Host", "speed.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	handler := trustedProxyMiddleware(s.Config.Server.TrustedProxies)(s.learnProxyOrigins(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if _, exists := s.learnedOrigins["https://speed.example"]; !exists {
		t.Fatalf("trusted proxy origin was not learned: %#v", s.learnedOrigins)
	}
}

func TestSecurityHeadersUseLocalScriptsAndSameOriginWebSockets(t *testing.T) {
	endpoint := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := securityHeaders()(endpoint)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	policy := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src 'self'") || strings.Contains(policy, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("script policy should allow only local scripts: %q", policy)
	}
	if !strings.Contains(policy, "ws://example.com") || !strings.Contains(policy, "wss://example.com") {
		t.Fatalf("websocket policy should be restricted to the request origin: %q", policy)
	}
	if strings.Contains(policy, "upgrade-insecure-requests") {
		t.Fatalf("plain HTTP must not upgrade insecure requests: %q", policy)
	}
}

func TestPublicPrivacyAPIIsStructured(t *testing.T) {
	rec := httptest.NewRecorder()
	minimalServer().handlePublicPageAPI(rec, httptest.NewRequest(http.MethodGet, "/api/v1/server/privacy", nil))
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want JSON", got)
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data, ok := response["data"].(map[string]any)
	if !ok || response["ok"] != true || data["summary"] == nil || data["cookies"] == nil || data["tracking"] == nil || data["retention"] == nil {
		t.Errorf("privacy response omitted structured policy fields: %#v", response)
	}
}

func TestPublicPageAPIContracts(t *testing.T) {
	tests := []struct {
		path string
		keys []string
	}{
		{path: "/api/v1/server/help", keys: []string{"title", "content", "format", "pages"}},
		{path: "/api/v1/server/help/mcp", keys: []string{"enabled", "url", "aliases", "auth", "tools", "project"}},
		{path: "/api/v1/server/dpo", keys: []string{"name", "email", "privacy_url"}},
		{path: "/api/v1/server/security/policy", keys: []string{"policy"}},
		{path: "/api/v1/server/security/thanks", keys: []string{"entries"}},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			minimalServer().handlePublicPageAPI(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
			var envelope map[string]interface{}
			if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode API envelope: %v", err)
			}
			data, ok := envelope["data"].(map[string]interface{})
			if !ok || envelope["ok"] != true {
				t.Fatalf("invalid API envelope: %#v", envelope)
			}
			for _, key := range test.keys {
				if _, exists := data[key]; !exists {
					t.Errorf("response data missing %q: %#v", key, data)
				}
			}
		})
	}
}

func TestMCPHelpDocumentsLiveToolsAndProjectRules(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/server/help/mcp", nil)
	content, project, tools, err := minimalServer().mcpHelp(req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "http://example.com/api/v1/server/mcp") || !strings.Contains(content, "MCP-Protocol-Version") || !strings.Contains(content, "startSpeedTest") {
		t.Fatalf("MCP help omitted live endpoint, protocol, or tools: %s", content)
	}
	if !strings.Contains(project, "explicit share link") || !strings.Contains(project, "remain private") || len(tools) == 0 {
		t.Fatalf("MCP project help or tools are incomplete: project=%q tools=%#v", project, tools)
	}
}

func TestPublicPageMarkdownIsRenderedSafely(t *testing.T) {
	page := publicPages["help"]
	rendered, err := renderMarkdown(page.Content)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, "<strong>Start speed test</strong>") || !strings.Contains(rendered, "<code>POST") {
		t.Fatalf("Markdown was not rendered: %s", rendered)
	}
	rendered, err = renderMarkdown("<script>alert(1)</script>")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered, "<script>") {
		t.Fatalf("raw HTML was not escaped: %s", rendered)
	}
	rendered, err = renderMarkdown("| Name | Value |\n|---|---|\n| Speed | 42 |\n\n[unsafe](javascript:alert(1))")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`class="table-wrapper"`, `class="data-table"`, `scope="col"`} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("sanitized table is missing %q: %s", expected, rendered)
		}
	}
	if strings.Contains(rendered, "javascript:") {
		t.Errorf("unsafe markdown link survived sanitization: %s", rendered)
	}
}

func TestAbsoluteRequestURLUsesRequestOrigin(t *testing.T) {
	t.Setenv("DOMAIN", "")
	request := httptest.NewRequest(http.MethodGet, "http://casspeed.example/server/about", nil)
	if got := absoluteRequestURL(request, "/server/privacy"); got != "http://casspeed.example/server/privacy" {
		t.Fatalf("absolute request URL = %q", got)
	}
}

func TestAbsoluteRequestURLTrustsProxyHeadersOnlyFromConfiguredPeers(t *testing.T) {
	t.Setenv("DOMAIN", "")
	request := httptest.NewRequest(http.MethodGet, "http://safe.example/path", nil)
	request.RemoteAddr = "203.0.113.10:12345"
	request.Header.Set("X-Forwarded-Host", "attacker.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	if got := absoluteRequestURL(request, "/target"); got != "http://safe.example/target" {
		t.Fatalf("untrusted proxy headers changed URL: %q", got)
	}

	request = httptest.NewRequest(http.MethodGet, "http://backend:64580/path", nil)
	request.RemoteAddr = "10.0.0.8:12345"
	request.Header.Set("X-Forwarded-Host", "speed.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Port", "8443")
	request.Header.Set("X-Forwarded-Prefix", "/speed")
	if got := absoluteRequestURL(request, "/target"); got != "https://speed.example:8443/speed/target" {
		t.Fatalf("trusted proxy URL resolution = %q", got)
	}

	request = httptest.NewRequest(http.MethodGet, "http://backend/path", nil)
	request.RemoteAddr = "198.51.100.8:12345"
	request.Header.Set("X-Forwarded-Host", "speed.example")
	resolved := ""
	proxy := trustedProxyMiddleware(config.TrustedProxyConfig{Additional: []string{"198.51.100.8"}})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resolved = absoluteRequestURL(r, "/target")
	}))
	proxy.ServeHTTP(httptest.NewRecorder(), request)
	if resolved != "http://speed.example/target" {
		t.Fatalf("configured proxy URL resolution = %q", resolved)
	}
}

func TestAbsoluteRequestURLRejectsHostHeaderOutsideDOMAIN(t *testing.T) {
	t.Setenv("DOMAIN", "service.example,www.service.example")
	request := httptest.NewRequest(http.MethodGet, "http://attacker.example/path", nil)
	if got := absoluteRequestURL(request, "/target"); got != "http://service.example/target" {
		t.Fatalf("host outside DOMAIN was copied into URL: %q", got)
	}
}

func TestTrustedProxyClientIPResolutionAndPinning(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://backend/", nil)
	request.RemoteAddr = "10.0.0.8:12345"
	request.Header.Set("X-Forwarded-For", "198.51.100.20, 10.0.0.7")
	var resolved string
	handler := trustedProxyMiddleware(config.TrustedProxyConfig{ClientIPHeader: "auto"})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resolved = r.RemoteAddr
	}))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if resolved != "198.51.100.20" {
		t.Fatalf("right-to-left client IP resolution = %q", resolved)
	}

	request = httptest.NewRequest(http.MethodGet, "http://backend/", nil)
	request.RemoteAddr = "10.0.0.8:12345"
	request.Header.Set("X-Forwarded-For", "198.51.100.20")
	request.Header.Set("CF-Connecting-IP", "203.0.113.42")
	resolved = ""
	handler = trustedProxyMiddleware(config.TrustedProxyConfig{ClientIPHeader: "CF-Connecting-IP"})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resolved = r.RemoteAddr
	}))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if resolved != "203.0.113.42" {
		t.Fatalf("pinned client IP resolution = %q", resolved)
	}

	request = httptest.NewRequest(http.MethodGet, "http://backend/", nil)
	request.RemoteAddr = "203.0.113.10:12345"
	request.Header.Set("X-Forwarded-For", "198.51.100.20")
	resolved = ""
	handler = trustedProxyMiddleware(config.TrustedProxyConfig{})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resolved = r.RemoteAddr
	}))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if resolved != "203.0.113.10:12345" {
		t.Fatalf("untrusted peer accepted forwarded client IP: %q", resolved)
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
		{name: "browser default", path: "/server/healthz", accept: "text/html", contentType: "text/html; charset=utf-8", contains: "Health status"},
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
	firstReq := httptest.NewRequest(http.MethodGet, "/api/v1/speed-tests/test-1/status", nil)
	firstDone := make(chan struct{})
	go func() {
		wrapped.ServeHTTP(firstRec, firstReq)
		close(firstDone)
	}()
	<-entered

	secondRec := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodGet, "/api/v1/speed-tests/test-2/status", nil)
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
	wrapped.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/api/v1/speed-tests", nil))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first target request status = %d, want 204", first.Code)
	}
	second := httptest.NewRecorder()
	wrapped.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/api/v1/speed-tests", nil))
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
		name     string
		url      string
		wantHSTS bool
	}{
		{name: "HTTP", url: "http://example.com/", wantHSTS: false},
		{name: "HTTPS", url: "https://example.com/", wantHSTS: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			rec := httptest.NewRecorder()
			securityHeaders()(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.url, nil))
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
	if !strings.Contains(body, "Sitemap: http://example.com/sitemap.xml") {
		t.Error("robots.txt should reference the request-derived sitemap URL")
	}
	// Admin path should be disallowed.
	if !strings.Contains(body, "admin") {
		t.Error("robots.txt should disallow admin path")
	}
}

func TestPublicSEOEndpoints(t *testing.T) {
	s := minimalServer()
	s.Config.Server.FQDN = "speedtest.example.com"
	request := httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil)
	request.Host = "speedtest.example.com"
	recorder := httptest.NewRecorder()
	s.handleSitemap(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "http://speedtest.example.com/server/docs/swagger") {
		t.Fatalf("sitemap response = %d %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "/api/") || strings.Contains(recorder.Body.String(), "/server/admin") {
		t.Fatal("sitemap contains a non-public route")
	}

	for _, test := range []struct {
		path        string
		handler     http.HandlerFunc
		contentType string
	}{
		{path: "/feed.xml", handler: s.handleAtomFeed, contentType: "application/atom+xml"},
		{path: "/rss.xml", handler: s.handleRSSFeed, contentType: "application/rss+xml"},
	} {
		feedRequest := httptest.NewRequest(http.MethodGet, test.path, nil)
		feedRequest.Host = "speedtest.example.com"
		feed := httptest.NewRecorder()
		test.handler(feed, feedRequest)
		if feed.Code != http.StatusOK || !strings.Contains(feed.Header().Get("Content-Type"), test.contentType) || feed.Header().Get("ETag") == "" || feed.Header().Get("Last-Modified") == "" {
			t.Fatalf("%s missing expected feed metadata: status=%d headers=%v", test.path, feed.Code, feed.Header())
		}
		conditional := httptest.NewRequest(http.MethodGet, test.path, nil)
		conditional.Host = "speedtest.example.com"
		conditional.Header.Set("If-None-Match", feed.Header().Get("ETag"))
		cached := httptest.NewRecorder()
		test.handler(cached, conditional)
		if cached.Code != http.StatusNotModified {
			t.Fatalf("%s conditional status = %d, want 304", test.path, cached.Code)
		}
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

	req := httptest.NewRequest(http.MethodGet, "http://speedtest.example.com/.well-known/security.txt", nil)
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
	if loc := rr.Header().Get("Location"); loc != "/server/auth/password/forgot" {
		t.Errorf("Location = %q, expected redirect to password recovery", loc)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
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
	s.Config.Server.Metrics.Auth.AllowUnauthenticated = true
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
