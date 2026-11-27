package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

func mcpTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	st, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	secret := "usr_" + strings.Repeat("A", 32)
	user := &model.User{Username: "mcp-user", Email: "mcp@example.test", PasswordHash: "hash", Approved: true, EmailVerified: true}
	if err := st.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(secret))
	if err := st.CreateAPIToken(t.Context(), &model.APIToken{ID: "mcp-test", UserID: model.UserIDString(user.ID), Token: hex.EncodeToString(hash[:]), TokenPrefix: secret[:8], Name: "MCP test"}); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	s.Router = chi.NewRouter()
	return s, secret
}

func mcpRequestFor(method, params string, token string) *http.Request {
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":` + params + `,"_meta":{"io.modelcontextprotocol/protocolVersion":"` + mcpProtocolVersion + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	req.Header.Set("Mcp-Method", method)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestMCPToolsListUsesOpenAPIOperationIDs(t *testing.T) {
	s, token := mcpTestServer(t)
	recorder := httptest.NewRecorder()
	s.handleMCP(recorder, mcpRequestFor("tools/list", `{}`, token))
	if recorder.Code != http.StatusOK {
		t.Fatalf("tools/list status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Result struct {
			Tools []mcpTool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Result.Tools) == 0 {
		t.Fatal("tools/list returned no OpenAPI operations")
	}
	for _, tool := range response.Result.Tools {
		if tool.Name == "startSpeedTest" {
			return
		}
	}
	t.Fatal("tools/list omitted startSpeedTest")
}

func TestMCPToolsRespectScopeAndOperatorAccess(t *testing.T) {
	s := minimalServer()
	s.Router = chi.NewRouter()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, test := range []struct {
		scope      string
		operator   bool
		wantStart  bool
		wantDelete bool
		wantAdmin  bool
	}{
		{scope: "read", wantStart: false},
		{scope: "read-write", wantStart: true},
		{scope: "global", wantStart: true, wantDelete: true},
		{scope: "global", operator: true, wantStart: true, wantDelete: true, wantAdmin: true},
	} {
		tools, err := s.mcpToolsFor(req, test.scope, test.operator)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, tool := range tools {
			got[tool.Name] = true
		}
		if got["startSpeedTest"] != test.wantStart {
			t.Errorf("scope %q startSpeedTest = %t, want %t", test.scope, got["startSpeedTest"], test.wantStart)
		}
		if got["deleteUserDevice"] != test.wantDelete {
			t.Errorf("scope %q deleteUserDevice = %t, want %t", test.scope, got["deleteUserDevice"], test.wantDelete)
		}
		if got["getServerSettings"] != test.wantAdmin {
			t.Errorf("scope %q operator tool = %t, want %t", test.scope, got["getServerSettings"], test.wantAdmin)
		}
	}
}

func TestMCPRouteFilterExcludesSystemAndSecretRoutes(t *testing.T) {
	for _, path := range []string{"/server/auth/login", "/users/tokens", "/server/passkeys/register", "/server/mcp", "/server/metrics/prometheus", "/server/debug", "/server/preferences/sync/import", "/api/autodiscover"} {
		if !mcpRouteExcluded(path) {
			t.Errorf("MCP route filter allowed %q", path)
		}
	}
	for _, path := range []string{"/speed-tests", "/speed-tests/{id}", "/shares/{code}"} {
		if mcpRouteExcluded(path) {
			t.Errorf("MCP route filter blocked ordinary API route %q", path)
		}
	}
}

func TestMCPToolCallDispatchesInProcess(t *testing.T) {
	s, token := mcpTestServer(t)
	s.Router.Post("/api/v1/speed-tests", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"data":{"id":"test-1"}}`))
	})
	req := mcpRequestFor("tools/call", `{"name":"startSpeedTest","arguments":{"body":{}}}`, token)
	req.Header.Set("Mcp-Name", "startSpeedTest")
	recorder := httptest.NewRecorder()
	s.handleMCP(recorder, req)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `test-1`) {
		t.Fatalf("tools/call response = %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestMCPToolCallRejectsOperationOutsideTokenScope(t *testing.T) {
	s, _ := mcpTestServer(t)
	secret := "usr_" + strings.Repeat("B", 32)
	hash := sha256.Sum256([]byte(secret))
	if err := s.Store.CreateAPIToken(t.Context(), &model.APIToken{ID: "mcp-read", UserID: "1", Token: hex.EncodeToString(hash[:]), TokenPrefix: secret[:8], Name: "read-only", Scope: "read"}); err != nil {
		t.Fatal(err)
	}
	s.Router.Post("/api/v1/speed-tests", func(http.ResponseWriter, *http.Request) { t.Fatal("out-of-scope tool was dispatched") })
	req := mcpRequestFor("tools/call", `{"name":"startSpeedTest","arguments":{"body":{}}}`, secret)
	req.Header.Set("Mcp-Name", "startSpeedTest")
	recorder := httptest.NewRecorder()
	s.handleMCP(recorder, req)
	if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), "Method not found") {
		t.Fatalf("out-of-scope tool response = %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestMCPRequestValidation(t *testing.T) {
	tests := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "unsupported HTTP method", method: http.MethodGet, want: http.StatusMethodNotAllowed},
		{name: "invalid JSON", method: http.MethodPost, body: "{", want: http.StatusBadRequest},
		{name: "legacy initialize", method: http.MethodPost, body: `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, token := mcpTestServer(t)
			method := test.method
			if method == "" {
				method = http.MethodPost
			}
			var req *http.Request
			if test.body == "" {
				req = mcpRequestFor("tools/list", `{}`, token)
				req.Method = method
			} else {
				req = httptest.NewRequest(method, "/mcp", strings.NewReader(test.body))
				req.Header.Set("Authorization", "Bearer "+token)
				if test.name != "legacy initialize" {
					req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
					req.Header.Set("Mcp-Method", "tools/list")
				}
			}
			recorder := httptest.NewRecorder()
			s.handleMCP(recorder, req)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}
}

func TestMCPHeaderMismatchAndUnknownMethod(t *testing.T) {
	for _, test := range []struct {
		name   string
		method string
		want   int
	}{
		{name: "header mismatch", method: "tools/list", want: http.StatusBadRequest},
		{name: "unknown method", method: "notifications/initialized", want: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, token := mcpTestServer(t)
			req := mcpRequestFor(test.method, `{}`, token)
			if test.name == "header mismatch" {
				req.Header.Set("Mcp-Method", "tools/call")
			}
			recorder := httptest.NewRecorder()
			s.handleMCP(recorder, req)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}
}

func TestMCPNameAndOriginValidation(t *testing.T) {
	if name, ok := decodeMCPName("=?base64?5pel5pys?="); !ok || name != "日本" {
		t.Fatalf("decoded MCP name = %q, %v", name, ok)
	}
	if _, ok := decodeMCPName("non-ascii-日"); ok {
		t.Fatal("plain non-ASCII MCP name was accepted")
	}
	if _, ok := decodeMCPName("=?base64?not-base64?="); ok {
		t.Fatal("malformed encoded MCP name was accepted")
	}
	s := minimalServer()
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	request.Header.Set("Origin", "http://example.com")
	if !s.mcpOriginAllowed(request) {
		t.Fatal("same-origin request was rejected")
	}
	request.Header.Set("Origin", "https://example.com")
	if s.mcpOriginAllowed(request) {
		t.Fatal("cross-scheme origin was accepted")
	}
	request.Header.Set("Origin", "://bad")
	if s.mcpOriginAllowed(request) {
		t.Fatal("malformed origin was accepted")
	}
}
