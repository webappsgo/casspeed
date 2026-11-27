package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/admin"
	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/mode"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
)

func TestNewServerRegistersPublicAndAuthenticatedAdminPages(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	dataDir := filepath.Join(root, "data")
	logDir := filepath.Join(root, "logs")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "db"), 0700); err != nil {
		t.Fatal(err)
	}
	secrets := "server:\n  token: adm_0123456789abcdefghijklmnopqrstuv\nsecurity:\n  encryption_key: " + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n  encryption_key_version: 1\n"
	if err := os.WriteFile(filepath.Join(configDir, "secrets.yml"), []byte(secrets), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	s, err := New(cfg, &mode.State{Mode: mode.Production}, configDir, dataDir, logDir, "1.2.3", "abcdef0", "2026-01-01")
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })
	for _, route := range []string{"/", "/server/about", "/server/privacy", "/server/help", "/server/help/mcp", "/server/contact", "/server/terms", "/server/dpo", "/server/security", "/server/security/policy", "/server/security/thanks", "/server/docs/graphql", "/server/docs/swagger", "/server/healthz", "/server/auth/register", "/server/auth/password/forgot", "/locales/en.json", "/sitemap.xml", "/feed.xml", "/rss.xml", "/robots.txt", "/static/css/style.css", "/static/css/graphiql-theme.css", "/static/js/app.js", "/static/js/docs-graphql.js", "/static/js/swagger-init.js", "/static/vendor/graphiql/graphiql.min.js", "/static/vendor/graphiql/graphiql.min.css", "/static/vendor/graphiql/react.production.min.js", "/static/vendor/graphiql/react-dom.production.min.js", "/static/vendor/swagger-ui/swagger-ui.css", "/static/vendor/swagger-ui/swagger-ui-bundle.js", "/static/vendor/swagger-ui/swagger-ui-standalone-preset.js"} {
		t.Run(route, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://casspeed.test"+route, nil)
			response := httptest.NewRecorder()
			s.Router.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s returned %d: %s", route, response.Code, response.Body.String())
			}
		})
	}
	for route, expected := range map[string]int{"/api/autodiscover": http.StatusOK, "/cli/binaries/casspeed-cli-linux-amd64": http.StatusNotFound} {
		response := httptest.NewRecorder()
		s.Router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://casspeed.test"+route, nil))
		if response.Code != expected {
			t.Errorf("GET %s returned %d, want %d: %s", route, response.Code, expected, response.Body.String())
		}
	}
	openAPIResponse := httptest.NewRecorder()
	s.Router.ServeHTTP(openAPIResponse, httptest.NewRequest(http.MethodGet, "http://casspeed.test/api/v1/server/swagger", nil))
	if openAPIResponse.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/server/swagger returned %d: %s", openAPIResponse.Code, openAPIResponse.Body.String())
	}
	var openAPIDocument struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openAPIResponse.Body.Bytes(), &openAPIDocument); err != nil {
		t.Fatalf("decode generated OpenAPI document: %v", err)
	}
	for _, path := range []string{"/server/auth/2fa", "/users/data/export/{id}", "/server/contact"} {
		if _, exists := openAPIDocument.Paths[path]; !exists {
			t.Errorf("generated OpenAPI document is missing registered API route %s", path)
		}
	}
	unauthorized := httptest.NewRecorder()
	s.Router.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/server/administration/settings", nil))
	if unauthorized.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated admin page status = %d", unauthorized.Code)
	}
	if err := s.Store.CreateAdminSession(t.Context(), &model.AdminSession{ID: "admin-session", AdminID: 1, IPAddress: "127.0.0.1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/server/administration", "/server/administration/admin/profile", "/server/administration/admin/preferences", "/server/administration/admin/notifications", "/server/administration/settings", "/server/administration/info", "/server/administration/logs", "/server/administration/logs/audit", "/server/administration/backup", "/server/administration/updates", "/server/administration/ssl", "/server/administration/email", "/server/administration/scheduler", "/server/administration/metrics", "/server/administration/tracking", "/server/administration/network/tor", "/server/administration/network/i2p", "/server/administration/network/geoip", "/server/administration/security/auth", "/server/administration/security/tokens", "/server/administration/privacy", "/server/administration/pages", "/server/administration/pages/privacy", "/server/administration/roles", "/server/administration/users", "/server/administration/users/invites", "/server/administration/moderation/users"} {
		t.Run("admin"+route, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://casspeed.test"+route, nil)
			request.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin-session"})
			response := httptest.NewRecorder()
			s.Router.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s returned %d: %s", route, response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "<main") {
				t.Fatalf("GET %s did not render the admin page shell", route)
			}
		})
	}
	for _, route := range []string{"/server/administration/network/i2p", "/server/administration/network/tor/vanity", "/server/administration/network/tor/import"} {
		request := httptest.NewRequest(http.MethodPost, "http://casspeed.test"+route, strings.NewReader(""))
		request.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin-session"})
		response := httptest.NewRecorder()
		s.Router.ServeHTTP(response, request)
		if response.Code == http.StatusNotFound || response.Code == http.StatusMethodNotAllowed {
			t.Errorf("POST %s returned %d; the admin page form route must be registered", route, response.Code)
		}
	}
	passwordHash, err := auth.HashPassword("route-user-password")
	if err != nil {
		t.Fatal(err)
	}
	user := &model.User{Username: "route-user", Email: "route-user@example.test", PasswordHash: passwordHash, Approved: true, EmailVerified: true}
	if err := s.Store.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	user, err = s.Store.GetUserByUsername(t.Context(), user.Username)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.CreateSession(t.Context(), &model.Session{ID: "user-session", UserID: fmt.Sprintf("%d", user.ID), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/users", "/users/route-user", "/users/settings", "/users/settings/email", "/users/settings/privacy", "/users/settings/notifications", "/users/settings/appearance", "/users/security", "/users/security/password", "/users/security/2fa", "/users/security/passkeys", "/users/security/sessions", "/users/notifications", "/users/data/export", "/users/tokens", "/history", "/devices"} {
		t.Run("user"+route, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://casspeed.test"+route, nil)
			request.AddCookie(&http.Cookie{Name: "user_session", Value: "user-session"})
			response := httptest.NewRecorder()
			s.Router.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s returned %d: %s", route, response.Code, response.Body.String())
			}
		})
	}
	operatorToken := "adm_" + strings.Repeat("a", 32)
	s.operatorTokenHash = sha256.Sum256([]byte(operatorToken))
	for _, endpoint := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/server/administration/network/tor", ""},
		{http.MethodPatch, "/server/administration/network/tor", `{}`},
		{http.MethodPost, "/server/administration/network/tor/validate", `{}`},
		{http.MethodPost, "/server/administration/network/tor/regenerate", `{}`},
		{http.MethodGet, "/server/administration/network/tor/vanity", ""},
		{http.MethodPost, "/server/administration/network/tor/vanity", `{}`},
		{http.MethodDelete, "/server/administration/network/tor/vanity", ""},
		{http.MethodPost, "/server/administration/network/tor/vanity/apply", `{}`},
		{http.MethodPost, "/server/administration/network/tor/import", `{}`},
		{http.MethodGet, "/server/administration/network/i2p", ""},
		{http.MethodPatch, "/server/administration/network/i2p", `{}`},
		{http.MethodPost, "/server/administration/network/i2p/validate", `{}`},
		{http.MethodPost, "/server/administration/network/i2p/regenerate", `{}`},
		{http.MethodPost, "/server/administration/network/i2p/restart", `{}`},
	} {
		t.Run(endpoint.method+" "+endpoint.path, func(t *testing.T) {
			request := httptest.NewRequest(endpoint.method, "http://casspeed.test/api/v1"+endpoint.path, strings.NewReader(endpoint.body))
			request.Header.Set("Authorization", "Bearer "+operatorToken)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			s.Router.ServeHTTP(response, request)
			if response.Code == http.StatusNotFound || response.Code == http.StatusUnauthorized {
				t.Fatalf("admin overlay API returned %d: %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestSharedLoginCreatesScopedAdminAndUserSessions(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	adminPassword := admin.HashPassword("correct-admin-password")
	if err := st.CreateAdmin(t.Context(), &model.Admin{Username: "operator", Password: adminPassword, Role: "admin", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	userPassword, err := auth.HashPassword("correct-user-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(t.Context(), &model.User{ID: 0, Username: "member", Email: "member@example.test", PasswordHash: userPassword, Approved: true, EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	admin.SetSetupComplete(true)
	t.Cleanup(func() { admin.SetSetupComplete(false) })
	s := minimalServer()
	s.Store = st
	s.AdminHandler = admin.NewHandler(st)
	for _, test := range []struct {
		name       string
		identifier string
		password   string
		redirect   string
		want       string
	}{
		{name: "administrator", identifier: "operator", password: "correct-admin-password", want: "/server/administration"},
		{name: "user by email", identifier: "member@example.test", password: "correct-user-password", redirect: "/users/devices", want: "/users/devices"},
	} {
		t.Run(test.name, func(t *testing.T) {
			loginForm := httptest.NewRecorder()
			get := httptest.NewRequest(http.MethodGet, "http://casspeed.test/server/auth/login", nil)
			s.handleSharedLogin(loginForm, get)
			csrfCookie := responseCookie(t, loginForm, loginCSRFCookie)
			form := url.Values{"username": {test.identifier}, "password": {test.password}, "csrf_token": {csrfCookie.Value}, "redirect": {test.redirect}}
			post := httptest.NewRequest(http.MethodPost, "http://casspeed.test/server/auth/login", strings.NewReader(form.Encode()))
			post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			origin, err := url.Parse(BuildURL(post, "/"))
			if err != nil {
				t.Fatal(err)
			}
			post.Header.Set("Origin", origin.Scheme+"://"+origin.Host)
			post.AddCookie(csrfCookie)
			response := httptest.NewRecorder()
			s.handleSharedLogin(response, post)
			if response.Code != http.StatusSeeOther || response.Header().Get("Location") != test.want {
				t.Fatalf("login response = %d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body.String())
			}
			cookieName := "user_session"
			if test.name == "administrator" {
				cookieName = "admin_session"
			}
			if responseCookie(t, response, cookieName).Value == "" {
				t.Fatalf("login did not issue %s cookie", cookieName)
			}
		})
	}
}

func TestSharedLogoutRequiresPostAndSessionCSRF(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.CreateSession(t.Context(), &model.Session{ID: "logout-session", UserID: "user", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	get := httptest.NewRecorder()
	s.handleSharedLogout(get, httptest.NewRequest(http.MethodGet, "/server/auth/logout", nil))
	if get.Code != http.StatusMethodNotAllowed || get.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET logout status = %d allow=%q", get.Code, get.Header().Get("Allow"))
	}
	bad := httptest.NewRequest(http.MethodPost, "/server/auth/logout", strings.NewReader("csrf_token=wrong"))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad.AddCookie(&http.Cookie{Name: "user_session", Value: "logout-session"})
	badResponse := httptest.NewRecorder()
	s.handleSharedLogout(badResponse, bad)
	if badResponse.Code != http.StatusForbidden {
		t.Fatalf("invalid logout CSRF status = %d", badResponse.Code)
	}
	good := httptest.NewRequest(http.MethodPost, "/server/auth/logout", strings.NewReader("csrf_token=logout-session"))
	good.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	good.AddCookie(&http.Cookie{Name: "user_session", Value: "logout-session"})
	goodResponse := httptest.NewRecorder()
	s.handleSharedLogout(goodResponse, good)
	if goodResponse.Code != http.StatusSeeOther {
		t.Fatalf("logout response status = %d", goodResponse.Code)
	}
	session, err := st.GetSession(t.Context(), "logout-session")
	if err != nil || session != nil {
		t.Fatalf("logout session remains: %#v, %v", session, err)
	}
}

func responseCookie(t *testing.T, response *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("response did not set %s cookie", name)
	return nil
}
