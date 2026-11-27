package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

func TestRolesAPIHandlerLifecycleAndErrors(t *testing.T) {
	cfg := config.Default()
	database, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s := &Server{Config: cfg, ConfigPath: filepath.Join(t.TempDir(), "server.yml"), Store: database}
	req := func(method, id, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/server/admin/roles", strings.NewReader(body))
		route := chi.NewRouteContext()
		if id != "" {
			route.URLParams.Add("id", id)
		}
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
		w := httptest.NewRecorder()
		s.handleRolesAPI(w, r)
		return w
	}
	if got := req(http.MethodGet, "", ""); got.Code != http.StatusOK {
		t.Fatalf("list roles status = %d", got.Code)
	}
	if got := req(http.MethodGet, "missing", ""); got.Code != http.StatusNotFound {
		t.Fatalf("unknown role status = %d", got.Code)
	}
	if got := req(http.MethodPost, "", "{"); got.Code != http.StatusBadRequest {
		t.Fatalf("malformed create status = %d", got.Code)
	}
	created := req(http.MethodPost, "", `{"name":"reviewer","permissions":["read"]}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", created.Code, created.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if got := req(http.MethodGet, "reviewer", ""); got.Code != http.StatusOK {
		t.Fatalf("get role status = %d", got.Code)
	}
	if got := req(http.MethodPatch, "reviewer", `{"permissions":["write"]}`); got.Code != http.StatusOK {
		t.Fatalf("update status = %d", got.Code)
	}
	if got := req(http.MethodPatch, "admin", `{"permissions":["read"]}`); got.Code != http.StatusConflict {
		t.Fatalf("protected update status = %d", got.Code)
	}
	if got := req(http.MethodDelete, "reviewer", ""); got.Code != http.StatusOK {
		t.Fatalf("delete status = %d", got.Code)
	}
	if got := req(http.MethodDelete, "user", ""); got.Code != http.StatusConflict {
		t.Fatalf("protected delete status = %d", got.Code)
	}
	if got := req(http.MethodPut, "", ""); got.Code != http.StatusMethodNotAllowed || got.Header().Get("Allow") == "" {
		t.Fatalf("unsupported method response = %d allow=%q", got.Code, got.Header().Get("Allow"))
	}
}

func TestTrackingAdminAPIHandlerValidationAndPersistence(t *testing.T) {
	s := minimalServer()
	s.ConfigPath = filepath.Join(t.TempDir(), "server.yml")
	request := func(method, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/server/admin/tracking", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.handleTrackingAdminAPI(w, r)
		return w
	}
	if got := request(http.MethodGet, ""); got.Code != http.StatusOK {
		t.Fatalf("get status = %d", got.Code)
	}
	if got := request(http.MethodPost, ""); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported method status = %d", got.Code)
	}
	if got := request(http.MethodPatch, "{"); got.Code != http.StatusBadRequest {
		t.Fatalf("malformed update status = %d", got.Code)
	}
	invalid := request(http.MethodPatch, `{"type":"google","id":"invalid"}`)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid config status = %d: %s", invalid.Code, invalid.Body.String())
	}
	valid := request(http.MethodPatch, `{"type":"google","id":"G-ABC123"}`)
	if valid.Code != http.StatusOK {
		t.Fatalf("valid update status = %d: %s", valid.Code, valid.Body.String())
	}
	if s.Config.Server.Tracking.Type != "google" {
		t.Fatalf("tracking settings were not persisted in memory: %+v", s.Config.Server.Tracking)
	}
	if _, err := json.Marshal(s.Config.Server.Tracking); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRolePageRequiresCSRFAndDeletesWithValidRequest(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Users.Roles.Available = append(cfg.Server.Users.Roles.Available, "reviewer")
	cfg.Server.Users.Roles.Permissions["reviewer"] = []string{"read"}
	database, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s := &Server{Config: cfg, ConfigPath: filepath.Join(t.TempDir(), "server.yml"), Store: database}
	request := func(valid bool) *httptest.ResponseRecorder {
		form := "csrf_token=token"
		r := httptest.NewRequest(http.MethodPost, "/server/admin/roles/reviewer/delete", bytes.NewBufferString(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://example.com")
		r.Host = "example.com"
		if valid {
			r.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "token"})
		}
		route := chi.NewRouteContext()
		route.URLParams.Add("id", "reviewer")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
		w := httptest.NewRecorder()
		s.handleDeleteRolePage(w, r)
		return w
	}
	if got := request(false); got.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", got.Code)
	}
	if got := request(true); got.Code != http.StatusSeeOther {
		t.Fatalf("valid delete status = %d: %s", got.Code, got.Body.String())
	}
	for _, name := range cfg.Server.Users.Roles.Available {
		if name == "reviewer" {
			t.Fatal("role remains after successful deletion")
		}
	}
}
