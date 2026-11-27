package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/config"
	"github.com/go-chi/chi/v5"
)

func TestAdminPagesAPIReadsAndUpdatesEachContentSection(t *testing.T) {
	cfg := config.Default()
	s := minimalServer()
	s.Config = cfg
	s.ConfigPath = filepath.Join(t.TempDir(), "server.yml")
	call := func(method, section, body string) *httptest.ResponseRecorder {
		t.Helper()
		target := "/api/v1/server/pages"
		if section != "" {
			target += "/" + section
		}
		request := httptest.NewRequest(method, target, strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		if section != "" {
			routeContext := chi.NewRouteContext()
			routeContext.URLParams.Add("section", section)
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
		}
		response := httptest.NewRecorder()
		s.handleAdminPagesAPI(response, request)
		return response
	}
	if response := call(http.MethodGet, "", ""); response.Code != http.StatusOK {
		t.Fatalf("all-pages API returned %d: %s", response.Code, response.Body.String())
	}
	for _, section := range []string{"about", "contact", "help", "terms"} {
		if response := call(http.MethodGet, section, ""); response.Code != http.StatusOK {
			t.Errorf("GET %s returned %d: %s", section, response.Code, response.Body.String())
		}
	}
	for section, body := range map[string]string{
		"about":   `{"content":"About update"}`,
		"help":    `{"content":"Help update"}`,
		"terms":   `{"content":"Terms update"}`,
		"contact": `{"enabled":true,"recipient_email":"support@example.test","captcha":"simple","success_message":"Thank you"}`,
	} {
		if response := call(http.MethodPatch, section, body); response.Code != http.StatusOK {
			t.Errorf("PATCH %s returned %d: %s", section, response.Code, response.Body.String())
		}
	}
	if cfg.Server.Branding.Content.About != "About update" || cfg.Server.Pages.Help.Content != "Help update" || cfg.Server.Branding.Content.Terms != "Terms update" || cfg.Server.Contact.General.Email != "support@example.test" {
		t.Fatal("page content patches were not applied")
	}
	if response := call(http.MethodPatch, "about", `{`); response.Code != http.StatusBadRequest {
		t.Fatalf("malformed patch returned %d", response.Code)
	}
	if response := call(http.MethodGet, "unknown", ""); response.Code != http.StatusNotFound {
		t.Fatalf("unknown section returned %d", response.Code)
	}
	if response := call(http.MethodPost, "about", ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported method returned %d", response.Code)
	}
}

func TestAdminPrivacyAPIDeepMergesAndPreservesExistingFields(t *testing.T) {
	cfg := config.Default()
	s := minimalServer()
	s.Config = cfg
	s.ConfigPath = filepath.Join(t.TempDir(), "server.yml")
	call := func(method, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "/api/v1/server/pages/privacy", strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		s.handlePrivacyAdminAPI(response, request)
		return response
	}
	if response := call(http.MethodGet, ""); response.Code != http.StatusOK {
		t.Fatalf("privacy GET returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPatch, `{"data":{"sold":true},"consent":{"policy":{"url":"https://policy.example.test/privacy"}}}`); response.Code != http.StatusOK {
		t.Fatalf("privacy PATCH returned %d: %s", response.Code, response.Body.String())
	}
	if !cfg.Server.Privacy.Data.Sold || cfg.Server.Privacy.Consent.Policy.URL != "https://policy.example.test/privacy" || cfg.Server.Privacy.Consent.Message == "" {
		t.Fatal("privacy patch did not preserve unrelated nested settings")
	}
	if response := call(http.MethodPatch, `{`); response.Code != http.StatusBadRequest {
		t.Fatalf("malformed privacy patch returned %d", response.Code)
	}
	if response := call(http.MethodPost, ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported privacy method returned %d", response.Code)
	}
}
