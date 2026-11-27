package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/config"
)

func TestPreferencesAPIAppliesValidValuesAndRejectsInvalidRequests(t *testing.T) {
	s := minimalServer()
	request := func(method, body string, consent bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/server/preferences", strings.NewReader(body))
		if strings.Contains(body, "{") {
			r.Header.Set("Content-Type", "application/json")
		}
		if consent {
			r.AddCookie(&http.Cookie{Name: "cookie_consent", Value: url.PathEscape(`{"preferences":true,"timestamp":1}`)})
		}
		w := httptest.NewRecorder()
		s.handlePreferencesAPI(w, r)
		return w
	}
	if got := request(http.MethodGet, "", false); got.Code != http.StatusOK || got.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET response = %d headers=%v", got.Code, got.Header())
	}
	if got := request(http.MethodDelete, "", false); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported method status = %d", got.Code)
	}
	if got := request(http.MethodPost, "{", false); got.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON status = %d", got.Code)
	}
	if got := request(http.MethodPost, `{"theme":"dark"}`, false); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"consent_required":true`) {
		t.Fatalf("consent-gated update = %d: %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPost, `{"theme":"light","casspeed_pref_map":"wide"}`, true); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "casspeed_pref_map") {
		t.Fatalf("valid update = %d: %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPost, `{"unknown":"value"}`, true); got.Code != http.StatusBadRequest {
		t.Fatalf("empty valid update status = %d", got.Code)
	}
}

func TestPreferenceSyncHandlersAndConsentFlow(t *testing.T) {
	s := minimalServer()
	s.Config = config.Default()
	s.Config.Server.Privacy.Cookies.Preferences.Enabled = true
	getPlain := httptest.NewRequest(http.MethodGet, "/server/preferences/sync", nil)
	getPlain.Header.Set("Accept", "text/plain")
	plain := httptest.NewRecorder()
	s.handlePreferenceSync(plain, getPlain)
	if plain.Code != http.StatusOK || !strings.Contains(plain.Body.String(), "Code:") {
		t.Fatalf("plain sync response = %d: %s", plain.Code, plain.Body.String())
	}
	getJSON := httptest.NewRequest(http.MethodGet, "/server/preferences/sync", nil)
	getJSON.Header.Set("Accept", "application/json")
	jsonResponse := httptest.NewRecorder()
	s.handlePreferenceSync(jsonResponse, getJSON)
	if jsonResponse.Code != http.StatusOK || !strings.Contains(jsonResponse.Body.String(), "\"code\"") {
		t.Fatalf("JSON sync response = %d: %s", jsonResponse.Code, jsonResponse.Body.String())
	}
	if _, err := decodePreferenceCode("not-valid!"); err == nil {
		t.Fatal("malformed preference code was accepted")
	}
	if values, err := decodePreferenceCode("https://example.test/?theme=light"); err != nil || values.Get("theme") != "light" {
		t.Fatalf("decode preference URL = %v, %v", values, err)
	}
	api := httptest.NewRecorder()
	s.handlePreferenceSyncAPI(api, httptest.NewRequest(http.MethodGet, "/api/v1/server/preferences/sync", nil))
	if api.Code != http.StatusOK {
		t.Fatalf("sync API export status = %d", api.Code)
	}
	importAPI := httptest.NewRecorder()
	s.handlePreferenceSyncAPI(importAPI, httptest.NewRequest(http.MethodGet, "/api/v1/server/preferences/sync/import?theme=dark", nil))
	if importAPI.Code != http.StatusOK {
		t.Fatalf("sync API import status = %d", importAPI.Code)
	}
	badAPI := httptest.NewRecorder()
	s.handlePreferenceSyncAPI(badAPI, httptest.NewRequest(http.MethodPost, "/api/v1/server/preferences/sync", nil))
	if badAPI.Code != http.StatusMethodNotAllowed {
		t.Fatalf("sync API unsupported method = %d", badAPI.Code)
	}
	page := httptest.NewRecorder()
	s.handlePreferences(page, httptest.NewRequest(http.MethodGet, "/server/preferences?consent_required=1", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `name="theme"`) {
		t.Fatalf("preferences page response = %d", page.Code)
	}
	if !validTheme("dark") || validTheme("orange") || !isPreferenceControl("csrf_token") || isPreferenceControl("username") || first(nil) != "" {
		t.Fatal("preference validation helpers returned unexpected results")
	}
	if name, ok := preferenceName("casspeed_pref_layout"); !ok || name != "layout" {
		t.Fatalf("preferenceName() = %q, %t", name, ok)
	}
	if _, ok := preferenceName("casspeed_pref_BAD"); ok || validPreferenceValue("spaces are invalid") {
		t.Fatal("invalid preference name or value was accepted")
	}
	if got := addQuery("/preferences?theme=dark", "consent_required", "1"); !strings.Contains(got, "consent_required=1") {
		t.Fatalf("addQuery() = %q", got)
	}
	if got := redirectTarget(httptest.NewRequest(http.MethodGet, "/", nil), "/fallback"); got != "/fallback" {
		t.Fatalf("unsafe redirect target = %q", got)
	}
	if values := preferenceInput(url.Values{"theme": {"light"}}, url.Values{"theme": {"dark"}}); values.Get("theme") != "light" {
		t.Fatalf("preference form value did not take precedence: %v", values)
	}
}

func TestPreferenceConsentRejectsBadRequestsAndSetsConsentCookie(t *testing.T) {
	s := minimalServer()
	s.Config.Server.Privacy.Cookies.Preferences.Enabled = true
	call := func(form string, validCSRF bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://example.test/server/consent", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://example.test")
		if validCSRF {
			r.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "token"})
		}
		w := httptest.NewRecorder()
		s.handleConsent(w, r)
		return w
	}
	if got := call("choice=accept", false); got.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", got.Code)
	}
	if got := call("choice=unknown&csrf_token=token", true); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid choice status = %d", got.Code)
	}
	accepted := call("choice=accept&csrf_token=token", true)
	if accepted.Code != http.StatusSeeOther || accepted.Header().Get("Cache-Control") != "no-store" || len(accepted.Result().Cookies()) == 0 {
		t.Fatalf("accept response = %d headers=%v", accepted.Code, accepted.Header())
	}
	if accepted.Header().Get("Clear-Site-Data") != "" {
		t.Fatal("accepting consent unexpectedly cleared site data")
	}
	declined := call("choice=decline&csrf_token=token", true)
	if declined.Code != http.StatusSeeOther || declined.Header().Get("Clear-Site-Data") == "" {
		t.Fatalf("decline response = %d headers=%v", declined.Code, declined.Header())
	}
	if got := hasConsentChoice(httptest.NewRequest(http.MethodGet, "/", nil)); got {
		t.Fatal("missing consent was treated as a choice")
	}
}

func TestPreferenceFormSaveAndResetProtectSessionCookies(t *testing.T) {
	s := minimalServer()
	request := func(form string, cookie bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://example.test/server/preferences", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://example.test")
		if cookie {
			r.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "csrf"})
			r.AddCookie(&http.Cookie{Name: "theme", Value: "light"})
			r.AddCookie(&http.Cookie{Name: "user_session", Value: "session"})
			r.AddCookie(&http.Cookie{Name: "casspeed_pref_width", Value: "wide"})
		}
		w := httptest.NewRecorder()
		s.handlePreferences(w, r)
		return w
	}
	if got := request("csrf_token=bad&theme=dark", false); got.Code != http.StatusForbidden {
		t.Fatalf("invalid form CSRF status = %d", got.Code)
	}
	saved := request("csrf_token=csrf&theme=dark", true)
	if saved.Code != http.StatusSeeOther || saved.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("save response = %d headers=%v", saved.Code, saved.Header())
	}
	reset := request("csrf_token=csrf&action=reset", true)
	if reset.Code != http.StatusSeeOther || reset.Header().Get("Clear-Site-Data") != `"storage"` {
		t.Fatalf("reset response = %d headers=%v", reset.Code, reset.Header())
	}
	cookies := reset.Result().Cookies()
	clearedTheme, clearedPreference, preservedSession := false, false, false
	for _, cookie := range cookies {
		if cookie.Name == "theme" && cookie.MaxAge == 0 {
			clearedTheme = true
		}
		if cookie.Name == "casspeed_pref_width" && cookie.MaxAge == 0 {
			clearedPreference = true
		}
		if cookie.Name == "user_session" && cookie.MaxAge == 0 {
			preservedSession = true
		}
	}
	if !clearedTheme || !clearedPreference || preservedSession {
		t.Fatalf("reset cookie policy theme=%t preference=%t session-cleared=%t cookies=%v", clearedTheme, clearedPreference, preservedSession, cookies)
	}
	if got := request("csrf_token=csrf&theme=dark", true); got.Code != http.StatusSeeOther {
		t.Fatalf("form save status = %d", got.Code)
	}
}
