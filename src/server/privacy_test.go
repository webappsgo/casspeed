package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/config"
)

func TestPrivacyPageUsesTorContactEmail(t *testing.T) {
	s := minimalServer()
	s.Config.Server.Contact.DPO.Email = "privacy@clearnet.example"
	s.Config.Server.Contact.General.Email = "general@clearnet.example"
	s.Config.Server.Tor.ContactEmail = "privacy@onion.example"
	request := httptest.NewRequest("GET", "http://casspeedexample.onion/server/privacy", nil)
	request = request.WithContext(context.WithValue(request.Context(), overlayRequestKey{}, "tor"))

	content, err := s.privacyPageContent(request, "")
	if err != nil {
		t.Fatalf("render privacy page: %v", err)
	}
	page := string(content)
	if !strings.Contains(page, "privacy@onion.example") || !strings.Contains(page, "mailto:privacy@onion.example") {
		t.Fatalf("Tor contact email missing from privacy page: %s", page)
	}
	if strings.Contains(page, "clearnet.example") {
		t.Fatalf("clearnet contact email leaked into Tor page: %s", page)
	}
}

func TestPrivacyPageOmitsEmailOnTorWhenTorContactIsUnset(t *testing.T) {
	s := minimalServer()
	s.Config.Server.Contact.DPO.Email = "privacy@clearnet.example"
	s.Config.Server.Contact.General.Email = "general@clearnet.example"
	request := httptest.NewRequest("GET", "http://casspeedexample.onion/server/privacy", nil)
	request = request.WithContext(context.WithValue(request.Context(), overlayRequestKey{}, "tor"))

	content, err := s.privacyPageContent(request, "")
	if err != nil {
		t.Fatalf("render privacy page: %v", err)
	}
	page := string(content)
	if strings.Contains(page, "mailto:") || strings.Contains(page, "clearnet.example") {
		t.Fatalf("email address leaked into Tor page without a Tor contact address: %s", page)
	}
}

func TestPrivacyTorResponsesOmitExternalPolicyURLs(t *testing.T) {
	s := minimalServer()
	s.Config.Server.Privacy.Consent.Policy.URL = "https://policy.clearnet.example/privacy"
	s.Config.Server.Privacy.ThirdParty.Services = []config.PrivacyThirdPartyService{{Name: "Analytics", Purpose: "Usage metrics", PolicyURL: "https://vendor.clearnet.example/privacy"}}
	request := httptest.NewRequest("GET", "http://casspeedexample.onion/server/privacy", nil)
	request = request.WithContext(context.WithValue(request.Context(), overlayRequestKey{}, "tor"))

	content, err := s.privacyPageContent(request, "")
	if err != nil {
		t.Fatalf("render privacy page: %v", err)
	}
	if strings.Contains(string(content), "clearnet.example") {
		t.Fatalf("external policy URL leaked into Tor privacy page: %s", content)
	}
	if !strings.Contains(string(content), "Analytics") || !strings.Contains(string(content), "Usage metrics") {
		t.Fatalf("Tor privacy page omitted non-URL service disclosures: %s", content)
	}

	encoded, err := json.Marshal(s.privacyPageAPI(request))
	if err != nil {
		t.Fatalf("encode privacy API response: %v", err)
	}
	if strings.Contains(string(encoded), "clearnet.example") {
		t.Fatalf("external policy URL leaked into Tor privacy API: %s", encoded)
	}
	if s.Config.Server.Privacy.Consent.Policy.URL != "https://policy.clearnet.example/privacy" || s.Config.Server.Privacy.ThirdParty.Services[0].PolicyURL != "https://vendor.clearnet.example/privacy" {
		t.Fatal("rendering a Tor response changed the saved policy URLs")
	}
}

func TestTorPrivacyAdminPreservesRedactedPolicyURLs(t *testing.T) {
	previous := config.PrivacyConfig{
		Consent:    config.PrivacyConsentConfig{Policy: config.PrivacyPolicyLink{URL: "https://policy.example/privacy"}},
		ThirdParty: config.PrivacyThirdPartyConfig{Services: []config.PrivacyThirdPartyService{{Name: "Analytics", Purpose: "Usage", PolicyURL: "https://vendor.example/privacy"}}},
	}
	candidate := config.PrivacyConfig{
		Consent:    config.PrivacyConsentConfig{Policy: config.PrivacyPolicyLink{}},
		ThirdParty: config.PrivacyThirdPartyConfig{Services: []config.PrivacyThirdPartyService{{Name: "Analytics", Purpose: "Usage"}}},
	}
	preserveTorPrivacyPolicyURLs(&previous, &candidate)
	if candidate.Consent.Policy.URL != previous.Consent.Policy.URL || candidate.ThirdParty.Services[0].PolicyURL != previous.ThirdParty.Services[0].PolicyURL {
		t.Fatalf("redacted Tor admin update lost saved policy URLs: %#v", candidate)
	}
}

func TestCCPAOptOutValidatesChoiceAndStoresPreference(t *testing.T) {
	s := minimalServer()
	s.Config.Server.Privacy.Data.Sold = true
	request := func(method, form string, csrf bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://example.test/server/ccpa", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://example.test")
		if csrf {
			r.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "csrf"})
		}
		w := httptest.NewRecorder()
		s.handleCCPA(w, r)
		return w
	}
	if got := request(http.MethodGet, "", false); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method response = %d", got.Code)
	}
	if got := request(http.MethodPost, "choice=opt-out&csrf_token=csrf", false); got.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF response = %d", got.Code)
	}
	if got := request(http.MethodPost, "choice=unknown&csrf_token=csrf", true); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid choice response = %d", got.Code)
	}
	optOut := request(http.MethodPost, "choice=opt-out&csrf_token=csrf", true)
	if optOut.Code != http.StatusSeeOther || optOut.Header().Get("Location") != "/server/privacy#ccpa-opt-out" {
		t.Fatalf("opt-out response = %d location=%q", optOut.Code, optOut.Header().Get("Location"))
	}
	foundOptOut := false
	for _, cookie := range optOut.Result().Cookies() {
		if cookie.Name == "ccpa_opt_out" && cookie.Value == "true" {
			foundOptOut = true
		}
	}
	if !foundOptOut {
		t.Fatal("opt-out choice did not persist the preference cookie")
	}
	if got := request(http.MethodPost, "choice=opt-in&csrf_token=csrf", true); got.Code != http.StatusSeeOther {
		t.Fatalf("opt-in response = %d", got.Code)
	}
	s.Config.Server.Privacy.Data.Sold = false
	if got := request(http.MethodPost, "choice=opt-out&csrf_token=csrf", true); got.Code != http.StatusNotFound {
		t.Fatalf("CCPA route while sales are disabled = %d", got.Code)
	}
}

func TestPrivacyAdminFormParsesAndPersistsAllSections(t *testing.T) {
	cfg := config.Default()
	s := minimalServer()
	s.Config = cfg
	s.ConfigPath = filepath.Join(t.TempDir(), "server.yml")
	values := url.Values{
		"sharing": {`[]`}, "services": {`[]`}, "retention_period": {cfg.Server.Privacy.Retention.Period},
		"message": {cfg.Server.Privacy.Consent.Message}, "message_if_sold": {cfg.Server.Privacy.Consent.MessageIfSold},
		"policy_text": {cfg.Server.Privacy.Consent.Policy.Text}, "policy_url": {cfg.Server.Privacy.Consent.Policy.URL},
		"policy_version": {cfg.Server.Privacy.Consent.Policy.Version}, "accept": {cfg.Server.Privacy.Consent.Buttons.Accept},
		"decline": {cfg.Server.Privacy.Consent.Buttons.Decline}, "position": {cfg.Server.Privacy.Consent.Position},
		"preferences_text":          {cfg.Server.Privacy.Consent.PreferencesText},
		"essential_description":     {cfg.Server.Privacy.Cookies.Essential.Description},
		"preferences_description":   {cfg.Server.Privacy.Cookies.Preferences.Description},
		"analytics_description":     {cfg.Server.Privacy.Cookies.Analytics.Description},
		"analytics_suffix_not_sold": {cfg.Server.Privacy.Cookies.Analytics.DescriptionSuffixNotSold},
		"analytics_suffix_sold":     {cfg.Server.Privacy.Cookies.Analytics.DescriptionSuffixSold},
		"show_until_acknowledged":   {"true"}, "show_preferences": {"true"},
		"preferences_enabled": {"true"}, "analytics_enabled": {"true"},
		"export_available": {"true"}, "deletion_available": {"true"},
	}
	invalid := httptest.NewRequest(http.MethodPost, "/server/administration/privacy", strings.NewReader("sharing={&services=%5B%5D"))
	if err := invalid.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if err := s.updatePrivacyFromForm(invalid); err == nil {
		t.Fatal("invalid sharing JSON was accepted")
	}
	request := httptest.NewRequest(http.MethodPost, "/server/administration/privacy", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := request.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if err := s.updatePrivacyFromForm(request); err != nil {
		t.Fatalf("valid privacy settings rejected: %v", err)
	}
	if !cfg.Server.Privacy.Cookies.Analytics.Enabled || !cfg.Server.Privacy.Retention.ExportAvailable || len(cfg.Server.Privacy.Data.Sharing) != 0 {
		t.Fatalf("privacy settings were not applied: %+v", cfg.Server.Privacy)
	}
	if _, err := os.Stat(s.ConfigPath); err != nil {
		t.Fatalf("privacy settings were not persisted: %v", err)
	}
}

func TestContactPageUsesOnlyTorAbuseEmail(t *testing.T) {
	handler := newTestContactHandler(t)
	handler.config.Server.Contact.Abuse.Email = "abuse@clearnet.example"
	handler.config.Server.Contact.General.Email = "general@clearnet.example"
	handler.config.Server.Tor.ContactEmail = "privacy@onion.example"
	request := httptest.NewRequest("GET", "http://casspeedexample.onion/server/contact", nil)
	request = request.WithContext(context.WithValue(request.Context(), overlayRequestKey{}, "tor"))

	if got := handler.publicAbuseEmail(request); got != "privacy@onion.example" {
		t.Fatalf("Tor public contact email = %q, want Tor contact email", got)
	}
	handler.config.Server.Tor.ContactEmail = ""
	if got := handler.publicAbuseEmail(request); got != "" {
		t.Fatalf("Tor public contact email without Tor address = %q, want empty", got)
	}
}
