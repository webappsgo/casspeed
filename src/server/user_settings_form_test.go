package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/server/model"
)

func TestApplyUserSettingsFormCategoriesAndValidation(t *testing.T) {
	s := minimalServer()
	user := &model.User{Language: "en"}
	settings := &model.UserSettings{}
	form := func(values url.Values) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/users/settings", strings.NewReader(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	if err := s.applyUserSettingsForm(form(url.Values{"display_name": {" Alice "}, "website": {"https://example.test/profile"}, "timezone": {"UTC"}, "language": {"en"}}), user, settings, "account"); err != nil {
		t.Fatalf("valid account form: %v", err)
	}
	if user.DisplayName != "Alice" || user.Website != "https://example.test/profile" {
		t.Fatalf("account values = %#v", user)
	}
	for _, values := range []url.Values{
		{"website": {"javascript:alert(1)"}, "language": {"en"}},
		{"website": {"https://example.test"}, "timezone": {"Not/AZone"}, "language": {"en"}},
		{"language": {"unsupported"}},
		{"display_name": {strings.Repeat("x", 101)}, "language": {"en"}},
	} {
		if err := s.applyUserSettingsForm(form(values), user, settings, "account"); err == nil {
			t.Errorf("invalid account form accepted: %v", values)
		}
	}
	if err := s.applyUserSettingsForm(form(url.Values{"visibility": {"private"}, "show_email": {"on"}, "searchable": {"true"}}), user, settings, "privacy"); err != nil {
		t.Fatalf("valid privacy form: %v", err)
	}
	if user.Visibility != "private" || !settings.ShowEmail || !settings.Searchable {
		t.Fatalf("privacy values user=%#v settings=%#v", user, settings)
	}
	if err := s.applyUserSettingsForm(form(url.Values{"visibility": {"secret"}}), user, settings, "privacy"); err == nil {
		t.Fatal("invalid privacy visibility was accepted")
	}
	if err := s.applyUserSettingsForm(form(url.Values{"email_digest": {"weekly"}, "email_session": {"on"}}), user, settings, "notifications"); err != nil {
		t.Fatalf("valid notification form: %v", err)
	}
	if !settings.EmailSecurity || !settings.EmailSession || settings.EmailDigest != "weekly" {
		t.Fatalf("notification values = %#v", settings)
	}
	if err := s.applyUserSettingsForm(form(url.Values{"email_digest": {"hourly"}}), user, settings, "notifications"); err == nil {
		t.Fatal("invalid notification digest was accepted")
	}
	appearance := url.Values{"theme": {"light"}, "font_size": {"large"}, "date_format": {"DD/MM/YYYY"}, "time_format": {"24h"}, "reduce_motion": {"true"}}
	if err := s.applyUserSettingsForm(form(appearance), user, settings, "appearance"); err != nil {
		t.Fatalf("valid appearance form: %v", err)
	}
	if settings.Theme != "light" || settings.FontSize != "large" || !settings.ReduceMotion {
		t.Fatalf("appearance values = %#v", settings)
	}
	appearance.Set("theme", "neon")
	if err := s.applyUserSettingsForm(form(appearance), user, settings, "appearance"); err == nil {
		t.Fatal("invalid appearance theme was accepted")
	}
}

func TestUpdateAdminPagesPersistsAndRollsBackInvalidConfiguration(t *testing.T) {
	s := minimalServer()
	s.Config = config.Default()
	s.ConfigPath = filepath.Join(t.TempDir(), "server.yml")
	request := httptest.NewRequest(http.MethodPost, "/server/administration/pages", strings.NewReader(url.Values{
		"about": {"About content"}, "terms": {"Terms content"}, "help": {"Help content"},
		"contact_enabled": {"true"}, "contact_captcha": {"simple"}, "contact_success": {" Thank you "},
		"contact_email": {"contact@example.test"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := s.updateAdminPages(request); err != nil {
		t.Fatalf("updateAdminPages: %v", err)
	}
	if s.Config.Server.Branding.Content.About != "About content" || s.Config.Server.Pages.Help.Content != "Help content" || s.Config.Server.Pages.Contact.SuccessMessage != "Thank you" {
		t.Fatalf("saved page config = %#v", s.Config.Server)
	}
	if _, err := config.Load(s.ConfigPath); err != nil {
		t.Fatalf("saved configuration cannot be loaded: %v", err)
	}
	s.Config.Server.I2P.VirtualPort = 0
	previous := *s.Config
	invalid := httptest.NewRequest(http.MethodPost, "/server/administration/pages", strings.NewReader("contact_captcha=invalid"))
	invalid.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := s.updateAdminPages(invalid); err == nil {
		t.Fatal("invalid page settings were accepted")
	}
	if s.Config.Server.Pages.Contact.Captcha != previous.Server.Pages.Contact.Captcha || s.Config.Server.Branding.Content.About != previous.Server.Branding.Content.About {
		t.Fatal("invalid update did not restore the previous configuration")
	}
}

func TestRenderPrivatePageErrorLocalizesAndEscapes(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusInternalServerError} {
		request := httptest.NewRequest(http.MethodGet, "/users/settings", nil)
		request = request.WithContext(contextWithLanguage(request, "en"))
		response := httptest.NewRecorder()
		minimalServer().renderPrivatePageError(response, request, status)
		if response.Code != status || !strings.Contains(response.Header().Get("Content-Type"), "text/html") || !strings.Contains(response.Body.String(), "request-error") {
			t.Errorf("private error page for %d = %d, %s", status, response.Code, response.Body.String())
		}
	}
}
