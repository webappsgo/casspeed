package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/server/store"
)

const (
	preferenceCSRFCookie = "casspeed_preferences_csrf"
	preferencePrefix     = "casspeed_pref_"
	preferenceMaxAge     = 31536000
	preferenceCodeLimit  = 2048
)

var preferenceKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var preferenceValuePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

var consentBannerTemplate = template.Must(template.New("cookie-consent-banner").Parse(`<aside class="consent-banner consent-banner--{{.Position}}" aria-label="Cookie consent"><p>{{.Message}}</p><form method="post" action="/server/consent"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button class="btn btn-primary" type="submit" name="choice" value="accept">{{.Accept}}</button><button class="btn btn-secondary" type="submit" name="choice" value="decline">{{.Decline}}</button>{{if .Manage}}<a href="/server/preferences#privacy">{{.Manage}}</a>{{end}}<a href="{{.PolicyURL}}">{{.PolicyText}}</a></form></aside>`))

func hasConsentChoice(r *http.Request) bool {
	consent := readConsent(r)
	return consent.Essential && consent.Timestamp > 0
}

type preferenceState struct {
	Theme string            `json:"theme"`
	Lang  string            `json:"lang"`
	Prefs map[string]string `json:"prefs"`
}

type preferenceResult struct {
	preferenceState
	Applied         []string `json:"applied"`
	Ignored         []string `json:"ignored"`
	ConsentRequired bool     `json:"consent_required,omitempty"`
}

type preferenceExport struct {
	preferenceState
	URL  string `json:"url"`
	Code string `json:"code"`
}

type preferencePageData struct {
	Theme              string
	Lang               string
	LanguageName       string
	Languages          []i18n.Metadata
	ThemeLabel         string
	DarkLabel          string
	LightLabel         string
	AutoLabel          string
	LanguageLabel      string
	AutomaticLabel     string
	EssentialLabel     string
	PreferencesLabel   string
	AnalyticsLabel     string
	CCPALabel          string
	ConsentPreferences bool
	ConsentAnalytics   bool
	CCPAOptOut         bool
	ShowCCPA           bool
	OfferPreferences   bool
	OfferAnalytics     bool
}

var preferenceAppearanceTemplate = template.Must(template.New("preferences-appearance").Parse(`<fieldset><legend>{{.ThemeLabel}}</legend>
<div class="form-group"><label><input type="radio" name="theme" value="dark" {{if eq .Theme "dark"}}checked{{end}}> {{.DarkLabel}}</label></div>
<div class="form-group"><label><input type="radio" name="theme" value="light" {{if eq .Theme "light"}}checked{{end}}> {{.LightLabel}}</label></div>
<div class="form-group"><label><input type="radio" name="theme" value="auto" {{if eq .Theme "auto"}}checked{{end}}> {{.AutoLabel}}</label></div></fieldset>`))

var preferenceLanguageTemplate = template.Must(template.New("preferences-language").Parse(`<div class="form-group"><label for="lang">{{.LanguageLabel}}</label><select class="form-input" id="lang" name="lang"><option value="automatic" {{if eq .Lang ""}}selected{{end}}>{{.AutomaticLabel}}</option>{{range .Languages}}<option value="{{.Language}}" lang="{{.Language}}" {{if eq $.Lang .Language}}selected{{end}}>{{.Native}}</option>{{end}}</select></div>`))

var preferencePrivacyTemplate = template.Must(template.New("preferences-privacy").Parse(`<input type="hidden" name="consent_form" value="1">
<div class="form-group"><label><input type="checkbox" disabled checked> {{.EssentialLabel}}</label></div>
{{if .OfferPreferences}}<div class="form-group"><label><input type="checkbox" name="consent_preferences" value="true" {{if .ConsentPreferences}}checked{{end}}> {{.PreferencesLabel}}</label></div>{{end}}
{{if .OfferAnalytics}}<div class="form-group"><label><input type="checkbox" name="consent_analytics" value="true" {{if .ConsentAnalytics}}checked{{end}}> {{.AnalyticsLabel}}</label></div>{{end}}
{{if .ShowCCPA}}<div class="form-group"><label><input type="checkbox" name="ccpa_opt_out" value="true" {{if .CCPAOptOut}}checked{{end}}> {{.CCPALabel}}</label></div>{{end}}`))

var preferencesActionsTemplate = template.Must(template.New("preferences-actions").Parse(`
<div class="form-actions"><a class="btn btn-secondary" href="{{.CancelURL}}">{{.CancelLabel}}</a><button class="btn btn-secondary" type="button" popovertarget="reset-preferences">{{.Reset}}</button><button class="btn btn-primary" type="submit">{{.Save}}</button></div>
<div id="reset-preferences" popover aria-labelledby="reset-preferences-title"><h2 id="reset-preferences-title">{{.Reset}}</h2><p>{{.Warning}}</p><button class="btn btn-ghost" type="button" popovertarget="reset-preferences" popovertargetaction="hide">{{.Keep}}</button><button class="btn btn-danger" type="submit" name="action" value="reset">{{.Erase}}</button></div>
`))

type preferenceSyncPageData struct {
	URL, Code, CSRF                                                                 string
	Export, ShareURL, ShortCode, Import, ImportHelp, Copy, CopySuccess, CopyFailure string
}

var preferenceSyncExportTemplate = template.Must(template.New("preference-sync-export").Parse(`<div class="form-group"><p>{{.ShareURL}}</p><div class="copy-value" id="preference-url">{{.URL}}</div><button class="btn btn-secondary copy-btn" type="button" data-copy="preference-url" data-copy-success="{{.CopySuccess}}" data-copy-failure="{{.CopyFailure}}">{{.Copy}}</button><span class="copy-feedback" aria-live="polite"></span></div><div class="form-group"><p>{{.ShortCode}}</p><div class="copy-value" id="preference-code">{{.Code}}</div><button class="btn btn-secondary copy-btn" type="button" data-copy="preference-code" data-copy-success="{{.CopySuccess}}" data-copy-failure="{{.CopyFailure}}">{{.Copy}}</button><span class="copy-feedback" aria-live="polite"></span></div>`))
var preferenceSyncImportTemplate = template.Must(template.New("preference-sync-import").Parse(`<form method="post" action="/server/preferences/sync"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><div class="form-group"><label for="code">{{.ImportHelp}}</label><textarea class="form-input" id="code" name="code" maxlength="2048" rows="3"></textarea></div><button class="btn btn-primary" type="submit">{{.Import}}</button></form>`))

func (s *Server) handlePreferences(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.savePreferences(w, r, false)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state := s.readPreferenceState(r)
	languages, err := i18n.Supported()
	if err != nil {
		http.Error(w, "Preferences unavailable", http.StatusInternalServerError)
		return
	}
	consent := readConsent(r)
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Preferences unavailable", http.StatusInternalServerError)
		return
	}
	languageName := language
	for _, supported := range languages {
		if supported.Language == language {
			languageName = supported.Native
			break
		}
	}
	selectedLanguage := state.Lang
	if _, err := r.Cookie("lang"); err != nil {
		selectedLanguage = ""
	}
	data := preferencePageData{
		Theme: state.Theme, Lang: selectedLanguage, LanguageName: languageName,
		Languages: languages, ConsentPreferences: consent.Preferences, ConsentAnalytics: consent.Analytics,
		CCPAOptOut: readCCPAOptOut(r), ShowCCPA: s.Config != nil && s.Config.Server.Privacy.Data.Sold,
		ThemeLabel: catalog.T("preferences.theme", nil), DarkLabel: catalog.T("theme.dark", nil),
		LightLabel: catalog.T("theme.light", nil), AutoLabel: catalog.T("theme.auto", nil),
		LanguageLabel:  catalog.T("preferences.language", nil),
		AutomaticLabel: catalog.T("preferences.automatic_language", map[string]string{"language": languageName}),
		EssentialLabel: catalog.T("preferences.essential", nil), PreferencesLabel: catalog.T("preferences.preference_cookies", nil),
		AnalyticsLabel: catalog.T("preferences.analytics_cookies", nil), CCPALabel: catalog.T("preferences.do_not_sell", nil),
	}
	if s.Config != nil {
		data.OfferPreferences = s.Config.Server.Privacy.Cookies.Preferences.Enabled
		data.OfferAnalytics = s.Config.Server.Privacy.Cookies.Analytics.Enabled
	}
	appearance := executeTemplate(preferenceAppearanceTemplate, data)
	languageSection := executeTemplate(preferenceLanguageTemplate, data)
	privacy := executeTemplate(preferencePrivacyTemplate, data)
	actions := executeTemplate(preferencesActionsTemplate, map[string]string{
		"CancelURL": redirectTarget(r, "/server/preferences"),
		"Save":      catalog.T("common.save", nil), "CancelLabel": catalog.T("common.cancel", nil),
		"Reset": catalog.T("preferences.reset", nil), "Warning": catalog.T("preferences.reset_warning", nil),
		"Keep": catalog.T("preferences.keep", nil), "Erase": catalog.T("preferences.erase", nil),
	})
	page := publicPageTemplateData{
		Title: catalog.T("pages.preferences", nil), Lead: catalog.T("preferences.lead", nil),
		Sections: []renderedPageSection{
			{ID: "appearance", Title: catalog.T("pages.appearance", nil), Content: template.HTML(appearance)},
			{ID: "language", Title: catalog.T("pages.language", nil), Content: template.HTML(languageSection)},
			{ID: "privacy", Title: catalog.T("pages.privacy", nil), Content: template.HTML(privacy)},
		},
		FormAction: "/server/preferences", FormActions: template.HTML(actions),
	}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, "Preferences unavailable", http.StatusInternalServerError)
		return
	}
	page.CSRF = page.CSRFToken
	bottom := ""
	if r.URL.Query().Get("consent_required") == "1" {
		bottom = `<p class="alert alert-warning" role="status">` + template.HTMLEscapeString(catalog.T("preferences.save_notice", nil)) + `</p>`
	}
	page.Bottom = template.HTML(bottom + preferencesHubCard(r))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.Execute(w, page); err != nil {
		http.Error(w, "Unable to render preferences", http.StatusInternalServerError)
	}
}

func (s *Server) handlePreferenceSync(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !validPreferenceCSRF(r) || !sameOriginPageRequest(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err == nil {
			result := s.applyPreferenceInputToResponse(w, r, preferenceInput(r.Form, r.URL.Query()))
			location := redirectTarget(r, "/server/preferences/sync")
			if result.ConsentRequired {
				location = addQuery(location, "consent_required", "1")
			}
			s.redirectNoStore(w, r, location)
			return
		}
		s.redirectNoStore(w, r, "/server/preferences/sync")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if accepts(r, "text/plain") {
		data := s.preferenceExport(r)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "URL: %s\nCode: %s\n", data.URL, data.Code)
		return
	}
	if accepts(r, "application/json") {
		writePreferenceJSON(w, http.StatusOK, s.preferenceExport(r))
		return
	}
	exportData := s.preferenceExport(r)
	page := publicPageTemplateData{
		BreadcrumbPath: "/server/preferences",
	}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, "Unable to prepare preference sync", http.StatusInternalServerError)
		return
	}
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Unable to prepare preference sync", http.StatusInternalServerError)
		return
	}
	page.Title = catalog.T("pages.sync", nil)
	page.Lead = catalog.T("pages.sync_description", nil)
	page.Breadcrumb = catalog.T("pages.preferences", nil)
	labels := preferenceSyncPageData{
		URL: exportData.URL, Code: exportData.Code, CSRF: page.CSRFToken,
		Export: catalog.T("preferences.export", nil), ShareURL: catalog.T("preferences.share_url", nil),
		ShortCode: catalog.T("preferences.short_code", nil), Import: catalog.T("preferences.import", nil),
		ImportHelp: catalog.T("preferences.import_help", nil), Copy: catalog.T("common.copy", nil), CopySuccess: catalog.T("common.copied", nil), CopyFailure: catalog.T("common.copy_failed", nil),
	}
	export := executeTemplate(preferenceSyncExportTemplate, labels)
	importForm := executeTemplate(preferenceSyncImportTemplate, labels)
	page.PageScript = "/static/js/copy.js"
	page.Sections = []renderedPageSection{
		{ID: "preference-export", Title: labels.Export, Content: template.HTML(export)},
		{ID: "preference-import", Title: labels.Import, Content: template.HTML(importForm)},
	}
	if r.URL.Query().Get("consent_required") == "1" {
		page.Bottom = template.HTML(`<p class="alert alert-warning" role="status">` + template.HTMLEscapeString(catalog.T("preferences.sync_notice", nil)) + `</p>`)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.Execute(w, page); err != nil {
		http.Error(w, "Unable to render preference sync", http.StatusInternalServerError)
	}
}

func (s *Server) handlePreferenceSyncImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result := s.applyPreferenceInputToResponse(w, r, preferenceInput(url.Values{}, r.URL.Query()))
	location := redirectTarget(r, "/server/preferences/sync")
	if result.ConsentRequired {
		location = addQuery(location, "consent_required", "1")
	}
	s.redirectNoStore(w, r, location)
}

func (s *Server) handlePreferenceSyncAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v1/server/preferences/sync" && r.Method == http.MethodGet {
		writePreferenceJSON(w, http.StatusOK, s.preferenceExport(r))
		return
	}
	if r.URL.Path != "/api/v1/server/preferences/sync/import" || r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result := s.applyPreferenceInputToResponse(w, r, preferenceInput(url.Values{}, r.URL.Query()))
	writePreferenceJSON(w, http.StatusOK, result)
}

func (s *Server) handlePreferencesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writePreferenceJSON(w, http.StatusOK, s.readPreferenceState(r))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	values, err := readPreferenceRequest(r)
	if err != nil {
		writePreferenceJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "VALIDATION_FAILED", "message": "No valid preference values were supplied"})
		return
	}
	result := s.applyPreferenceInputToResponse(w, r, values)
	if len(result.Applied) == 0 && !result.ConsentRequired {
		writePreferenceJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "VALIDATION_FAILED", "message": "No valid preference values were supplied"})
		return
	}
	writePreferenceJSON(w, http.StatusOK, result)
}

func (s *Server) savePreferences(w http.ResponseWriter, r *http.Request, syncForm bool) {
	if !validPreferenceCSRF(r) || !sameOriginPageRequest(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.redirectNoStore(w, r, "/server/preferences")
		return
	}
	if r.FormValue("action") == "reset" {
		s.resetPreferences(w, r)
		return
	}
	if r.FormValue("consent_form") == "1" {
		s.saveConsent(w, r)
	}
	values := preferenceInput(r.Form, r.URL.Query())
	if !syncForm {
		values.Del("code")
	}
	if theme := values.Get("theme"); validTheme(theme) {
		identity, identityErr := s.userPageIdentity(r)
		if identityErr != nil {
			http.Error(w, "Unable to load account preferences", http.StatusInternalServerError)
			return
		}
		if identity != nil && identity.User != nil {
			if settingsStore, ok := s.Store.(store.UserSettingsStore); ok {
				settings, err := settingsStore.GetOrCreateUserSettings(r.Context(), userIDString(identity.User.ID))
				if err != nil {
					http.Error(w, "Unable to load account preferences", http.StatusInternalServerError)
					return
				}
				settings.Theme = theme
				if err := settingsStore.UpdateUserSettings(r.Context(), settings); err != nil {
					http.Error(w, "Unable to save account preferences", http.StatusInternalServerError)
					return
				}
			}
		}
	}
	result := s.applyPreferenceInputToResponse(w, r, values)
	location := redirectTarget(r, "/server/preferences")
	if syncForm {
		location = redirectTarget(r, "/server/preferences/sync")
	}
	if result.ConsentRequired {
		location = addQuery(location, "consent_required", "1")
	}
	s.redirectNoStore(w, r, location)
}

func (s *Server) readPreferenceState(r *http.Request) preferenceState {
	state := preferenceState{Theme: "dark", Lang: "en", Prefs: map[string]string{}}
	if cookie, err := r.Cookie("theme"); err == nil && validTheme(cookie.Value) {
		state.Theme = cookie.Value
	}
	if cookie, err := r.Cookie("lang"); err == nil && i18n.IsSupportedTag(cookie.Value) {
		state.Lang = resolveLanguage(cookie.Value)
	} else if r != nil {
		state.Lang, _ = requestLanguage(r)
	}
	if r != nil {
		for _, cookie := range r.Cookies() {
			if key, ok := preferenceName(cookie.Name); ok && validPreferenceValue(cookie.Value) {
				state.Prefs[key] = cookie.Value
			}
		}
	}
	return state
}

func (s *Server) preferenceExport(r *http.Request) preferenceExport {
	state := s.readPreferenceState(r)
	values := url.Values{"lang": {state.Lang}, "theme": {state.Theme}}
	for key, value := range state.Prefs {
		values.Set(preferencePrefix+key, value)
	}
	query := values.Encode()
	code := base64.RawURLEncoding.EncodeToString([]byte(query))
	return preferenceExport{preferenceState: state, URL: BuildURL(r, "/server/preferences/sync/import?"+query), Code: code}
}

func (s *Server) applyPreferenceInput(w http.ResponseWriter, r *http.Request, values url.Values) preferenceResult {
	state := s.readPreferenceState(r)
	result := preferenceResult{preferenceState: state, Applied: []string{}, Ignored: []string{}}
	requested := mergePreferenceInput(values)
	valid := make(map[string]string)
	names := make([]string, 0, len(requested))
	for name := range requested {
		names = append(names, name)
	}
	sort.Strings(names)
	considered := 0
	for _, name := range names {
		value := requested[name]
		if isPreferenceControl(name) {
			continue
		}
		considered++
		if considered > 32 || len(value) > 64 {
			result.Ignored = append(result.Ignored, name)
			continue
		}
		if value == "" {
			continue
		}
		switch name {
		case "theme":
			if validTheme(value) {
				valid[name] = value
			} else {
				result.Ignored = append(result.Ignored, name)
			}
		case "lang":
			language := resolveLanguage(value)
			if i18n.IsSupportedTag(value) {
				valid[name] = language
			} else {
				result.Ignored = append(result.Ignored, name)
			}
		default:
			if key, ok := preferenceName(name); ok && validPreferenceValue(value) {
				valid[preferencePrefix+key] = value
			} else {
				result.Ignored = append(result.Ignored, name)
			}
		}
	}
	if values.Get("lang") == "automatic" {
		http.SetCookie(w, &http.Cookie{Name: "lang", Value: "", Path: "/", MaxAge: 0, Secure: requestIsHTTPS(r), SameSite: http.SameSiteLaxMode})
	}
	consentGranted := preferencesConsent(r)
	if values.Get("consent_form") == "1" {
		consentGranted = values.Get("consent_preferences") == "true"
	}
	if len(valid) > 0 && !consentGranted {
		result.ConsentRequired = true
		for name := range valid {
			result.Ignored = append(result.Ignored, name)
		}
		return result
	}
	if values.Get("lang") == "automatic" {
		result.Lang, _ = requestLanguage(r)
	}
	for name, value := range valid {
		s.setPreferenceCookie(w, r, name, value)
		result.Applied = append(result.Applied, name)
		if name == "theme" {
			result.Theme = value
		} else if name == "lang" {
			result.Lang = value
		} else if strings.HasPrefix(name, preferencePrefix) {
			result.Prefs[strings.TrimPrefix(name, preferencePrefix)] = value
		}
	}
	sort.Strings(result.Applied)
	sort.Strings(result.Ignored)
	return result
}

func preferenceInput(body, query url.Values) url.Values {
	merged := make(url.Values)
	for name, values := range query {
		merged[name] = append([]string(nil), values...)
	}
	for name, values := range body {
		if name == "code" || isPreferenceControl(name) {
			merged[name] = append([]string(nil), values...)
		} else {
			merged[name] = append([]string(nil), values...)
		}
	}
	return merged
}

func mergePreferenceInput(values url.Values) map[string]string {
	merged := make(map[string]string)
	code := first(values["code"])
	if code != "" && len(code) <= preferenceCodeLimit {
		if decoded, err := decodePreferenceCode(code); err == nil {
			for name, entries := range decoded {
				if len(entries) > 0 {
					merged[name] = entries[0]
				}
			}
		}
	}
	for name, entries := range values {
		if len(entries) > 0 && name != "code" {
			merged[name] = entries[0]
		}
	}
	return merged
}

func decodePreferenceCode(code string) (url.Values, error) {
	code = strings.TrimSpace(code)
	if question := strings.IndexByte(code, '?'); question >= 0 {
		code = code[question+1:]
	}
	if strings.Contains(strings.TrimRight(code, "="), "=") {
		return url.ParseQuery(code)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(code, "="))
	if err != nil {
		padded := code + strings.Repeat("=", (4-len(code)%4)%4)
		decoded, err = base64.URLEncoding.DecodeString(padded)
	}
	if err != nil {
		return nil, err
	}
	return url.ParseQuery(string(decoded))
}

func (s *Server) setPreferenceCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	if name != "theme" && name != "lang" && !strings.HasPrefix(name, preferencePrefix) {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: preferenceMaxAge, SameSite: http.SameSiteLaxMode, Secure: requestIsHTTPS(r)})
}

func (s *Server) issuePreferenceCSRF(w http.ResponseWriter, r *http.Request) string {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return ""
	}
	token := base64.RawURLEncoding.EncodeToString(value)
	http.SetCookie(w, &http.Cookie{Name: preferenceCSRFCookie, Value: token, Path: "/", MaxAge: 600, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	return token
}

func validPreferenceCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(preferenceCSRFCookie)
	if err != nil {
		return false
	}
	provided := r.FormValue("csrf_token")
	if len(cookie.Value) == 0 || len(cookie.Value) != len(provided) {
		return false
	}
	left := sha256.Sum256([]byte(cookie.Value))
	right := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func (s *Server) saveConsent(w http.ResponseWriter, r *http.Request) {
	previous := readConsent(r)
	preferencesAccepted := r.FormValue("consent_preferences") == "true"
	analyticsAccepted := r.FormValue("consent_analytics") == "true"
	if s.Config != nil {
		preferencesAccepted = preferencesAccepted && s.Config.Server.Privacy.Cookies.Preferences.Enabled
		analyticsAccepted = analyticsAccepted && s.Config.Server.Privacy.Cookies.Analytics.Enabled
	}
	consent := map[string]any{
		"essential": true, "preferences": preferencesAccepted,
		"analytics": analyticsAccepted, "timestamp": time.Now().Unix(),
	}
	encoded, err := json.Marshal(consent)
	if err == nil {
		http.SetCookie(w, &http.Cookie{Name: "cookie_consent", Value: url.PathEscape(string(encoded)), Path: "/", MaxAge: preferenceMaxAge, SameSite: http.SameSiteLaxMode, Secure: requestIsHTTPS(r)})
	}
	if previous.Preferences && !preferencesAccepted {
		for _, cookie := range r.Cookies() {
			if cookie.Name == "theme" || cookie.Name == "lang" || strings.HasPrefix(cookie.Name, preferencePrefix) {
				http.SetCookie(w, &http.Cookie{Name: cookie.Name, Value: "", Path: "/", MaxAge: 0, Secure: requestIsHTTPS(r), SameSite: http.SameSiteLaxMode})
			}
		}
		w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
	}
	if s.Config != nil && s.Config.Server.Privacy.Data.Sold {
		value := "false"
		if r.FormValue("ccpa_opt_out") == "true" {
			value = "true"
		}
		http.SetCookie(w, &http.Cookie{Name: "ccpa_opt_out", Value: value, Path: "/", MaxAge: preferenceMaxAge, SameSite: http.SameSiteLaxMode, Secure: requestIsHTTPS(r)})
	}
	s.auditPrivacyEvent("compliance.consent_updated", map[string]any{"preferences": preferencesAccepted, "analytics": analyticsAccepted})
}

func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOriginPageRequest(r) || !validPreferenceCSRF(r) {
		http.Error(w, "Invalid consent form", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.redirectNoStore(w, r, "/")
		return
	}
	choice := r.FormValue("choice")
	if choice != "accept" && choice != "decline" && choice != "save" {
		http.Error(w, "Invalid consent choice", http.StatusBadRequest)
		return
	}
	preferencesAccepted, analyticsAccepted := choice == "accept", choice == "accept"
	if choice == "save" {
		preferencesAccepted = r.FormValue("preferences") == "true"
		analyticsAccepted = r.FormValue("analytics") == "true"
	}
	if s.Config != nil {
		preferencesAccepted = preferencesAccepted && s.Config.Server.Privacy.Cookies.Preferences.Enabled
		analyticsAccepted = analyticsAccepted && s.Config.Server.Privacy.Cookies.Analytics.Enabled
	}
	consent := map[string]any{"essential": true, "preferences": preferencesAccepted, "analytics": analyticsAccepted, "timestamp": time.Now().Unix()}
	encoded, err := json.Marshal(consent)
	if err != nil {
		http.Error(w, "Unable to save consent", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "cookie_consent", Value: url.PathEscape(string(encoded)), Path: "/", MaxAge: preferenceMaxAge, Secure: requestIsHTTPS(r), SameSite: http.SameSiteLaxMode})
	if !preferencesAccepted {
		for _, cookie := range r.Cookies() {
			if cookie.Name == "theme" || cookie.Name == "lang" || strings.HasPrefix(cookie.Name, preferencePrefix) {
				http.SetCookie(w, &http.Cookie{Name: cookie.Name, Value: "", Path: "/", MaxAge: 0, Secure: requestIsHTTPS(r), SameSite: http.SameSiteLaxMode})
			}
		}
		w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
	}
	s.auditPrivacyEvent("compliance.consent_updated", map[string]any{"preferences": preferencesAccepted, "analytics": analyticsAccepted})
	s.redirectNoStore(w, r, redirectTarget(r, "/"))
}

func readConsent(r *http.Request) consentCookie {
	cookie, err := r.Cookie("cookie_consent")
	if err != nil {
		return consentCookie{}
	}
	decoded, err := url.PathUnescape(cookie.Value)
	if err != nil {
		return consentCookie{}
	}
	var consent consentCookie
	if err := json.Unmarshal([]byte(decoded), &consent); err != nil {
		return consentCookie{}
	}
	return consent
}

func readCCPAOptOut(r *http.Request) bool {
	cookie, err := r.Cookie("ccpa_opt_out")
	return err == nil && cookie.Value == "true"
}

func preferenceName(name string) (string, bool) {
	if !strings.HasPrefix(name, preferencePrefix) {
		return "", false
	}
	key := strings.TrimPrefix(name, preferencePrefix)
	return key, preferenceKeyPattern.MatchString(key)
}

func validPreferenceValue(value string) bool {
	return preferenceValuePattern.MatchString(value)
}

func validTheme(value string) bool {
	return value == "dark" || value == "light" || value == "auto"
}

func isPreferenceControl(name string) bool {
	switch name {
	case "csrf_token", "code", "redirect", "action", "consent_form", "consent_preferences", "consent_analytics", "ccpa_opt_out":
		return true
	default:
		return false
	}
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (s *Server) redirectNoStore(w http.ResponseWriter, r *http.Request, location string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, location, http.StatusSeeOther)
}

func redirectTarget(r *http.Request, fallback string) string {
	for _, candidate := range []string{r.FormValue("redirect"), sameOriginRefererPath(r)} {
		if safePreferenceRedirect(candidate) && candidate != "/server/preferences/sync/import" && candidate != "/server/preferences" && candidate != "/server/preferences/sync" {
			return candidate
		}
	}
	return fallback
}

func sameOriginRefererPath(r *http.Request) string {
	referrer := r.Referer()
	if referrer == "" || !sameOriginPageRequest(r) {
		return ""
	}
	parsed, err := url.Parse(referrer)
	if err != nil {
		return ""
	}
	return parsed.RequestURI()
}

func safePreferenceRedirect(candidate string) bool {
	if !strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "//") || strings.HasPrefix(candidate, "/\\") || strings.ContainsAny(candidate, "\r\n") {
		return false
	}
	parsed, err := url.Parse(candidate)
	return err == nil && parsed.Scheme == "" && parsed.Host == "" && parsed.Path != ""
}

func addQuery(path, name, value string) string {
	parsed, err := url.Parse(path)
	if err != nil {
		return path
	}
	query := parsed.Query()
	query.Set(name, value)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func requestIsHTTPS(r *http.Request) bool {
	return strings.HasPrefix(BuildURL(r, "/"), "https://")
}

func (s *Server) resetPreferences(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		if isPreferenceCredential(cookie.Name) {
			continue
		}
		http.SetCookie(w, &http.Cookie{Name: cookie.Name, Value: "", Path: "/", MaxAge: 0, Secure: requestIsHTTPS(r), SameSite: http.SameSiteLaxMode})
	}
	w.Header().Set("Clear-Site-Data", `"storage"`)
	s.redirectNoStore(w, r, "/")
}

func isPreferenceCredential(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "session") || strings.Contains(lower, "csrf") || strings.Contains(lower, "token") || strings.Contains(lower, "owner")
}

func (s *Server) applyPreferenceInputToResponse(w http.ResponseWriter, r *http.Request, values url.Values) preferenceResult {
	return s.applyPreferenceInput(w, r, values)
}

func accepts(r *http.Request, mediaType string) bool {
	for _, value := range strings.Split(r.Header.Get("Accept"), ",") {
		if strings.TrimSpace(strings.SplitN(value, ";", 2)[0]) == mediaType || strings.TrimSpace(value) == "*/*" {
			return true
		}
	}
	return false
}

func executeTemplate(tmpl *template.Template, data any) string {
	var output strings.Builder
	if err := tmpl.Execute(&output, data); err != nil {
		return ""
	}
	return output.String()
}

func writePreferenceJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": status >= 200 && status < 300, "data": data})
}

func readPreferenceRequest(r *http.Request) (url.Values, error) {
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body map[string]any
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 65536)).Decode(&body); err != nil {
			return nil, err
		}
		values := make(url.Values)
		for name, value := range body {
			if text, ok := value.(string); ok {
				values.Set(name, text)
			}
		}
		return values, nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return preferenceInput(r.Form, r.URL.Query()), nil
}

func preferencesHubCard(r *http.Request) string {
	var content strings.Builder
	content.WriteString(`<section class="section-card" aria-labelledby="more-preferences"><h2 id="more-preferences">More preferences</h2><ul class="hub-list">`)
	for _, page := range registeredPagesForHub("/server/preferences") {
		label, description := page.Path, ""
		if language, _ := requestLanguage(r); language != "" {
			if catalog, err := i18n.Resolve(language); err == nil {
				if translated := catalog.T(page.TitleKey, nil); translated != page.TitleKey {
					label = translated
				}
				if page.Path == "/server/preferences/sync" {
					description = catalog.T("pages.sync_description", nil)
				}
			}
		}
		content.WriteString(`<li class="hub-item"><a class="hub-link" href="` + page.Path + `"><span class="hub-title">` + template.HTMLEscapeString(label) + `</span><span class="hub-desc">` + template.HTMLEscapeString(description) + `</span></a></li>`)
	}
	content.WriteString("</ul></section>")
	return content.String()
}
