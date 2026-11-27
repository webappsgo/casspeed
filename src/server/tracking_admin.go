package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"github.com/casapps/casspeed/src/config"
)

var trackingAdminTemplate = template.Must(template.New("tracking-admin").Parse(`<form method="post" action="{{.Path}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label>{{index .Labels "platform"}}<select name="type">{{range .Types}}<option value="{{.}}" {{if eq $.Tracking.Type .}}selected{{end}}>{{.}}</option>{{end}}</select></label><label>{{index .Labels "tracking_id"}}<input name="id" value="{{.Tracking.ID}}"></label>{{if not .TorRequest}}<label>{{index .Labels "analytics_url"}}<input type="url" name="url" value="{{.Tracking.URL}}"></label>{{end}}<p>{{index .Labels "provider_url_help"}}</p><h2>{{index .Labels "generated_markup"}}</h2><pre><code>{{.Preview}}</code></pre><button type="submit">{{index .Labels "save"}}</button></form>`))

func (s *Server) handleTrackingAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
			http.Error(w, serverAdminText(r, "admin.legacy.errors.tracking_security"), http.StatusForbidden)
			return
		}
		candidate := config.TrackingConfig{Type: r.FormValue("type"), ID: r.FormValue("id"), URL: r.FormValue("url")}
		if overlayRequestKind(r) == "tor" {
			s.configMu.RLock()
			candidate.URL = s.Config.Server.Tracking.URL
			s.configMu.RUnlock()
		}
		if err := config.ValidateTracking(&candidate); err != nil {
			http.Error(w, trackingAdminValidationMessage(r, err), http.StatusBadRequest)
			return
		}
		s.configMu.Lock()
		previous := s.Config.Server.Tracking
		s.Config.Server.Tracking = candidate
		if err := config.Save(s.Config, s.ConfigPath); err != nil {
			s.Config.Server.Tracking = previous
			s.configMu.Unlock()
			http.Error(w, serverAdminText(r, "admin.legacy.errors.tracking_save"), http.StatusInternalServerError)
			return
		}
		s.configMu.Unlock()
		s.auditPrivacyEvent("tracking.settings_updated", map[string]any{"type": candidate.Type})
		http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/"+configuredAdminPath(s.Config)+"/tracking"), http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, serverAdminText(r, "errors.http_405_message"), http.StatusMethodNotAllowed)
		return
	}
	csrf := s.issuePreferenceCSRF(w, r)
	s.configMu.RLock()
	tracking := s.Config.Server.Tracking
	s.configMu.RUnlock()
	torRequest := overlayRequestKind(r) == "tor"
	markup := configuredTracking(tracking)
	preview := markup.tags
	if markup.body != "" {
		preview += `\n<script async src="` + prefixPagePath(requestPathPrefix(r), "/server/tracking.js") + `"></script>`
	}
	if torRequest {
		tracking.URL = ""
		preview = serverAdminText(r, "admin.legacy.tracking.hidden_on_tor")
	}
	labels := serverAdminLabels(r, "admin.legacy.tracking", "platform", "tracking_id", "analytics_url", "provider_url_help", "generated_markup", "save")
	content := executeTemplate(trackingAdminTemplate, map[string]any{"Path": prefixPagePath(requestPathPrefix(r), "/server/"+configuredAdminPath(s.Config)+"/tracking"), "CSRF": csrf, "Tracking": tracking, "Types": []string{"none", "google", "matomo", "piwik", "owa", "fathom", "plausible", "umami", "simple", "cloudflare"}, "Preview": preview, "Labels": labels, "TorRequest": torRequest})
	catalog := serverAdminCatalog(r)
	s.AdminHandler.RenderContentPage(w, r, catalog.T("admin.legacy.tracking.title", nil), catalog.T("admin.legacy.tracking.description", nil), content)
}

func trackingAdminValidationMessage(r *http.Request, err error) string {
	if err == nil {
		return serverAdminText(r, "admin.legacy.errors.tracking_invalid")
	}
	keys := map[string]string{
		"invalid Google Analytics ID format":                               "admin.legacy.tracking.error_google_id",
		"matomo/piwik ID must be an integer":                               "admin.legacy.tracking.error_matomo_id",
		"matomo/piwik requires URL":                                        "admin.legacy.tracking.error_matomo_url",
		"OWA requires site ID and URL":                                     "admin.legacy.tracking.error_owa_fields",
		"invalid Umami website UUID":                                       "admin.legacy.tracking.error_umami_id",
		"umami requires URL":                                               "admin.legacy.tracking.error_umami_url",
		"cloudflare Web Analytics requires beacon token":                   "admin.legacy.tracking.error_cloudflare_token",
		"tracking URL must be an absolute HTTP(S) URL without credentials": "admin.legacy.tracking.error_url",
	}
	if key, ok := keys[err.Error()]; ok {
		return serverAdminText(r, key)
	}
	if strings.HasPrefix(err.Error(), "fathom requires an ID") {
		return serverAdminText(r, "admin.legacy.tracking.error_fathom_id")
	}
	if strings.HasPrefix(err.Error(), "plausible requires an ID") {
		return serverAdminText(r, "admin.legacy.tracking.error_plausible_id")
	}
	return serverAdminText(r, "admin.legacy.errors.tracking_invalid")
}

func (s *Server) handleTrackingAdminAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.configMu.RLock()
		tracking := s.Config.Server.Tracking
		s.configMu.RUnlock()
		if overlayRequestKind(r) == "tor" {
			tracking.URL = ""
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": tracking})
		return
	}
	if r.Method != http.MethodPatch {
		w.Header().Set("Allow", "GET, PATCH")
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": serverAdminText(r, "errors.http_405_message")})
		return
	}
	var candidate config.TrackingConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&candidate); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": serverAdminText(r, "admin.legacy.errors.invalid_request")})
		return
	}
	if overlayRequestKind(r) == "tor" {
		s.configMu.RLock()
		candidate.URL = s.Config.Server.Tracking.URL
		s.configMu.RUnlock()
	}
	if err := config.ValidateTracking(&candidate); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": trackingAdminValidationMessage(r, err)})
		return
	}
	s.configMu.Lock()
	previous := s.Config.Server.Tracking
	s.Config.Server.Tracking = candidate
	err := config.Save(s.Config, s.ConfigPath)
	if err != nil {
		s.Config.Server.Tracking = previous
	}
	s.configMu.Unlock()
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": serverAdminText(r, "admin.legacy.errors.tracking_save")})
		return
	}
	s.auditPrivacyEvent("tracking.settings_updated", map[string]any{"type": candidate.Type})
	response := candidate
	if overlayRequestKind(r) == "tor" {
		response.URL = ""
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": response})
}
