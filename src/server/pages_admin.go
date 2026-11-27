package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/config"
	"github.com/go-chi/chi/v5"
)

func serverAdminCatalog(r *http.Request) *i18n.Catalog {
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		catalog, _ = i18n.Resolve("en")
	}
	return catalog
}

func serverAdminText(r *http.Request, key string) string {
	return serverAdminCatalog(r).T(key, nil)
}

func serverAdminLabels(r *http.Request, namespace string, keys ...string) map[string]string {
	catalog := serverAdminCatalog(r)
	labels := make(map[string]string, len(keys))
	for _, key := range keys {
		labels[key] = catalog.T(namespace+"."+key, nil)
	}
	return labels
}

var pagesAdminTemplate = template.Must(template.New("admin-pages").Parse(`<form method="post" action="{{.Path}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><section><h2>{{index .Labels "about"}}</h2><label for="about-content">{{index .Labels "additional_markdown"}}</label><textarea id="about-content" name="about" rows="8">{{.About}}</textarea><p><a href="{{.AboutPreview}}" target="_blank" rel="noopener">{{index .Labels "preview_public_page"}}</a></p></section><section><h2>{{index .Labels "privacy_policy"}}</h2><p>{{index .Labels "privacy_builtin_description"}}</p><a href="{{.PrivacyPath}}">{{index .Labels "edit_privacy"}}</a></section><section><h2>{{index .Labels "contact"}}</h2><label><input type="checkbox" name="contact_enabled" value="true" {{if .ContactEnabled}}checked{{end}}>{{index .Labels "enable_reporting"}}</label>{{if not .TorRequest}}<label for="contact-recipient">{{index .Labels "general_recipient_email"}}</label><input id="contact-recipient" type="email" name="contact_email" value="{{.ContactEmail}}">{{end}}<label for="contact-captcha">{{index .Labels "captcha"}}</label><select id="contact-captcha" name="contact_captcha"><option value="simple" {{if eq .ContactCaptcha "simple"}}selected{{end}}>{{index .Labels "simple"}}</option><option value="recaptcha" {{if eq .ContactCaptcha "recaptcha"}}selected{{end}}>reCAPTCHA</option><option value="hcaptcha" {{if eq .ContactCaptcha "hcaptcha"}}selected{{end}}>hCaptcha</option></select><label for="contact-success">{{index .Labels "success_message"}}</label><textarea id="contact-success" name="contact_success" rows="3">{{.ContactSuccess}}</textarea></section><section><h2>{{index .Labels "help"}}</h2><label for="help-content">{{index .Labels "help_markdown"}}</label><textarea id="help-content" name="help" rows="10">{{.Help}}</textarea><p><a href="{{.HelpPreview}}" target="_blank" rel="noopener">{{index .Labels "preview_public_page"}}</a></p></section><section><h2>{{index .Labels "terms"}}</h2><label for="terms-content">{{index .Labels "override_markdown"}}</label><textarea id="terms-content" name="terms" rows="8">{{.Terms}}</textarea><p><a href="{{.TermsPreview}}" target="_blank" rel="noopener">{{index .Labels "preview_public_page"}}</a></p></section><button type="submit">{{index .Labels "save_page_settings"}}</button></form>`))

func (s *Server) handlePagesAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
			http.Error(w, serverAdminText(r, "admin.legacy.errors.page_settings_security"), http.StatusForbidden)
			return
		}
		if err := s.updateAdminPages(r); err != nil {
			http.Error(w, serverAdminText(r, "admin.legacy.errors.page_settings_invalid"), http.StatusBadRequest)
			return
		}
		s.auditPrivacyEvent("pages.settings_updated", map[string]any{"source": "admin_web"})
		http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/"+configuredAdminPath(s.Config)+"/pages"), http.StatusSeeOther)
	} else if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, serverAdminText(r, "errors.http_405_message"), http.StatusMethodNotAllowed)
		return
	}
	csrf := s.issuePreferenceCSRF(w, r)
	s.configMu.RLock()
	contactEmail := s.Config.Server.Contact.General.Email
	torRequest := overlayRequestKind(r) == "tor"
	if torRequest {
		contactEmail = ""
	}
	adminPath := configuredAdminPath(s.Config)
	base := prefixPagePath(requestPathPrefix(r), "/server/"+adminPath)
	data := map[string]any{"Path": base + "/pages", "CSRF": csrf, "About": s.Config.Server.Branding.Content.About, "PrivacyPath": base + "/pages/privacy", "AboutPreview": prefixPagePath(requestPathPrefix(r), "/server/about"), "HelpPreview": prefixPagePath(requestPathPrefix(r), "/server/help"), "TermsPreview": prefixPagePath(requestPathPrefix(r), "/server/terms"), "ContactEnabled": s.Config.Server.Pages.Contact.Enabled, "ContactEmail": contactEmail, "TorRequest": torRequest, "ContactCaptcha": s.Config.Server.Pages.Contact.Captcha, "ContactSuccess": s.Config.Server.Pages.Contact.SuccessMessage, "Help": s.Config.Server.Pages.Help.Content, "Terms": s.Config.Server.Branding.Content.Terms, "Labels": serverAdminLabels(r, "admin.legacy.pages", "about", "additional_markdown", "preview_public_page", "privacy_policy", "privacy_builtin_description", "edit_privacy", "contact", "enable_reporting", "general_recipient_email", "captcha", "simple", "success_message", "help", "help_markdown", "terms", "override_markdown", "save_page_settings")}
	s.configMu.RUnlock()
	content := executeTemplate(pagesAdminTemplate, data)
	catalog := serverAdminCatalog(r)
	s.AdminHandler.RenderContentPage(w, r, catalog.T("admin.legacy.pages.title", nil), catalog.T("admin.legacy.pages.description", nil), content)
}

func (s *Server) updateAdminPages(r *http.Request) error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	previous := *s.Config
	s.Config.Server.Branding.Content.About = r.FormValue("about")
	s.Config.Server.Branding.Content.Terms = r.FormValue("terms")
	s.Config.Server.Pages.Help.Content = r.FormValue("help")
	s.Config.Server.Pages.Contact.Enabled = r.FormValue("contact_enabled") == "true"
	s.Config.Server.Pages.Contact.Captcha = r.FormValue("contact_captcha")
	s.Config.Server.Pages.Contact.SuccessMessage = strings.TrimSpace(r.FormValue("contact_success"))
	if overlayRequestKind(r) != "tor" {
		s.Config.Server.Contact.General.Email = strings.TrimSpace(r.FormValue("contact_email"))
	}
	if err := s.Config.Validate(); err != nil {
		*s.Config = previous
		return err
	}
	if err := config.Save(s.Config, s.ConfigPath); err != nil {
		*s.Config = previous
		return err
	}
	return nil
}

func (s *Server) handleAdminPagesAPI(w http.ResponseWriter, r *http.Request) {
	section := chi.URLParam(r, "section")
	if section == "" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": serverAdminText(r, "errors.http_405_message")})
			return
		}
		s.configMu.RLock()
		contactEmail := s.Config.Server.Contact.General.Email
		if overlayRequestKind(r) == "tor" {
			contactEmail = strings.TrimSpace(s.Config.Server.Tor.ContactEmail)
		}
		data := map[string]any{"about": s.Config.Server.Branding.Content.About, "privacy": map[string]any{"path": prefixPagePath(requestPathPrefix(r), "/server/"+configuredAdminPath(s.Config)+"/pages/privacy"), "data_sold": s.Config.Server.Privacy.Data.Sold}, "contact": map[string]any{"enabled": s.Config.Server.Pages.Contact.Enabled, "recipient_email": contactEmail, "captcha": s.Config.Server.Pages.Contact.Captcha, "success_message": s.Config.Server.Pages.Contact.SuccessMessage}, "help": s.Config.Server.Pages.Help.Content, "terms": s.Config.Server.Branding.Content.Terms}
		s.configMu.RUnlock()
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": data})
		return
	}
	if section == "privacy" {
		s.handlePrivacyAdminAPI(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPatch {
		w.Header().Set("Allow", "GET, PATCH")
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": serverAdminText(r, "errors.http_405_message")})
		return
	}
	if r.Method == http.MethodGet {
		s.configMu.RLock()
		contactEmail := s.Config.Server.Contact.General.Email
		if overlayRequestKind(r) == "tor" {
			contactEmail = strings.TrimSpace(s.Config.Server.Tor.ContactEmail)
		}
		var data any
		switch section {
		case "about":
			data = map[string]any{"content": s.Config.Server.Branding.Content.About}
		case "contact":
			data = map[string]any{"enabled": s.Config.Server.Pages.Contact.Enabled, "recipient_email": contactEmail, "captcha": s.Config.Server.Pages.Contact.Captcha, "success_message": s.Config.Server.Pages.Contact.SuccessMessage}
		case "help":
			data = map[string]any{"content": s.Config.Server.Pages.Help.Content}
		case "terms":
			data = map[string]any{"content": s.Config.Server.Branding.Content.Terms}
		default:
			s.configMu.RUnlock()
			http.NotFound(w, r)
			return
		}
		s.configMu.RUnlock()
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": data})
		return
	}
	var patch map[string]json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&patch); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": serverAdminText(r, "admin.legacy.errors.invalid_request")})
		return
	}
	s.configMu.Lock()
	previous := *s.Config
	var err error
	switch section {
	case "about":
		err = patchString(patch, "content", &s.Config.Server.Branding.Content.About)
	case "terms":
		err = patchString(patch, "content", &s.Config.Server.Branding.Content.Terms)
	case "help":
		err = patchString(patch, "content", &s.Config.Server.Pages.Help.Content)
	case "contact":
		err = patchBool(patch, "enabled", &s.Config.Server.Pages.Contact.Enabled)
		if overlayRequestKind(r) == "tor" {
			if err == nil {
				err = patchString(patch, "recipient_email", &s.Config.Server.Tor.ContactEmail)
			}
		} else if err == nil {
			err = patchString(patch, "recipient_email", &s.Config.Server.Contact.General.Email)
		}
		if err == nil {
			err = patchString(patch, "captcha", &s.Config.Server.Pages.Contact.Captcha)
		}
		if err == nil {
			err = patchString(patch, "success_message", &s.Config.Server.Pages.Contact.SuccessMessage)
		}
	default:
		s.configMu.Unlock()
		http.NotFound(w, r)
		return
	}
	if err == nil {
		err = s.Config.Validate()
	}
	if err == nil {
		err = config.Save(s.Config, s.ConfigPath)
	}
	if err != nil {
		*s.Config = previous
	}
	s.configMu.Unlock()
	if err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": serverAdminText(r, "admin.legacy.errors.pages_update_failed")})
		return
	}
	s.auditPrivacyEvent("pages.settings_updated", map[string]any{"source": "admin_api", "section": section})
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func patchString(patch map[string]json.RawMessage, key string, target *string) error {
	if value, ok := patch[key]; ok {
		return json.Unmarshal(value, target)
	}
	return nil
}

func patchBool(patch map[string]json.RawMessage, key string, target *bool) error {
	if value, ok := patch[key]; ok {
		return json.Unmarshal(value, target)
	}
	return nil
}
