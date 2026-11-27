package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"github.com/casapps/casspeed/src/config"
)

var privacyAdminTemplate = template.Must(template.New("privacy-admin").Parse(`{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}<form method="post" action="{{.Path}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><section><h2>{{index .Labels "data_policies"}}</h2><p>{{index .Labels "stored_readonly"}}</p><label><input type="checkbox" name="data_sold" value="true" {{if .Privacy.Data.Sold}}checked{{end}}>{{index .Labels "data_sold"}}</label>{{if .Privacy.Data.Sold}}<p role="alert">{{index .Labels "data_sales_warning"}}</p>{{end}}<label>{{index .Labels "sharing_rules"}}<textarea name="sharing" rows="8">{{.Sharing}}</textarea></label></section><section><h2>{{index .Labels "consent_banner"}}</h2><label><input type="checkbox" name="show_until_acknowledged" value="true" {{if .Privacy.Consent.ShowUntilAcknowledged}}checked{{end}}>{{index .Labels "show_until_choice"}}</label><label>{{index .Labels "message_not_sold"}}<textarea name="message" required>{{.Privacy.Consent.Message}}</textarea></label><label>{{index .Labels "message_sold"}}<textarea name="message_if_sold" required {{if not .Privacy.Data.Sold}}disabled{{end}}>{{.Privacy.Consent.MessageIfSold}}</textarea></label>{{if not .Privacy.Data.Sold}}<input type="hidden" name="message_if_sold" value="{{.Privacy.Consent.MessageIfSold}}">{{end}}<label>{{index .Labels "policy_link_text"}}<input name="policy_text" value="{{.Privacy.Consent.Policy.Text}}"></label><label>{{index .Labels "policy_url"}}<input name="policy_url" value="{{.Privacy.Consent.Policy.URL}}"></label><label>{{index .Labels "policy_version"}}<input name="policy_version" value="{{.Privacy.Consent.Policy.Version}}"></label><label>{{index .Labels "accept_label"}}<input name="accept" value="{{.Privacy.Consent.Buttons.Accept}}"></label><label>{{index .Labels "decline_label"}}<input name="decline" value="{{.Privacy.Consent.Buttons.Decline}}"></label><label>{{index .Labels "position"}}<select name="position"><option value="bottom" {{if eq .Privacy.Consent.Position "bottom"}}selected{{end}}>{{index .Labels "bottom"}}</option><option value="top" {{if eq .Privacy.Consent.Position "top"}}selected{{end}}>{{index .Labels "top"}}</option></select></label><label><input type="checkbox" name="show_preferences" value="true" {{if .Privacy.Consent.ShowPreferences}}checked{{end}}>{{index .Labels "show_manage_preferences"}}</label><label>{{index .Labels "manage_preferences_label"}}<input name="preferences_text" value="{{.Privacy.Consent.PreferencesText}}"></label></section><section><h2>{{index .Labels "cookie_descriptions"}}</h2><label>{{index .Labels "essential_cookies"}}<textarea name="essential_description">{{.Privacy.Cookies.Essential.Description}}</textarea></label><label><input type="checkbox" name="preferences_enabled" value="true" {{if .Privacy.Cookies.Preferences.Enabled}}checked{{end}}>{{index .Labels "offer_preference_cookies"}}</label><label>{{index .Labels "preference_cookies"}}<textarea name="preferences_description">{{.Privacy.Cookies.Preferences.Description}}</textarea></label><label><input type="checkbox" name="analytics_enabled" value="true" {{if .Privacy.Cookies.Analytics.Enabled}}checked{{end}}>{{index .Labels "offer_analytics_cookies"}}</label><label>{{index .Labels "analytics_cookies"}}<textarea name="analytics_description">{{.Privacy.Cookies.Analytics.Description}}</textarea></label><label>{{index .Labels "analytics_suffix_not_sold"}}<input name="analytics_suffix_not_sold" value="{{.Privacy.Cookies.Analytics.DescriptionSuffixNotSold}}"></label><label>{{index .Labels "analytics_suffix_sold"}}<input name="analytics_suffix_sold" value="{{.Privacy.Cookies.Analytics.DescriptionSuffixSold}}"></label></section><section><h2>{{index .Labels "additional_text"}}</h2><label>{{index .Labels "privacy_extension"}}<textarea name="privacy_extension" rows="12">{{.Extension}}</textarea></label></section><section><h2>{{index .Labels "data_retention"}}</h2><label>{{index .Labels "retention_period"}}<textarea name="retention_period" required>{{.Privacy.Retention.Period}}</textarea></label><label><input type="checkbox" name="export_available" value="true" {{if .Privacy.Retention.ExportAvailable}}checked{{end}}>{{index .Labels "data_export_available"}}</label><label><input type="checkbox" name="deletion_available" value="true" {{if .Privacy.Retention.DeletionAvailable}}checked{{end}}>{{index .Labels "account_deletion_available"}}</label></section><section><h2>{{index .Labels "third_parties"}}</h2><label>{{index .Labels "services_json"}}<textarea name="services" rows="8">{{.Services}}</textarea></label></section><section><h2>{{index .Labels "preview"}}</h2><details><summary>{{index .Labels "data_not_sold"}}</summary><p>{{.Privacy.Consent.Message}}</p>{{.BuiltinNotSold}}</details><details><summary>{{index .Labels "data_sold_summary"}}</summary><p>{{.Privacy.Consent.MessageIfSold}}</p>{{.BuiltinSold}}</details></section><button type="submit">{{index .Labels "save"}}</button></form>`))

func (s *Server) handlePrivacyAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
			http.Error(w, serverAdminText(r, "admin.legacy.errors.privacy_security"), http.StatusForbidden)
			return
		}
		if err := s.updatePrivacyFromForm(r); err != nil {
			http.Error(w, serverAdminText(r, "admin.legacy.errors.privacy_invalid"), http.StatusBadRequest)
			return
		}
		s.auditPrivacyEvent("privacy.settings_updated", map[string]any{"source": "admin_web"})
		http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/"+configuredAdminPath(s.Config)+"/privacy"), http.StatusSeeOther)
	} else if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, serverAdminText(r, "errors.http_405_message"), http.StatusMethodNotAllowed)
		return
	}
	csrf := s.issuePreferenceCSRF(w, r)
	s.configMu.RLock()
	privacy := privacyConfigForRequest(r, s.Config.Server.Privacy)
	sharing, _ := json.MarshalIndent(privacy.Data.Sharing, "", "  ")
	services, _ := json.MarshalIndent(privacy.ThirdParty.Services, "", "  ")
	data := map[string]any{"Path": prefixPagePath(requestPathPrefix(r), "/server/"+configuredAdminPath(s.Config)+"/privacy"), "CSRF": csrf, "Privacy": privacy, "Sharing": string(sharing), "Services": string(services), "Extension": s.Config.Server.Branding.Content.Privacy, "BuiltinNotSold": builtinPrivacyDataUsage, "BuiltinSold": builtinPrivacyDataUsageIfSold, "Labels": serverAdminLabels(r, "admin.legacy.privacy", "data_policies", "stored_readonly", "data_sold", "data_sales_warning", "sharing_rules", "consent_banner", "show_until_choice", "message_not_sold", "message_sold", "policy_link_text", "policy_url", "policy_version", "accept_label", "decline_label", "position", "bottom", "top", "show_manage_preferences", "manage_preferences_label", "cookie_descriptions", "essential_cookies", "offer_preference_cookies", "preference_cookies", "offer_analytics_cookies", "analytics_cookies", "analytics_suffix_not_sold", "analytics_suffix_sold", "additional_text", "privacy_extension", "data_retention", "retention_period", "data_export_available", "account_deletion_available", "third_parties", "services_json", "preview", "data_not_sold", "data_sold_summary", "save")}
	s.configMu.RUnlock()
	content := executeTemplate(privacyAdminTemplate, data)
	catalog := serverAdminCatalog(r)
	s.AdminHandler.RenderContentPage(w, r, catalog.T("admin.legacy.privacy.title", nil), catalog.T("admin.legacy.privacy.description", nil), content)
}

func (s *Server) updatePrivacyFromForm(r *http.Request) error {
	var sharing []config.PrivacySharingRule
	if err := json.Unmarshal([]byte(r.FormValue("sharing")), &sharing); err != nil {
		return err
	}
	var services []config.PrivacyThirdPartyService
	if err := json.Unmarshal([]byte(r.FormValue("services")), &services); err != nil {
		return err
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	previous := *s.Config
	s.Config.Server.Privacy.Data.Sold = r.FormValue("data_sold") == "true"
	s.Config.Server.Privacy.Data.Sharing = sharing
	s.Config.Server.Privacy.Retention.Period = strings.TrimSpace(r.FormValue("retention_period"))
	s.Config.Server.Privacy.Retention.ExportAvailable = r.FormValue("export_available") == "true"
	s.Config.Server.Privacy.Retention.DeletionAvailable = r.FormValue("deletion_available") == "true"
	s.Config.Server.Privacy.Consent.Message = r.FormValue("message")
	s.Config.Server.Privacy.Consent.MessageIfSold = r.FormValue("message_if_sold")
	s.Config.Server.Privacy.Consent.Policy.Text = r.FormValue("policy_text")
	s.Config.Server.Privacy.Consent.Policy.URL = r.FormValue("policy_url")
	s.Config.Server.Privacy.Consent.Policy.Version = r.FormValue("policy_version")
	s.Config.Server.Privacy.Consent.Buttons.Accept = r.FormValue("accept")
	s.Config.Server.Privacy.Consent.Buttons.Decline = r.FormValue("decline")
	s.Config.Server.Privacy.Consent.Position = r.FormValue("position")
	s.Config.Server.Privacy.Consent.ShowPreferences = r.FormValue("show_preferences") == "true"
	s.Config.Server.Privacy.Consent.ShowUntilAcknowledged = r.FormValue("show_until_acknowledged") == "true"
	s.Config.Server.Privacy.Consent.PreferencesText = r.FormValue("preferences_text")
	s.Config.Server.Privacy.Cookies.Essential.Enabled = true
	s.Config.Server.Privacy.Cookies.Essential.Description = r.FormValue("essential_description")
	s.Config.Server.Privacy.Cookies.Preferences.Enabled = r.FormValue("preferences_enabled") == "true"
	s.Config.Server.Privacy.Cookies.Preferences.Description = r.FormValue("preferences_description")
	s.Config.Server.Privacy.Cookies.Analytics.Enabled = r.FormValue("analytics_enabled") == "true"
	s.Config.Server.Privacy.Cookies.Analytics.Description = r.FormValue("analytics_description")
	s.Config.Server.Privacy.Cookies.Analytics.DescriptionSuffixNotSold = r.FormValue("analytics_suffix_not_sold")
	s.Config.Server.Privacy.Cookies.Analytics.DescriptionSuffixSold = r.FormValue("analytics_suffix_sold")
	s.Config.Server.Privacy.ThirdParty.Services = services
	s.Config.Server.Branding.Content.Privacy = r.FormValue("privacy_extension")
	if overlayRequestKind(r) == "tor" {
		preserveTorPrivacyPolicyURLs(&previous.Server.Privacy, &s.Config.Server.Privacy)
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

func (s *Server) handlePrivacyAdminAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.configMu.RLock()
		privacy := privacyConfigForRequest(r, s.Config.Server.Privacy)
		s.configMu.RUnlock()
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": privacy})
	case http.MethodPatch:
		var patch map[string]json.RawMessage
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&patch); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": serverAdminText(r, "admin.legacy.errors.invalid_request")})
			return
		}
		s.configMu.Lock()
		previous := *s.Config
		currentJSON, err := json.Marshal(s.Config.Server.Privacy)
		if err == nil {
			var current map[string]json.RawMessage
			err = json.Unmarshal(currentJSON, &current)
			if err == nil {
				err = mergePrivacyJSON(current, patch)
			}
			if err == nil {
				merged, marshalErr := json.Marshal(current)
				if marshalErr != nil {
					err = marshalErr
				} else {
					err = json.Unmarshal(merged, &s.Config.Server.Privacy)
					if err == nil && overlayRequestKind(r) == "tor" {
						preserveTorPrivacyPolicyURLs(&previous.Server.Privacy, &s.Config.Server.Privacy)
					}
				}
			}
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
		privacy := s.Config.Server.Privacy
		s.configMu.Unlock()
		if err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": serverAdminText(r, "admin.legacy.errors.privacy_update_failed")})
			return
		}
		s.auditPrivacyEvent("privacy.settings_updated", map[string]any{"source": "admin_api"})
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": privacyConfigForRequest(r, privacy)})
	default:
		w.Header().Set("Allow", "GET, PATCH")
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": serverAdminText(r, "errors.http_405_message")})
	}
}

func mergePrivacyJSON(destination, patch map[string]json.RawMessage) error {
	for key, value := range patch {
		if !json.Valid(value) {
			return http.ErrBodyNotAllowed
		}
		var nested map[string]json.RawMessage
		if json.Unmarshal(value, &nested) == nil {
			var current map[string]json.RawMessage
			if len(destination[key]) > 0 {
				_ = json.Unmarshal(destination[key], &current)
			}
			if current == nil {
				current = make(map[string]json.RawMessage)
			}
			if err := mergePrivacyJSON(current, nested); err != nil {
				return err
			}
			encoded, err := json.Marshal(current)
			if err != nil {
				return err
			}
			destination[key] = encoded
		} else {
			destination[key] = append(json.RawMessage(nil), value...)
		}
	}
	return nil
}
