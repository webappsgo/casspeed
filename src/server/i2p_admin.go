package server

import (
	"context"
	"html"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/common/i18n"
)

func overlayAdminText(r *http.Request, key string, values map[string]string) string {
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		return key
	}
	return catalog.T("overlay_admin."+key, values)
}

func overlayAdminHTTPError(r *http.Request, status int) string {
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		catalog, _ = i18n.Resolve("en")
	}
	if catalog == nil {
		return "Service error."
	}
	if status == http.StatusMethodNotAllowed {
		return catalog.T("overlay_admin.common.method_not_allowed", nil)
	}
	if status == http.StatusBadGateway || status == http.StatusServiceUnavailable {
		status = http.StatusServiceUnavailable
	}
	return catalog.T("errors.http_"+strconv.Itoa(status)+"_message", nil)
}

func overlayAdminValue(r *http.Request, value string) string {
	key := map[string]string{"running": "running", "stopped": "stopped", "starting": "starting", "stopping": "stopping", "error": "error", "idle": "idle", "searching": "searching", "complete": "complete", "cancelled": "cancelled"}[value]
	if key == "" {
		return value
	}
	return overlayAdminText(r, "common.status_"+key, nil)
}

func (s *Server) handleI2PAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.saveI2PAdminPage(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, overlayAdminText(r, "common.method_not_allowed", nil), http.StatusMethodNotAllowed)
		return
	}
	state := s.currentI2PState()
	info := s.i2PHealth()
	csrf := s.issuePreferenceCSRF(w, r)
	s.configMu.RLock()
	configured := s.Config.Server.I2P
	adminPath := s.Config.Server.AdminPath
	s.configMu.RUnlock()
	if strings.Trim(adminPath, "/") == "" {
		adminPath = "administration"
	}
	pagePath := prefixPagePath(requestPathPrefix(r), "/server/"+adminPath+"/network/i2p")
	var content strings.Builder
	content.WriteString(`<section class="section-card"><h2>` + overlayAdminText(r, "common.runtime_status", nil) + `</h2><dl class="health-details">`)
	content.WriteString("<dt>" + overlayAdminText(r, "common.activation", nil) + "</dt><dd>")
	if configured.Enabled {
		content.WriteString(overlayAdminText(r, "common.status_enabled", nil))
	} else {
		content.WriteString(overlayAdminText(r, "common.status_disabled", nil))
	}
	content.WriteString("</dd><dt>" + overlayAdminText(r, "common.health", nil) + "</dt><dd>" + html.EscapeString(overlayAdminValue(r, info.Status)) + "</dd><dt>" + overlayAdminText(r, "common.lifecycle", nil) + "</dt><dd>" + html.EscapeString(overlayAdminValue(r, state.Status)) + "</dd><dt>" + overlayAdminText(r, "common.provider", nil) + "</dt><dd>" + html.EscapeString(overlayAdminValue(r, info.Provider)) + "</dd>")
	if state.BinaryPath != "" {
		content.WriteString("<dt>" + overlayAdminText(r, "common.binary_path", nil) + "</dt><dd>" + html.EscapeString(state.BinaryPath) + "</dd>")
	}
	if state.SAMAddress != "" {
		content.WriteString("<dt>" + overlayAdminText(r, "common.sam_address", nil) + "</dt><dd>" + html.EscapeString(state.SAMAddress) + "</dd>")
	}
	if !state.StartedAt.IsZero() && state.Status == "running" {
		content.WriteString("<dt>" + overlayAdminText(r, "common.uptime", nil) + "</dt><dd>" + overlayAdminText(r, "common.seconds", map[string]string{"count": strconv.FormatInt(int64(time.Since(state.StartedAt).Seconds()), 10)}) + "</dd>")
	}
	content.WriteString("<dt>" + overlayAdminText(r, "common.address", nil) + "</dt><dd>")
	if info.Hostname != "" {
		content.WriteString(html.EscapeString(info.Hostname))
	} else {
		content.WriteString(overlayAdminText(r, "common.not_available", nil))
	}
	content.WriteString("</dd><dt>" + overlayAdminText(r, "common.public_discovery", nil) + "</dt><dd>")
	if configured.Expose {
		content.WriteString(overlayAdminText(r, "common.status_enabled", nil))
	} else {
		content.WriteString(overlayAdminText(r, "common.status_disabled", nil))
	}
	content.WriteString("</dd></dl></section><section class=\"section-card\"><h2>" + overlayAdminText(r, "common.configuration", nil) + "</h2><form method=\"post\" action=\"" + html.EscapeString(pagePath) + "\"><input type=\"hidden\" name=\"csrf_token\" value=\"" + html.EscapeString(csrf) + "\">")
	content.WriteString("<label><input type=\"checkbox\" name=\"enabled\" value=\"true\"")
	if configured.Enabled {
		content.WriteString(" checked")
	}
	content.WriteString("> " + overlayAdminText(r, "i2p.enable", nil) + "</label><label><input type=\"checkbox\" name=\"expose\" value=\"true\"")
	if configured.Expose {
		content.WriteString(" checked")
	}
	content.WriteString("> " + overlayAdminText(r, "common.publish_discovery", nil) + "</label>")
	content.WriteString(i2pAdminInput(r, "binary", "i2p.binary", configured.Binary, "text"))
	content.WriteString(i2pAdminInput(r, "sam_address", "i2p.sam_address", configured.SAMAddress, "text"))
	content.WriteString(i2pAdminInput(r, "virtual_port", "i2p.virtual_port", strconv.Itoa(configured.VirtualPort), "number"))
	content.WriteString(i2pAdminInput(r, "inbound_length", "i2p.inbound_length", strconv.Itoa(configured.InboundLength), "number"))
	content.WriteString(i2pAdminInput(r, "outbound_length", "i2p.outbound_length", strconv.Itoa(configured.OutboundLength), "number"))
	content.WriteString(i2pAdminInput(r, "inbound_quantity", "i2p.inbound_quantity", strconv.Itoa(configured.InboundQuantity), "number"))
	content.WriteString(i2pAdminInput(r, "outbound_quantity", "i2p.outbound_quantity", strconv.Itoa(configured.OutboundQuantity), "number"))
	content.WriteString(i2pAdminInput(r, "signature_type", "i2p.signature_type", strconv.Itoa(configured.SignatureType), "number"))
	content.WriteString(i2pAdminInput(r, "bootstrap_timeout", "i2p.bootstrap_timeout", strconv.Itoa(configured.BootstrapTimeout), "number"))
	content.WriteString("<button type=\"submit\" name=\"action\" value=\"save\">" + overlayAdminText(r, "common.save_apply", nil) + "</button> <button type=\"submit\" name=\"action\" value=\"restart\">" + overlayAdminText(r, "i2p.restart_provider", nil) + "</button> <button class=\"btn btn-danger\" type=\"button\" popovertarget=\"regenerate-i2p-address\">" + overlayAdminText(r, "common.regenerate_address", nil) + "</button><div id=\"regenerate-i2p-address\" popover aria-labelledby=\"regenerate-i2p-title\"><h3 id=\"regenerate-i2p-title\">" + overlayAdminText(r, "i2p.regenerate_title", nil) + "</h3><p>" + overlayAdminText(r, "i2p.regenerate_warning", nil) + "</p><button class=\"btn btn-secondary\" type=\"button\" popovertarget=\"regenerate-i2p-address\" popovertargetaction=\"hide\">" + overlayAdminText(r, "common.cancel", nil) + "</button><button class=\"btn btn-danger\" type=\"submit\" name=\"action\" value=\"regenerate\">" + overlayAdminText(r, "common.confirm_regeneration", nil) + "</button></div></form></section>")
	s.AdminHandler.RenderContentPage(w, r, overlayAdminText(r, "i2p.page_title", nil), overlayAdminText(r, "i2p.page_lead", nil), content.String())
}

func i2pAdminInput(r *http.Request, name, label, value, inputType string) string {
	return "<label>" + html.EscapeString(overlayAdminText(r, label, nil)) + " <input type=\"" + html.EscapeString(inputType) + "\" name=\"" + html.EscapeString(name) + "\" value=\"" + html.EscapeString(value) + "\"></label>"
}

func (s *Server) saveI2PAdminPage(w http.ResponseWriter, r *http.Request) {
	if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
		http.Error(w, overlayAdminHTTPError(r, http.StatusForbidden), http.StatusForbidden)
		return
	}
	s.configMu.RLock()
	candidate := s.Config.Server.I2P
	adminPath := s.Config.Server.AdminPath
	s.configMu.RUnlock()
	if strings.Trim(adminPath, "/") == "" {
		adminPath = "administration"
	}
	if r.FormValue("action") == "restart" {
		s.overlayMu.RLock()
		manager := s.i2pManager
		s.overlayMu.RUnlock()
		if manager == nil {
			http.Error(w, overlayAdminHTTPError(r, http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if err := manager.UpdateConfig(s.i2pRuntimeConfig(filepath.Dir(s.ConfigPath), s.DataDir, s.LogDir, candidate)); err != nil {
			http.Error(w, overlayAdminHTTPError(r, http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/"+adminPath+"/network/i2p"), http.StatusSeeOther)
		return
	}
	if r.FormValue("action") == "regenerate" {
		s.overlayMu.RLock()
		manager := s.i2pManager
		s.overlayMu.RUnlock()
		if manager == nil {
			http.Error(w, overlayAdminHTTPError(r, http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 11*time.Minute)
		defer cancel()
		if _, err := manager.RegenerateAddress(ctx); err != nil {
			http.Error(w, overlayAdminHTTPError(r, http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/"+adminPath+"/network/i2p"), http.StatusSeeOther)
		return
	}
	candidate.Enabled = r.FormValue("enabled") == "true"
	candidate.Expose = r.FormValue("expose") == "true"
	candidate.Binary = strings.TrimSpace(r.FormValue("binary"))
	candidate.SAMAddress = strings.TrimSpace(r.FormValue("sam_address"))
	for _, field := range []struct {
		name   string
		target *int
	}{
		{"virtual_port", &candidate.VirtualPort}, {"inbound_length", &candidate.InboundLength},
		{"outbound_length", &candidate.OutboundLength}, {"inbound_quantity", &candidate.InboundQuantity},
		{"outbound_quantity", &candidate.OutboundQuantity}, {"signature_type", &candidate.SignatureType},
		{"bootstrap_timeout", &candidate.BootstrapTimeout},
	} {
		parsed, err := strconv.Atoi(r.FormValue(field.name))
		if err != nil {
			http.Error(w, overlayAdminHTTPError(r, http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		*field.target = parsed
	}
	if err := s.validateI2PAdminConfig(candidate); err != nil {
		http.Error(w, overlayAdminHTTPError(r, http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := s.updateI2PAdminConfig(candidate); err != nil {
		http.Error(w, overlayAdminHTTPError(r, http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/"+adminPath+"/network/i2p"), http.StatusSeeOther)
}
