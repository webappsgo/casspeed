package server

import (
	"context"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/tor"
)

func (s *Server) handleTorAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.saveTorAdminPage(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, overlayAdminText(r, "common.method_not_allowed", nil), http.StatusMethodNotAllowed)
		return
	}
	state := s.currentTorState()
	csrf := s.issuePreferenceCSRF(w, r)
	s.overlayMu.RLock()
	vanityManager := s.torVanity
	s.overlayMu.RUnlock()
	vanityStatus := tor.VanityStatus{State: "idle", Candidates: []string{}}
	if vanityManager != nil {
		vanityStatus = vanityManager.Status()
	}
	s.configMu.RLock()
	configured := s.Config.Server.Tor
	adminPath := s.Config.Server.AdminPath
	s.configMu.RUnlock()
	if strings.Trim(adminPath, "/") == "" {
		adminPath = "administration"
	}
	var content strings.Builder
	content.WriteString(`<section class="section-card"><h2>` + overlayAdminText(r, "common.runtime_status", nil) + `</h2><dl class="health-details"><dt>` + overlayAdminText(r, "common.status", nil) + `</dt><dd>` + html.EscapeString(overlayAdminValue(r, state.Status)) + `</dd><dt>` + overlayAdminText(r, "tor.binary", nil) + `</dt><dd>`)
	if state.Binary != "" {
		content.WriteString(html.EscapeString(state.Binary))
	} else {
		content.WriteString(overlayAdminText(r, "tor.not_detected", nil))
	}
	content.WriteString(`</dd><dt>` + overlayAdminText(r, "tor.version", nil) + `</dt><dd>` + html.EscapeString(state.Version) + `</dd><dt>` + overlayAdminText(r, "tor.active_circuits", nil) + `</dt><dd>` + strconv.Itoa(state.CircuitsActive) + `</dd><dt>` + overlayAdminText(r, "tor.onion_address", nil) + `</dt><dd>`)
	if state.Hostname != "" {
		content.WriteString(html.EscapeString(state.Hostname))
	} else {
		content.WriteString(overlayAdminText(r, "common.not_available", nil))
	}
	content.WriteString(`</dd>`)
	if !state.StartedAt.IsZero() && state.Running {
		content.WriteString(`<dt>` + overlayAdminText(r, "common.uptime", nil) + `</dt><dd>` + overlayAdminText(r, "common.seconds", map[string]string{"count": strconv.FormatInt(int64(time.Since(state.StartedAt).Seconds()), 10)}) + `</dd>`)
	}
	content.WriteString(`</dl></section><section class="section-card"><h2>` + overlayAdminText(r, "common.configuration", nil) + `</h2><p>` + overlayAdminText(r, "tor.isolated_explanation", nil) + `</p><form method="post" action="/server/` + html.EscapeString(adminPath) + `/network/tor"><input type="hidden" name="csrf_token" value="` + html.EscapeString(csrf) + `">`)
	content.WriteString(torAdminInput(r, "binary", "tor.binary_input", configured.Binary, "text"))
	content.WriteString(torAdminCheckbox(r, "expose", "common.publish_discovery", configured.Expose))
	content.WriteString(torAdminInput(r, "contact_email", "tor.contact_email", configured.ContactEmail, "email"))
	content.WriteString(torAdminCheckbox(r, "use_network", "tor.route_requests", configured.UseNetwork))
	content.WriteString(torAdminCheckbox(r, "allow_user_preference", "tor.allow_preference", configured.AllowUserPreference))
	content.WriteString(torAdminInput(r, "max_circuits", "tor.max_circuits", strconv.Itoa(configured.MaxCircuits), "number"))
	content.WriteString(torAdminInput(r, "startup_timeout", "tor.startup_timeout", strconv.Itoa(configured.StartupTimeout), "number"))
	content.WriteString(torAdminInput(r, "circuit_timeout", "tor.circuit_timeout", strconv.Itoa(configured.CircuitTimeout), "number"))
	content.WriteString(torAdminInput(r, "bootstrap_timeout", "tor.bootstrap_timeout", strconv.Itoa(configured.BootstrapTimeout), "number"))
	content.WriteString(torAdminCheckbox(r, "safe_logging", "tor.safe_logging", configured.SafeLogging))
	content.WriteString(torAdminInput(r, "max_streams_per_circuit", "tor.max_streams", strconv.Itoa(configured.MaxStreamsPerCircuit), "number"))
	content.WriteString(torAdminCheckbox(r, "close_circuit_on_stream_limit", "tor.close_on_limit", configured.CloseCircuitOnStreamLimit))
	content.WriteString(torAdminInput(r, "bandwidth_rate", "tor.bandwidth_rate", configured.BandwidthRate, "text"))
	content.WriteString(torAdminInput(r, "bandwidth_burst", "tor.bandwidth_burst", configured.BandwidthBurst, "text"))
	content.WriteString(torAdminInput(r, "max_monthly_bandwidth", "tor.monthly_bandwidth", configured.MaxMonthlyBandwidth, "text"))
	content.WriteString(torAdminInput(r, "num_intro_points", "tor.intro_points", strconv.Itoa(configured.NumIntroPoints), "number"))
	content.WriteString(torAdminInput(r, "virtual_port", "tor.virtual_port", strconv.Itoa(configured.VirtualPort), "number"))
	t := func(key string) string { return overlayAdminText(r, "tor."+key, nil) }
	content.WriteString(`<button type="submit" name="action" value="save">` + t("save_restart") + `</button> <button type="submit" name="action" value="restart">` + t("restart") + `</button> <button class="btn btn-danger" type="button" popovertarget="regenerate-tor-address">` + t("regenerate_address") + `</button><div id="regenerate-tor-address" popover aria-labelledby="regenerate-tor-title"><h3 id="regenerate-tor-title">` + t("regenerate_address") + `</h3><p>` + t("regenerate_warning") + `</p><button class="btn btn-secondary" type="button" popovertarget="regenerate-tor-address" popovertargetaction="hide">` + overlayAdminText(r, "common.cancel", nil) + `</button><button class="btn btn-danger" type="submit" name="action" value="regenerate">` + overlayAdminText(r, "common.confirm_regeneration", nil) + `</button></div></form></section>`)
	content.WriteString(`<section class="section-card"><h2>` + t("vanity_title") + `</h2><p>` + t("vanity_explanation") + `</p><p>` + t("search_state") + `: ` + html.EscapeString(overlayAdminValue(r, vanityStatus.State)))
	if vanityStatus.Prefix != "" {
		content.WriteString(` — ` + t("prefix") + ` <code>` + html.EscapeString(vanityStatus.Prefix) + `</code>, ` + strconv.FormatUint(vanityStatus.Attempts, 10) + ` ` + t("attempts") + `, ` + strconv.FormatUint(vanityStatus.Rate, 10) + ` ` + t("attempts_per_second"))
	}
	content.WriteString(`</p><form method="post" action="/server/` + html.EscapeString(adminPath) + `/network/tor/vanity"><input type="hidden" name="csrf_token" value="` + html.EscapeString(csrf) + `"><label>` + t("prefix") + ` <input name="prefix" minlength="1" maxlength="6" pattern="[a-z2-7]+" required></label><label>` + t("workers") + ` <input type="number" name="workers" min="1" value="` + strconv.Itoa(tor.DefaultVanityWorkers()) + `"></label><button name="action" value="start">` + t("start_search") + `</button> <button name="action" value="cancel">` + t("cancel_search") + `</button></form>`)
	for _, address := range vanityStatus.Candidates {
		popoverID := "apply-vanity-" + address
		content.WriteString(`<div class="vanity-candidate"><code>` + html.EscapeString(address) + `</code> <form method="post" action="/server/` + html.EscapeString(adminPath) + `/network/tor/vanity"><input type="hidden" name="csrf_token" value="` + html.EscapeString(csrf) + `"><input type="hidden" name="address" value="` + html.EscapeString(address) + `"><button class="btn btn-danger" type="button" popovertarget="` + html.EscapeString(popoverID) + `">` + t("apply_address") + `</button><div id="` + html.EscapeString(popoverID) + `" popover aria-labelledby="` + html.EscapeString(popoverID) + `-title"><h3 id="` + html.EscapeString(popoverID) + `-title">` + t("apply_vanity_title") + `</h3><p>` + t("apply_vanity_warning") + `</p><button class="btn btn-secondary" type="button" popovertarget="` + html.EscapeString(popoverID) + `" popovertargetaction="hide">` + overlayAdminText(r, "common.cancel", nil) + `</button><button class="btn btn-danger" type="submit" name="action" value="apply">` + t("confirm_apply") + `</button></div></form></div>`)
	}
	content.WriteString(`<h3>` + t("import_title") + `</h3><p>` + t("import_explanation") + `</p><form method="post" enctype="multipart/form-data" action="/server/` + html.EscapeString(adminPath) + `/network/tor/import"><input type="hidden" name="csrf_token" value="` + html.EscapeString(csrf) + `"><label>` + t("zip_archive") + ` <input type="file" name="archive" accept=".zip,application/zip"></label><label>` + t("hostname_optional") + ` <input type="file" name="hostname"></label><label>` + t("secret_key") + ` <input type="file" name="hs_ed25519_secret_key"></label><label>` + t("public_key_optional") + ` <input type="file" name="hs_ed25519_public_key"></label><button type="submit">` + t("import_candidate") + `</button></form></section>`)
	s.AdminHandler.RenderContentPage(w, r, t("page_title"), t("page_lead"), content.String())
}

func (s *Server) handleTorVanityPageAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
		http.Error(w, overlayAdminText(r, "tor.error_security", nil), http.StatusForbidden)
		return
	}
	s.overlayMu.RLock()
	vanity, manager := s.torVanity, s.torManager
	s.overlayMu.RUnlock()
	if vanity == nil || manager == nil {
		http.Error(w, overlayAdminText(r, "tor.error_unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	s.configMu.RLock()
	adminPath := s.Config.Server.AdminPath
	s.configMu.RUnlock()
	if strings.Trim(adminPath, "/") == "" {
		adminPath = "administration"
	}
	switch r.FormValue("action") {
	case "start":
		workers, err := strconv.Atoi(r.FormValue("workers"))
		if err != nil {
			http.Error(w, overlayAdminText(r, "tor.error_workers", nil), http.StatusBadRequest)
			return
		}
		if err := vanity.Start(context.Background(), strings.TrimSpace(r.FormValue("prefix")), workers); err != nil {
			http.Error(w, overlayAdminText(r, "tor.error_search_start", nil), http.StatusConflict)
			return
		}
	case "cancel":
		if !vanity.Cancel() {
			http.Error(w, overlayAdminText(r, "tor.error_no_search", nil), http.StatusConflict)
			return
		}
	case "apply":
		address := r.FormValue("address")
		go func() {
			if err := manager.ApplyVanityCandidate(vanity, address); err != nil && s.Logger != nil && s.Logger.Error != nil {
				s.Logger.Error.Printf("Tor vanity candidate apply failed: %v", err)
			}
		}()
	default:
		http.Error(w, overlayAdminText(r, "tor.error_action", nil), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/server/"+adminPath+"/network/tor", http.StatusSeeOther)
}

func torAdminInput(r *http.Request, name, label, value, inputType string) string {
	return `<label>` + html.EscapeString(overlayAdminText(r, label, nil)) + ` <input type="` + html.EscapeString(inputType) + `" name="` + html.EscapeString(name) + `" value="` + html.EscapeString(value) + `"></label>`
}

func torAdminCheckbox(r *http.Request, name, label string, checked bool) string {
	checkedAttr := ""
	if checked {
		checkedAttr = " checked"
	}
	return `<label><input type="checkbox" name="` + html.EscapeString(name) + `" value="true"` + checkedAttr + `> ` + html.EscapeString(overlayAdminText(r, label, nil)) + `</label>`
}

func (s *Server) saveTorAdminPage(w http.ResponseWriter, r *http.Request) {
	if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
		http.Error(w, overlayAdminText(r, "tor.error_security", nil), http.StatusForbidden)
		return
	}
	s.configMu.RLock()
	candidate := s.Config.Server.Tor
	adminPath := s.Config.Server.AdminPath
	s.configMu.RUnlock()
	if strings.Trim(adminPath, "/") == "" {
		adminPath = "administration"
	}
	if r.FormValue("action") == "restart" || r.FormValue("action") == "regenerate" {
		s.overlayMu.RLock()
		manager := s.torManager
		s.overlayMu.RUnlock()
		if manager == nil {
			http.Error(w, overlayAdminText(r, "tor.error_unavailable", nil), http.StatusServiceUnavailable)
			return
		}
		if r.FormValue("action") == "restart" {
			if err := manager.Restart(); err != nil {
				http.Error(w, overlayAdminText(r, "tor.error_restart", nil), http.StatusBadGateway)
				return
			}
		} else {
			go func() {
				if _, err := manager.RegenerateAddress(); err != nil && s.Logger != nil && s.Logger.Error != nil {
					s.Logger.Error.Printf("Tor address regeneration failed: %v", err)
				}
			}()
		}
		http.Redirect(w, r, "/server/"+adminPath+"/network/tor", http.StatusSeeOther)
		return
	}
	candidate.Binary = strings.TrimSpace(r.FormValue("binary"))
	candidate.Expose = r.FormValue("expose") == "true"
	candidate.ContactEmail = strings.TrimSpace(r.FormValue("contact_email"))
	candidate.UseNetwork = r.FormValue("use_network") == "true"
	candidate.AllowUserPreference = r.FormValue("allow_user_preference") == "true"
	candidate.SafeLogging = r.FormValue("safe_logging") == "true"
	candidate.CloseCircuitOnStreamLimit = r.FormValue("close_circuit_on_stream_limit") == "true"
	candidate.BandwidthRate = strings.TrimSpace(r.FormValue("bandwidth_rate"))
	candidate.BandwidthBurst = strings.TrimSpace(r.FormValue("bandwidth_burst"))
	candidate.MaxMonthlyBandwidth = strings.TrimSpace(r.FormValue("max_monthly_bandwidth"))
	for _, field := range []struct {
		name   string
		target *int
	}{
		{"max_circuits", &candidate.MaxCircuits}, {"startup_timeout", &candidate.StartupTimeout},
		{"circuit_timeout", &candidate.CircuitTimeout}, {"bootstrap_timeout", &candidate.BootstrapTimeout},
		{"max_streams_per_circuit", &candidate.MaxStreamsPerCircuit}, {"num_intro_points", &candidate.NumIntroPoints},
		{"virtual_port", &candidate.VirtualPort},
	} {
		parsed, err := strconv.Atoi(r.FormValue(field.name))
		if err != nil {
			http.Error(w, overlayAdminText(r, "tor.error_number", nil), http.StatusBadRequest)
			return
		}
		*field.target = parsed
	}
	if err := s.validateTorAdminConfig(candidate); err != nil {
		http.Error(w, overlayAdminText(r, "tor.error_config", nil), http.StatusBadRequest)
		return
	}
	if err := s.updateTorAdminConfig(candidate); err != nil {
		http.Error(w, overlayAdminText(r, "tor.error_apply", nil), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/server/"+adminPath+"/network/tor", http.StatusSeeOther)
}
