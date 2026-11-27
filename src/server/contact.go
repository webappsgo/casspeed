package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/server/store"
)

func contactText(r *http.Request, key string) string {
	return serverAdminCatalog(r).T("contact."+key, nil)
}

func localizedContactMessage(r *http.Request, message string) string {
	keys := map[string]string{
		"Invalid form submission": "invalid_form", "Please submit the form from this site": "same_site_only",
		"Security report token is invalid or expired": "invalid_security_token", "Security reports do not use a report type": "security_no_type",
		"Choose an available report type": "choose_report_type", "Invalid submission step": "invalid_step", "Unknown field": "unknown_field",
		"Invalid confirmation fields": "invalid_confirmation", "Please wait a moment and submit again": "wait_and_retry",
		"Edit your report and submit it again": "edit_and_resubmit", "Captcha verification is temporarily unavailable; please try again": "captcha_unavailable",
		"Answer the captcha challenge correctly": "captcha_incorrect", "Your message could not be sent": "message_not_sent",
		"Unable to prepare the review": "review_unavailable", "Please read the details and confirm": "confirm_review",
		"Unable to submit security report": "security_submit_failed", "Report delivery is not configured": "delivery_unavailable",
		"Report delivery failed": "delivery_failed",
	}
	if key := keys[message]; key != "" {
		return contactText(r, key)
	}
	if strings.HasPrefix(message, "unknown field ") {
		return contactText(r, "unknown_field")
	}
	for suffix, key := range map[string]string{" is required": "validation_required", " is too long": "validation_too_long", " contains unsupported characters": "validation_characters", " has an invalid value": "validation_value", " must be checked": "validation_checked"} {
		if strings.HasSuffix(message, suffix) {
			return serverAdminCatalog(r).T("contact."+key, map[string]string{"field": strings.TrimSuffix(message, suffix)})
		}
	}
	validationKeys := map[string]string{"email must be one valid address": "validation_email", "message rejected": "validation_rejected", "markup is not allowed": "validation_markup", "links are not allowed": "validation_links", "link host is not allowed": "validation_link_host", "blocked content": "validation_blocked", "too many links": "validation_too_many_links", "reported URL must be on this service": "validation_reported_url"}
	if key := validationKeys[message]; key != "" {
		return contactText(r, key)
	}
	return message
}

func localizeContactFields(r *http.Request, fields []contactField) []contactField {
	labels := map[string]string{"name": "field_name", "email": "field_email", "type": "field_type", "reported_url": "field_reported_url", "reason": "field_reason", "copyrighted_work": "field_copyrighted_work", "good_faith": "field_good_faith", "accuracy": "field_accuracy", "signature": "field_signature", "request_kind": "field_request_kind", "subject": "field_subject", "message": "field_message", "researcher_gpg": "field_researcher_gpg", "affected_component": "field_affected_component", "affected_endpoint": "field_affected_endpoint", "severity": "field_severity", "vulnerability_summary": "field_vulnerability_summary", "steps_to_reproduce": "field_steps_to_reproduce", "impact": "field_impact", "suggested_fix": "field_suggested_fix"}
	for i := range fields {
		if key := labels[fields[i].Name]; key != "" {
			fields[i].Label = contactText(r, key)
		}
		fields[i].OptionLabels = make([]string, len(fields[i].Options))
		for optionIndex, option := range fields[i].Options {
			fields[i].OptionLabels[optionIndex] = contactText(r, "option_"+option)
		}
	}
	return fields
}

type contactField struct {
	Name          string      `json:"name"`
	Label         string      `json:"label"`
	Type          string      `json:"type"`
	Required      bool        `json:"required"`
	MaxLength     interface{} `json:"max_length"`
	Options       []string    `json:"options,omitempty"`
	OptionLabels  []string    `json:"option_labels,omitempty"`
	RequiredWhen  interface{} `json:"required_when"`
	MaxLengthWhen interface{} `json:"max_length_when"`
}

type captchaChallenge struct {
	ID        string
	Answer    string
	Question  string
	ExpiresAt time.Time
	Provider  string
	SiteKey   string
}

type ContactHandler struct {
	config            *config.Config
	secret            []byte
	deliver           func(role, to, replyTo, subject, body string) error
	mu                sync.Mutex
	forms             map[string]time.Time
	captchaStore      store.CaptchaChallengeStore
	captchaProvider   string
	captchaSiteKey    string
	captchaSecretKey  string
	captchaCalls      map[string][]time.Time
	captchaHTTPClient *http.Client
	reviews           map[string]time.Time
	limits            map[string][]time.Time
	strikes           map[string][]time.Time
	bans              map[string]time.Time
	duplicates        map[string]time.Time
	securityReports   ContactSecuritySubmitter
}

// ContactSecuritySubmitter is the narrow contact-form adapter for the dedicated security pipeline.
type ContactSecuritySubmitter interface {
	ValidSecurityID(string, time.Time) bool
	Submit(context.Context, string, map[string]string, string) (string, string, error)
	LogInvalidSecurityID(string, string, string)
}

var contactMarkupPattern = regexp.MustCompile(`(?i)(<\s*/?\s*[a-z!]|&(?:lt|gt|#0*60|#0*62);|\[(?:/?(?:url|img|b))\b)`)
var contactLinkPattern = regexp.MustCompile(`(?i)(?:\b[a-z][a-z0-9+.-]*://[^\s<>]+|\bwww\.[a-z0-9.-]+(?:\.[a-z]{2,})?\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b)`)
var contactZeroWidthPattern = regexp.MustCompile(`[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{206F}\x{FEFF}]`)

// NewContactHandler creates an in-memory contact form service with a private signing key.
func NewContactHandler(cfg *config.Config) (*ContactHandler, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("create contact signing key: %w", err)
	}
	provider := strings.ToLower(strings.TrimSpace(cfg.Server.Pages.Contact.Captcha))
	siteKey := strings.TrimSpace(cfg.Server.Pages.Contact.CaptchaSiteKey)
	secretKey := strings.TrimSpace(cfg.Server.Pages.Contact.CaptchaSecretKey)
	if provider == "" {
		provider = "simple"
	}
	if provider != "simple" && provider != "recaptcha" && provider != "hcaptcha" {
		log.Printf("contact CAPTCHA provider %q is invalid; using simple", provider)
		provider = "simple"
	}
	if provider != "simple" && (siteKey == "" || secretKey == "") {
		missing := make([]string, 0, 2)
		if siteKey == "" {
			missing = append(missing, "server.pages.contact.captcha_site_key")
		}
		if secretKey == "" {
			missing = append(missing, "server.pages.contact.captcha_secret_key")
		}
		log.Printf("contact CAPTCHA keys missing (%s); using simple", strings.Join(missing, ", "))
		provider = "simple"
	}
	return &ContactHandler{config: cfg, secret: secret, forms: make(map[string]time.Time), reviews: make(map[string]time.Time), captchaProvider: provider, captchaSiteKey: siteKey, captchaSecretKey: secretKey, captchaCalls: make(map[string][]time.Time), captchaHTTPClient: &http.Client{Timeout: 5 * time.Second}, limits: make(map[string][]time.Time), strikes: make(map[string][]time.Time), bans: make(map[string]time.Time), duplicates: make(map[string]time.Time)}, nil
}

func (h *ContactHandler) SetCaptchaStore(challenges store.CaptchaChallengeStore) {
	h.captchaStore = challenges
}

func (h *ContactHandler) SetCaptchaHTTPClient(client *http.Client) {
	if client != nil {
		client.Timeout = 5 * time.Second
		h.captchaHTTPClient = client
	}
}

func (h *ContactHandler) SelectedCaptchaProvider(r *http.Request) string {
	if r != nil && contactIsOnionOrI2P(r) {
		return "simple"
	}
	return h.captchaProvider
}

func (h *ContactHandler) issueCaptcha(r *http.Request) (captchaChallenge, time.Duration, bool, error) {
	if allowed, retry := h.allowCaptchaAction(r, time.Now()); !allowed {
		return captchaChallenge{}, retry, true, nil
	}
	challenge, err := h.newCaptcha()
	if err != nil {
		return captchaChallenge{}, 0, false, err
	}
	challenge.Provider = h.SelectedCaptchaProvider(r)
	challenge.SiteKey = h.captchaSiteKey
	return challenge, 0, false, nil
}

func (h *ContactHandler) allowCaptchaAction(r *http.Request, now time.Time) (bool, time.Duration) {
	policy := h.config.Server.Pages.Contact.Antispam
	if policy.PerIP <= 0 || r == nil {
		return true, 0
	}
	window, err := time.ParseDuration(policy.Window)
	if err != nil || window <= 0 {
		window = time.Hour
	}
	ip := contactClientIP(r)
	h.mu.Lock()
	defer h.mu.Unlock()
	times := pruneTimes(h.captchaCalls[ip], now.Add(-window))
	if len(times) >= policy.PerIP {
		return false, times[0].Add(window).Sub(now)
	}
	if len(h.captchaCalls) >= 50000 {
		for client, recent := range h.captchaCalls {
			recent = pruneTimes(recent, now.Add(-window))
			if len(recent) == 0 {
				delete(h.captchaCalls, client)
			} else {
				h.captchaCalls[client] = recent
			}
		}
		if len(h.captchaCalls) >= 50000 {
			var oldestIP string
			var oldest time.Time
			for client, recent := range h.captchaCalls {
				if len(recent) > 0 && (oldest.IsZero() || recent[0].Before(oldest)) {
					oldestIP, oldest = client, recent[0]
				}
			}
			delete(h.captchaCalls, oldestIP)
		}
	}
	h.captchaCalls[ip] = append(times, now)
	return true, 0
}

func captchaDescriptor(provider string, challenge captchaChallenge) map[string]any {
	fallback := map[string]any{"provider": "simple", "captcha_id": challenge.ID, "question": challenge.Question}
	if provider == "simple" {
		return fallback
	}
	return map[string]any{"provider": provider, "site_key": challenge.SiteKey, "fallback": fallback}
}

// SetDelivery installs the configured delivery implementation.
func (h *ContactHandler) SetDelivery(deliver func(role, to, replyTo, subject, body string) error) {
	h.deliver = deliver
}

func (h *ContactHandler) SetSecurityReportService(service ContactSecuritySubmitter) {
	h.securityReports = service
}

// ServeHTTP serves the no-JavaScript contact page and its form submission.
func (h *ContactHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.config.Server.Pages.Contact.Enabled {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, contactText(r, "method_not_allowed"), http.StatusMethodNotAllowed)
		return
	}
	h.pageHeaders(w)
	if r.Method == http.MethodGet {
		h.servePage(w, r, nil, "")
		return
	}
	h.submitHTML(w, r)
}

// API serves the JSON form descriptor and JSON submissions.
func (h *ContactHandler) API(w http.ResponseWriter, r *http.Request) {
	if !h.config.Server.Pages.Contact.Enabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	switch r.Method {
	case http.MethodGet:
		h.writeDescriptor(w, r)
	case http.MethodPost:
		h.submitAPI(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeContactJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "METHOD_NOT_ALLOWED", "message": contactText(r, "method_not_allowed")})
	}
}

func (h *ContactHandler) pageHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
}

func (h *ContactHandler) servePage(w http.ResponseWriter, r *http.Request, values map[string]string, message string) {
	h.servePageWithStatus(w, r, values, message, http.StatusOK)
}

func (h *ContactHandler) servePageWithStatus(w http.ResponseWriter, r *http.Request, values map[string]string, message string, status int) {
	message = localizedContactMessage(r, message)
	typeName := r.URL.Query().Get("type")
	securityID := r.URL.Query().Get("security_id")
	if values != nil && values["type"] != "" {
		typeName = values["type"]
	}
	securityMode := securityID != "" && h.securityReports != nil && h.securityReports.ValidSecurityID(securityID, time.Now())
	if securityID != "" && !securityMode {
		if values == nil && h.securityReports != nil {
			h.securityReports.LogInvalidSecurityID(securityID, r.RemoteAddr, r.UserAgent())
		}
		securityID = ""
	}
	if values != nil && values["security_id"] != "" {
		securityID = values["security_id"]
		securityMode = h.securityReports != nil && h.securityReports.ValidSecurityID(securityID, time.Now())
	}
	var fields []contactField
	ok := false
	if securityMode {
		typeName = "security"
		fields, ok = append(contactBaseFields(), contactSecurityFields()...), true
	} else {
		fields, ok = contactFields(typeName)
	}
	if !ok {
		fields = nil
	}
	fields = localizeContactFields(r, fields)
	formToken, err := h.newFormToken(time.Now())
	if err != nil {
		h.renderMessage(w, r, http.StatusInternalServerError, contactText(r, "form_unavailable"), contactText(r, "form_prepare_failed"))
		return
	}
	captcha, retry, limited, err := h.issueCaptcha(r)
	if limited {
		h.writeRateLimit(w, r, false, retry)
		return
	}
	if err != nil {
		h.renderMessage(w, r, http.StatusInternalServerError, contactText(r, "form_unavailable"), contactText(r, "form_prepare_failed"))
		return
	}
	data := map[string]interface{}{
		"Type": typeName, "Fields": fields, "Values": values, "Message": message,
		"ContactPath":  prefixPagePath(requestPathPrefix(r), "/server/contact"),
		"SecurityPath": prefixPagePath(requestPathPrefix(r), "/server/security"),
		"FormToken":    formToken, "Captcha": captcha, "Purpose": contactText(r, "purpose"),
		"AbuseEmail": h.publicAbuseEmail(r), "HasForm": fields != nil, "Honeypot": true,
		"FQDN":         h.requestFQDN(r),
		"SecurityMode": securityMode, "SecurityID": securityID, "Labels": map[string]string{"required": contactText(r, "required"), "optional": contactText(r, "optional"), "choose": contactText(r, "choose"), "reported_url_help": contactText(r, "reported_url_help"), "captcha": contactText(r, "captcha"), "captcha_fallback": contactText(r, "captcha_fallback"), "honeypot": contactText(r, "honeypot"), "send_report": contactText(r, "send_report"), "send_security_report": contactText(r, "send_security_report"), "security_page_pointer": contactText(r, "security_page_pointer"), "security_page_label": contactText(r, "security_page_label")},
	}
	page := publicPageTemplateData{Title: contactText(r, "title"), Lead: contactText(r, "purpose"), NoIndex: true}
	shell := &Server{Config: h.config}
	if err := shell.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, contactText(r, "page_unavailable"), http.StatusInternalServerError)
		return
	}
	if fields != nil {
		data["CSRFToken"] = page.CSRFToken
		body := executeTemplate(contactFormBodyTemplate, data)
		page.Sections = []renderedPageSection{{ID: "contact-form", Title: contactText(r, "submit_report"), Content: template.HTML(body)}}
	} else {
		page.Sections = []renderedPageSection{
			{ID: "abuse-report", Title: contactText(r, "chooser_title"), Content: template.HTML(`<p>` + template.HTMLEscapeString(contactText(r, "chooser_lead")) + `</p><p><a href="` + template.HTMLEscapeString(prefixPagePath(requestPathPrefix(r), "/server/contact")) + `?type=abuse">` + template.HTMLEscapeString(contactText(r, "report_abuse")) + `</a> · <a href="` + template.HTMLEscapeString(prefixPagePath(requestPathPrefix(r), "/server/contact")) + `?type=dmca">` + template.HTMLEscapeString(contactText(r, "report_dmca")) + `</a> · <a href="` + template.HTMLEscapeString(prefixPagePath(requestPathPrefix(r), "/server/contact")) + `?type=privacy">` + template.HTMLEscapeString(contactText(r, "privacy_request")) + `</a></p>`)},
			{ID: "security-report", Title: contactText(r, "security_reports"), Content: template.HTML(`<p>` + template.HTMLEscapeString(contactText(r, "security_pointer")) + ` <a href="` + template.HTMLEscapeString(prefixPagePath(requestPathPrefix(r), "/server/security")) + `">` + template.HTMLEscapeString(contactText(r, "security_page_label")) + `</a>.</p>`)},
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pageTemplate.Execute(w, page); err != nil {
		http.Error(w, contactText(r, "render_failed"), http.StatusInternalServerError)
	}
}

var contactFormBodyTemplate = template.Must(template.New("contact-form-body").Funcs(template.FuncMap{"hasMax": func(value interface{}) bool { return value != nil }}).Parse(`<p>{{.Purpose}}</p>{{if .Message}}<p class="alert alert-warning" role="status">{{.Message}}</p>{{end}}
<form method="post" action="{{.ContactPath}}?{{if .SecurityMode}}security_id={{urlquery .SecurityID}}{{else}}type={{urlquery .Type}}{{end}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}">{{if .SecurityMode}}<input type="hidden" name="security_id" value="{{.SecurityID}}">{{else}}<input type="hidden" name="type" value="{{.Type}}">{{end}}<input type="hidden" name="form_token" value="{{.FormToken}}"><input type="hidden" name="step" value="submit">
{{range .Fields}}<div class="form-group"><label for="{{.Name}}">{{.Label}}{{if .Required}} <span>({{$.Labels.required}})</span>{{else}} <span>({{$.Labels.optional}})</span>{{end}}</label>{{if eq .Type "select"}}<select class="form-input" id="{{.Name}}" name="{{.Name}}" {{if .Required}}required{{end}}><option value="">{{$.Labels.choose}}</option>{{$field := .}}{{range $i,$option := .Options}}<option value="{{$option}}">{{index $field.OptionLabels $i}}</option>{{end}}</select>{{else if eq .Type "textarea"}}<textarea class="form-input" id="{{.Name}}" name="{{.Name}}" {{if hasMax .MaxLength}}maxlength="{{.MaxLength}}"{{end}} {{if .Required}}required{{end}}>{{index $.Values .Name}}</textarea>{{else if eq .Type "checkbox"}}<input class="form-input" id="{{.Name}}" name="{{.Name}}" type="checkbox" value="true" {{if .Required}}required{{end}}>{{else}}<input class="form-input" id="{{.Name}}" name="{{.Name}}" type="{{.Type}}" {{if hasMax .MaxLength}}maxlength="{{.MaxLength}}"{{end}} value="{{index $.Values .Name}}" {{if .Required}}required{{end}}>{{end}}{{if eq .Name "reported_url"}}<small>{{$.Labels.reported_url_help}} https://{{$.FQDN}}/...</small>{{end}}</div>{{end}}
{{if eq .Captcha.Provider "simple"}}<div class="form-group"><label for="captcha_answer">{{$.Labels.captcha}}: {{.Captcha.Question}} ({{$.Labels.required}})</label><input class="form-input" id="captcha_answer" name="captcha_answer" inputmode="numeric" required><input type="hidden" name="captcha_id" value="{{.Captcha.ID}}"></div>{{else if eq .Captcha.Provider "recaptcha"}}<fieldset class="form-group"><legend>{{$.Labels.captcha}} ({{$.Labels.required}})</legend><div class="g-recaptcha" data-sitekey="{{.Captcha.SiteKey}}"></div></fieldset><noscript><div class="form-group"><label for="captcha_answer">{{$.Labels.captcha_fallback}}: {{.Captcha.Question}} ({{$.Labels.required}})</label><input class="form-input" id="captcha_answer" name="captcha_answer" inputmode="numeric" required><input type="hidden" name="captcha_id" value="{{.Captcha.ID}}"></div></noscript><script src="https://www.google.com/recaptcha/api.js" async defer></script>{{else}}<fieldset class="form-group"><legend>{{$.Labels.captcha}} ({{$.Labels.required}})</legend><div class="h-captcha" data-sitekey="{{.Captcha.SiteKey}}"></div></fieldset><noscript><div class="form-group"><label for="captcha_answer">{{$.Labels.captcha_fallback}}: {{.Captcha.Question}} ({{$.Labels.required}})</label><input class="form-input" id="captcha_answer" name="captcha_answer" inputmode="numeric" required><input type="hidden" name="captcha_id" value="{{.Captcha.ID}}"></div></noscript><script src="https://js.hcaptcha.com/1/api.js" async defer></script>{{end}}
{{if .Honeypot}}<div class="visually-hidden" aria-hidden="true"><label for="website">{{.Labels.honeypot}}</label><input id="website" name="website" tabindex="-1" autocomplete="off"></div>{{end}}<button class="btn btn-primary" type="submit">{{if .SecurityMode}}{{.Labels.send_security_report}}{{else}}{{.Labels.send_report}}{{end}}</button></form><p>{{.Labels.security_page_pointer}} <a href="{{.SecurityPath}}">{{.Labels.security_page_label}}</a>.</p>`))

func (h *ContactHandler) writeDescriptor(w http.ResponseWriter, r *http.Request) {
	fields := []contactField{
		{Name: "name", Label: "Name", Type: "text", Required: true, MaxLength: 100},
		{Name: "email", Label: "Email", Type: "email", Required: true, MaxLength: 254},
		{Name: "type", Label: "Type", Type: "select", Required: true, Options: []string{"abuse", "dmca", "privacy"}},
		{Name: "reported_url", Label: "Reported URL", Type: "url", MaxLength: 2048, RequiredWhen: map[string]any{"field": "type", "in": []string{"abuse", "dmca"}}},
		{Name: "reason", Label: "Reason", Type: "select", Options: []string{"illegal_content", "terms_violation", "harassment", "malware_phishing", "other"}, RequiredWhen: map[string]string{"field": "type", "equals": "abuse"}},
		{Name: "copyrighted_work", Label: "Copyrighted work", Type: "textarea", MaxLength: 2000, RequiredWhen: map[string]string{"field": "type", "equals": "dmca"}},
		{Name: "good_faith", Label: "Good-faith statement", Type: "checkbox", RequiredWhen: map[string]string{"field": "type", "equals": "dmca"}},
		{Name: "accuracy", Label: "Accuracy statement", Type: "checkbox", RequiredWhen: map[string]string{"field": "type", "equals": "dmca"}},
		{Name: "signature", Label: "Signature", Type: "text", MaxLength: 100, RequiredWhen: map[string]string{"field": "type", "equals": "dmca"}},
		{Name: "request_kind", Label: "Request kind", Type: "select", Options: []string{"access", "export", "deletion", "correction", "opt_out", "other"}, RequiredWhen: map[string]string{"field": "type", "equals": "privacy"}},
		{Name: "subject", Label: "Subject", Type: "text", Required: true, MaxLength: 200},
		{Name: "message", Label: "Message", Type: "textarea", Required: true, MaxLength: 5000},
	}
	selectedType := r.URL.Query().Get("type")
	securityID := r.URL.Query().Get("security_id")
	securityMode := securityID != "" && h.securityReports != nil && h.securityReports.ValidSecurityID(securityID, time.Now())
	if securityID != "" && !securityMode {
		if h.securityReports != nil {
			h.securityReports.LogInvalidSecurityID(securityID, r.RemoteAddr, r.UserAgent())
		}
		securityID = ""
	}
	if selectedType != "" {
		selectedFields, valid := contactFields(selectedType)
		if !valid {
			writeContactJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "VALIDATION_FAILED", "field": "type", "message": contactText(r, "choose_report_type")})
			return
		}
		fields = selectedFields
	}
	if securityMode {
		fields = append(contactBaseFields(), contactSecurityFields()...)
		fields = append(fields, contactField{Name: "security_id", Label: "Security token", Type: "hidden", Required: true})
	} else {
		fields = append([]contactField{{Name: "type", Label: "Type", Type: "select", Required: true, Options: []string{"abuse", "dmca", "privacy"}}}, fields...)
	}
	fields = localizeContactFields(r, fields)
	captcha, retry, limited, err := h.issueCaptcha(r)
	if limited {
		h.writeRateLimit(w, r, false, retry)
		return
	}
	if err != nil {
		writeContactJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "SERVER_ERROR"})
		return
	}
	formToken, err := h.newFormToken(time.Now())
	if err != nil {
		writeContactJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "SERVER_ERROR"})
		return
	}
	types := []string{"abuse", "dmca", "privacy"}
	if securityMode {
		types = []string{"security"}
	}
	data := map[string]any{"fields": fields, "captcha": captchaDescriptor(h.SelectedCaptchaProvider(r), captcha), "form_token": formToken, "types": types, "security_url": absoluteRequestURL(r, "/server/security"), "abuse_email": h.publicAbuseEmail(r)}
	if selectedType != "" {
		data["selected_type"] = selectedType
	}
	if securityMode {
		data["security_id"] = securityID
		data["selected_type"] = "security"
	}
	writeContactJSON(w, http.StatusOK, map[string]any{"ok": true, "data": data})
}

func contactFields(typeName string) ([]contactField, bool) {
	base := contactBaseFields()
	common := []contactField{{Name: "subject", Label: "Subject", Type: "text", Required: true, MaxLength: 200}, {Name: "message", Label: "Message", Type: "textarea", Required: true, MaxLength: 5000}}
	fields := append([]contactField{}, base...)
	switch typeName {
	case "abuse":
		fields = append(fields, contactField{Name: "reported_url", Label: "Reported URL", Type: "url", Required: true, MaxLength: 2048, RequiredWhen: map[string]string{"field": "type", "equals": "abuse"}}, contactField{Name: "reason", Label: "Reason", Type: "select", Required: true, Options: []string{"illegal_content", "terms_violation", "harassment", "malware_phishing", "other"}})
	case "dmca":
		fields = append(fields, contactField{Name: "reported_url", Label: "Reported URL", Type: "url", Required: true, MaxLength: 2048, RequiredWhen: map[string]string{"field": "type", "equals": "dmca"}}, contactField{Name: "copyrighted_work", Label: "Copyrighted work", Type: "textarea", Required: true, MaxLength: 2000}, contactField{Name: "good_faith", Label: "Good-faith statement", Type: "checkbox", Required: true}, contactField{Name: "accuracy", Label: "Accuracy statement", Type: "checkbox", Required: true}, contactField{Name: "signature", Label: "Signature", Type: "text", Required: true, MaxLength: 100})
	case "privacy":
		fields = append(fields, contactField{Name: "request_kind", Label: "Request kind", Type: "select", Required: true, Options: []string{"access", "export", "deletion", "correction", "opt_out", "other"}})
	default:
		return nil, false
	}
	fields = append(fields, common...)
	for i := range fields {
		if fields[i].RequiredWhen == nil {
			fields[i].RequiredWhen = nil
		}
		fields[i].MaxLengthWhen = nil
	}
	return fields, true
}

func contactBaseFields() []contactField {
	return []contactField{{Name: "name", Label: "Name", Type: "text", Required: true, MaxLength: 100}, {Name: "email", Label: "Email", Type: "email", Required: true, MaxLength: 254}}
}

func contactSecurityFields() []contactField {
	return []contactField{
		{Name: "researcher_gpg", Label: "Researcher GPG", Type: "textarea", MaxLength: 16384, MaxLengthWhen: []map[string]any{{"prefix": "https://", "max_length": 2048}}},
		{Name: "affected_component", Label: "Affected component", Type: "text", Required: true, MaxLength: 255},
		{Name: "affected_endpoint", Label: "Affected endpoint / URL", Type: "text", MaxLength: 2048},
		{Name: "severity", Label: "Severity (researcher's self-assessment)", Type: "select", Required: true, Options: []string{"critical", "high", "medium", "low", "informational"}},
		{Name: "vulnerability_summary", Label: "Vulnerability summary", Type: "text", Required: true, MaxLength: 200},
		{Name: "steps_to_reproduce", Label: "Steps to reproduce", Type: "textarea", Required: true, MaxLength: 10000},
		{Name: "impact", Label: "Impact", Type: "textarea", Required: true, MaxLength: 5000},
		{Name: "suggested_fix", Label: "Suggested fix", Type: "textarea", MaxLength: 5000},
		{Name: "cve_requested", Label: "CVE requested?", Type: "checkbox"},
		{Name: "disclosure_days", Label: "Disclosure timeline preference", Type: "number"},
		{Name: "credit_preference", Label: "Credit preference", Type: "select", Required: true, Options: []string{"real_name", "handle", "no", "anonymous"}},
		{Name: "credit_handle", Label: "Credit handle", Type: "text", MaxLength: 100, RequiredWhen: map[string]string{"field": "credit_preference", "equals": "handle"}},
		{Name: "coordinated_disclosure", Label: "Coordinated disclosure agreement", Type: "checkbox", Required: true},
	}
}

func (h *ContactHandler) submitHTML(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	if err := r.ParseForm(); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			http.Error(w, contactText(r, "too_large"), http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, contactText(r, "invalid_form"), http.StatusBadRequest)
		}
		return
	}
	for key, entries := range r.PostForm {
		if len(entries) > 1 {
			h.logBlocked("shape", r)
			h.contactFailure(w, r, contactValues(r.PostForm), false, key, "Invalid form submission")
			return
		}
	}
	if !sameContactOrigin(r) {
		h.recordStrike(r, time.Now())
		h.logBlocked("origin", r)
		h.pageHeaders(w)
		w.WriteHeader(http.StatusBadRequest)
		h.servePage(w, r, contactValues(r.PostForm), "Please submit the form from this site")
		return
	}
	values := contactValues(r.PostForm)
	h.handleSubmission(w, r, values, false)
}

func (h *ContactHandler) submitAPI(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	body, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(readErr, &maxBytesError) {
			writeContactJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "REQUEST_TOO_LARGE"})
		} else {
			writeContactJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "INVALID_REQUEST"})
		}
		return
	}
	if !utf8.Valid(body) {
		writeContactJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "VALIDATION_FAILED", "field": "body"})
		return
	}
	var rawValues map[string]json.RawMessage
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(&rawValues); err != nil || rawValues == nil {
		writeContactJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "INVALID_REQUEST", "message": contactText(r, "invalid_json")})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeContactJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "INVALID_REQUEST", "message": contactText(r, "invalid_json")})
		return
	}
	values := make(map[string]string, len(rawValues))
	for key, raw := range rawValues {
		if strings.ContainsAny(key, "\r\n") {
			writeContactJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "VALIDATION_FAILED", "field": key})
			return
		}
		var value string
		if err := json.Unmarshal(raw, &value); err == nil {
			values[key] = value
			continue
		}
		var boolean bool
		if err := json.Unmarshal(raw, &boolean); err == nil {
			if boolean {
				values[key] = "true"
			} else {
				values[key] = "false"
			}
			continue
		}
		writeContactJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "VALIDATION_FAILED", "field": key})
		return
	}
	h.handleSubmission(w, r, values, true)
}

func contactValues(values map[string][]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, entries := range values {
		if len(entries) > 0 {
			result[key] = entries[0]
		}
	}
	return result
}

func (h *ContactHandler) handleSubmission(w http.ResponseWriter, r *http.Request, values map[string]string, api bool) {
	typeName := values["type"]
	securityID := values["security_id"]
	securityMode := securityID != "" && h.securityReports != nil && h.securityReports.ValidSecurityID(securityID, time.Now())
	if securityID != "" && !securityMode {
		if h.securityReports != nil {
			h.securityReports.LogInvalidSecurityID(securityID, r.RemoteAddr, r.UserAgent())
		}
		h.contactFailure(w, r, values, api, "security_id", "Security report token is invalid or expired")
		return
	}
	var fields []contactField
	ok := false
	if securityMode {
		if typeName != "" {
			h.contactFailure(w, r, values, api, "type", "Security reports do not use a report type")
			return
		}
		typeName = "security"
		fields, ok = append(contactBaseFields(), contactSecurityFields()...), true
	} else {
		fields, ok = contactFields(typeName)
	}
	if !ok {
		h.contactFailure(w, r, values, api, "type", "Choose an available report type")
		return
	}
	step := values["step"]
	if step == "" {
		step = "submit"
	}
	if step != "submit" && step != "confirm" && step != "edit" {
		h.logBlocked("shape", r)
		h.contactFailure(w, r, values, api, "step", "Invalid submission step")
		return
	}
	if step != "confirm" && (values["review_token"] != "" || values["confirmed"] != "") {
		h.contactFailure(w, r, values, api, "field", "Unknown field")
		return
	}
	now := time.Now()
	if err := validateContactShape(values, fields); err != nil {
		h.logBlocked("shape", r)
		h.contactFailure(w, r, values, api, "field", err.Error())
		return
	}
	if step == "confirm" {
		if values["form_token"] == "" || values["captcha_id"] != "" || values["captcha_answer"] != "" {
			h.logBlocked("shape", r)
			h.contactFailure(w, r, values, api, "field", "Invalid confirmation fields")
			return
		}
		if !h.consumeReviewFormToken(values["form_token"], now) {
			h.logBlocked("replay", r)
			h.contactFailure(w, r, values, api, "form_token", "Please wait a moment and submit again")
			return
		}
	}
	if step == "submit" || step == "confirm" {
		if banned, retry := h.checkBan(r, now); banned {
			h.logBlocked("banned", r)
			h.writeRateLimit(w, r, api, retry)
			return
		}
	}
	if step == "edit" {
		delete(values, "step")
		delete(values, "review_token")
		delete(values, "confirmed")
		if api {
			h.contactFailure(w, r, values, true, "message", "Edit your report and submit it again")
		} else {
			h.servePage(w, r, values, "Edit your report and submit it again")
		}
		return
	}
	if step == "submit" {
		if values["website"] != "" {
			h.recordStrike(r, now)
			h.logBlocked("honeypot", r)
		}
		if reason := h.consumeFormTokenFailure(values["form_token"], now); reason != "" {
			if reason == "replay" {
				h.recordStrike(r, now)
			}
			h.logBlocked(reason, r)
			h.contactFailure(w, r, values, api, "form_token", "Please wait a moment and submit again")
			return
		}
		captchaOK, captchaUnavailable, captchaLimited, captchaRetry := h.verifyCaptchaSubmission(r, values, now)
		if captchaLimited {
			h.writeRateLimit(w, r, api, captchaRetry)
			return
		}
		if captchaUnavailable {
			h.contactFailure(w, r, values, api, "CAPTCHA_UNAVAILABLE", "Captcha verification is temporarily unavailable; please try again")
			return
		}
		if !captchaOK {
			h.recordStrike(r, now)
			h.logBlocked("captcha", r)
			h.contactFailure(w, r, values, api, "captcha", "Answer the captcha challenge correctly")
			return
		}
		if limited, retry := h.checkLimits(r, values["email"], now); limited {
			h.logBlocked(h.limitReason(r, values["email"], now), r)
			h.writeRateLimit(w, r, api, retry)
			return
		}
		if !securityMode {
			if err := validateContactContent(r, values, fields, h.config.Server.Pages.Contact.Antispam.RejectMarkup, h.config); err != nil {
				h.recordStrike(r, now)
				reason := "content"
				if strings.Contains(strings.ToLower(err.Error()), "markup") {
					reason = "markup"
				}
				h.logBlocked(reason, r)
				h.contactFailure(w, r, values, api, "content", "Your message could not be sent")
				return
			}
		}
		freshFormToken, tokenErr := h.newFormToken(now)
		if tokenErr != nil {
			h.contactFailure(w, r, values, api, "SERVER_ERROR", "Unable to prepare the review")
			return
		}
		values["form_token"] = freshFormToken
		reviewToken, err := h.newReviewToken(values, now)
		if err != nil {
			h.contactFailure(w, r, values, api, "SERVER_ERROR", "Unable to prepare the review")
			return
		}
		if api {
			reviewSubject := values["subject"]
			if securityMode {
				reviewSubject = values["vulnerability_summary"]
			}
			writeContactJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"review": map[string]string{"type": typeName, "email": values["email"], "subject": reviewSubject}, "review_token": reviewToken, "form_token": freshFormToken, "confirm_after_seconds": h.config.Server.Pages.Contact.Antispam.ReviewMinSeconds}})
			return
		}
		h.serveReview(w, r, values, reviewToken)
		return
	}
	if step != "confirm" || values["confirmed"] != "true" && values["confirmed"] != "on" {
		h.contactReviewFailure(w, r, values, api, "confirmed", "Please read the details and confirm", now)
		return
	}
	if !h.consumeReviewToken(values["review_token"], values, now) {
		h.logBlocked("review", r)
		h.contactReviewFailure(w, r, values, api, "review_token", "Please read the details and confirm", now)
		return
	}
	if limited, retry := h.checkLimits(r, values["email"], now); limited {
		h.logBlocked(h.limitReason(r, values["email"], now), r)
		h.writeRateLimit(w, r, api, retry)
		return
	}
	if securityMode {
		if h.securityReports == nil || !h.securityReports.ValidSecurityID(values["security_id"], now) {
			h.contactFailure(w, r, values, api, "security_id", "Security report token is invalid or expired")
			return
		}
		if values["website"] == "dropped" {
			h.countAccepted(r, values["email"], now)
			h.writeAccepted(w, r, api)
			return
		}
		reportFields := make(map[string]string, len(fields)+2)
		reportFields["name"], reportFields["email"] = values["name"], values["email"]
		for _, field := range fields {
			reportFields[field.Name] = values[field.Name]
		}
		trackingID, statusURL, err := h.securityReports.Submit(r.Context(), values["security_id"], reportFields, r.UserAgent())
		if err != nil {
			h.contactFailure(w, r, values, api, "SERVER_ERROR", "Unable to submit security report")
			return
		}
		acknowledgmentSent := false
		if h.deliver != nil && statusURL != "" {
			body := []byte("We received your security report.\n\nTracking ID: " + trackingID + "\nStatus page: " + statusURL + "\n")
			researcherKey := strings.TrimSpace(reportFields["researcher_gpg"])
			if researcherKey != "" {
				encrypted, encryptionErr := EncryptResearcherAcknowledgment(r.Context(), researcherKey, body)
				if encryptionErr != nil {
					body = nil
				} else {
					body = encrypted
				}
			}
			if len(body) > 0 {
				acknowledgmentSent = h.deliver("security", values["email"], "", "Security report received", string(body)) == nil
			}
		}
		if logger, ok := h.securityReports.(interface {
			LogReportReceived(context.Context, string, bool)
		}); ok {
			logger.LogReportReceived(r.Context(), trackingID, acknowledgmentSent)
		}
		h.countAccepted(r, values["email"], now)
		if api {
			message := serverAdminCatalog(r).T("contact.submitted_tracking", map[string]string{"id": trackingID})
			if acknowledgmentSent {
				message += " " + contactText(r, "confirmation_email_sent")
			}
			writeContactJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]string{"tracking_id": trackingID, "message": message}})
			return
		}
		message := serverAdminCatalog(r).T("contact.submitted_tracking", map[string]string{"id": trackingID})
		if acknowledgmentSent {
			message += " " + contactText(r, "confirmation_email_sent")
		}
		h.renderMessage(w, r, http.StatusOK, contactText(r, "report_received"), message)
		return
	}
	if h.isDuplicate(values, now) {
		h.recordStrike(r, now)
		h.logBlocked("duplicate", r)
		h.writeAccepted(w, r, api)
		return
	}
	if values["website"] != "dropped" && h.deliver == nil {
		h.contactFailure(w, r, values, api, "SERVER_ERROR", "Report delivery is not configured")
		return
	}
	if values["website"] != "dropped" {
		role := "abuse"
		recipient := h.resolveRecipient(role)
		if typeName == "privacy" {
			role = "privacy"
			recipient = h.resolveRecipient(role)
		}
		if recipient == "" {
			h.contactFailure(w, r, values, api, "SERVER_ERROR", "Report delivery is not configured")
			return
		}
		if err := h.deliver(role, recipient, values["email"], "[CasSpeed contact] "+values["subject"], formatContactBody(typeName, values)); err != nil {
			h.contactFailure(w, r, values, api, "SERVER_ERROR", "Report delivery failed")
			return
		}
	}
	h.countAccepted(r, values["email"], now)
	h.rememberDuplicate(values, now)
	h.writeAccepted(w, r, api)
}

func (h *ContactHandler) verifyCaptchaSubmission(r *http.Request, values map[string]string, now time.Time) (valid, unavailable, limited bool, retry time.Duration) {
	if allowed, retry := h.allowCaptchaAction(r, now); !allowed {
		return false, false, true, retry
	}
	provider := h.SelectedCaptchaProvider(r)
	response := values["captcha_response"]
	externalProofPresent := response != "" || values["g-recaptcha-response"] != "" || values["h-captcha-response"] != ""
	if provider == "recaptcha" {
		if values["g-recaptcha-response"] != "" {
			response = values["g-recaptcha-response"]
		}
	} else if provider == "hcaptcha" {
		if values["h-captcha-response"] != "" {
			response = values["h-captcha-response"]
		}
	}
	if externalProofPresent {
		if values["captcha_id"] != "" {
			h.discardCaptcha(values["captcha_id"])
		}
		if provider == "simple" || response == "" {
			return false, false, false, 0
		}
		valid, reachable := h.verifyExternalCaptcha(r, provider, response)
		return valid, !reachable, false, 0
	}
	return h.consumeCaptcha(values["captcha_id"], values["captcha_answer"], now), false, false, 0
}

func (h *ContactHandler) verifyExternalCaptcha(r *http.Request, provider, response string) (bool, bool) {
	endpoint := ""
	switch provider {
	case "recaptcha":
		endpoint = "https://www.google.com/recaptcha/api/siteverify"
	case "hcaptcha":
		endpoint = "https://api.hcaptcha.com/siteverify"
	default:
		return false, false
	}
	form := url.Values{"secret": {h.captchaSecretKey}, "response": {response}, "remoteip": {contactClientIP(r)}}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, false
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := h.captchaHTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	result, err := client.Do(request)
	if err != nil {
		return false, false
	}
	defer result.Body.Close()
	if result.StatusCode < http.StatusOK || result.StatusCode >= http.StatusMultipleChoices {
		return false, false
	}
	var payload struct {
		Success bool `json:"success"`
	}
	decoder := json.NewDecoder(io.LimitReader(result.Body, 1<<20))
	if err := decoder.Decode(&payload); err != nil {
		return false, false
	}
	return payload.Success, true
}

func (h *ContactHandler) writeAccepted(w http.ResponseWriter, r *http.Request, api bool) {
	if api {
		writeContactJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]bool{"accepted": true}})
		return
	}
	message := strings.TrimSpace(h.config.Server.Pages.Contact.SuccessMessage)
	if message == "" {
		message = contactText(r, "submitted")
	}
	h.renderMessage(w, r, http.StatusOK, contactText(r, "report_received"), message)
}

func (h *ContactHandler) renderMessage(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	page := publicPageTemplateData{Title: title, Lead: message, NoIndex: true, Sections: []renderedPageSection{{ID: "contact-message", Title: title, Content: template.HTML(`<p role="status">` + template.HTMLEscapeString(message) + `</p>`)}}}
	shell := &Server{Config: h.config}
	if err := shell.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, contactText(r, "page_unavailable"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, page)
}

func (h *ContactHandler) contactFailure(w http.ResponseWriter, r *http.Request, values map[string]string, api bool, field, message string) {
	message = localizedContactMessage(r, message)
	status := http.StatusBadRequest
	errorCode := "VALIDATION_FAILED"
	if field == "SERVER_ERROR" {
		status = http.StatusServiceUnavailable
		errorCode = "SERVER_ERROR"
	} else if field == "CAPTCHA_UNAVAILABLE" {
		status = http.StatusServiceUnavailable
		errorCode = "CAPTCHA_UNAVAILABLE"
	}
	if api {
		captcha, retry, limited, captchaErr := h.issueCaptcha(r)
		if limited {
			h.writeRateLimit(w, r, true, retry)
			return
		}
		formToken, tokenErr := h.newFormToken(time.Now())
		payload := map[string]any{"ok": false, "error": errorCode, "field": field, "message": message}
		if captchaErr == nil {
			payload["captcha"] = captchaDescriptor(h.SelectedCaptchaProvider(r), captcha)
		}
		if tokenErr == nil {
			payload["form_token"] = formToken
		}
		writeContactJSON(w, status, payload)
		return
	}
	h.pageHeaders(w)
	h.servePageWithStatus(w, r, values, message, status)
}

func (h *ContactHandler) writeRateLimit(w http.ResponseWriter, r *http.Request, api bool, retry time.Duration) {
	seconds := int(retry.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	if api {
		writeContactJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "RATE_LIMITED", "message": contactText(r, "try_again_later")})
		return
	}
	h.renderMessage(w, r, http.StatusTooManyRequests, contactText(r, "try_again_later_title"), contactText(r, "try_again_later"))
}

func (h *ContactHandler) policyWindow() time.Duration {
	duration, err := time.ParseDuration(h.config.Server.Pages.Contact.Antispam.Window)
	if err != nil || duration <= 0 {
		return time.Hour
	}
	return duration
}

func (h *ContactHandler) limitReason(r *http.Request, email string, now time.Time) string {
	if !contactIsOnionOrI2P(r) {
		ip := "ip:" + contactClientIP(r)
		h.mu.Lock()
		banned := now.Before(h.bans[contactClientIP(r)])
		ipCount := len(pruneTimes(h.limits[ip], now.Add(-h.policyWindow())))
		h.mu.Unlock()
		if banned {
			return "banned"
		}
		if max := h.config.Server.Pages.Contact.Antispam.PerIP; max > 0 && ipCount >= max {
			return "rate_ip"
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if max := h.config.Server.Pages.Contact.Antispam.PerEmail; max > 0 && len(pruneTimes(h.limits["email:"+strings.ToLower(strings.TrimSpace(email))], now.Add(-h.policyWindow()))) >= max {
		return "rate_email"
	}
	return "rate_global"
}

func contactClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func contactIsOnionOrI2P(r *http.Request) bool {
	host := strings.ToLower(r.Host)
	return strings.HasSuffix(host, ".onion") || strings.HasSuffix(host, ".i2p")
}

func (h *ContactHandler) checkLimits(r *http.Request, email string, now time.Time) (bool, time.Duration) {
	ip := contactClientIP(r)
	window := h.policyWindow()
	h.mu.Lock()
	defer h.mu.Unlock()
	if until := h.bans[ip]; !contactIsOnionOrI2P(r) && now.Before(until) {
		return true, until.Sub(now)
	}
	if until := h.bans[ip]; !now.Before(until) {
		delete(h.bans, ip)
	}
	keys := []struct {
		key string
		max int
	}{{"email:" + strings.ToLower(strings.TrimSpace(email)), h.config.Server.Pages.Contact.Antispam.PerEmail}, {"global", h.config.Server.Pages.Contact.Antispam.Global}}
	if !contactIsOnionOrI2P(r) {
		keys = append([]struct {
			key string
			max int
		}{{"ip:" + ip, h.config.Server.Pages.Contact.Antispam.PerIP}}, keys...)
	}
	for _, limit := range keys {
		times := pruneTimes(h.limits[limit.key], now.Add(-window))
		h.limits[limit.key] = times
		if limit.max > 0 && len(times) >= limit.max {
			return true, times[0].Add(window).Sub(now)
		}
	}
	return false, 0
}

func (h *ContactHandler) checkBan(r *http.Request, now time.Time) (bool, time.Duration) {
	if contactIsOnionOrI2P(r) {
		return false, 0
	}
	ip := contactClientIP(r)
	h.mu.Lock()
	defer h.mu.Unlock()
	until, exists := h.bans[ip]
	if !exists || !now.Before(until) {
		delete(h.bans, ip)
		return false, 0
	}
	return true, until.Sub(now)
}

func (h *ContactHandler) countAccepted(r *http.Request, email string, now time.Time) {
	window := h.policyWindow()
	ip := contactClientIP(r)
	h.mu.Lock()
	defer h.mu.Unlock()
	keys := []string{"email:" + strings.ToLower(strings.TrimSpace(email)), "global"}
	if !contactIsOnionOrI2P(r) {
		keys = append(keys, "ip:"+ip)
	}
	for _, key := range keys {
		h.limits[key] = append(pruneTimes(h.limits[key], now.Add(-window)), now)
	}
}

func pruneTimes(times []time.Time, cutoff time.Time) []time.Time {
	first := 0
	for first < len(times) && times[first].Before(cutoff) {
		first++
	}
	return append([]time.Time(nil), times[first:]...)
}

func (h *ContactHandler) recordStrike(r *http.Request, now time.Time) {
	if contactIsOnionOrI2P(r) {
		return
	}
	ip := contactClientIP(r)
	policy := h.config.Server.Pages.Contact.Antispam
	h.mu.Lock()
	defer h.mu.Unlock()
	window := h.policyWindow()
	times := append(pruneTimes(h.strikes[ip], now.Add(-window)), now)
	h.strikes[ip] = times
	if policy.Strikes > 0 && len(times) >= policy.Strikes {
		h.bans[ip] = now.Add(time.Duration(policy.BanHours) * time.Hour)
	}
}

func (h *ContactHandler) logBlocked(reason string, r *http.Request) {
	log.Printf("contact.spam_blocked reason=%q ip=%q", reason, contactClientIP(r))
}

func normalizedDuplicateKey(values map[string]string) string {
	normalize := func(value string) string {
		return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(value)), " "))
	}
	return contactHash(normalize(values["email"]) + "\n" + normalize(values["subject"]) + "\n" + normalize(values["message"]))
}

func (h *ContactHandler) isDuplicate(values map[string]string, now time.Time) bool {
	key := normalizedDuplicateKey(values)
	h.mu.Lock()
	defer h.mu.Unlock()
	for hash, expires := range h.duplicates {
		if !now.Before(expires) {
			delete(h.duplicates, hash)
		}
	}
	expires, exists := h.duplicates[key]
	return exists && now.Before(expires)
}

func (h *ContactHandler) rememberDuplicate(values map[string]string, now time.Time) {
	window := time.Duration(h.config.Server.Pages.Contact.Antispam.DuplicateWindowHours) * time.Hour
	if window <= 0 {
		return
	}
	key := normalizedDuplicateKey(values)
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.duplicates) >= 10000 {
		var oldestKey string
		var oldest time.Time
		for candidate, expires := range h.duplicates {
			if oldest.IsZero() || expires.Before(oldest) {
				oldestKey, oldest = candidate, expires
			}
		}
		delete(h.duplicates, oldestKey)
	}
	h.duplicates[key] = now.Add(window)
}

func (h *ContactHandler) serveReview(w http.ResponseWriter, r *http.Request, values map[string]string, token string) {
	h.pageHeaders(w)
	subject := values["subject"]
	if values["type"] == "" && values["security_id"] != "" {
		subject = values["vulnerability_summary"]
	}
	h.renderContactReview(w, r, map[string]interface{}{"Email": values["email"], "Type": contactReviewType(values), "Subject": subject, "Values": contactReviewFields(values), "ReviewToken": token})
}

func (h *ContactHandler) renderContactReview(w http.ResponseWriter, r *http.Request, data map[string]interface{}) {
	if kind, ok := data["Type"].(string); ok && kind != "" {
		data["Type"] = contactText(r, "option_"+kind)
	}
	page := publicPageTemplateData{Title: contactText(r, "review_title"), Lead: contactText(r, "review_lead"), NoIndex: true}
	shell := &Server{Config: h.config}
	if err := shell.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, contactText(r, "page_unavailable"), http.StatusInternalServerError)
		return
	}
	data["CSRFToken"] = page.CSRFToken
	data["ContactPath"] = prefixPagePath(requestPathPrefix(r), "/server/contact")
	data["EmailLabel"] = contactText(r, "email_label")
	data["TypeLabel"] = contactText(r, "type_label")
	data["SubjectLabel"] = contactText(r, "subject_label")
	data["ConfirmStatement"] = contactText(r, "confirm_statement")
	data["Confirm"] = contactText(r, "confirm")
	data["Edit"] = contactText(r, "edit")
	body := executeTemplate(contactReviewBodyTemplate, data)
	page.Sections = []renderedPageSection{{ID: "contact-review", Title: contactText(r, "review_title"), Content: template.HTML(body)}}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTemplate.Execute(w, page)
}

func (h *ContactHandler) contactReviewFailure(w http.ResponseWriter, r *http.Request, values map[string]string, api bool, field, message string, now time.Time) {
	message = localizedContactMessage(r, message)
	if api {
		formToken, formErr := h.newFormToken(now)
		token, tokenErr := h.newReviewToken(values, now)
		payload := map[string]any{"ok": false, "error": "VALIDATION_FAILED", "field": field, "message": message}
		if formErr == nil && tokenErr == nil {
			payload["data"] = map[string]any{
				"review":       map[string]string{"type": values["type"], "email": values["email"], "subject": values["subject"]},
				"review_token": token, "form_token": formToken,
				"confirm_after_seconds": h.config.Server.Pages.Contact.Antispam.ReviewMinSeconds,
			}
		}
		writeContactJSON(w, http.StatusBadRequest, payload)
		return
	}
	if freshToken, err := h.newFormToken(now); err == nil {
		values["form_token"] = freshToken
	}
	if token, err := h.newReviewToken(values, now); err == nil {
		subject := values["subject"]
		if values["type"] == "" && values["security_id"] != "" {
			subject = values["vulnerability_summary"]
		}
		data := map[string]interface{}{"Email": values["email"], "Type": contactReviewType(values), "Subject": subject, "Values": contactReviewFields(values), "ReviewToken": token, "Message": message}
		h.renderContactReview(w, r, data)
		return
	}
	h.servePage(w, r, values, message)
}

func contactReviewFields(values map[string]string) map[string]string {
	fields := make(map[string]string, len(values))
	for key, value := range values {
		if key == "step" || key == "review_token" || key == "confirmed" || key == "csrf_token" || key == "__dropped" || key == "captcha_id" || key == "captcha_answer" {
			continue
		}
		fields[key] = value
	}
	return fields
}

func contactReviewType(values map[string]string) string {
	if values["type"] != "" {
		return values["type"]
	}
	if values["security_id"] != "" {
		return "security"
	}
	return ""
}

var contactReviewBodyTemplate = template.Must(template.New("contact-review-body").Parse(`<p>{{.EmailLabel}}: <strong>{{.Email}}</strong></p><p>{{.TypeLabel}}: {{.Type}}</p><p>{{.SubjectLabel}}: {{.Subject}}</p><form method="post" action="{{.ContactPath}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="step" value="confirm"><input type="hidden" name="review_token" value="{{.ReviewToken}}">{{range $key,$value := .Values}}<input type="hidden" name="{{$key}}" value="{{$value}}">{{end}}<label><input type="checkbox" name="confirmed" value="true" required>{{.ConfirmStatement}}</label><button type="submit">{{.Confirm}}</button></form><form method="post" action="{{.ContactPath}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="step" value="edit">{{range $key,$value := .Values}}<input type="hidden" name="{{$key}}" value="{{$value}}">{{end}}<button type="submit">{{.Edit}}</button></form>`))

func validateContactShape(values map[string]string, fields []contactField) error {
	allowed := map[string]bool{"type": true, "security_id": true, "form_token": true, "csrf_token": true, "captcha_id": true, "captcha_answer": true, "captcha_response": true, "g-recaptcha-response": true, "h-captcha-response": true, "website": true, "step": true, "review_token": true, "confirmed": true}
	for _, field := range fields {
		allowed[field.Name] = true
	}
	for key := range values {
		if !allowed[key] {
			return fmt.Errorf("unknown field %s", key)
		}
	}
	for _, field := range fields {
		value := strings.TrimSpace(values[field.Name])
		required := field.Required || field.Name == "credit_handle" && values["credit_preference"] == "handle"
		if required && value == "" {
			return fmt.Errorf("%s is required", field.Label)
		}
		maxLength, _ := field.MaxLength.(int)
		if field.Name == "researcher_gpg" && strings.HasPrefix(value, "https://") {
			maxLength = 2048
		}
		if maxLength > 0 && utf8.RuneCountInString(value) > maxLength {
			return fmt.Errorf("%s is too long", field.Label)
		}
		if !utf8.ValidString(value) || contactZeroWidthPattern.MatchString(value) {
			return fmt.Errorf("%s contains unsupported characters", field.Label)
		}
		for _, r := range value {
			if unicode.IsControl(r) && (field.Name == "name" || field.Name == "email" || field.Name == "subject" || field.Name == "vulnerability_summary") {
				return fmt.Errorf("%s contains unsupported characters", field.Label)
			}
		}
		if field.Type == "select" && value != "" && !slicesContains(field.Options, value) {
			return fmt.Errorf("%s has an invalid value", field.Label)
		}
		if field.Type == "checkbox" && value != "" && value != "true" && value != "on" {
			return fmt.Errorf("%s must be checked", field.Label)
		}
	}
	if _, err := mail.ParseAddress(values["email"]); err != nil || strings.ContainsAny(values["email"], ",;<>\r\n") {
		return fmt.Errorf("email must be one valid address")
	}
	return nil
}

func validateContactContent(r *http.Request, values map[string]string, fields []contactField, rejectMarkup bool, configs ...*config.Config) error {
	policy := config.ContactAntispamConfig{MaxLinks: 10}
	fqdn := ""
	adminPath := "administration"
	if len(configs) > 0 && configs[0] != nil {
		policy = configs[0].Server.Pages.Contact.Antispam
		fqdn = configs[0].Server.FQDN
		if configs[0].Server.AdminPath != "" {
			adminPath = configs[0].Server.AdminPath
		}
	}
	if blocked := strings.ToLower(strings.TrimSpace(values["email"])); blocked != "" {
		_, address, _ := strings.Cut(blocked, "@")
		for _, domain := range policy.BlockedEmailDomains {
			if address == strings.ToLower(strings.TrimPrefix(domain, "@")) {
				return fmt.Errorf("message rejected")
			}
		}
	}
	if rejectMarkup {
		for key, value := range values {
			decoded := html.UnescapeString(value)
			if key != "website" && (contactMarkupPattern.MatchString(value) || decoded != value && strings.ContainsAny(decoded, "<>")) {
				return fmt.Errorf("markup is not allowed")
			}
		}
	}
	for _, key := range []string{"name", "subject"} {
		if hasContactLink(values[key]) {
			return fmt.Errorf("links are not allowed")
		}
	}
	links := 0
	for key, value := range values {
		if key == "email" || key == "name" || key == "subject" || key == "type" || key == "website" || key == "form_token" || key == "step" || key == "review_token" || key == "captcha_id" || key == "captcha_answer" || key == "confirmed" {
			continue
		}
		for _, span := range contactLinkPattern.FindAllStringIndex(value, -1) {
			if span[0] > 0 && value[span[0]-1] == '@' {
				continue
			}
			match := value[span[0]:span[1]]
			links++
			host := contactLinkHost(match)
			if host != "" && !contactHostAllowed(r, host, fqdn) {
				return fmt.Errorf("link host is not allowed")
			}
		}
	}
	for _, word := range policy.BlockedWords {
		if word != "" && strings.Contains(strings.ToLower(strings.Join([]string{values["name"], values["subject"], values["message"], values["reported_url"], values["copyrighted_work"], values["signature"]}, " ")), strings.ToLower(word)) {
			return fmt.Errorf("blocked content")
		}
	}
	if policy.MaxLinks > 0 && links > policy.MaxLinks {
		return fmt.Errorf("too many links")
	}
	if values["reported_url"] != "" {
		u, err := url.ParseRequestURI(values["reported_url"])
		if err != nil || u.Host == "" || !contactHostAllowed(r, u.Host, fqdn) || !contactReportedPathExists(u.Path, adminPath) {
			return fmt.Errorf("reported URL must be on this service")
		}
	}
	return nil
}

func slicesContains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func contactLinkHost(raw string) string {
	if strings.HasPrefix(strings.ToLower(raw), "www.") {
		return raw
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err == nil {
			return u.Host
		}
	}
	if strings.Contains(raw, "@") {
		return ""
	}
	return raw
}

func hasContactLink(value string) bool {
	for _, span := range contactLinkPattern.FindAllStringIndex(value, -1) {
		if span[0] > 0 && value[span[0]-1] == '@' {
			continue
		}
		return true
	}
	return false
}

func contactHostAllowed(r *http.Request, host, fqdn string) bool {
	if sameContactHost(host, r.Host) || fqdn != "" && sameContactHost(host, fqdn) {
		return true
	}
	for _, domain := range strings.Split(os.Getenv("DOMAIN"), ",") {
		if sameContactHost(host, strings.TrimSpace(domain)) {
			return true
		}
	}
	return false
}

func contactReportedPathExists(path, adminPath string) bool {
	if path == "" || path == "/" || path == "/server/contact" || strings.HasPrefix(path, "/api/") {
		return false
	}
	if path == "/server/"+adminPath || strings.HasPrefix(path, "/server/"+adminPath+"/") {
		return false
	}
	if strings.HasPrefix(path, "/static/") {
		file, err := staticFS.Open("static/" + strings.TrimPrefix(path, "/static/"))
		if err != nil {
			return false
		}
		_ = file.Close()
		return true
	}
	switch path {
	case "/server/about", "/server/privacy", "/server/help", "/server/terms", "/server/dpo", "/server/security", "/server/security/policy", "/server/security/thanks", "/server/docs/swagger", "/server/docs/graphql", "/healthz", "/server/healthz", "/robots.txt", "/.well-known/security.txt", "/.well-known/change-password":
		return true
	default:
		return false
	}
}

func sameContactHost(left, right string) bool {
	lh, _, le := net.SplitHostPort(left)
	rh, _, re := net.SplitHostPort(right)
	if le == nil {
		left = lh
	}
	if re == nil {
		right = rh
	}
	return strings.EqualFold(left, right)
}

func sameContactOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if referer, err := url.Parse(r.Header.Get("Referer")); err == nil {
			origin = referer.Scheme + "://" + referer.Host
		}
	}
	if origin == "" || r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || !sameContactHost(u.Host, r.Host) {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return u.Scheme == scheme
}

func (h *ContactHandler) newCaptcha() (captchaChallenge, error) {
	if h.captchaStore == nil {
		return captchaChallenge{}, errors.New("captcha challenge store is unavailable")
	}
	left, err := rand.Int(rand.Reader, big.NewInt(20))
	if err != nil {
		return captchaChallenge{}, err
	}
	right, err := rand.Int(rand.Reader, big.NewInt(20))
	if err != nil {
		return captchaChallenge{}, err
	}
	a, b := left.Int64()+1, right.Int64()+1
	if a < b {
		a, b = b, a
	}
	answer := strconv.FormatInt(a-b, 10)
	question := fmt.Sprintf("What is %d - %d?", a, b)
	if a == b {
		question = fmt.Sprintf("What is %d + %d?", a, b)
		answer = strconv.FormatInt(a+b, 10)
	}
	id, err := contactRandomToken(16)
	if err != nil {
		return captchaChallenge{}, err
	}
	challenge := captchaChallenge{ID: id, Answer: contactHash(answer), Question: question, ExpiresAt: time.Now().Add(10 * time.Minute)}
	ctx := context.Background()
	if err := h.captchaStore.DeleteExpiredCaptchaChallenges(ctx, time.Now()); err != nil {
		return captchaChallenge{}, err
	}
	if err := h.captchaStore.CreateCaptchaChallenge(ctx, id, challenge.Answer, challenge.ExpiresAt); err != nil {
		return captchaChallenge{}, err
	}
	return challenge, nil
}

func (h *ContactHandler) consumeCaptcha(id, answer string, now time.Time) bool {
	if h.captchaStore == nil {
		return false
	}
	answerHash, expiresAt, err := h.captchaStore.ConsumeCaptchaChallenge(context.Background(), id)
	if err != nil || !now.Before(expiresAt) {
		return false
	}
	return hmac.Equal([]byte(answerHash), []byte(contactHash(strings.TrimSpace(answer))))
}

func (h *ContactHandler) discardCaptcha(id string) {
	if h.captchaStore != nil && id != "" {
		_, _, _ = h.captchaStore.ConsumeCaptchaChallenge(context.Background(), id)
	}
}

func (h *ContactHandler) newFormToken(now time.Time) (string, error) {
	nonce, err := contactRandomToken(16)
	if err != nil {
		return "", err
	}
	stamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, h.secret)
	_, _ = mac.Write([]byte("contact-form|" + stamp + "|" + nonce))
	token := stamp + "." + nonce + "." + hex.EncodeToString(mac.Sum(nil))
	return token, nil
}

func (h *ContactHandler) consumeFormToken(token string, now time.Time) bool {
	return h.consumeFormTokenFailure(token, now) == ""
}

func (h *ContactHandler) consumeFormTokenFailure(token string, now time.Time) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "fill_time"
	}
	issued, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return "fill_time"
	}
	age := now.Sub(time.Unix(issued, 0))
	policy := h.config.Server.Pages.Contact.Antispam
	if age < time.Duration(policy.MinFillSeconds)*time.Second || age > time.Duration(policy.MaxAgeSeconds)*time.Second {
		return "fill_time"
	}
	mac := hmac.New(sha256.New, h.secret)
	_, _ = mac.Write([]byte("contact-form|" + parts[0] + "|" + parts[1]))
	if !hmac.Equal([]byte(parts[2]), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return "fill_time"
	}
	if !h.markFormNonceUsed(parts[1], now, policy.MaxAgeSeconds) {
		return "replay"
	}
	return ""
}

func (h *ContactHandler) consumeReviewFormToken(token string, now time.Time) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	issued, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	policy := h.config.Server.Pages.Contact.Antispam
	age := now.Sub(time.Unix(issued, 0))
	if age < 0 || age > time.Duration(policy.MaxAgeSeconds)*time.Second {
		return false
	}
	mac := hmac.New(sha256.New, h.secret)
	_, _ = mac.Write([]byte("contact-form|" + parts[0] + "|" + parts[1]))
	if !hmac.Equal([]byte(parts[2]), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return false
	}
	return h.markFormNonceUsed(parts[1], now, policy.MaxAgeSeconds)
}

func (h *ContactHandler) markFormNonceUsed(nonce string, now time.Time, maxAgeSeconds int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for existingNonce, expiry := range h.forms {
		if !now.Before(expiry) {
			delete(h.forms, existingNonce)
		}
	}
	if _, replayed := h.forms[nonce]; replayed {
		return false
	}
	if len(h.forms) >= 50000 {
		var oldestNonce string
		var oldest time.Time
		for existingNonce, expiry := range h.forms {
			if oldest.IsZero() || expiry.Before(oldest) {
				oldestNonce, oldest = existingNonce, expiry
			}
		}
		delete(h.forms, oldestNonce)
	}
	h.forms[nonce] = now.Add(time.Duration(maxAgeSeconds) * time.Second)
	return true
}

func (h *ContactHandler) newReviewToken(values map[string]string, now time.Time) (string, error) {
	nonce, err := contactRandomToken(16)
	if err != nil {
		return "", err
	}
	stamp := strconv.FormatInt(now.Unix(), 10)
	fieldsHash := contactFieldsHash(values)
	flags := ""
	if values["website"] != "" {
		flags = "d"
	}
	payload := "contact-review|" + stamp + "|" + nonce + "|" + flags + "|" + fieldsHash
	mac := hmac.New(sha256.New, h.secret)
	_, _ = mac.Write([]byte(payload))
	return stamp + "." + nonce + "." + flags + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

func (h *ContactHandler) consumeReviewToken(token string, values map[string]string, now time.Time) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return false
	}
	issued, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	age := now.Sub(time.Unix(issued, 0))
	policy := h.config.Server.Pages.Contact.Antispam
	if age < time.Duration(policy.ReviewMinSeconds)*time.Second || age > time.Duration(policy.ReviewMaxSeconds)*time.Second {
		return false
	}
	mac := hmac.New(sha256.New, h.secret)
	fieldsHash := contactFieldsHash(values)
	_, _ = mac.Write([]byte("contact-review|" + parts[0] + "|" + parts[1] + "|" + parts[2] + "|" + fieldsHash))
	if !hmac.Equal([]byte(parts[3]), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for nonce, expiry := range h.reviews {
		if !now.Before(expiry) {
			delete(h.reviews, nonce)
		}
	}
	if _, replayed := h.reviews[parts[1]]; replayed {
		return false
	}
	if len(h.reviews) >= 50000 {
		var oldestNonce string
		var oldest time.Time
		for nonce, expiry := range h.reviews {
			if oldest.IsZero() || expiry.Before(oldest) {
				oldestNonce, oldest = nonce, expiry
			}
		}
		delete(h.reviews, oldestNonce)
	}
	h.reviews[parts[1]] = now.Add(time.Duration(policy.ReviewMaxSeconds) * time.Second)
	if parts[2] == "d" {
		values["website"] = "dropped"
	}
	return true
}

func contactFieldsHash(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "form_token" && key != "captcha_id" && key != "captcha_answer" && key != "review_token" && key != "confirmed" && key != "step" && key != "__dropped" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, key := range keys {
		canonical.WriteString(key)
		canonical.WriteByte('=')
		canonical.WriteString(strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(values[key])), " ")))
		canonical.WriteByte('\n')
	}
	return contactHash(canonical.String())
}

func contactHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func contactRandomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (h *ContactHandler) resolveRecipient(role string) string {
	contact := h.config.Server.Contact
	switch role {
	case "privacy":
		if contact.DPO.Email != "" {
			return contact.DPO.Email
		}
	case "abuse":
		if contact.Abuse.Email != "" {
			return contact.Abuse.Email
		}
	}
	if contact.General.Email != "" {
		return contact.General.Email
	}
	return contact.Admin.Email
}

func (h *ContactHandler) publicAbuseEmail(r *http.Request) string {
	if overlayRequestKind(r) == "tor" {
		return strings.TrimSpace(h.config.Server.Tor.ContactEmail)
	}
	if email := h.config.Server.Contact.Abuse.Email; email != "" {
		return email
	}
	return h.config.Server.Contact.General.Email
}

func (h *ContactHandler) requestFQDN(r *http.Request) string {
	if configured := strings.TrimSpace(h.config.Server.FQDN); configured != "" {
		return configured
	}
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		return host
	}
	return r.Host
}

func formatContactBody(typeName string, values map[string]string) string {
	var output strings.Builder
	fmt.Fprintf(&output, "Type: %s\n", typeName)
	for _, key := range []string{"name", "email", "reported_url", "reason", "copyrighted_work", "good_faith", "accuracy", "signature", "request_kind", "subject", "message"} {
		if value := strings.TrimSpace(values[key]); value != "" {
			fmt.Fprintf(&output, "%s: %s\n", strings.ReplaceAll(key, "_", " "), value)
		}
	}
	return output.String()
}

func writeContactJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
