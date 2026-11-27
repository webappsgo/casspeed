package server

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/config"
)

type privacyPageData struct {
	Title, Lead, Updated, CSRF                          string
	Sold, StoredOnServer, CCPAOptedOut                  bool
	CookieEssential, CookiePreferences, CookieAnalytics string
	OfferPreferences, OfferAnalytics                    bool
	AnalyticsDescription                                string
	DataCollection, DataUsage, DataSecurity             template.HTML
	Sharing                                             []privacySharingView
	Retention                                           string
	ExportAvailable, DeletionAvailable                  bool
	ThirdParty                                          []privacyThirdPartyView
	Extension                                           template.HTML
	Contact                                             template.HTML
	ConsentPreferences, ConsentAnalytics                bool
}

type privacySharingView struct {
	Condition string `json:"condition"`
	When      string `json:"when"`
	Data      string `json:"data"`
}

type privacyThirdPartyView struct {
	Name      string `json:"name"`
	Purpose   string `json:"purpose"`
	DataSent  string `json:"data_sent"`
	PolicyURL string `json:"policy_url"`
}

func privacyConfigForRequest(r *http.Request, privacy config.PrivacyConfig) config.PrivacyConfig {
	if overlayRequestKind(r) != "tor" {
		return privacy
	}
	if isExternalPolicyURL(r, privacy.Consent.Policy.URL) {
		privacy.Consent.Policy.URL = ""
	}
	privacy.ThirdParty.Services = append([]config.PrivacyThirdPartyService(nil), privacy.ThirdParty.Services...)
	for i := range privacy.ThirdParty.Services {
		if isExternalPolicyURL(r, privacy.ThirdParty.Services[i].PolicyURL) {
			privacy.ThirdParty.Services[i].PolicyURL = ""
		}
	}
	return privacy
}

func isExternalPolicyURL(r *http.Request, value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || !parsed.IsAbs() && parsed.Host == "" {
		return false
	}
	return !strings.EqualFold(parsed.Host, r.Host)
}

func preserveTorPrivacyPolicyURLs(previous, candidate *config.PrivacyConfig) {
	if candidate.Consent.Policy.URL == "" {
		candidate.Consent.Policy.URL = previous.Consent.Policy.URL
	}
	used := make([]bool, len(previous.ThirdParty.Services))
	for i := range candidate.ThirdParty.Services {
		service := &candidate.ThirdParty.Services[i]
		if service.PolicyURL != "" {
			continue
		}
		for j, old := range previous.ThirdParty.Services {
			if !used[j] && old.Name == service.Name && old.Purpose == service.Purpose {
				service.PolicyURL = old.PolicyURL
				used[j] = true
				break
			}
		}
		if service.PolicyURL == "" {
			for j, old := range previous.ThirdParty.Services {
				if !used[j] && old.Name == service.Name {
					service.PolicyURL = old.PolicyURL
					used[j] = true
					break
				}
			}
		}
		if service.PolicyURL == "" && i < len(previous.ThirdParty.Services) && !used[i] {
			service.PolicyURL = previous.ThirdParty.Services[i].PolicyURL
			used[i] = true
		}
	}
}

var privacyPolicyTemplate = template.Must(template.New("privacy-policy").Parse(`<article class="privacy-policy"><h1 class="page-title">{{.Title}}</h1><p class="last-updated">{{.Updated}}</p>
<section id="summary"><h2>Summary</h2><ul><li>Your data is stored on our servers.</li>{{if .Sold}}<li class="warning">Your data may be sold. <a href="#ccpa-opt-out">Opt out of data sales</a>.</li>{{else}}<li>We never sell your data.</li>{{end}}<li>You control your data through account settings.</li></ul></section>
<section id="cookies"><h2>Cookie Policy</h2><h3>Essential Cookies</h3><p>{{.CookieEssential}}</p><h3>Preference Cookies</h3><p>{{.CookiePreferences}}</p><h3>Analytics Cookies</h3>{{if .AnalyticsDescription}}<p>{{.AnalyticsDescription}}</p>{{else}}<p>We do not use analytics tracking on this site.</p>{{end}}<div id="cookie-preferences"><form method="post" action="/server/consent"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="choice" value="save"><label><input type="checkbox" checked disabled> Essential cookies (always on)</label>{{if .OfferPreferences}}<label><input type="checkbox" name="preferences" value="true" {{if .ConsentPreferences}}checked{{end}}> Preference cookies</label>{{end}}{{if .OfferAnalytics}}<label><input type="checkbox" name="analytics" value="true" {{if .ConsentAnalytics}}checked{{end}}> Analytics cookies</label>{{end}}<button type="submit">Save Cookie Preferences</button></form></div></section>
<section id="data-collection"><h2>Data We Collect</h2>{{.DataCollection}}</section><section id="data-usage"><h2>How We Use Your Data</h2>{{.DataUsage}}</section><section id="data-security"><h2>Data Security</h2>{{.DataSecurity}}</section>
<section id="data-storage"><h2>Data Storage &amp; Third-Party Sharing</h2>{{if .StoredOnServer}}<p><strong>All your data is stored on our servers.</strong></p>{{else}}<p>Data storage locations depend on the services listed below.</p>{{end}}<h3>When Data May Be Shared</h3>{{if .Sharing}}<ul>{{range .Sharing}}<li><strong>{{.Condition}}:</strong> {{.When}} — {{.Data}}</li>{{end}}</ul>{{else}}<p>No third-party sharing conditions are configured.</p>{{end}}{{if .Sold}}<p>Your data may be sold to third parties. See the CCPA opt-out below.</p>{{else}}<p>Your data is never sold.</p>{{end}}</section>
<section id="data-retention"><h2>Data Retention</h2><p>{{.Retention}}</p></section><section id="third-parties"><h2>Third-Party Services</h2>{{if .ThirdParty}}<table><thead><tr><th>Service</th><th>Purpose</th><th>Data Sent</th><th>Privacy Policy</th></tr></thead><tbody>{{range .ThirdParty}}<tr><td>{{.Name}}</td><td>{{.Purpose}}</td><td>{{.DataSent}}</td><td>{{if .PolicyURL}}<a href="{{.PolicyURL}}" target="_blank" rel="noopener">View Policy</a>{{end}}</td></tr>{{end}}</tbody></table>{{else}}<p>We do not currently use any third-party services that receive your data.</p>{{end}}</section>
<section id="your-rights"><h2>Your Rights</h2><ul><li>Access and correct your account information in settings.</li>{{if .ExportAvailable}}<li>Export a copy of your data.</li>{{end}}{{if .DeletionAvailable}}<li>Delete your account and associated data.</li>{{end}}<li><a href="/server/preferences#privacy">Manage cookie preferences</a></li></ul></section>
{{if .Sold}}<section id="ccpa-opt-out"><h2>California Privacy Rights (CCPA)</h2><p>You may know, delete, or opt out of the sale of personal information. You will not be discriminated against for exercising these rights.</p><h3>Do Not Sell My Personal Information</h3>{{if .CCPAOptedOut}}<p>You have opted out of data sales.</p><form method="post" action="/server/ccpa"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="choice" value="opt-in"><button type="submit">Opt Back In</button></form>{{else}}<form method="post" action="/server/ccpa"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="choice" value="opt-out"><button type="submit">Do Not Sell My Personal Information</button></form>{{end}}<p>Essential cookies and site functionality continue to work normally.</p></section>{{end}}
{{if .Extension}}<section id="operator-extension"><h2>Additional Information</h2>{{.Extension}}</section>{{end}}<section id="contact"><h2>Contact</h2>{{.Contact}}</section></article>`))

const builtinPrivacyDataCollection = `**We collect only what is necessary to provide our service:**

**Account Information:**
- Email address (for account recovery and notifications)
- Username (for identification)
- Password (stored securely hashed, never in plain text)

**Usage Information (with consent):**
- Pages visited and features used
- Browser type and device information
- Approximate location (country/region from IP, not precise)

**Technical Information:**
- IP address (for security and abuse prevention)
- Session data (for keeping you logged in)

**We do NOT collect:**
- Payment information
- Precise location data
- Data from other websites or apps`

const builtinPrivacyDataUsage = `**Your data is used solely to:**

- **Provide the service:** Account management, authentication, and core functionality
- **Improve the experience:** Performance optimization, bug fixes, and feature improvements
- **Ensure security:** Prevent abuse, detect fraud, and protect your account
- **Communicate:** Service updates and security alerts

**Your data is NEVER:**
- Sold to third parties
- Used for targeted advertising
- Shared without your explicit consent (except as required by law)`

const builtinPrivacyDataUsageIfSold = `**Your data may be used to:**

- **Provide the service:** Account management, authentication, and core functionality
- **Improve the experience:** Performance optimization, bug fixes, and feature improvements
- **Ensure security:** Prevent abuse, detect fraud, and protect your account
- **Communicate:** Service updates and security alerts
- **Third-party sharing:** Data may be shared or sold as described below

You can opt out of data sales using the control on this page.`

const builtinPrivacyDataSecurity = `**How we protect your data:**

- Data is stored on this server
- Passwords use Argon2id hashing
- Connections use HTTPS/TLS when served over TLS
- Access controls and audit logging protect administrative actions`

func markdownPrivacy(source string) (template.HTML, error) {
	htmlText, err := renderMarkdown(source)
	if err != nil {
		return "", err
	}
	return template.HTML(htmlText), nil
}

func (s *Server) privacyPageContent(r *http.Request, csrf string) (template.HTML, error) {
	s.configMu.RLock()
	privacyConfig := s.Config.Server.Privacy
	brandingExtension := s.Config.Server.Branding.Content.Privacy
	s.configMu.RUnlock()
	config := privacyConfigForRequest(r, privacyConfig)
	dataCollection, err := markdownPrivacy(builtinPrivacyDataCollection)
	if err != nil {
		return "", err
	}
	usage := builtinPrivacyDataUsage
	if config.Data.Sold {
		usage = builtinPrivacyDataUsageIfSold
	}
	dataUsage, err := markdownPrivacy(usage)
	if err != nil {
		return "", err
	}
	dataSecurity, err := markdownPrivacy(builtinPrivacyDataSecurity)
	if err != nil {
		return "", err
	}
	sharing := make([]privacySharingView, 0, len(config.Data.Sharing))
	for _, item := range config.Data.Sharing {
		sharing = append(sharing, privacySharingView{Condition: item.Condition, When: item.When, Data: item.Data})
	}
	thirdParty := make([]privacyThirdPartyView, 0, len(config.ThirdParty.Services))
	for _, item := range config.ThirdParty.Services {
		thirdParty = append(thirdParty, privacyThirdPartyView{Name: item.Name, Purpose: item.Purpose, DataSent: item.DataSent, PolicyURL: item.PolicyURL})
	}
	analyticsDescription := ""
	if config.Cookies.Analytics.Enabled {
		analyticsDescription = config.Cookies.Analytics.Description
		if config.Data.Sold {
			analyticsDescription += " " + config.Cookies.Analytics.DescriptionSuffixSold
		} else {
			analyticsDescription += " " + config.Cookies.Analytics.DescriptionSuffixNotSold
		}
	}
	retention := config.Retention.Period
	if retention == "" {
		retention = "Account data remains while your account is active. Anonymous speed test data follows the configured results retention period."
	}
	name, email := s.dpoContact()
	if overlayRequestKind(r) == "tor" {
		s.configMu.RLock()
		name = ""
		email = strings.TrimSpace(s.Config.Server.Tor.ContactEmail)
		s.configMu.RUnlock()
	}
	contactText := "For privacy-related inquiries, see [how to reach us](/server/security)."
	if email != "" {
		if parsed, parseErr := mail.ParseAddress(email); parseErr == nil && parsed.Address == email {
			contactText = "Contact the data protection officer at [" + email + "](mailto:" + email + ")."
		}
	}
	contact, err := markdownPrivacy(contactText)
	if err != nil {
		return "", err
	}
	if name != "" && strings.Contains(contactText, email) {
		contact, err = markdownPrivacy("**" + name + "**\n\n" + contactText)
		if err != nil {
			return "", err
		}
	}
	var extension template.HTML
	if content := brandingExtension; strings.TrimSpace(content) != "" {
		extensionText, extensionErr := markdownPrivacy(content)
		if extensionErr != nil {
			return "", extensionErr
		}
		extension = extensionText
	}
	page := privacyPageData{Title: "Privacy Policy", Updated: time.Now().UTC().Format("2006-01-02"), CSRF: csrf, Sold: config.Data.Sold, StoredOnServer: config.Data.StoredOnServer, CCPAOptedOut: readCCPAOptOut(r), CookieEssential: config.Cookies.Essential.Description, CookiePreferences: config.Cookies.Preferences.Description, CookieAnalytics: config.Cookies.Analytics.Description, OfferPreferences: config.Cookies.Preferences.Enabled, OfferAnalytics: config.Cookies.Analytics.Enabled, AnalyticsDescription: analyticsDescription, DataCollection: dataCollection, DataUsage: dataUsage, DataSecurity: dataSecurity, Sharing: sharing, Retention: retention, ExportAvailable: config.Retention.ExportAvailable, DeletionAvailable: config.Retention.DeletionAvailable, ThirdParty: thirdParty, Extension: extension, Contact: contact, ConsentPreferences: readConsent(r).Preferences, ConsentAnalytics: readConsent(r).Analytics}
	var out bytes.Buffer
	if err := privacyPolicyTemplate.Execute(&out, page); err != nil {
		return "", err
	}
	return template.HTML(out.String()), nil
}

func (s *Server) handleCCPA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.Config == nil || !s.Config.Server.Privacy.Data.Sold {
		http.NotFound(w, r)
		return
	}
	if !sameOriginPageRequest(r) || !validPreferenceCSRF(r) {
		http.Error(w, "Invalid privacy form", http.StatusForbidden)
		return
	}
	choice := r.FormValue("choice")
	if choice != "opt-out" && choice != "opt-in" {
		http.Error(w, "Invalid privacy choice", http.StatusBadRequest)
		return
	}
	value := "false"
	if choice == "opt-out" {
		value = "true"
	}
	http.SetCookie(w, &http.Cookie{Name: "ccpa_opt_out", Value: value, Path: "/", MaxAge: preferenceMaxAge, SameSite: http.SameSiteLaxMode, Secure: requestIsHTTPS(r)})
	s.auditPrivacyEvent("compliance.ccpa_preference_updated", map[string]any{"opted_out": choice == "opt-out"})
	s.redirectNoStore(w, r, "/server/privacy#ccpa-opt-out")
}

func (s *Server) auditPrivacyEvent(event string, fields map[string]any) {
	if s.Logger == nil || s.Logger.Audit == nil {
		return
	}
	entry := map[string]any{"event": event, "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}
	for key, value := range fields {
		entry[key] = value
	}
	if s.Config != nil {
		entry["policy_version"] = s.Config.Server.Privacy.Consent.Policy.Version
	}
	encoded, err := json.Marshal(entry)
	if err == nil {
		s.Logger.Audit.Printf("%s\n", encoded)
	}
}

func (s *Server) privacyPageAPI(r *http.Request) map[string]any {
	s.configMu.RLock()
	p := s.Config.Server.Privacy
	s.configMu.RUnlock()
	p = privacyConfigForRequest(r, p)
	s.configMu.RLock()
	trackingConfig := s.Config.Server.Tracking
	s.configMu.RUnlock()
	tracking := map[string]any{"enabled": trackingConfig.Type != "" && trackingConfig.Type != "none", "type": trackingConfig.Type, "type_name": trackingConfig.Type}
	cookie := func(enabled bool, description string) map[string]any {
		return map[string]any{"enabled": enabled, "description": description}
	}
	analyticsDescription := p.Cookies.Analytics.Description
	if p.Data.Sold {
		analyticsDescription += " " + p.Cookies.Analytics.DescriptionSuffixSold
	} else {
		analyticsDescription += " " + p.Cookies.Analytics.DescriptionSuffixNotSold
	}
	usage := builtinPrivacyDataUsage
	if p.Data.Sold {
		usage = builtinPrivacyDataUsageIfSold
	}
	message := privacyConsentMessage(p.Consent, p.Data.Sold)
	data := map[string]any{"summary": map[string]any{"data_stored_on_server": p.Data.StoredOnServer, "data_sold": p.Data.Sold, "user_control": true}, "cookies": map[string]any{"essential": cookie(true, p.Cookies.Essential.Description), "preferences": cookie(p.Cookies.Preferences.Enabled, p.Cookies.Preferences.Description), "analytics": cookie(p.Cookies.Analytics.Enabled, analyticsDescription)}, "data": map[string]any{"sold": p.Data.Sold, "stored_on_server": p.Data.StoredOnServer, "sharing": p.Data.Sharing}, "tracking": tracking, "retention": map[string]any{"period": p.Retention.Period, "export_available": p.Retention.ExportAvailable, "deletion_available": p.Retention.DeletionAvailable}, "third_party": map[string]any{"services": p.ThirdParty.Services}, "content": map[string]any{"consent_message": message, "data_usage": usage}}
	if p.Data.Sold {
		data["ccpa"] = map[string]any{"applicable": true, "opt_out_url": "/server/privacy#ccpa-opt-out", "user_opted_out": readCCPAOptOut(r)}
	}
	return data
}

func privacyConsentMessage(config config.PrivacyConsentConfig, sold bool) string {
	if sold && config.MessageIfSold != "" {
		return config.MessageIfSold
	}
	return config.Message
}
