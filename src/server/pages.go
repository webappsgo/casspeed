package server

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

type publicPage struct {
	Title   string
	Lead    string
	Content string
}

var publicPages = map[string]publicPage{
	"about":           {Title: "About CasSpeed", Lead: "A self-hosted, privacy-respecting internet speed test.", Content: "CasSpeed is a free, open-source alternative to commercial speed test sites for home users, network administrators, and developers. It measures download and upload throughput, latency, jitter, and packet loss without advertisements or tracking.\n\nYou can run a test anonymously. Registered users can keep history, associate tests with named devices, and use API tokens for automation. Results stay private unless their owner explicitly creates a share link.\n\nThe product has no paid feature gates and does not require an external testing API. Source code and documentation are available at [GitHub](https://github.com/webappsgo/casspeed)."},
	"privacy":         {Title: "Privacy", Lead: "How this CasSpeed deployment handles speed test and account data.", Content: "This CasSpeed service is operated by the organization that installed it. The operator controls service availability and server-side retention settings.\n\nSpeed tests store measurement results, a one-way hash of the client IP address, and the user agent. The application does not store the plain client IP address. Anonymous results are retained for {retention}. Account history remains until the user deletes it or the account is removed.\n\nUnshared results are visible only to the originating anonymous browser session or the account that owns them. A result becomes public only after its owner explicitly creates a share link. A shared result contains measurements and does not disclose the plain IP address or user agent.\n\nAccount profile details, devices, and API tokens are private to their owner. Raw API tokens are shown once at creation and stored as SHA-256 hashes. Contact the service operator for privacy requests."},
	"terms":           {Title: "Terms of Service", Lead: "Use the service responsibly and only on networks you are authorized to test.", Content: "Use CasSpeed only to measure networks you are authorized to use. Do not use the service to disrupt its operation, evade access controls, or submit harmful content. The service is provided by its operator, who controls availability, retention, and applicable terms."},
	"help":            {Title: "Help", Lead: "Run a test, understand your result, or use the API.", Content: "Choose **Start speed test** on the [home page](/). The test measures latency, download speed, and upload speed using this CasSpeed server. Keep the page open while the test runs.\n\nUnshared results remain private to the browser session that started the test. Choose **Share result** to create a public link. Registered users can sign in to keep history and manage devices and API tokens.\n\n### API quick start\n\nStart a test with `POST /api/v1/speed-tests`. The response includes an `id`; connect to `GET /api/v1/speed-tests/{id}/status` for live updates. Retrieve an owned result with `GET /api/v1/speed-tests/{id}`. See the [API reference](/server/docs/swagger) for the API contract.\n\n### API documentation\n\n- [Swagger UI](/server/docs/swagger) explores REST operations.\n- [GraphiQL](/server/docs/graphql) runs read-only queries for public health, your own results, and shared results.\n- [MCP server](/server/help/mcp) makes API operations available to configured MCP clients.\n\nFor machine use, send a bearer API token in the `Authorization` header. Never place tokens in a URL or share them in logs. MCP clients use the same API token."},
	"help/mcp":        {Title: "MCP Help", Lead: "Connect an MCP client with a dedicated API bearer token.", Content: "CasSpeed exposes a Streamable HTTP MCP endpoint at `/api/v1/server/mcp`, with direct aliases at `/api/mcp` and `/mcp`. The endpoint accepts JSON-RPC over HTTP POST and requires the same `Authorization: Bearer …` API token used by the REST API.\n\nConfigure your MCP client to use the endpoint URL and a dedicated, revocable API token. Keep the token secret. The MCP transport uses protocol revision `2026-07-28`; clients must send `MCP-Protocol-Version` and `Mcp-Method` headers that match the JSON-RPC request metadata.\n\nMCP operations must enforce the same ownership and permissions as the matching API operations."},
	"dpo":             {Title: "Data Protection Contact", Lead: "Contact details for privacy requests.", Content: ""},
	"security":        {Title: "Security", Lead: "Report vulnerabilities privately and give the operator time to investigate.", Content: ""},
	"security/policy": {Title: "Security Disclosure Policy", Lead: "Coordinated disclosure helps protect users while issues are investigated.", Content: "Please report suspected vulnerabilities privately to the service operator. Allow reasonable time for investigation and remediation before public disclosure. Do not access, modify, or retain other users' data."},
	"security/thanks": {Title: "Security Hall of Fame", Lead: "Acknowledging responsible security research.", Content: "No security acknowledgements have been published."},
}

type registeredPublicPage struct {
	Path     string
	Hub      string
	TitleKey string
	Order    int
	Always   bool
}

// Public pages and their hub links share one route registry.
var publicPageRegistry = []registeredPublicPage{
	{Path: "/server/about", TitleKey: "page_titles.about", Always: true},
	{Path: "/server/privacy", TitleKey: "page_titles.privacy", Always: true},
	{Path: "/server/help", TitleKey: "page_titles.help", Always: true},
	{Path: "/server/terms", TitleKey: "page_titles.terms", Always: true},
	{Path: "/server/dpo", TitleKey: "page_titles.dpo", Always: true},
	{Path: "/server/security", TitleKey: "page_titles.security", Always: true},
	{Path: "/server/security/policy", TitleKey: "page_titles.security_policy", Always: true},
	{Path: "/server/security/thanks", TitleKey: "page_titles.security_thanks", Always: true},
	{Path: "/server/preferences/sync", Hub: "/server/preferences", TitleKey: "pages.sync", Order: 10, Always: true},
	{Path: "/server/help/mcp", Hub: "/server/help", TitleKey: "page_titles.help_mcp", Order: 10, Always: true},
}

var swaggerPageContentTemplate = template.Must(template.New("swagger-content").Parse(`<noscript><p>{{.NoScript}} <a href="{{.SpecURL}}">{{.SpecURL}}</a>.</p></noscript><div id="swagger-ui" data-spec-url="{{.SpecURL}}" aria-live="polite"></div>`))
var graphqlPageContentTemplate = template.Must(template.New("graphql-content").Parse(`<div id="graphiql" class="graphiql-container" data-endpoint="{{.Endpoint}}">{{.Loading}}</div><noscript><p>{{.NoScript}} <a href="{{.Endpoint}}?query=%7Bhealth%7Bstatus%7D%7D">{{.Endpoint}}</a>.</p></noscript>`))
var accountActionsTemplate = template.Must(template.New("account-actions").Parse(`<div class="notification-bell"><details><summary aria-label="{{.Notifications}}"><svg class="bell-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>{{if gt .Unread 0}}<span class="badge" aria-label="{{.UnreadLabel}}">{{.UnreadDisplay}}</span>{{end}}</summary><div class="notification-dropdown"><div class="dropdown-header"><strong>{{.Notifications}}</strong><form method="post" action="/users/notifications/read"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button type="submit">{{.MarkAllRead}}</button></form></div><div class="notification-list">{{if .Items}}{{range .Items}}<form method="post" action="/users/notifications/{{.ID}}/read" class="notification-item {{if .Unread}}unread{{end}}"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="next" value="{{.Link}}"><button type="submit"><span class="notification-icon" aria-hidden="true">{{.Icon}}</span><span class="notification-title">{{.Title}}</span><span class="notification-message">{{.Message}}</span><time class="notification-time">{{.CreatedAt}}</time></button></form>{{end}}{{else}}<p>{{.Empty}}</p>{{end}}</div><a class="dropdown-footer" href="/users/notifications">{{.ViewAll}}</a></div></details></div><details class="profile-menu"><summary aria-label="{{.Profile}}">{{.Username}}</summary><div class="profile-dropdown"><a href="/users">{{.Profile}}</a><a href="/history">{{.History}}</a><a href="/devices">{{.Devices}}</a><a href="/users/settings">{{.Settings}}</a><a href="/users/settings/email">{{.EmailSettings}}</a><a href="/users/security">{{.Security}}</a><a href="/users/tokens">{{.Tokens}}</a><a href="/users/data/export">{{.DataExport}}</a><a href="/server/preferences">{{.Preferences}}</a><a href="/server/help">{{.Help}}</a><form method="post" action="/server/auth/logout"><input type="hidden" name="csrf_token" value="{{.SessionCSRF}}"><button type="submit">{{.SignOut}}</button></form>{{if .ShowThemeToggle}}<form method="post" action="/server/preferences"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="theme" value="{{.NextTheme}}"><button type="submit" aria-label="{{.ThemeLabel}}">{{.ThemeLabel}}</button></form>{{end}}</div></details>`))
var notificationListTemplate = template.Must(template.New("notification-list").Parse(`<form method="post" action="/users/notifications/read"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button class="btn btn-secondary" type="submit">{{.MarkAllRead}}</button></form><form method="post" action="/users/notifications/clear"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button class="btn btn-danger" type="button" popovertarget="clear-notifications">{{.ClearAll}}</button><div id="clear-notifications" popover aria-labelledby="clear-notifications-title"><h3 id="clear-notifications-title">{{.ClearAll}}</h3><p>{{.ClearAll}}?</p><button class="btn btn-secondary" type="button" popovertarget="clear-notifications" popovertargetaction="hide">{{.Cancel}}</button><button class="btn btn-danger" type="submit">{{.Confirm}}</button></div></form>{{if .Items}}<div class="notification-list">{{range .Items}}<form method="post" action="/users/notifications/{{.ID}}/read" class="notification-item {{if .Unread}}unread{{end}}"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="next" value="{{.Link}}"><button type="submit"><span class="notification-icon" aria-hidden="true">{{.Icon}}</span><span class="notification-title">{{.Title}}</span><span class="notification-message">{{.Message}}</span><time class="notification-time">{{.CreatedAt}}</time></button></form>{{end}}</div>{{else}}<p class="empty-state">{{.Empty}}</p>{{end}}`))
var userProfilePageTemplate = template.Must(template.New("user-profile").Parse(`<dl><dt>{{.UsernameLabel}}</dt><dd>{{.Username}}</dd><dt>{{.EmailLabel}}</dt><dd>{{.Email}}</dd></dl>{{.SettingsForm}}<p><a href="/users/tokens">{{.Tokens}}</a></p><p><a href="/users/notifications">{{.Notifications}}</a></p>`))
var publicProfileTemplate = template.Must(template.New("public-profile").Parse(`<div class="profile-card">{{if .Avatar}}<img class="profile-avatar" src="{{.Avatar}}" alt="">{{end}}<h2>{{.DisplayName}}</h2><p class="profile-username">@{{.Username}}</p>{{if .Verified}}<p>{{.VerifiedLabel}}</p>{{end}}{{if .Bio}}<p>{{.Bio}}</p>{{end}}{{if .Location}}<p>{{.Location}}</p>{{end}}{{if .Website}}<p><a href="{{.Website}}" rel="nofollow noopener">{{.Website}}</a></p>{{end}}{{if .Email}}<p><a href="mailto:{{.Email}}">{{.Email}}</a></p>{{end}}<p>{{.JoinedLabel}} {{.CreatedAt}}</p></div>`))
var emailVerificationFormTemplate = template.Must(template.New("email-verification").Parse(`<p>{{.Message}}</p><form method="post" action="/server/auth/verify"><input type="hidden" name="token" value="{{.Token}}"><button type="submit">{{.Confirm}}</button></form>`))
var userEmailSettingsTemplate = template.Must(template.New("user-email-settings").Parse(`{{if .Status}}<p role="status">{{.Status}}</p>{{end}}{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}<section class="settings-section"><h2>{{.AccountTitle}}</h2><p>{{.AccountValue}} — {{.AccountVerified}}</p><form method="post" action="/users/settings/email"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="type" value="account"><div class="form-group"><label for="account_email">{{.NewEmail}}</label><input class="form-input" id="account_email" type="email" name="email" autocomplete="email" required></div><div class="form-group"><label for="account_current_password">{{.CurrentPassword}}</label><input class="form-input" id="account_current_password" type="password" name="current_password" autocomplete="current-password" required></div><button type="submit">{{.ChangeAccount}}</button></form></section><section class="settings-section"><h2>{{.NotificationTitle}}</h2><p>{{.NotificationValue}} — {{.NotificationStatus}}</p><form method="post" action="/users/settings/email"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="type" value="notification"><div class="form-group"><label for="notification_email">{{.NotificationEmail}}</label><input class="form-input" id="notification_email" type="email" name="email" value="{{.NotificationAddress}}" autocomplete="email"></div><button type="submit">{{.SaveNotification}}</button></form></section>`))
var userTokensPageTemplate = template.Must(template.New("user-tokens").Parse(`<p>{{.Description}}</p>{{if .OneTimeToken}}<p role="status">{{.OneTimeLabel}}</p><pre><code>{{.OneTimeToken}}</code></pre>{{end}}<form method="post" action="/users/tokens/create"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><div class="form-group"><label for="new-token-name">{{.NameLabel}}</label><input class="form-input" id="new-token-name" name="name" maxlength="64" required></div><div class="form-group"><label for="new-token-scope">{{.ScopeLabel}}</label><select class="form-input" id="new-token-scope" name="scope"><option value="read">{{.ReadScope}}</option><option value="read-write">{{.WriteScope}}</option></select></div><button class="btn btn-primary" type="submit">{{.CreateToken}}</button></form>{{if .Tokens}}<div class="table-wrapper"><table class="data-table"><thead><tr><th scope="col">{{.NameLabel}}</th><th scope="col">{{.ScopeLabel}}</th><th scope="col">{{.CreatedLabel}}</th><th scope="col">{{.ActionsLabel}}</th></tr></thead><tbody>{{range .Tokens}}<tr><td>{{.Name}}</td><td>{{.Scope}}</td><td>{{.CreatedAt}}</td><td><form method="post" action="/users/tokens/{{.ID}}/revoke"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><button class="btn btn-danger" type="button" popovertarget="revoke-token-{{.ID}}">{{$.Revoke}}</button><div id="revoke-token-{{.ID}}" popover aria-labelledby="revoke-token-title-{{.ID}}"><h3 id="revoke-token-title-{{.ID}}">{{$.Revoke}}</h3><p>{{$.Revoke}}: {{.Name}}</p><button class="btn btn-secondary" type="button" popovertarget="revoke-token-{{.ID}}" popovertargetaction="hide">{{$.Cancel}}</button><button class="btn btn-danger" type="submit">{{$.Confirm}}</button></div></form></td></tr>{{end}}</tbody></table></div>{{else}}<p class="empty-state">{{.Empty}}</p>{{end}}`))
var userSettingsPageTemplate = template.Must(template.New("user-settings-page").Parse(`{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}<form method="post" action="{{.Action}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}">{{range .Fields}}<div class="form-group"><label for="{{.Name}}">{{.Label}}</label>{{if eq .Type "select"}}<select class="form-input" id="{{.Name}}" name="{{.Name}}">{{range .Options}}<option value="{{.Value}}" {{if .Selected}}selected{{end}}>{{.Label}}</option>{{end}}</select>{{else if eq .Type "textarea"}}<textarea class="form-input" id="{{.Name}}" name="{{.Name}}" maxlength="{{.MaxLength}}">{{.Value}}</textarea>{{else if eq .Type "checkbox"}}<input class="form-input" id="{{.Name}}" name="{{.Name}}" type="checkbox" value="true" {{if .Checked}}checked{{end}} {{if .Disabled}}disabled{{end}}>{{if not .Disabled}}<input type="hidden" name="{{.Name}}" value="false">{{end}}{{else}}<input class="form-input" id="{{.Name}}" name="{{.Name}}" type="{{.Type}}" value="{{.Value}}" maxlength="{{.MaxLength}}">{{end}}</div>{{end}}<button class="btn btn-primary" type="submit">{{.Save}}</button></form>`))
var userSecurityHomeTemplate = template.Must(template.New("user-security-home").Parse(`<ul><li><a href="/users/security/password">{{.Password}}</a></li><li><a href="/users/security/2fa">{{.TwoFactor}}</a></li><li><a href="/users/security/passkeys">{{.Passkeys}}</a></li><li><a href="/users/security/sessions">{{.Sessions}}</a></li></ul>`))
var userPasswordFormTemplate = template.Must(template.New("user-password-form").Parse(`{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}<form method="post" action="/users/security/password"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><div class="form-group"><label for="current_password">{{.Current}}</label><input class="form-input" type="password" id="current_password" name="current_password" autocomplete="current-password" required></div><div class="form-group"><label for="new_password">{{.New}}</label><input class="form-input" type="password" id="new_password" name="new_password" autocomplete="new-password" required></div><div class="form-group"><label for="confirm_password">{{.Confirm}}</label><input class="form-input" type="password" id="confirm_password" name="confirm_password" autocomplete="new-password" required></div><button class="btn btn-primary" type="submit">{{.Save}}</button></form>`))
var userSessionsTemplate = template.Must(template.New("user-sessions").Parse(`<p>{{.Description}}</p><ul>{{range .Sessions}}<li>{{.CreatedAt}} {{if .Current}}<strong>{{$.CurrentLabel}}</strong>{{else}}<form method="post" action="/users/security/sessions/{{.ID}}/revoke"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><button class="btn btn-danger" type="button" popovertarget="revoke-session-{{.ID}}">{{$.Revoke}}</button><div id="revoke-session-{{.ID}}" popover aria-labelledby="revoke-session-title-{{.ID}}"><h3 id="revoke-session-title-{{.ID}}">{{$.Revoke}}</h3><p>{{$.Revoke}}: {{.CreatedAt}}</p><button class="btn btn-secondary" type="button" popovertarget="revoke-session-{{.ID}}" popovertargetaction="hide">{{$.Cancel}}</button><button class="btn btn-danger" type="submit">{{$.Confirm}}</button></div></form>{{end}}</li>{{else}}<li class="empty-state">{{.Empty}}</li>{{end}}</ul>`))

var userRegistrationFormTemplate = template.Must(template.New("user-registration-form").Parse(`<form method="post" action="/server/auth/register"><input type="hidden" name="csrf_token" value="{{.CSRF}}">{{if .Error}}<p class="alert alert-danger" role="alert">{{.Error}}</p>{{end}}<div class="form-group"><label for="register-username">{{.Username}}</label><input id="register-username" name="username" type="text" autocomplete="username" minlength="2" maxlength="39" required></div><div class="form-group"><label for="register-email">{{.Email}}</label><input id="register-email" name="email" type="email" autocomplete="email" required></div><div class="form-group"><label for="register-password">{{.Password}}</label><input id="register-password" name="password" type="password" autocomplete="new-password" minlength="8" required></div><button type="submit">{{.Submit}}</button></form><p><a href="/server/auth/login">{{.Login}}</a></p>`))

func (s *Server) renderUserRegistrationPage(w http.ResponseWriter, r *http.Request, csrf, message string, status int) {
	language, _ := requestLanguage(r)
	catalog, _ := i18n.Resolve(language)
	errorMessage := ""
	if message != "" {
		errorMessage = catalog.T("auth.register_failed", nil)
	}
	content := executeTemplate(userRegistrationFormTemplate, map[string]string{
		"CSRF": csrf, "Error": errorMessage, "Username": catalog.T("auth.username_create", nil),
		"Email": catalog.T("auth.email", nil), "Password": catalog.T("auth.password", nil),
		"Submit": catalog.T("auth.register", nil), "Login": catalog.T("auth.already_have_account", nil),
	})
	page := publicPageTemplateData{Title: catalog.T("auth.register", nil), Lead: catalog.T("auth.registration_lead", nil), NoIndex: true, CSRFToken: csrf, Sections: []renderedPageSection{{ID: "registration", Title: catalog.T("auth.register", nil), Content: template.HTML(content)}}}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, "Page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, page)
}

func (s *Server) handleEmailVerificationPage(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if len(token) < 32 || len(token) > 256 {
		http.NotFound(w, r)
		return
	}
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Verification page unavailable", http.StatusInternalServerError)
		return
	}
	content := executeTemplate(emailVerificationFormTemplate, map[string]string{
		"Token":   token,
		"Message": catalog.T("auth.verify_email_lead", nil),
		"Confirm": catalog.T("auth.verify_email", nil),
	})
	page := publicPageTemplateData{Title: catalog.T("auth.verify_email", nil), Lead: catalog.T("auth.verify_email_lead", nil), NoIndex: true, Sections: []renderedPageSection{{ID: "email-verification", Title: catalog.T("auth.verify_email", nil), Content: template.HTML(content)}}}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, "Verification page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if err := pageTemplate.Execute(w, page); err != nil {
		return
	}
}

func (s *Server) handleUserEmailSettings(w http.ResponseWriter, r *http.Request) {
	identity, err := s.userPageIdentity(r)
	if err != nil {
		http.Error(w, "Unable to load email settings", http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		http.Redirect(w, r, "/server/auth/login?redirect="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
		return
	}
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Email settings unavailable", http.StatusInternalServerError)
		return
	}
	statusMessage := ""
	errorMessage := ""
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil || !sameOriginPageRequest(r) || !validPreferenceCSRF(r) {
			http.Error(w, "Email settings request failed security validation", http.StatusForbidden)
			return
		}
		payload, _ := json.Marshal(map[string]string{"type": r.FormValue("type"), "email": r.FormValue("email"), "current_password": r.FormValue("current_password")})
		apiRequest := r.Clone(r.Context())
		apiRequest.Body = io.NopCloser(strings.NewReader(string(payload)))
		apiRequest.Header = r.Header.Clone()
		apiRequest.Header.Set("Content-Type", "application/json")
		apiResponse := httptest.NewRecorder()
		s.UserHandler.UpdateEmail(apiResponse, apiRequest)
		if apiResponse.Code == http.StatusAccepted {
			statusMessage = catalog.T("auth.email_verification_sent", nil)
		} else if apiResponse.Code >= 200 && apiResponse.Code < 300 {
			statusMessage = catalog.T("auth.email_settings_updated", nil)
		} else {
			errorMessage = catalog.T("auth.email_settings_failed", nil)
		}
	}
	user, err := s.Store.GetUser(r.Context(), userIDString(identity.User.ID))
	if err != nil || user == nil {
		http.Error(w, "Unable to load email settings", http.StatusInternalServerError)
		return
	}
	csrf := s.issuePreferenceCSRF(w, r)
	verified := catalog.T("auth.email_unverified", nil)
	if user.EmailVerified {
		verified = catalog.T("auth.email_verified", nil)
	}
	notificationEmail := user.NotificationEmail
	notificationStatus := catalog.T("auth.email_verified", nil)
	if user.NotificationEmail != "" && !user.NotificationEmailVerified {
		notificationStatus = catalog.T("auth.email_unverified", nil)
	}
	if notificationEmail == "" {
		notificationEmail = catalog.T("auth.account_email_default", nil)
	}
	content := executeTemplate(userEmailSettingsTemplate, map[string]string{
		"CSRF": csrf, "Status": statusMessage, "Error": errorMessage,
		"AccountTitle": catalog.T("auth.account_email", nil), "AccountValue": user.Email, "AccountVerified": verified,
		"NewEmail": catalog.T("auth.new_email", nil), "CurrentPassword": catalog.T("auth.current_password", nil), "ChangeAccount": catalog.T("auth.change_account_email", nil),
		"NotificationTitle": catalog.T("auth.notification_email", nil), "NotificationValue": notificationEmail, "NotificationStatus": notificationStatus,
		"NotificationEmail": catalog.T("auth.notification_email", nil), "NotificationAddress": user.NotificationEmail,
		"SaveNotification": catalog.T("user_settings.save", nil),
	})
	page := publicPageTemplateData{Title: catalog.T("auth.email_settings", nil), Lead: catalog.T("auth.email_settings_lead", nil), NoIndex: true, CSRFToken: csrf, Sections: []renderedPageSection{{ID: "email-settings", Title: catalog.T("auth.email_settings", nil), Content: template.HTML(content)}}}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, "Unable to prepare email settings", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := pageTemplate.Execute(w, page); err != nil {
		return
	}
}

type publicUserProfile struct {
	Username    string            `json:"username"`
	DisplayName string            `json:"display_name"`
	Avatar      map[string]string `json:"avatar,omitempty"`
	Bio         string            `json:"bio,omitempty"`
	Location    string            `json:"location,omitempty"`
	Website     string            `json:"website,omitempty"`
	Email       string            `json:"email,omitempty"`
	Verified    bool              `json:"verified"`
	CreatedAt   time.Time         `json:"created_at"`
}

func (s *Server) publicUserProfile(r *http.Request, username string) (*publicUserProfile, error) {
	user, err := s.Store.GetUserByUsername(r.Context(), username)
	if err != nil || user == nil || user.Visibility == "private" {
		return nil, err
	}
	settings := &model.UserSettings{}
	if settingsStore, ok := s.Store.(store.UserSettingsStore); ok {
		settings, err = settingsStore.GetOrCreateUserSettings(r.Context(), userIDString(user.ID))
		if err != nil {
			return nil, err
		}
	}
	profile := &publicUserProfile{
		Username: user.Username, DisplayName: user.DisplayName, Bio: user.Bio,
		Website: user.Website, Verified: user.EmailVerified, CreatedAt: user.CreatedAt,
	}
	torRequest := overlayRequestKind(r) == "tor"
	if profile.DisplayName == "" {
		profile.DisplayName = user.Username
	}
	profile.Location = user.Location
	if settings.ShowEmail && !torRequest {
		profile.Email = user.Email
	}
	if torRequest {
		profile.Website = ""
		profile.CreatedAt = profile.CreatedAt.UTC()
	} else {
		avatarURL := user.AvatarURL
		if avatarURL == "" {
			digest := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(user.Email))))
			avatarURL = "https://www.gravatar.com/avatar/" + hex.EncodeToString(digest[:]) + "?s=256&d=identicon"
		}
		profile.Avatar = map[string]string{"256": avatarURL}
	}
	return profile, nil
}

func publicPageText(r *http.Request, key string, values map[string]string) string {
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		catalog, _ = i18n.Resolve("en")
	}
	return catalog.T(key, values)
}

func (s *Server) handlePublicUserProfileAPI(w http.ResponseWriter, r *http.Request) {
	profile, err := s.publicUserProfile(r, chi.URLParam(r, "username"))
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": publicPageText(r, "pages.security.profile_load_failed", nil)})
		return
	}
	if profile == nil {
		writeUserJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": publicPageText(r, "pages.security.profile_not_found", nil)})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": profile})
}

func (s *Server) handlePublicUserProfilePage(w http.ResponseWriter, r *http.Request) {
	profile, err := s.publicUserProfile(r, chi.URLParam(r, "username"))
	if err != nil {
		http.Error(w, publicPageText(r, "pages.security.profile_load_failed", nil), http.StatusInternalServerError)
		return
	}
	if profile == nil {
		http.Error(w, publicPageText(r, "pages.security.profile_not_found", nil), http.StatusNotFound)
		return
	}
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, publicPageText(r, "pages.security.profile_unavailable", nil), http.StatusInternalServerError)
		return
	}
	avatar := profile.Avatar["256"]
	content := executeTemplate(publicProfileTemplate, map[string]any{
		"Username": profile.Username, "DisplayName": profile.DisplayName, "Avatar": avatar,
		"Bio": profile.Bio, "Location": profile.Location, "Website": profile.Website, "Email": profile.Email,
		"Verified": profile.Verified, "VerifiedLabel": catalog.T("auth.email_verified", nil),
		"JoinedLabel": catalog.T("profile.joined", nil), "CreatedAt": profile.CreatedAt.Format("2006-01-02"),
	})
	page := publicPageTemplateData{Title: profile.DisplayName, Lead: "@" + profile.Username, Sections: []renderedPageSection{{ID: "public-profile", Title: profile.DisplayName, Content: template.HTML(content)}}}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, publicPageText(r, "pages.security.profile_unavailable", nil), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
	if err := pageTemplate.Execute(w, page); err != nil {
		return
	}
}

type userSettingsOption struct {
	Value, Label string
	Selected     bool
}
type userSettingsField struct {
	Name, Label, Type, Value string
	MaxLength                int
	Checked, Disabled        bool
	Options                  []userSettingsOption
}

func (s *Server) handleUserSettingsPage(w http.ResponseWriter, r *http.Request) {
	category := strings.Trim(strings.TrimPrefix(r.URL.Path, "/users/settings"), "/")
	if category == "" {
		category = "account"
	}
	if category != "account" && category != "privacy" && category != "notifications" && category != "appearance" {
		http.NotFound(w, r)
		return
	}
	identity, err := s.userPageIdentity(r)
	if err != nil {
		http.Error(w, "Unable to load account settings", http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		http.Redirect(w, r, "/server/auth/login?redirect="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
		return
	}
	settingsStore, ok := s.Store.(store.UserSettingsStore)
	if !ok {
		http.Error(w, "Account settings are unavailable", http.StatusServiceUnavailable)
		return
	}
	settings, err := settingsStore.GetOrCreateUserSettings(r.Context(), userIDString(identity.User.ID))
	if err != nil {
		http.Error(w, "Unable to load account settings", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid settings form", http.StatusBadRequest)
			return
		}
		if !sameOriginPageRequest(r) || !validPreferenceCSRF(r) {
			http.Error(w, "Settings request failed security validation", http.StatusForbidden)
			return
		}
		if err := s.applyUserSettingsForm(r, identity.User, settings, category); err != nil {
			s.renderUserSettingsForm(w, r, identity.User, settings, category, err.Error(), http.StatusBadRequest)
			return
		}
		if err := settingsStore.UpdateUserSettings(r.Context(), settings); err != nil {
			http.Error(w, "Unable to save account settings", http.StatusInternalServerError)
			return
		}
		if category == "account" {
			if err := s.Store.UpdateUser(r.Context(), identity.User); err != nil {
				http.Error(w, "Unable to save account settings", http.StatusInternalServerError)
				return
			}
		}
		if err := s.createUserNotification(r.Context(), userIDString(identity.User.ID), "success", "notifications.profile_updated", "notifications.settings_saved", r.URL.Path); err != nil {
			log.Printf("user settings notification failed: %v", err)
		}
		http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
		return
	}
	s.renderUserSettingsForm(w, r, identity.User, settings, category, "", http.StatusOK)
}

func (s *Server) createUserNotification(ctx context.Context, userID, kind, title, message, link string) error {
	notifications, ok := s.Store.(store.UserNotificationStore)
	if !ok {
		return fmt.Errorf("notification storage is unavailable")
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return fmt.Errorf("generate notification ID: %w", err)
	}
	if err := notifications.CreateUserNotification(ctx, &model.Notification{
		ID: hex.EncodeToString(idBytes), UserID: userID, Type: kind, Title: title,
		Message: message, Link: link, CreatedAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	if kind != "security" && kind != "activity" && kind != "product" || s.EmailService == nil || !s.EmailService.Available() {
		return nil
	}
	user, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("load notification recipient: %w", err)
	}
	if user == nil {
		return nil
	}
	if settingsStore, ok := s.Store.(store.UserSettingsStore); ok {
		settings, settingsErr := settingsStore.GetOrCreateUserSettings(ctx, userID)
		if settingsErr != nil {
			return fmt.Errorf("load notification preferences: %w", settingsErr)
		}
		if kind == "security" && (!settings.EmailSecurity || title == "notifications.session_started" && !settings.EmailSession) || kind == "activity" && !settings.EmailMentions || kind == "product" && !settings.EmailUpdates {
			return nil
		}
	}
	recipient := user.Email
	if kind != "security" && user.NotificationEmail != "" {
		if !user.NotificationEmailVerified {
			return nil
		}
		recipient = user.NotificationEmail
	} else if !user.EmailVerified {
		return nil
	}
	if recipient == "" {
		return nil
	}
	language := user.Language
	if language == "" {
		language = "en"
	}
	catalog, err := i18n.Resolve(language)
	if err != nil {
		return fmt.Errorf("resolve notification language: %w", err)
	}
	subject := catalog.T("notifications.security_subject", nil)
	body := catalog.T(title, nil) + "\n\n" + catalog.T(message, nil) + "\n"
	if err := s.EmailService.SendMessage(recipient, "", subject, body); err != nil {
		log.Printf("user notification email delivery failed: %v", err)
	}
	return nil
}

func (s *Server) handleUserSecurityPage(w http.ResponseWriter, r *http.Request) {
	identity, err := s.userPageIdentity(r)
	if err != nil {
		http.Error(w, "Unable to load account security", http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		http.Redirect(w, r, "/server/auth/login?redirect="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
		return
	}
	language, _ := requestLanguage(r)
	catalog, _ := i18n.Resolve(language)
	title := catalog.T("auth.security", nil)
	var content string
	status := http.StatusOK
	switch {
	case r.URL.Path == "/users/security/password":
		errText := ""
		if r.Method == http.MethodPost {
			if parseErr := r.ParseForm(); parseErr != nil {
				http.Error(w, "Invalid password form", http.StatusBadRequest)
				return
			}
			if !sameOriginPageRequest(r) || !validPreferenceCSRF(r) {
				http.Error(w, "Password request failed security validation", http.StatusForbidden)
				return
			}
			current, next, confirm := r.FormValue("current_password"), r.FormValue("new_password"), r.FormValue("confirm_password")
			switch {
			case !auth.VerifyPassword(current, identity.User.PasswordHash):
				errText = catalog.T("auth.invalid_credentials", nil)
			case s.validateUserPassword(next) != nil:
				errText = catalog.T("auth.password_requirements", nil)
			case next != confirm:
				errText = catalog.T("auth.password_mismatch", nil)
			default:
				hash, hashErr := auth.HashPassword(next)
				if hashErr != nil {
					http.Error(w, "Unable to update password", http.StatusInternalServerError)
					return
				}
				identity.User.PasswordHash = hash
				if updateErr := s.Store.UpdateUser(r.Context(), identity.User); updateErr != nil {
					http.Error(w, "Unable to update password", http.StatusInternalServerError)
					return
				}
				if eventErr := s.createUserNotification(r.Context(), userIDString(identity.User.ID), "security", "notifications.password_changed", "notifications.password_changed_message", "/users/security"); eventErr != nil {
					log.Printf("password change notification failed: %v", eventErr)
				}
				if clearErr := s.Store.DeleteUserSessions(r.Context(), userIDString(identity.User.ID)); clearErr != nil {
					http.Error(w, "Password changed but sessions could not be invalidated", http.StatusInternalServerError)
					return
				}
				http.SetCookie(w, &http.Cookie{Name: "user_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
				http.Redirect(w, r, "/server/auth/login?password_changed=1", http.StatusSeeOther)
				return
			}
			status = http.StatusBadRequest
		}
		csrf := s.issuePreferenceCSRF(w, r)
		content = executeTemplate(userPasswordFormTemplate, map[string]string{"CSRF": csrf, "Current": catalog.T("auth.current_password", nil), "New": catalog.T("auth.new_password", nil), "Confirm": catalog.T("auth.confirm_password", nil), "Save": catalog.T("user_settings.save", nil), "Error": errText})
		title = catalog.T("auth.change_password", nil)
	case strings.HasPrefix(r.URL.Path, "/users/security/sessions"):
		sessionStore, ok := s.Store.(store.UserSessionStore)
		if !ok {
			http.Error(w, "Session management is unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodPost {
			if parseErr := r.ParseForm(); parseErr != nil {
				http.Error(w, "Invalid session form", http.StatusBadRequest)
				return
			}
			if !sameOriginPageRequest(r) || !validPreferenceCSRF(r) {
				http.Error(w, "Session request failed security validation", http.StatusForbidden)
				return
			}
			if revokeErr := sessionStore.RevokeUserSession(r.Context(), userIDString(identity.User.ID), chi.URLParam(r, "sessionID")); revokeErr != nil {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, "/users/security/sessions", http.StatusSeeOther)
			return
		}
		items, err := sessionStore.ListUserSessions(r.Context(), userIDString(identity.User.ID))
		if err != nil {
			http.Error(w, "Unable to load sessions", http.StatusInternalServerError)
			return
		}
		current := ""
		if cookie, cookieErr := r.Cookie("user_session"); cookieErr == nil {
			digest := sha256.Sum256([]byte(cookie.Value))
			current = hex.EncodeToString(digest[:])
		}
		views := make([]map[string]any, 0, len(items))
		for _, item := range items {
			views = append(views, map[string]any{"ID": item.ID, "CreatedAt": item.CreatedAt.UTC().Format(time.RFC3339), "Current": item.ID == current})
		}
		csrf := s.issuePreferenceCSRF(w, r)
		content = executeTemplate(userSessionsTemplate, map[string]any{"Sessions": views, "Description": catalog.T("auth.sessions_description", nil), "Empty": catalog.T("auth.no_sessions", nil), "CSRF": csrf, "CurrentLabel": catalog.T("auth.current_session", nil), "Revoke": catalog.T("auth.revoke_session", nil), "Cancel": catalog.T("common.cancel", nil), "Confirm": catalog.T("common.confirm", nil)})
		title = catalog.T("auth.sessions", nil)
	default:
		content = executeTemplate(userSecurityHomeTemplate, map[string]string{"Password": catalog.T("auth.change_password", nil), "TwoFactor": catalog.T("auth.two_factor", nil), "Passkeys": catalog.T("auth.passkeys", nil), "Sessions": catalog.T("auth.sessions", nil)})
	}
	csrf := s.issuePreferenceCSRF(w, r)
	page := publicPageTemplateData{Title: title, Lead: catalog.T("auth.security_lead", nil), NoIndex: true, CSRFToken: csrf, Sections: []renderedPageSection{{ID: "account-security", Title: title, Content: template.HTML(content)}}}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, "Unable to prepare security page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, page)
}

func (s *Server) applyUserSettingsForm(r *http.Request, user *model.User, settings *model.UserSettings, category string) error {
	formBool := func(key string) bool { return r.FormValue(key) == "true" || r.FormValue(key) == "on" }
	switch category {
	case "account":
		user.DisplayName = strings.TrimSpace(r.FormValue("display_name"))
		user.Bio = strings.TrimSpace(r.FormValue("bio"))
		user.Location = strings.TrimSpace(r.FormValue("location"))
		user.Website = strings.TrimSpace(r.FormValue("website"))
		user.Timezone = strings.TrimSpace(r.FormValue("timezone"))
		user.Language = strings.TrimSpace(r.FormValue("language"))
		if len(user.DisplayName) > 100 || len(user.Bio) > 500 || len(user.Location) > 100 || len(user.Website) > 2048 {
			return fmt.Errorf("one or more fields exceed their length limit")
		}
		if user.Website != "" {
			parsed, err := url.ParseRequestURI(user.Website)
			if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				return fmt.Errorf("website must be an absolute HTTP or HTTPS URL")
			}
		}
		if user.Timezone != "" {
			if _, err := time.LoadLocation(user.Timezone); err != nil {
				return fmt.Errorf("choose a valid IANA timezone")
			}
		}
		if !s.isLanguageAvailable(user.Language) {
			return fmt.Errorf("choose a supported language")
		}
	case "privacy":
		user.Visibility = r.FormValue("visibility")
		if user.Visibility != "public" && user.Visibility != "private" {
			return fmt.Errorf("choose public or private visibility")
		}
		user.OrgVisibility = formBool("org_visibility")
		settings.ShowEmail, settings.ShowActivity = formBool("show_email"), formBool("show_activity")
		settings.ShowOrgs, settings.Searchable = formBool("show_orgs"), formBool("searchable")
	case "notifications":
		settings.EmailSecurity = true
		settings.EmailSession = formBool("email_session")
		settings.EmailMentions, settings.EmailUpdates, settings.EmailNewsletter = formBool("email_mentions"), formBool("email_updates"), formBool("email_newsletter")
		settings.EmailDigest = r.FormValue("email_digest")
		if settings.EmailDigest != "never" && settings.EmailDigest != "daily" && settings.EmailDigest != "weekly" {
			return fmt.Errorf("choose a valid digest frequency")
		}
		settings.PushEnabled, settings.PushMentions = formBool("push_enabled"), formBool("push_mentions")
	case "appearance":
		settings.Theme, settings.FontSize = r.FormValue("theme"), r.FormValue("font_size")
		settings.ReduceMotion = formBool("reduce_motion")
		settings.DateFormat, settings.TimeFormat = r.FormValue("date_format"), r.FormValue("time_format")
		if settings.Theme != "dark" && settings.Theme != "light" && settings.Theme != "auto" {
			return fmt.Errorf("choose a valid theme")
		}
		if settings.FontSize != "small" && settings.FontSize != "medium" && settings.FontSize != "large" {
			return fmt.Errorf("choose a valid font size")
		}
		if settings.DateFormat != "YYYY-MM-DD" && settings.DateFormat != "MM/DD/YYYY" && settings.DateFormat != "DD/MM/YYYY" {
			return fmt.Errorf("choose a valid date format")
		}
		if settings.TimeFormat != "12h" && settings.TimeFormat != "24h" {
			return fmt.Errorf("choose a valid time format")
		}
	}
	return nil
}

func (s *Server) renderUserSettingsForm(w http.ResponseWriter, r *http.Request, user *model.User, settings *model.UserSettings, category, message string, status int) {
	language, _ := requestLanguage(r)
	catalog, _ := i18n.Resolve(language)
	key := "auth.settings"
	if category != "account" {
		key += "_" + category
	}
	fields := s.userSettingsFields(catalog, user, settings, category)
	csrf := s.issuePreferenceCSRF(w, r)
	content := executeTemplate(userSettingsPageTemplate, map[string]any{"Action": r.URL.Path, "CSRF": csrf, "Fields": fields, "Save": catalog.T("user_settings.save", nil), "Error": message})
	page := publicPageTemplateData{Title: catalog.T(key, nil), Lead: catalog.T("user_settings.lead", nil), NoIndex: true, CSRFToken: csrf, Sections: []renderedPageSection{{ID: "user-settings", Title: catalog.T(key, nil), Content: template.HTML(content)}}}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, "Unable to prepare settings page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, page)
}

func (s *Server) userSettingsFields(catalog *i18n.Catalog, user *model.User, settings *model.UserSettings, category string) []userSettingsField {
	field := func(name, kind, value string, max int) userSettingsField {
		return userSettingsField{Name: name, Type: kind, Value: value, MaxLength: max, Label: catalog.T("user_settings."+name, nil)}
	}
	checkbox := func(name string, checked bool) userSettingsField {
		result := field(name, "checkbox", "", 0)
		result.Checked = checked
		return result
	}
	selectField := func(name, selected string, values []string) userSettingsField {
		result := field(name, "select", "", 0)
		for _, value := range values {
			result.Options = append(result.Options, userSettingsOption{Value: value, Label: catalog.T("user_settings.option_"+value, nil), Selected: selected == value})
		}
		return result
	}
	switch category {
	case "account":
		fields := []userSettingsField{field("display_name", "text", user.DisplayName, 100), field("bio", "textarea", user.Bio, 500), field("location", "text", user.Location, 100), field("website", "url", user.Website, 2048), field("timezone", "text", user.Timezone, 128)}
		locales, _ := i18n.Supported()
		language := selectField("language", user.Language, []string{})
		for _, locale := range locales {
			if s.isLanguageAvailable(locale.Language) {
				language.Options = append(language.Options, userSettingsOption{Value: locale.Language, Label: locale.Native, Selected: user.Language == locale.Language})
			}
		}
		return append(fields, language)
	case "privacy":
		return []userSettingsField{selectField("visibility", user.Visibility, []string{"public", "private"}), checkbox("show_email", settings.ShowEmail), checkbox("show_activity", settings.ShowActivity), checkbox("show_orgs", settings.ShowOrgs), checkbox("searchable", settings.Searchable), checkbox("org_visibility", user.OrgVisibility)}
	case "notifications":
		security := checkbox("email_security", true)
		security.Disabled = true
		return []userSettingsField{security, checkbox("email_session", settings.EmailSession), checkbox("email_mentions", settings.EmailMentions), checkbox("email_updates", settings.EmailUpdates), checkbox("email_newsletter", settings.EmailNewsletter), selectField("email_digest", settings.EmailDigest, []string{"never", "daily", "weekly"}), checkbox("push_enabled", settings.PushEnabled), checkbox("push_mentions", settings.PushMentions)}
	default:
		return []userSettingsField{selectField("theme", settings.Theme, []string{"dark", "light", "auto"}), selectField("font_size", settings.FontSize, []string{"small", "medium", "large"}), checkbox("reduce_motion", settings.ReduceMotion), selectField("date_format", settings.DateFormat, []string{"YYYY-MM-DD", "MM/DD/YYYY", "DD/MM/YYYY"}), selectField("time_format", settings.TimeFormat, []string{"12h", "24h"})}
	}
}

func (s *Server) handleSwaggerPage(w http.ResponseWriter, r *http.Request) {
	lang, _ := requestLanguage(r)
	catalog, _ := i18n.Resolve(lang)
	specURL := BuildURL(r, s.Config.APIBasePath()+"/server/swagger")
	content := executeTemplate(swaggerPageContentTemplate, map[string]string{
		"NoScript": catalog.T("docs.javascript_required", nil), "SpecURL": specURL,
	})
	page := publicPageTemplateData{
		Title: catalog.T("page_titles.swagger", nil), Lead: catalog.T("docs.swagger_lead", nil),
		Sections:    []renderedPageSection{{ID: "interactive-api-reference", Title: catalog.T("docs.interactive_api_reference", nil), Content: template.HTML(content)}},
		PageAssets:  template.HTML(`<link rel="stylesheet" href="/static/vendor/swagger-ui/swagger-ui.css"><link rel="stylesheet" href="/static/css/swagger-ui-theme.css">`),
		PageScripts: []string{"/static/vendor/swagger-ui/swagger-ui-bundle.js", "/static/vendor/swagger-ui/swagger-ui-standalone-preset.js", "/static/js/swagger-init.js", "/static/js/app.js"},
	}
	s.renderPageShell(w, r, page)
}

func (s *Server) handleGraphQLPage(w http.ResponseWriter, r *http.Request) {
	lang, _ := requestLanguage(r)
	catalog, _ := i18n.Resolve(lang)
	endpoint := BuildURL(r, s.Config.APIBasePath()+"/server/graphql")
	content := executeTemplate(graphqlPageContentTemplate, map[string]string{
		"Endpoint": endpoint, "Loading": catalog.T("docs.graphql_loading", nil),
		"NoScript": catalog.T("docs.javascript_required", nil),
	})
	page := publicPageTemplateData{
		Title: catalog.T("page_titles.graphql", nil), Lead: catalog.T("docs.graphql_lead", nil),
		Sections:    []renderedPageSection{{ID: "graphql-explorer", Title: catalog.T("docs.interactive_explorer", nil), Content: template.HTML(content)}},
		PageAssets:  template.HTML(`<link rel="stylesheet" href="/static/vendor/graphiql/graphiql.min.css"><link rel="stylesheet" href="/static/css/graphiql-theme.css">`),
		PageScripts: []string{"/static/vendor/graphiql/react.production.min.js", "/static/vendor/graphiql/react-dom.production.min.js", "/static/vendor/graphiql/graphiql.min.js", "/static/js/docs-graphql.js"},
	}
	s.renderPageShell(w, r, page)
}

func (s *Server) renderPageShell(w http.ResponseWriter, r *http.Request, page publicPageTemplateData) {
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, "Unable to prepare page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTemplate.Execute(w, page)
}

func (s *Server) renderPrivatePageError(w http.ResponseWriter, r *http.Request, status int) {
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, http.StatusText(status), status)
		return
	}
	key := "500"
	switch status {
	case http.StatusBadRequest, http.StatusMethodNotAllowed:
		key = "400"
	case http.StatusUnauthorized, http.StatusForbidden:
		key = "403"
	case http.StatusNotFound:
		key = "404"
	case http.StatusTooManyRequests:
		key = "429"
	case http.StatusServiceUnavailable:
		key = "503"
	}
	title := catalog.T("errors.http_"+key+"_title", nil)
	message := catalog.T("errors.http_"+key+"_message", nil)
	page := publicPageTemplateData{
		Title: title, Lead: message, NoIndex: true,
		Sections: []renderedPageSection{{ID: "request-error", Title: catalog.T("common.error", nil), Content: template.HTML(`<p class="alert alert-danger" role="alert">` + template.HTMLEscapeString(message) + `</p>`)}},
	}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, page)
}

func (s *Server) handleUserNotifications(w http.ResponseWriter, r *http.Request) {
	identity, err := s.userPageIdentity(r)
	if err != nil {
		http.Error(w, "Unable to load notifications", http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		http.Redirect(w, r, "/server/auth/login?redirect=%2Fusers%2Fnotifications", http.StatusSeeOther)
		return
	}
	notificationStore, ok := s.Store.(store.UserNotificationStore)
	if !ok {
		http.Error(w, "Notifications are unavailable", http.StatusServiceUnavailable)
		return
	}
	items, err := notificationStore.GetUserNotifications(r.Context(), userIDString(identity.User.ID), 100)
	if err != nil {
		http.Error(w, "Unable to load notifications", http.StatusInternalServerError)
		return
	}
	language, _ := requestLanguage(r)
	catalog, _ := i18n.Resolve(language)
	views := make([]notificationView, 0, len(items))
	for _, item := range items {
		views = append(views, notificationView{ID: item.ID, Icon: notificationIcon(item.Type), Title: catalog.T(item.Title, nil), Message: catalog.T(item.Message, nil), Link: safeNotificationLink(item.Link), CreatedAt: relativeNotificationTime(catalog, time.Since(item.CreatedAt)), Unread: item.ReadAt == nil})
	}
	csrf := s.issuePreferenceCSRF(w, r)
	content := executeTemplate(notificationListTemplate, map[string]any{
		"CSRF": csrf, "Items": views, "Empty": catalog.T("notifications.empty", nil),
		"MarkAllRead": catalog.T("notifications.mark_all_read", nil), "ClearAll": catalog.T("notifications.clear_all", nil),
		"Cancel": catalog.T("common.cancel", nil), "Confirm": catalog.T("common.confirm", nil),
	})
	page := publicPageTemplateData{Title: catalog.T("notifications.title", nil), Lead: catalog.T("notifications.history", nil), NoIndex: true, CSRFToken: csrf, Sections: []renderedPageSection{{ID: "notifications", Title: catalog.T("notifications.title", nil), Content: template.HTML(content)}}}
	s.renderPageShell(w, r, page)
}

func (s *Server) handleUserProfilePage(w http.ResponseWriter, r *http.Request) {
	identity, err := s.userPageIdentity(r)
	if err != nil {
		http.Error(w, "Unable to load profile", http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		http.Redirect(w, r, "/server/auth/login?redirect=%2Fusers", http.StatusSeeOther)
		return
	}
	settingsStore, ok := s.Store.(store.UserSettingsStore)
	if !ok {
		http.Error(w, "Account settings are unavailable", http.StatusServiceUnavailable)
		return
	}
	settings, err := settingsStore.GetOrCreateUserSettings(r.Context(), userIDString(identity.User.ID))
	if err != nil {
		http.Error(w, "Unable to load account settings", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid profile form", http.StatusBadRequest)
			return
		}
		if !sameOriginPageRequest(r) || !validPreferenceCSRF(r) {
			http.Error(w, "Profile request failed security validation", http.StatusForbidden)
			return
		}
		if err := s.applyUserSettingsForm(r, identity.User, settings, "account"); err != nil {
			http.Error(w, "Invalid profile values", http.StatusBadRequest)
			return
		}
		if err := s.Store.UpdateUser(r.Context(), identity.User); err != nil {
			http.Error(w, "Unable to save profile", http.StatusInternalServerError)
			return
		}
		if err := settingsStore.UpdateUserSettings(r.Context(), settings); err != nil {
			http.Error(w, "Unable to save profile settings", http.StatusInternalServerError)
			return
		}
		if err := s.createUserNotification(r.Context(), userIDString(identity.User.ID), "success", "notifications.profile_updated", "notifications.settings_saved", "/users"); err != nil {
			log.Printf("profile update notification failed: %v", err)
		}
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	language, _ := requestLanguage(r)
	catalog, _ := i18n.Resolve(language)
	csrf := s.issuePreferenceCSRF(w, r)
	form := executeTemplate(userSettingsPageTemplate, map[string]any{"Action": "/users", "CSRF": csrf, "Fields": s.userSettingsFields(catalog, identity.User, settings, "account"), "Save": catalog.T("user_settings.save", nil)})
	content := executeTemplate(userProfilePageTemplate, map[string]any{
		"UsernameLabel": catalog.T("auth.username_label", nil), "Username": identity.User.Username,
		"EmailLabel": catalog.T("auth.email", nil), "Email": identity.User.Email,
		"Tokens": catalog.T("pages.tokens", nil), "Notifications": catalog.T("notifications.title", nil),
		"SettingsForm": template.HTML(form),
	})
	page := publicPageTemplateData{Title: catalog.T("auth.profile", nil), Lead: catalog.T("auth.profile_lead", nil), NoIndex: true, CSRFToken: csrf, Sections: []renderedPageSection{{ID: "profile", Title: catalog.T("auth.profile", nil), Content: template.HTML(content)}}}
	s.renderPageShell(w, r, page)
}

func (s *Server) handleUserTokensPage(w http.ResponseWriter, r *http.Request) {
	identity, err := s.userPageIdentity(r)
	if err != nil {
		http.Error(w, "Unable to load API tokens", http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		http.Redirect(w, r, "/server/auth/login?redirect=%2Fusers%2Ftokens", http.StatusSeeOther)
		return
	}
	oneTimeToken := ""
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid token form", http.StatusBadRequest)
			return
		}
		if !sameOriginPageRequest(r) || !validPreferenceCSRF(r) {
			http.Error(w, "Token request failed security validation", http.StatusForbidden)
			return
		}
		payload, err := json.Marshal(map[string]string{"name": strings.TrimSpace(r.FormValue("name")), "scope": r.FormValue("scope")})
		if err != nil {
			http.Error(w, "Unable to create API token", http.StatusInternalServerError)
			return
		}
		apiRequest := r.Clone(r.Context())
		apiRequest.Body = io.NopCloser(bytes.NewReader(payload))
		apiRequest.Header.Set("Content-Type", "application/json")
		apiResponse := httptest.NewRecorder()
		s.UserHandler.CreateToken(apiResponse, apiRequest)
		var envelope struct {
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
		}
		if apiResponse.Code != http.StatusCreated || json.Unmarshal(apiResponse.Body.Bytes(), &envelope) != nil || envelope.Data.Token == "" {
			http.Error(w, "Unable to create API token", http.StatusBadRequest)
			return
		}
		oneTimeToken = envelope.Data.Token
	}
	tokens, err := s.Store.GetUserAPITokens(r.Context(), userIDString(identity.User.ID))
	if err != nil {
		http.Error(w, "Unable to load API tokens", http.StatusInternalServerError)
		return
	}
	language, _ := requestLanguage(r)
	catalog, _ := i18n.Resolve(language)
	csrf := s.issuePreferenceCSRF(w, r)
	content := executeTemplate(userTokensPageTemplate, map[string]any{
		"Tokens": tokens, "CSRF": csrf, "Description": catalog.T("auth.tokens_description", nil), "OneTimeToken": oneTimeToken, "OneTimeLabel": catalog.T("auth.token_one_time", nil),
		"NameLabel": catalog.T("auth.token_name", nil), "ScopeLabel": catalog.T("auth.token_scope", nil),
		"CreatedLabel": catalog.T("auth.token_created", nil), "ActionsLabel": catalog.T("auth.actions", nil),
		"Revoke": catalog.T("auth.revoke_token", nil), "Empty": catalog.T("auth.no_tokens", nil), "CreateToken": catalog.T("auth.create_token", nil),
		"Cancel": catalog.T("common.cancel", nil), "Confirm": catalog.T("common.confirm", nil),
		"ReadScope": catalog.T("auth.scope_read", nil), "WriteScope": catalog.T("auth.scope_read_write", nil),
	})
	page := publicPageTemplateData{Title: catalog.T("pages.tokens", nil), Lead: catalog.T("auth.tokens_description", nil), NoIndex: true, ContainerClass: "container-lg", CSRFToken: csrf, Sections: []renderedPageSection{{ID: "api-tokens", Title: catalog.T("pages.tokens", nil), Content: template.HTML(content)}}}
	s.renderPageShell(w, r, page)
}

func (s *Server) handleRevokeUserTokenPage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid token form", http.StatusBadRequest)
		return
	}
	if !sameOriginPageRequest(r) || !validPreferenceCSRF(r) {
		http.Error(w, "Token request failed security validation", http.StatusForbidden)
		return
	}
	identity, err := s.userPageIdentity(r)
	if err != nil {
		http.Error(w, "Unable to load API token", http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		http.Redirect(w, r, "/server/auth/login?redirect=%2Fusers%2Ftokens", http.StatusSeeOther)
		return
	}
	token, err := s.Store.GetAPIToken(r.Context(), chi.URLParam(r, "tokenID"))
	if err != nil {
		http.Error(w, "Unable to load API token", http.StatusInternalServerError)
		return
	}
	if token == nil || token.UserID != userIDString(identity.User.ID) {
		http.NotFound(w, r)
		return
	}
	if err := s.Store.DeleteAPIToken(r.Context(), token.ID); err != nil {
		http.Error(w, "Unable to revoke API token", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/users/tokens", http.StatusSeeOther)
}

func (s *Server) userPageIdentity(r *http.Request) (*pageIdentity, error) {
	identity := pageIdentityFromRequest(r)
	if identity != nil || s.Store == nil {
		return identity, nil
	}
	return s.resolvePageIdentity(r)
}

func (s *Server) mutateUserNotifications(w http.ResponseWriter, r *http.Request, mutate func(store.UserNotificationStore, string) error) {
	if !sameOriginPageRequest(r) || !validPreferenceCSRF(r) {
		http.Error(w, "Notification request failed security validation", http.StatusForbidden)
		return
	}
	identity, err := s.userPageIdentity(r)
	if err != nil {
		http.Error(w, "Unable to load notifications", http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		http.Redirect(w, r, "/server/auth/login?redirect=%2Fusers%2Fnotifications", http.StatusSeeOther)
		return
	}
	notificationStore, ok := s.Store.(store.UserNotificationStore)
	if !ok {
		http.Error(w, "Notifications are unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := mutate(notificationStore, userIDString(identity.User.ID)); err != nil {
		http.Error(w, "Unable to update notifications", http.StatusInternalServerError)
		return
	}
	next := safeNotificationLink(r.FormValue("next"))
	if next == "/users/notifications" {
		next = "/users/notifications"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) handleMarkAllUserNotificationsRead(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid notification form", http.StatusBadRequest)
		return
	}
	s.mutateUserNotifications(w, r, func(notificationStore store.UserNotificationStore, userID string) error {
		return notificationStore.MarkAllUserNotificationsRead(r.Context(), userID, time.Now().UTC())
	})
}

func (s *Server) handleMarkUserNotificationRead(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid notification form", http.StatusBadRequest)
		return
	}
	notificationID := chi.URLParam(r, "notificationID")
	s.mutateUserNotifications(w, r, func(notificationStore store.UserNotificationStore, userID string) error {
		return notificationStore.MarkUserNotificationRead(r.Context(), userID, notificationID, time.Now().UTC())
	})
}

func (s *Server) handleClearUserNotifications(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid notification form", http.StatusBadRequest)
		return
	}
	s.mutateUserNotifications(w, r, func(notificationStore store.UserNotificationStore, userID string) error {
		return notificationStore.ClearUserNotifications(r.Context(), userID)
	})
}

var legacyMainPattern = regexp.MustCompile(`(?is)<main\b[^>]*>(.*?)</main>`)
var legacyHeadingPattern = regexp.MustCompile(`(?is)<h1\b[^>]*>(.*?)</h1>`)
var legacyTagPattern = regexp.MustCompile(`<[^>]+>`)

func (s *Server) pageShellHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		if !strings.HasPrefix(recorder.Header().Get("Content-Type"), "text/html") {
			copyResponse(w, recorder)
			return
		}
		match := legacyMainPattern.FindSubmatch(recorder.Body.Bytes())
		if len(match) != 2 {
			copyResponse(w, recorder)
			return
		}
		for key, values := range recorder.Header() {
			if strings.EqualFold(key, "Content-Length") {
				continue
			}
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		title := "Account"
		if heading := legacyHeadingPattern.FindSubmatch(match[1]); len(heading) == 2 {
			title = strings.TrimSpace(html.UnescapeString(legacyTagPattern.ReplaceAllString(string(heading[1]), "")))
		}
		legacyContent := strings.ReplaceAll(string(match[1]), "<h1>", `<h1 class="page-title">`)
		page := publicPageTemplateData{Title: title, Lead: title, MainContent: template.HTML(legacyContent), NoIndex: strings.Contains(recorder.Header().Get("X-Robots-Tag"), "noindex")}
		if err := s.preparePageChrome(w, r, &page); err != nil {
			http.Error(w, "Unable to prepare page", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(recorder.Code)
		_ = pageTemplate.Execute(w, page)
	})
}

func registeredPagesForHub(hub string) []registeredPublicPage {
	pages := make([]registeredPublicPage, 0)
	for _, page := range publicPageRegistry {
		if page.Hub == hub && page.Always {
			pages = append(pages, page)
		}
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].Order < pages[j].Order })
	return pages
}

var pageTemplate = template.Must(template.New("public-page").Parse(`<!doctype html>
<html lang="{{.Lang}}" dir="{{.Dir}}" {{if ne .Theme "auto"}}data-theme="{{.Theme}}"{{end}}><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">{{if .NoIndex}}<meta name="robots" content="noindex,nofollow">{{end}}<meta name="description" content="{{.Lead}}"><title>{{.Title}} — CasSpeed</title><link rel="stylesheet" href="{{.BasePath}}/static/css/theme-dark.css"><link rel="stylesheet" href="{{.BasePath}}/static/css/theme-light.css"><link rel="stylesheet" href="{{.BasePath}}/static/css/style.css">{{if .PageAssets}}{{.PageAssets}}{{end}}</head>
<body><a class="skip-link" href="#main-content" aria-label="{{.SkipMain}}">{{.SkipMain}}</a><a class="skip-link" href="#site-navigation" aria-label="{{.SkipNavigation}}">{{.SkipNavigation}}</a>{{.TrackingNoscript}}<input class="nav-toggle" id="nav-toggle" type="checkbox" aria-label="{{.NavToggleLabel}}">
<header class="site-header"><a class="site-header__brand" href="{{.BasePath}}/" aria-label="{{.Brand}}">{{.Brand}}</a><nav id="site-navigation" class="nav-links" aria-label="{{.NavAria}}"><a href="{{.BasePath}}/" {{if .NavHomeCurrent}}aria-current="page" class="active"{{end}}>{{.NavHome}}</a>{{if .ShowLogin}}<a href="{{.BasePath}}/server/auth/login" {{if .NavAuthCurrent}}aria-current="page" class="active"{{end}}>{{.NavAuth}}</a>{{end}}{{if .ShowRegister}}<a href="{{.BasePath}}/server/auth/register" {{if .NavRegisterCurrent}}aria-current="page" class="active"{{end}}>{{.NavRegister}}</a>{{end}}</nav><label class="nav-toggle-label" for="nav-toggle" aria-label="{{.NavOpenLabel}}">☰</label><div class="header-actions">{{if .Authenticated}}{{.AccountActions}}{{else}}<a class="preferences-link" href="{{.BasePath}}/server/preferences">{{.Preferences}}</a>{{if not .SuppressThemeToggle}}<form action="{{.BasePath}}/server/preferences" method="post" class="theme-toggle-form"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="theme" value="{{.NextTheme}}"><button class="theme-button" type="submit" aria-label="{{.ThemeButtonLabel}}" title="{{.ThemeButtonLabel}}"><svg class="icon-theme" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor"/></svg></button></form>{{end}}{{end}}</div></header><nav class="nav-drawer" aria-label="{{.NavAria}}"><a href="{{.BasePath}}/" {{if .NavHomeCurrent}}aria-current="page" class="active"{{end}}>{{.NavHome}}</a>{{if .ShowLogin}}<a href="{{.BasePath}}/server/auth/login" {{if .NavAuthCurrent}}aria-current="page" class="active"{{end}}>{{.NavAuth}}</a>{{end}}{{if .ShowRegister}}<a href="{{.BasePath}}/server/auth/register" {{if .NavRegisterCurrent}}aria-current="page" class="active"{{end}}>{{.NavRegister}}</a>{{end}}</nav><label class="nav-scrim" for="nav-toggle" aria-label="{{.NavCloseLabel}}"></label>
{{.ConsentBannerTop}}<main id="main-content">{{if .MainContent}}{{.MainContent}}{{else}}<div class="container {{if .ContainerClass}}{{.ContainerClass}}{{else}}container-md{{end}}"><header class="page-header">{{if .Breadcrumb}}<nav class="breadcrumb" aria-label="Breadcrumb"><a href="{{.BreadcrumbPath}}">← {{.Breadcrumb}}</a></nav>{{end}}<h1 class="page-title">{{.Title}}</h1><p class="page-lead">{{.Lead}}</p></header>{{if .FormAction}}<form method="post" action="{{.FormAction}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}">{{end}}{{range .Sections}}<section class="section-card" aria-labelledby="{{.ID}}"><h2 id="{{.ID}}">{{.Title}}</h2><div class="page-content">{{.Content}}</div></section>{{end}}{{if .FormActions}}{{.FormActions}}{{end}}{{if .FormAction}}</form>{{end}}{{.Bottom}}</div>{{end}}</main>
{{if not .ConsentBannerTop}}{{.ConsentBanner}}{{end}}<footer class="site-footer"><a href="{{.BasePath}}/server/about">{{.FooterAbout}}</a> · <a href="{{.BasePath}}/server/privacy">{{.FooterPrivacy}}</a> · <a href="{{.BasePath}}/server/help">{{.FooterHelp}}</a> · <a href="{{.BasePath}}/server/preferences#language">{{.LanguageName}}</a></footer>{{.TrackingMarkup}}{{range .PageScripts}}<script src="{{.}}" defer></script>{{end}}{{if .PageScript}}<script src="{{.PageScript}}" defer></script>{{end}}</body></html>`))

var pageURLAttributePattern = regexp.MustCompile(`(?i)(href|action|src|formaction|data-spec-url)="([^"]*)"`)

func requestPathPrefix(r *http.Request) string {
	resolved, err := url.Parse(BuildURL(r, "/"))
	if err != nil {
		return ""
	}
	prefix := strings.TrimSuffix(resolved.EscapedPath(), "/")
	if prefix == "/" {
		return ""
	}
	return prefix
}

func requestRoutePath(r *http.Request) string {
	path := r.URL.Path
	if prefix := requestPathPrefix(r); prefix != "" && strings.HasPrefix(path, prefix+"/") {
		path = strings.TrimPrefix(path, prefix)
	}
	return path
}

func prefixPagePath(prefix, value string) string {
	if prefix == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || value == prefix || strings.HasPrefix(value, prefix+"/") {
		return value
	}
	return prefix + value
}

func prefixPageHTML(prefix string, content template.HTML) template.HTML {
	if prefix == "" || content == "" {
		return content
	}
	return template.HTML(pageURLAttributePattern.ReplaceAllStringFunc(string(content), func(attribute string) string {
		parts := pageURLAttributePattern.FindStringSubmatch(attribute)
		if len(parts) != 3 {
			return attribute
		}
		return parts[1] + `="` + prefixPagePath(prefix, parts[2]) + `"`
	}))
}

func (s *Server) handlePublicPage(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/server/")
	page, ok := publicPages[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	page = s.localizePublicPage(r, name, page)
	page.Content = s.publicPageContent(r, name, page.Content)
	if name == "help" {
		page.Content += s.helpHubContent(r)
	}
	if name == "security" {
		page.Content = s.securityPageContent(r)
	} else if name == "security/thanks" {
		content, err := s.securityThanksMarkdown(r)
		if err != nil {
			http.Error(w, publicPageText(r, "pages.security.thanks_load_failed", nil), http.StatusInternalServerError)
			return
		}
		page.Content = content
	}
	if name == "help/mcp" {
		content, _, _, err := s.mcpHelp(r)
		if err != nil {
			http.Error(w, "Unable to load MCP tools", http.StatusInternalServerError)
			return
		}
		page.Content = content
	}
	sections, err := renderPageSections(page.Content)
	if err != nil {
		http.Error(w, "Unable to render page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := publicPageTemplateData{Title: page.Title, Lead: page.Lead, Sections: sections}
	if name == "help/mcp" {
		data.ContainerClass = "container-lg"
	}
	if err := s.preparePageChrome(w, r, &data); err != nil {
		http.Error(w, "Unable to prepare page", http.StatusInternalServerError)
		return
	}
	if name == "privacy" {
		content, err := s.privacyPageContent(r, data.CSRFToken)
		if err != nil {
			http.Error(w, "Unable to render privacy policy", http.StatusInternalServerError)
			return
		}
		data.Title = "Privacy Policy"
		data.MainContent = content
	}
	if err := pageTemplate.Execute(w, data); err != nil {
		http.Error(w, "Unable to render page", http.StatusInternalServerError)
	}
}

func (s *Server) preparePageChrome(w http.ResponseWriter, r *http.Request, data *publicPageTemplateData) error {
	language, direction := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		return err
	}
	data.Lang, data.Dir = language, direction
	data.TrackingMarkup = s.trackingPageMarkup(r)
	data.TrackingNoscript = s.trackingNoscript(r)
	data.Theme = s.readPreferenceState(r).Theme
	data.NextTheme = nextTheme(data.Theme)
	if data.CSRFToken == "" {
		data.CSRFToken = s.issuePreferenceCSRF(w, r)
	}
	if data.CSRFToken == "" {
		return fmt.Errorf("issue page CSRF token")
	}
	data.Brand = "CasSpeed"
	data.NavHome = catalog.T("nav.home", nil)
	data.NavAria = catalog.T("nav.main_navigation", nil)
	data.NavToggleLabel = catalog.T("nav.toggle_navigation", nil)
	data.NavOpenLabel = catalog.T("nav.open_navigation", nil)
	data.NavCloseLabel = catalog.T("nav.close_navigation", nil)
	data.NavAuth = catalog.T("auth.sign_in", nil)
	requestPath := requestRoutePath(r)
	data.NavAuthCurrent = requestPath == "/server/auth/login"
	data.NavRegister = catalog.T("auth.register", nil)
	data.NavRegisterCurrent = requestPath == "/server/auth/register"
	data.NavHomeCurrent = requestPath == "/"
	data.SuppressThemeToggle = requestPath == "/server/preferences"
	data.Preferences = catalog.T("common.preferences", nil)
	data.SkipMain = catalog.T("nav.skip_to_content", nil)
	data.SkipNavigation = catalog.T("nav.skip_to_navigation", nil)
	data.FooterAbout = catalog.T("pages.about", nil)
	data.FooterPrivacy = catalog.T("pages.privacy", nil)
	data.FooterHelp = catalog.T("pages.help", nil)
	themeLabel := catalog.T("theme."+data.NextTheme, nil)
	data.ThemeButtonLabel = catalog.T("theme.switch_to", map[string]string{"theme": themeLabel})
	showConsent := s.Config == nil || s.Config.Server.Privacy.Consent.ShowUntilAcknowledged
	if showConsent && !hasConsentChoice(r) {
		message, accept, decline, manage := catalog.T("cookie_consent.message", nil), catalog.T("cookie_consent.accept", nil), catalog.T("cookie_consent.decline", nil), catalog.T("cookie_consent.manage_preferences", nil)
		position := "bottom"
		policyText, policyURL := catalog.T("pages.privacy", nil), prefixPagePath(requestPathPrefix(r), "/server/privacy")
		if s.Config != nil {
			privacy := s.Config.Server.Privacy
			if configured := privacyConsentMessage(privacy.Consent, privacy.Data.Sold); configured != "" {
				message = configured
			}
			if privacy.Consent.Buttons.Accept != "" {
				accept = privacy.Consent.Buttons.Accept
			}
			if privacy.Consent.Buttons.Decline != "" {
				decline = privacy.Consent.Buttons.Decline
			}
			if privacy.Consent.PreferencesText != "" {
				manage = privacy.Consent.PreferencesText
			}
			if privacy.Consent.Position == "top" {
				position = "top"
			}
			if !privacy.Consent.ShowPreferences {
				manage = ""
			}
			if privacy.Consent.Policy.Text != "" {
				policyText = privacy.Consent.Policy.Text
			}
			if privacy.Consent.Policy.URL != "" && overlayRequestKind(r) != "tor" {
				policyURL = privacy.Consent.Policy.URL
			}
		}
		banner := template.HTML(executeTemplate(consentBannerTemplate, map[string]string{
			"CSRF":       data.CSRFToken,
			"Message":    message,
			"Accept":     accept,
			"Decline":    decline,
			"Manage":     manage,
			"Position":   position,
			"PolicyText": policyText,
			"PolicyURL":  policyURL,
		}))
		if position == "top" {
			data.ConsentBannerTop = banner
		} else {
			data.ConsentBanner = banner
		}
	}
	data.LanguageName = language
	if locales, localeErr := i18n.Supported(); localeErr == nil {
		for _, locale := range locales {
			if locale.Language == language {
				data.LanguageName = locale.Native
				break
			}
		}
	}
	identity := pageIdentityFromRequest(r)
	if identity == nil && s.Store != nil {
		resolved, resolveErr := s.resolvePageIdentity(r)
		if resolveErr != nil {
			return resolveErr
		}
		identity = resolved
	}
	data.ShowLogin = identity == nil || identity.User == nil
	data.ShowRegister = data.ShowLogin && s.Config != nil && s.Config.Server.Users.Enabled && s.Config.Server.Users.Registration.Mode == "open"
	if identity != nil && identity.User != nil {
		data.Authenticated = true
		if settingsStore, ok := s.Store.(store.UserSettingsStore); ok {
			settings, settingsErr := settingsStore.GetOrCreateUserSettings(r.Context(), userIDString(identity.User.ID))
			if settingsErr != nil {
				return settingsErr
			}
			if settings.Theme == "dark" || settings.Theme == "light" || settings.Theme == "auto" {
				data.Theme = settings.Theme
				data.NextTheme = nextTheme(data.Theme)
			}
		}
		items := make([]notificationView, 0)
		unread := 0
		if notificationStore, ok := s.Store.(store.UserNotificationStore); ok {
			stored, listErr := notificationStore.GetUserNotifications(r.Context(), userIDString(identity.User.ID), 5)
			if listErr != nil {
				return listErr
			}
			unread, listErr = notificationStore.CountUnreadUserNotifications(r.Context(), userIDString(identity.User.ID))
			if listErr != nil {
				return listErr
			}
			for _, item := range stored {
				items = append(items, notificationView{ID: item.ID, Icon: notificationIcon(item.Type), Title: catalog.T(item.Title, nil), Message: catalog.T(item.Message, nil), Link: safeNotificationLink(item.Link), CreatedAt: relativeNotificationTime(catalog, time.Since(item.CreatedAt)), Unread: item.ReadAt == nil})
			}
		}
		unreadDisplay := fmt.Sprint(unread)
		if unread > 9 {
			unreadDisplay = "9+"
		}
		data.AccountActions = template.HTML(executeTemplate(accountActionsTemplate, accountActionsData{
			CSRF: data.CSRFToken, SessionCSRF: identity.SessionID, NextTheme: data.NextTheme, UnreadDisplay: unreadDisplay,
			Username: identity.User.Username, Items: items, Unread: unread,
			UnreadLabel:   catalog.T("notifications.unread", nil),
			Notifications: catalog.T("notifications.title", nil), Empty: catalog.T("notifications.empty", nil),
			MarkAllRead: catalog.T("notifications.mark_all_read", nil), ViewAll: catalog.T("notifications.view_all", nil),
			Profile: catalog.T("auth.profile", nil), Settings: catalog.T("auth.settings", nil), Security: catalog.T("auth.security", nil), Tokens: catalog.T("pages.tokens", nil),
			History: catalog.T("user_admin.history_nav", nil), Devices: catalog.T("user_admin.devices_nav", nil),
			DataExport:    catalog.T("user_admin.data_title", nil),
			EmailSettings: catalog.T("auth.email_settings", nil),
			Preferences:   data.Preferences, Help: data.FooterHelp, SignOut: catalog.T("auth.sign_out", nil),
			ThemeLabel: data.ThemeButtonLabel, ShowThemeToggle: !data.SuppressThemeToggle,
		}))
	}
	data.BasePath = requestPathPrefix(r)
	data.BreadcrumbPath = prefixPagePath(data.BasePath, data.BreadcrumbPath)
	data.FormAction = prefixPagePath(data.BasePath, data.FormAction)
	data.PageScript = prefixPagePath(data.BasePath, data.PageScript)
	for index, script := range data.PageScripts {
		data.PageScripts[index] = prefixPagePath(data.BasePath, script)
	}
	data.PageAssets = prefixPageHTML(data.BasePath, data.PageAssets)
	data.MainContent = prefixPageHTML(data.BasePath, data.MainContent)
	data.AccountActions = prefixPageHTML(data.BasePath, data.AccountActions)
	data.ConsentBanner = prefixPageHTML(data.BasePath, data.ConsentBanner)
	data.ConsentBannerTop = prefixPageHTML(data.BasePath, data.ConsentBannerTop)
	data.TrackingMarkup = prefixPageHTML(data.BasePath, data.TrackingMarkup)
	data.TrackingNoscript = prefixPageHTML(data.BasePath, data.TrackingNoscript)
	data.FormActions = prefixPageHTML(data.BasePath, data.FormActions)
	data.Bottom = prefixPageHTML(data.BasePath, data.Bottom)
	for index := range data.Sections {
		data.Sections[index].Content = prefixPageHTML(data.BasePath, data.Sections[index].Content)
	}
	return nil
}

type pageIdentityContextKey struct{}

type pageIdentity struct {
	User      *model.User
	SessionID string
}

type notificationView struct {
	ID        string
	Icon      string
	Title     string
	Message   string
	Link      string
	CreatedAt string
	Unread    bool
}

type accountActionsData struct {
	CSRF, SessionCSRF, NextTheme, Username, UnreadLabel, UnreadDisplay                                                       string
	Notifications, Empty, MarkAllRead, ViewAll                                                                               string
	Profile, Settings, EmailSettings, Security, Tokens, History, Devices, DataExport, Preferences, Help, SignOut, ThemeLabel string
	Items                                                                                                                    []notificationView
	Unread                                                                                                                   int
	ShowThemeToggle                                                                                                          bool
}

func (s *Server) pageIdentityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		identity, err := s.resolvePageIdentity(r)
		if err != nil {
			http.Error(w, "Unable to resolve user session", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), pageIdentityContextKey{}, identity)))
	})
}

func (s *Server) resolvePageIdentity(r *http.Request) (*pageIdentity, error) {
	cookie, err := r.Cookie("user_session")
	if err != nil || cookie.Value == "" || s.Store == nil {
		return nil, nil
	}
	session, err := s.Store.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}
	if session == nil || !session.ExpiresAt.After(time.Now()) {
		return nil, nil
	}
	user, err := s.Store.GetUser(r.Context(), session.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Disabled || !user.Approved {
		return nil, nil
	}
	return &pageIdentity{User: user, SessionID: session.ID}, nil
}

func pageIdentityFromRequest(r *http.Request) *pageIdentity {
	identity, _ := r.Context().Value(pageIdentityContextKey{}).(*pageIdentity)
	return identity
}

func safeNotificationLink(value string) string {
	if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") && !strings.ContainsAny(value, "\\\r\n") {
		return value
	}
	return "/users/notifications"
}

func notificationIcon(kind string) string {
	switch kind {
	case "success":
		return "✓"
	case "warning":
		return "⚠"
	case "error":
		return "✕"
	case "security":
		return "🔒"
	default:
		return "ℹ"
	}
}

func relativeNotificationTime(catalog *i18n.Catalog, elapsed time.Duration) string {
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed < time.Minute {
		return catalog.T("time.just_now", nil)
	}
	if elapsed < time.Hour {
		return catalog.Plural("time.minutes_ago", int(elapsed/time.Minute), nil)
	}
	if elapsed < 24*time.Hour {
		return catalog.Plural("time.hours_ago", int(elapsed/time.Hour), nil)
	}
	if elapsed < 48*time.Hour {
		return catalog.T("time.yesterday", nil)
	}
	return catalog.Plural("time.days_ago", int(elapsed/(24*time.Hour)), nil)
}

func nextTheme(theme string) string {
	switch theme {
	case "dark":
		return "light"
	case "light":
		return "auto"
	default:
		return "dark"
	}
}

func (s *Server) publicErrorShellMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminPath := ""
		if s.Config != nil {
			adminPath = s.Config.Server.AdminPath
		}
		if adminPath == "" {
			adminPath = "administration"
		}
		adminPrefix := "/server/" + adminPath
		isPublicPage := strings.HasPrefix(r.URL.Path, "/server/") || strings.HasPrefix(r.URL.Path, "/speed-tests/") || strings.HasPrefix(r.URL.Path, "/shares/") || strings.HasPrefix(r.URL.Path, "/users/") || r.URL.Path == "/users"
		if !isPublicPage || r.URL.Path == adminPrefix || strings.HasPrefix(r.URL.Path, adminPrefix+"/") {
			next.ServeHTTP(w, r)
			return
		}
		accept := r.Header.Get("Accept")
		if accept != "" && !strings.Contains(accept, "text/html") && !strings.Contains(accept, "*/*") {
			next.ServeHTTP(w, r)
			return
		}
		recorder := httptest.NewRecorder()
		next.ServeHTTP(recorder, r)
		contentType := recorder.Header().Get("Content-Type")
		if recorder.Code < 400 || (contentType != "" && !strings.HasPrefix(contentType, "text/plain")) {
			copyResponse(w, recorder)
			return
		}
		for key, values := range recorder.Header() {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		page := s.publicErrorPage(r, recorder.Code)
		if err := s.preparePageChrome(w, r, &page); err != nil {
			http.Error(w, "Page unavailable", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(recorder.Code)
		_ = pageTemplate.Execute(w, page)
	})
}

func copyResponse(w http.ResponseWriter, recorder *httptest.ResponseRecorder) {
	for key, values := range recorder.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(recorder.Code)
	_, _ = w.Write(recorder.Body.Bytes())
}

func (s *Server) publicErrorPage(r *http.Request, status int) publicPageTemplateData {
	title, lead := "Request failed", "The request could not be completed."
	switch status {
	case http.StatusNotFound:
		title, lead = "Page not found", "The requested page could not be found."
	case http.StatusForbidden:
		title, lead = "Request denied", "This request could not be accepted."
	case http.StatusBadRequest:
		title, lead = "Invalid request", "Check the submitted information and try again."
	case http.StatusInternalServerError:
		title, lead = "Service error", "The page could not be displayed. Please try again later."
	}
	language, _ := requestLanguage(r)
	if catalog, err := i18n.Resolve(language); err == nil {
		if translated := catalog.T(fmt.Sprintf("errors.http_%d_title", status), nil); !strings.HasPrefix(translated, "errors.") {
			title = translated
		}
		if translated := catalog.T(fmt.Sprintf("errors.http_%d_message", status), nil); !strings.HasPrefix(translated, "errors.") {
			lead = translated
		}
	}
	return publicPageTemplateData{Title: title, Lead: lead, NoIndex: true, Sections: []renderedPageSection{{ID: "error", Title: title, Content: template.HTML(`<p role="alert">` + template.HTMLEscapeString(lead) + `</p>`)}}}
}

func (s *Server) localizePublicPage(r *http.Request, name string, page publicPage) publicPage {
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		return page
	}
	key := "page_titles." + strings.ReplaceAll(name, "/", "_")
	for _, registered := range publicPageRegistry {
		if strings.TrimPrefix(registered.Path, "/server/") == name {
			key = registered.TitleKey
			break
		}
	}
	if translated := catalog.T(key, nil); translated != key {
		page.Title = translated
	}
	leadKey := "page_leads." + strings.ReplaceAll(name, "/", "_")
	if translated := catalog.T(leadKey, nil); translated != leadKey {
		page.Lead = translated
	}
	contentKey := "page_content." + strings.ReplaceAll(name, "/", "_")
	if translated := catalog.T(contentKey, nil); translated != contentKey {
		page.Content = translated
	}
	if strings.Contains(page.Content, "{retention}") {
		retention := catalog.T("privacy.retention_unlimited", nil)
		if s.Config != nil && s.Config.Test.ResultsRetention > 0 {
			retention = catalog.T("privacy.retention_days", map[string]string{"days": fmt.Sprint(s.Config.Test.ResultsRetention)})
		}
		page.Content = strings.ReplaceAll(page.Content, "{retention}", retention)
	}
	return page
}

type speedTestPageData struct {
	ID         string
	CSRFToken  string
	Timestamp  string
	Download   string
	Upload     string
	Ping       string
	Jitter     string
	PacketLoss string
}

// handleSpeedTestPage renders a private, server-side result view through the canonical API authorization path.
func (s *Server) handleSpeedTestPage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	test, err := s.Store.GetSpeedTest(r.Context(), id)
	if err != nil {
		http.Error(w, "Unable to load speed test result", http.StatusInternalServerError)
		return
	}
	if test == nil || !s.canViewSpeedTestPage(r, test) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Unable to prepare speed test result", http.StatusInternalServerError)
		return
	}
	data := speedTestPageData{
		ID: test.ID, Timestamp: test.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"),
		Download: fmt.Sprintf("%.2f", test.DownloadMbps), Upload: fmt.Sprintf("%.2f", test.UploadMbps),
		Ping: fmt.Sprintf("%.2f", test.PingMs), Jitter: fmt.Sprintf("%.2f", test.JitterMs),
		PacketLoss: fmt.Sprintf("%.2f", test.PacketLoss),
	}
	detailData := map[string]string{
		"Download": data.Download, "Upload": data.Upload, "Ping": data.Ping, "Jitter": data.Jitter,
		"PacketLoss": data.PacketLoss, "Timestamp": data.Timestamp,
		"DownloadLabel": catalog.T("result_page.download", nil), "UploadLabel": catalog.T("result_page.upload", nil),
		"PingLabel": catalog.T("result_page.ping", nil), "JitterLabel": catalog.T("result_page.jitter", nil),
		"PacketLossLabel": catalog.T("result_page.packet_loss", nil), "TestedLabel": catalog.T("result_page.tested", nil),
	}
	details := executeTemplate(speedTestResultDetailsTemplate, detailData)
	page := publicPageTemplateData{
		Title: catalog.T("result_page.title", nil), Lead: catalog.T("result_page.lead", nil), NoIndex: true,
		Sections: []renderedPageSection{
			{ID: "measurements", Title: catalog.T("result_page.measurements", nil), Content: template.HTML(details)},
			{ID: "share-result", Title: catalog.T("result_page.share", nil)},
		},
	}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, "Unable to prepare speed test result", http.StatusInternalServerError)
		return
	}
	data.CSRFToken = page.CSRFToken
	page.Sections[1].Content = template.HTML(executeTemplate(speedTestShareTemplate, map[string]string{
		"ID": data.ID, "CSRFToken": data.CSRFToken, "Warning": catalog.T("result_page.share_warning", nil),
		"CreateShare": catalog.T("result_page.create_share", nil),
	}))
	if err := pageTemplate.Execute(w, page); err != nil {
		http.Error(w, "Unable to render speed test result", http.StatusInternalServerError)
	}
}

var speedTestResultDetailsTemplate = template.Must(template.New("speed-test-result-details").Parse(`<dl class="health-details"><dt>{{.DownloadLabel}}</dt><dd>{{.Download}} Mbps</dd><dt>{{.UploadLabel}}</dt><dd>{{.Upload}} Mbps</dd><dt>{{.PingLabel}}</dt><dd>{{.Ping}} ms</dd><dt>{{.JitterLabel}}</dt><dd>{{.Jitter}} ms</dd><dt>{{.PacketLossLabel}}</dt><dd>{{.PacketLoss}}%</dd><dt>{{.TestedLabel}}</dt><dd><time>{{.Timestamp}}</time></dd></dl>`))
var speedTestShareTemplate = template.Must(template.New("speed-test-share").Parse(`<p>{{.Warning}}</p><form method="post" action="/speed-tests/{{.ID}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button class="btn btn-primary" type="submit">{{.CreateShare}}</button></form>`))

func (s *Server) canViewSpeedTestPage(r *http.Request, test *model.SpeedTest) bool {
	if cookie, err := r.Cookie("user_session"); err == nil && cookie.Value != "" {
		session, err := s.Store.GetSession(r.Context(), cookie.Value)
		if err == nil && session != nil && session.ExpiresAt.After(time.Now()) {
			user, err := s.Store.GetUser(r.Context(), session.UserID)
			if err == nil && user != nil && userIDString(user.ID) == test.UserID {
				return true
			}
		}
	}
	cookie, err := r.Cookie("casspeed_owner")
	if err != nil {
		return false
	}
	secret, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(secret) != 32 || test.OwnerTokenHash == "" {
		return false
	}
	hash := sha256.Sum256(secret)
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash[:])), []byte(test.OwnerTokenHash)) == 1
}

// createSpeedTestSharePage requires a same-origin browser submission before making a private result public.
func (s *Server) createSpeedTestSharePage(w http.ResponseWriter, r *http.Request) {
	if !sameOriginPageRequest(r) || !validPreferenceCSRF(r) {
		http.Error(w, "Cross-origin share request rejected", http.StatusForbidden)
		return
	}
	recorder := httptest.NewRecorder()
	s.Handler.CreateShare(recorder, r)
	if recorder.Code < 200 || recorder.Code >= 300 {
		if recorder.Code == http.StatusNotFound || recorder.Code == http.StatusUnauthorized {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Unable to create share link", recorder.Code)
		return
	}
	var response struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil || !strings.HasPrefix(response.Data.URL, "/shares/") {
		http.Error(w, "Unable to create share link", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, response.Data.URL, http.StatusSeeOther)
}

func sameOriginPageRequest(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		origin = strings.TrimSpace(r.Header.Get("Referer"))
	}
	if origin == "" {
		return false
	}
	actual, err := url.Parse(origin)
	if err != nil || actual.Host == "" || actual.User != nil {
		return false
	}
	expected, err := url.Parse(BuildURL(r, "/"))
	return err == nil && strings.EqualFold(actual.Host, expected.Host) && strings.EqualFold(actual.Scheme, expected.Scheme)
}

func renderMarkdown(source string) (string, error) {
	var rendered bytes.Buffer
	markdown := goldmark.New(goldmark.WithExtensions(extension.Table))
	if err := markdown.Convert([]byte(source), &rendered); err != nil {
		return "", err
	}
	policy := bluemonday.UGCPolicy()
	policy.AllowTables()
	safe := policy.Sanitize(rendered.String())
	safe = strings.ReplaceAll(safe, "<table>", `<div class="table-wrapper"><table class="data-table">`)
	safe = strings.ReplaceAll(safe, "</table>", "</table></div>")
	safe = strings.ReplaceAll(safe, "<th>", `<th scope="col">`)
	return safe, nil
}

type renderedPageSection struct {
	ID      string
	Title   string
	Content template.HTML
}

type publicPageTemplateData struct {
	Title               string
	Lead                string
	BasePath            string
	Lang                string
	Dir                 string
	Theme               string
	NextTheme           string
	CSRFToken           string
	Brand               string
	NavHome             string
	NavAria             string
	NavToggleLabel      string
	NavOpenLabel        string
	NavCloseLabel       string
	NavAuth             string
	NavRegister         string
	NavAuthCurrent      bool
	NavRegisterCurrent  bool
	NavHomeCurrent      bool
	ShowLogin           bool
	ShowRegister        bool
	Authenticated       bool
	SuppressThemeToggle bool
	AccountActions      template.HTML
	Preferences         string
	ThemeButtonLabel    string
	SkipMain            string
	SkipNavigation      string
	FooterAbout         string
	FooterPrivacy       string
	FooterHelp          string
	LanguageName        string
	ConsentBanner       template.HTML
	ConsentBannerTop    template.HTML
	TrackingMarkup      template.HTML
	TrackingNoscript    template.HTML
	PageScript          string
	PageScripts         []string
	PageAssets          template.HTML
	MainContent         template.HTML
	NoIndex             bool
	ContainerClass      string
	Sections            []renderedPageSection
	Breadcrumb          string
	BreadcrumbPath      string
	FormAction          string
	CSRF                string
	FormActions         template.HTML
	Bottom              template.HTML
}

func renderPageSections(source string) ([]renderedPageSection, error) {
	var sections []renderedPageSection
	var title string
	var body strings.Builder
	flush := func() error {
		if title == "" && strings.TrimSpace(body.String()) == "" {
			return nil
		}
		if title == "" {
			title = "Overview"
		}
		rendered, err := renderMarkdown(strings.TrimSpace(body.String()))
		if err != nil {
			return err
		}
		sections = append(sections, renderedPageSection{ID: pageSectionID(title), Title: title, Content: template.HTML(rendered)})
		title = ""
		body.Reset()
		return nil
	}
	for _, line := range strings.Split(source, "\n") {
		if strings.HasPrefix(line, "## ") {
			if err := flush(); err != nil {
				return nil, err
			}
			title = strings.TrimSpace(strings.TrimPrefix(line, "## "))
			continue
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return sections, nil
}

func pageSectionID(title string) string {
	mcpSections := map[string]string{
		"what this is":        "overview",
		"endpoint":            "endpoint",
		"authentication":      "authentication",
		"connect a client":    "connect",
		"tools":               "tools",
		"behavior and limits": "limits",
		"troubleshooting":     "troubleshooting",
		"project":             "project",
	}
	if id, ok := mcpSections[strings.ToLower(strings.TrimSpace(title))]; ok {
		return id
	}
	return markdownHeadingID(title)
}

func markdownHeadingID(title string) string {
	var id strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(title) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			id.WriteRune(r)
			lastDash = false
		} else if !lastDash && id.Len() > 0 {
			id.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(id.String(), "-")
}

func (s *Server) handlePublicPageAPI(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/server/")
	page, ok := publicPages[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	page = s.localizePublicPage(r, name, page)
	page.Content = s.publicPageContent(r, name, page.Content)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	var data any = map[string]interface{}{"title": page.Title, "content": page.Content, "format": "markdown"}
	switch name {
	case "privacy":
		data = s.privacyPageAPI(r)
	case "help":
		pages := registeredPagesForHub("/server/help")
		links := make([]map[string]string, 0, len(pages))
		for _, registered := range pages {
			name := strings.TrimPrefix(registered.Path, "/server/")
			page := s.localizePublicPage(r, name, publicPages[name])
			links = append(links, map[string]string{"title": page.Title, "path": registered.Path})
		}
		data.(map[string]interface{})["pages"] = links
	case "help/mcp":
		_, project, tools, err := s.mcpHelp(r)
		if err != nil {
			http.Error(w, "Unable to load MCP tools", http.StatusInternalServerError)
			return
		}
		data = map[string]interface{}{"enabled": true, "url": absoluteRequestURL(r, "/api/v1/server/mcp"), "aliases": []string{absoluteRequestURL(r, "/api/mcp"), absoluteRequestURL(r, "/mcp")}, "auth": map[string]string{"scheme": "Bearer"}, "tools": tools, "project": project}
	case "dpo":
		name, email := s.dpoContactForRequest(r)
		if parsed, err := mail.ParseAddress(email); err != nil || parsed.Address != email {
			name, email = "", ""
		}
		data = map[string]interface{}{"name": name, "email": email, "privacy_url": absoluteRequestURL(r, "/server/privacy")}
	case "security/policy":
		data = map[string]interface{}{"policy": page.Content}
	case "security":
		data = s.securityPageData(r)
	case "security/thanks":
		publicEntries := make([]map[string]string, 0)
		if s.SecurityReports != nil {
			entries, err := s.SecurityReports.ListSecurityThanks(r.Context())
			if err != nil {
				http.Error(w, publicPageText(r, "pages.security.thanks_load_failed", nil), http.StatusInternalServerError)
				return
			}
			for _, entry := range entries {
				publicEntries = append(publicEntries, map[string]string{"credit": entry.Credit, "date": entry.DisclosedOn.UTC().Format("2006-01-02"), "severity": entry.Severity})
			}
		}
		data = map[string]interface{}{"entries": publicEntries}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "data": data})
}

func (s *Server) helpHubContent(r *http.Request) string {
	var content strings.Builder
	content.WriteString("\n\n## More help\n\n")
	for _, page := range registeredPagesForHub("/server/help") {
		name := strings.TrimPrefix(page.Path, "/server/")
		registered := s.localizePublicPage(r, name, publicPages[name])
		content.WriteString("- [" + registered.Title + "](" + page.Path + ") — " + registered.Lead + "\n")
	}
	return content.String()
}

func (s *Server) securityThanksMarkdown(r *http.Request) (string, error) {
	empty := publicPageText(r, "pages.security.thanks_empty", nil)
	if s.SecurityReports == nil {
		return empty + "\n", nil
	}
	entries, err := s.SecurityReports.ListSecurityThanks(r.Context())
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return empty + "\n", nil
	}
	var content strings.Builder
	content.WriteString(publicPageText(r, "pages.security.thanks_intro", nil) + "\n\n")
	for _, entry := range entries {
		credit := strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "<", "&lt;", ">", "&gt;").Replace(entry.Credit)
		content.WriteString("- **" + credit + "** — " + entry.DisclosedOn.UTC().Format("2006-01-02") + " — " + entry.Severity + "\n")
	}
	return content.String(), nil
}

type securityContact struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type securityPageData struct {
	Contacts  []securityContact `json:"contacts"`
	Expires   string            `json:"expires"`
	PGP       map[string]any    `json:"pgp"`
	PolicyURL string            `json:"policy_url"`
	ThanksURL string            `json:"thanks_url"`
	ReportURL string            `json:"report_url,omitempty"`
}

func (s *Server) securityPageData(r *http.Request) securityPageData {
	overlayKind := overlayRequestKind(r)
	now := time.Now().UTC()
	expires := now.AddDate(1, 0, 0)
	if value := strings.TrimSpace(s.Config.Web.Security.Expires); value != "" {
		if value == "1y" {
			expires = now.AddDate(1, 0, 0)
		} else if duration, err := time.ParseDuration(value); err == nil && duration > 0 {
			expires = now.Add(duration)
		}
	}
	data := securityPageData{
		Contacts: []securityContact{}, Expires: expires.Format("2006-01-02T15:04:05Z"),
		PGP:       map[string]any{"available": false, "url": nil, "fingerprint": nil},
		PolicyURL: absoluteRequestURL(r, "/server/security/policy"),
		ThanksURL: absoluteRequestURL(r, "/server/security/thanks"),
	}
	if s.Config.Web.Security.PublishPGPKey && s.SecurityKeypair != nil {
		if metadata, err := s.SecurityKeypair.Metadata(r.Context()); err == nil && metadata != nil && !metadata.Revoked {
			data.PGP = map[string]any{"available": true, "url": absoluteRequestURL(r, "/.well-known/pgp-key.asc"), "fingerprint": metadata.Fingerprint}
		}
	}
	if overlayKind == "" {
		if reportURL := strings.TrimSpace(s.Config.Web.Security.ReportURL); reportURL != "" {
			data.Contacts = append(data.Contacts, securityContact{Type: "github", Value: reportURL})
		}
	}
	if s.Config.Server.Pages.Contact.Enabled {
		if s.SecurityReports != nil {
			contactURL := absoluteRequestURL(r, "/server/contact")
			parsed, err := url.Parse(contactURL)
			if err == nil {
				query := parsed.Query()
				query.Set("security_id", s.SecurityReports.SecurityID(now))
				parsed.RawQuery = query.Encode()
				data.Contacts = append(data.Contacts, securityContact{Type: "contact_form", Value: parsed.String()})
			}
			data.ReportURL = absoluteRequestURL(r, "/server/contact")
		}
	}
	securityEmail := ""
	if overlayKind == "tor" {
		securityEmail = strings.TrimSpace(s.Config.Server.Tor.ContactEmail)
	} else if overlayKind == "" {
		securityEmail = strings.TrimSpace(s.Config.Server.Contact.Security.Email)
		if securityEmail == "" {
			securityEmail = strings.TrimSpace(s.Config.Server.Contact.Admin.Email)
		}
	}
	if parsed, err := mail.ParseAddress(securityEmail); err == nil && parsed.Address == securityEmail {
		data.Contacts = append(data.Contacts, securityContact{Type: "email", Value: "mailto:" + securityEmail})
	}
	return data
}

func (s *Server) securityPageContent(r *http.Request) string {
	data := s.securityPageData(r)
	text := func(key string, values map[string]string) string {
		return publicPageText(r, "pages.security."+key, values)
	}
	var content strings.Builder
	content.WriteString(text("intro", nil) + "\n\n")
	content.WriteString("## " + text("reporting_channels", nil) + "\n\n")
	for _, contact := range data.Contacts {
		label := ""
		switch contact.Type {
		case "github":
			label = text("github_reporting", nil)
		case "contact_form":
			label = text("submit_report", nil)
		case "email":
			label = text("email_contact", nil)
		}
		if label != "" {
			content.WriteString("- [" + label + "](" + contact.Value + ")\n")
		}
	}
	content.WriteString("\n" + text("coordinated_reporting", map[string]string{"policy": data.PolicyURL, "thanks": data.ThanksURL, "security_txt": absoluteRequestURL(r, "/.well-known/security.txt")}) + "\n")
	if available, _ := data.PGP["available"].(bool); available {
		if pgpURL, ok := data.PGP["url"].(string); ok {
			fingerprint, _ := data.PGP["fingerprint"].(string)
			content.WriteString("\n[" + text("download_pgp", nil) + "](" + pgpURL + ") (fingerprint `" + fingerprint + "`).\n")
		}
	}
	if data.ReportURL != "" {
		content.WriteString("\n" + text("terms_privacy", map[string]string{"report_form": data.ReportURL}) + "\n")
	}
	return content.String()
}

func (s *Server) publicPageContent(r *http.Request, name, content string) string {
	switch name {
	case "about":
		if extension := strings.TrimSpace(s.Config.Server.Branding.Content.About); extension != "" {
			return content + "\n\n## Additional information\n\n" + extension
		}
	case "privacy":
		content = strings.ReplaceAll(content, "Contact the service operator for privacy requests.", "For privacy requests, see the [security and reporting page](/server/security).")
		if s.Config.Test.ResultsRetention == 0 {
			return strings.ReplaceAll(content, "{retention}", "without an automatic expiry")
		}
		return strings.ReplaceAll(content, "{retention}", fmt.Sprintf("for %d days", s.Config.Test.ResultsRetention))
	case "terms":
		if configured := strings.TrimSpace(s.Config.Server.Branding.Content.Terms); configured != "" {
			return configured
		}
	case "help":
		if configured := strings.TrimSpace(s.Config.Server.Pages.Help.Content); configured != "" {
			return content + "\n\n" + configured
		}
	case "dpo":
		name, email := s.dpoContactForRequest(r)
		text := func(key string, values map[string]string) string {
			return publicPageText(r, "pages.security."+key, values)
		}
		links := map[string]string{"security": absoluteRequestURL(r, "/server/security"), "privacy": absoluteRequestURL(r, "/server/privacy")}
		if email == "" {
			return text("dpo_missing", links)
		}
		address, err := mail.ParseAddress(email)
		if err != nil || address.Address != email {
			return text("dpo_missing", links)
		}
		if name != "" {
			return fmt.Sprintf("**%s**\n\n[%s](mailto:%s).\n\n%s", name, text("dpo_email", nil), email, text("dpo_privacy", map[string]string{"privacy": links["privacy"]}))
		}
		return fmt.Sprintf("[%s](mailto:%s).\n\n%s", text("dpo_email", nil), email, text("dpo_privacy", map[string]string{"privacy": links["privacy"]}))
	}
	return content
}

func (s *Server) dpoContact() (string, string) {
	name := s.Config.Server.Contact.DPO.Name
	email := s.Config.Server.Contact.DPO.Email
	if email == "" {
		email = s.Config.Server.Contact.General.Email
	}
	return name, email
}

func (s *Server) dpoContactForRequest(r *http.Request) (string, string) {
	if overlayRequestKind(r) == "tor" {
		if s.Config == nil {
			return "", ""
		}
		return "", strings.TrimSpace(s.Config.Server.Tor.ContactEmail)
	}
	return s.dpoContact()
}

func absoluteRequestURL(r *http.Request, path string) string {
	return buildRequestURL(r, path)
}

func writeHealthPage(s *Server, w http.ResponseWriter, r *http.Request, response healthResponse) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Unable to prepare health page", http.StatusInternalServerError)
		return
	}
	health := map[string]string{
		"Status": response.Status, "Version": response.Version, "GoVersion": response.GoVersion,
		"Mode": response.Mode, "Uptime": response.Uptime, "Database": response.Checks.Database,
		"StatusLabel": catalog.T("health_page.status", nil), "VersionLabel": catalog.T("health_page.version", nil),
		"GoVersionLabel": catalog.T("health_page.go_version", nil), "ModeLabel": catalog.T("health_page.mode", nil),
		"UptimeLabel": catalog.T("health_page.uptime", nil), "DatabaseLabel": catalog.T("health_page.database", nil),
	}
	section := executeTemplate(healthDetailsTemplate, health)
	data := publicPageTemplateData{Title: catalog.T("health_page.title", nil), Lead: catalog.T("health_page.lead", nil), Sections: []renderedPageSection{{ID: "health-details", Title: catalog.T("health_page.service", nil), Content: template.HTML(section)}}}
	if err := s.preparePageChrome(w, r, &data); err != nil {
		http.Error(w, "Unable to prepare health page", http.StatusInternalServerError)
		return
	}
	if err := pageTemplate.Execute(w, data); err != nil {
		http.Error(w, "Unable to render health page", http.StatusInternalServerError)
	}
}

var healthDetailsTemplate = template.Must(template.New("health-details").Parse(`<p class="health-status">{{.Status}}</p><dl class="health-details"><dt>{{.StatusLabel}}</dt><dd>{{.Status}}</dd><dt>{{.VersionLabel}}</dt><dd>{{.Version}}</dd><dt>{{.GoVersionLabel}}</dt><dd>{{.GoVersion}}</dd><dt>{{.ModeLabel}}</dt><dd>{{.Mode}}</dd><dt>{{.UptimeLabel}}</dt><dd>{{.Uptime}}</dd><dt>{{.DatabaseLabel}}</dt><dd>{{.Database}}</dd></dl>`))
