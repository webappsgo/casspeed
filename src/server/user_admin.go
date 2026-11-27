package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/admin"
	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

var userAdminTemplate = template.Must(template.New("user-admin").Parse(`<p>{{.Message}}</p><p><a href="{{.InvitesURL}}">{{.InviteCodes}}</a></p><form method="get" action="{{.Path}}"><label for="user-search">{{.SearchLabel}}</label><input id="user-search" name="q" value="{{.Search}}"><button type="submit">{{.SearchButton}}</button></form><h2>{{.CreateTitle}}</h2><form method="post" action="{{.Path}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="new-username">{{.UsernameLabel}}</label><input id="new-username" name="username" minlength="2" maxlength="39" required><label for="new-email">{{.EmailLabel}}</label><input id="new-email" name="email" type="email" required><button name="delivery" value="invite">{{.CreateInvite}}</button><button name="delivery" value="direct">{{.CreateDirect}}</button></form>{{if .Link}}<p role="status">{{.LinkLabel}}: <a href="{{.Link}}">{{.Link}}</a></p>{{end}}<div class="table-wrapper"><table class="data-table"><thead><tr><th scope="col">{{.IDLabel}}</th><th scope="col">{{.UsernameLabel}}</th><th scope="col">{{.EmailLabel}}</th><th scope="col">{{.StatusLabel}}</th><th scope="col">{{.CreatedLabel}}</th><th scope="col">{{.ActionsLabel}}</th></tr></thead><tbody>{{range .Users}}<tr><td>{{.ID}}</td><td><a href="{{$.Path}}/{{.ID}}">{{.Username}}</a></td><td>{{.Email}}</td><td>{{.Status}}</td><td>{{.CreatedAt}}</td><td><form method="post" action="{{$.Path}}/{{.ID}}/{{.Action}}"><input type="hidden" name="csrf_token" value="{{$.CSRF}}">{{if .ConfirmAction}}<button class="btn btn-danger" type="button" popovertarget="suspend-user-{{.ID}}">{{.ActionLabel}}</button><div id="suspend-user-{{.ID}}" popover aria-labelledby="suspend-user-title-{{.ID}}"><h3 id="suspend-user-title-{{.ID}}">{{.ActionLabel}}</h3><p>{{$.UsernameLabel}}: {{.Username}}</p><button class="btn btn-secondary" type="button" popovertarget="suspend-user-{{.ID}}" popovertargetaction="hide">{{$.Cancel}}</button><button class="btn btn-danger" type="submit">{{$.Confirm}}</button></div>{{else}}<button class="btn btn-secondary" type="submit">{{.ActionLabel}}</button>{{end}}</form><form method="post" action="{{$.Path}}/{{.ID}}/sessions/revoke"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><button class="btn btn-danger" type="button" popovertarget="revoke-user-sessions-{{.ID}}">{{$.RevokeSessions}}</button><div id="revoke-user-sessions-{{.ID}}" popover aria-labelledby="revoke-user-sessions-title-{{.ID}}"><h3 id="revoke-user-sessions-title-{{.ID}}">{{$.RevokeSessions}}</h3><p>{{$.UsernameLabel}}: {{.Username}}</p><button class="btn btn-secondary" type="button" popovertarget="revoke-user-sessions-{{.ID}}" popovertargetaction="hide">{{$.Cancel}}</button><button class="btn btn-danger" type="submit">{{$.Confirm}}</button></div></form><a href="{{$.Path}}/{{.ID}}">{{$.Details}}</a></td></tr>{{else}}<tr><td colspan="6">{{$.NoUsers}}</td></tr>{{end}}</tbody></table></div><nav aria-label="{{.PageNav}}">{{if .Previous}}<a href="{{.Previous}}">{{$.PreviousLabel}}</a>{{end}} {{if .Next}}<a href="{{.Next}}">{{$.NextLabel}}</a>{{end}}</nav>`))

var userAdminDetailTemplate = template.Must(template.New("user-admin-detail").Parse(`<dl><dt>{{.UsernameLabel}}</dt><dd>{{.Username}}</dd><dt>{{.EmailLabel}}</dt><dd>{{.Email}}</dd><dt>{{.StatusLabel}}</dt><dd>{{.Status}}</dd><dt>{{.TwoFactorLabel}}</dt><dd>{{.TOTP}}</dd><dt>{{.LastLoginLabel}}</dt><dd>{{.LastLogin}}</dd></dl><form method="post" action="{{.Path}}/{{.ID}}/{{.Action}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}">{{if .ConfirmAction}}<button class="btn btn-danger" type="button" popovertarget="suspend-user-detail">{{.ActionLabel}}</button><div id="suspend-user-detail" popover aria-labelledby="suspend-user-detail-title"><h3 id="suspend-user-detail-title">{{.ActionLabel}}</h3><p>{{.UsernameLabel}}: {{.Username}}</p><button class="btn btn-secondary" type="button" popovertarget="suspend-user-detail" popovertargetaction="hide">{{.Cancel}}</button><button class="btn btn-danger" type="submit">{{.Confirm}}</button></div>{{else}}<button class="btn btn-secondary" type="submit">{{.ActionLabel}}</button>{{end}}</form><form method="post" action="{{.Path}}/{{.ID}}/sessions/revoke"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button class="btn btn-danger" type="button" popovertarget="revoke-user-sessions-detail">{{.RevokeSessions}}</button><div id="revoke-user-sessions-detail" popover aria-labelledby="revoke-user-sessions-detail-title"><h3 id="revoke-user-sessions-detail-title">{{.RevokeSessions}}</h3><p>{{.UsernameLabel}}: {{.Username}}</p><button class="btn btn-secondary" type="button" popovertarget="revoke-user-sessions-detail" popovertargetaction="hide">{{.Cancel}}</button><button class="btn btn-danger" type="submit">{{.Confirm}}</button></div></form><h2>{{.DeleteUser}}</h2><p>{{.DeleteWarning}}</p><form method="post" action="{{.Path}}/{{.ID}}/delete"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="delete-confirm">{{.UsernameConfirmation}}</label><input id="delete-confirm" name="confirm" autocomplete="off" required><button class="btn btn-danger" type="button" popovertarget="delete-user-detail">{{.DeleteUser}}</button><div id="delete-user-detail" popover aria-labelledby="delete-user-detail-title"><h3 id="delete-user-detail-title">{{.DeleteUser}}</h3><p>{{.DeleteWarning}}</p><button class="btn btn-secondary" type="button" popovertarget="delete-user-detail" popovertargetaction="hide">{{.Cancel}}</button><button class="btn btn-danger" type="submit">{{.Confirm}}</button></div></form><p><a href="{{.Path}}">{{.Back}}</a></p>`))

var userActivationTemplate = template.Must(template.New("user-activation").Parse(`<p>{{.Message}}</p>{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}<form method="post" action="{{.Action}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="activation-password">{{.ChoosePassword}}</label><input id="activation-password" type="password" name="password" autocomplete="new-password" minlength="8" required><label for="activation-confirm">{{.ConfirmPassword}}</label><input id="activation-confirm" type="password" name="confirm_password" autocomplete="new-password" minlength="8" required><button type="submit">{{.Activate}}</button></form>`))

var userInvitesTemplate = template.Must(template.New("user-invites").Parse(`<h2>{{.GenerateTitle}}</h2>{{if .Link}}<p role="status">{{.LinkLabel}}: <a href="{{.Link}}">{{.Link}}</a></p>{{end}}<form method="post" action="{{.Path}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="invite-role">{{.RoleLabel}}</label><select id="invite-role" name="role">{{range .Roles}}<option value="{{.Value}}" {{if .Selected}}selected{{end}}>{{.Label}}</option>{{end}}</select><label for="invite-expiry">{{.ExpiryLabel}}</label><input id="invite-expiry" name="expires_at" type="datetime-local" value="{{.ExpiryDefault}}" required><small>{{.ExpiryUTC}}</small><label for="invite-max-uses">{{.MaxUsesLabel}}</label><input id="invite-max-uses" name="max_uses" type="number" min="0" value="1" required><small>{{.UnlimitedHint}}</small><button type="submit">{{.GenerateInvite}}</button></form><h2>{{.InviteListTitle}}</h2>{{if .Invites}}<div class="table-wrapper"><table class="data-table"><thead><tr><th scope="col">{{.RoleLabel}}</th><th scope="col">{{.UsesLabel}}</th><th scope="col">{{.ExpiryLabel}}</th><th scope="col">{{.ActionsLabel}}</th></tr></thead><tbody>{{range .Invites}}<tr><td>{{.Role}}</td><td>{{.UseCount}} / {{.MaxUses}}</td><td>{{.ExpiresAt}}</td><td><form method="post" action="{{$.Path}}/{{.ID}}/revoke"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><button class="btn btn-danger" type="button" popovertarget="revoke-invite-{{.ID}}">{{$.RevokeLabel}}</button><div id="revoke-invite-{{.ID}}" popover aria-labelledby="revoke-invite-title-{{.ID}}"><h3 id="revoke-invite-title-{{.ID}}">{{$.RevokeLabel}}</h3><p>{{$.RoleLabel}}: {{.Role}}</p><button class="btn btn-secondary" type="button" popovertarget="revoke-invite-{{.ID}}" popovertargetaction="hide">{{$.Cancel}}</button><button class="btn btn-danger" type="submit">{{$.Confirm}}</button></div></form></td></tr>{{end}}</tbody></table></div>{{else}}<p>{{.NoInvites}}</p>{{end}}<p><a href="{{.BackURL}}">{{.Back}}</a></p>`))

var userInviteAcceptanceTemplate = template.Must(template.New("user-invite-acceptance").Parse(`<p>{{.InviteLead}}</p><form method="post" action="{{.Action}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="invite-username">{{.UsernameLabel}}</label><input id="invite-username" name="username" autocomplete="username" minlength="2" maxlength="39" required><label for="invite-email">{{.EmailLabel}}</label><input id="invite-email" name="email" type="email" autocomplete="email" required><label for="invite-password">{{.ChoosePassword}}</label><input id="invite-password" name="password" type="password" autocomplete="new-password" minlength="8" required><label for="invite-confirm">{{.ConfirmPassword}}</label><input id="invite-confirm" name="confirm_password" type="password" autocomplete="new-password" minlength="8" required><button type="submit">{{.AcceptInvite}}</button></form>`))

var verificationResendTemplate = template.Must(template.New("verification-resend").Parse(`<p>{{.Lead}}</p>{{if .Message}}<p role="status">{{.Message}}</p>{{end}}<form method="post" action="/server/auth/verify/resend"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="resend-email">{{.EmailLabel}}</label><input id="resend-email" name="email" type="email" autocomplete="email" required><button type="submit">{{.Button}}</button></form>`))

type userAdminRow struct {
	ID            int64  `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	Status        string `json:"status"`
	CreatedAt     string `json:"created_at"`
	Action        string `json:"action"`
	ActionLabel   string `json:"action_label"`
	ConfirmAction bool   `json:"confirm_action"`
}

type userInviteRow struct {
	ID        int64
	Role      string
	UseCount  int
	MaxUses   string
	ExpiresAt string
}

func (s *Server) userLifecycleStore() (store.UserLifecycleStore, bool) {
	lifecycle, ok := s.Store.(store.UserLifecycleStore)
	return lifecycle, ok
}

func (s *Server) userInviteStore() (store.UserInviteStore, bool) {
	invites, ok := s.Store.(store.UserInviteStore)
	return invites, ok
}

func userAdminMessage(r *http.Request, key string) string {
	return serverAdminCatalog(r).T("user_admin.errors."+key, nil)
}

func (s *Server) handleAdminUsersPage(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(r.URL.Path, "/")
	labels, catalog := userAdminLabels(r)
	if rawID := chi.URLParam(r, "id"); rawID != "" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, userAdminMessage(r, "method_not_allowed"), http.StatusMethodNotAllowed)
			return
		}
		id, err := strconv.ParseInt(rawID, 10, 64)
		if err != nil || id < 1 {
			http.NotFound(w, r)
			return
		}
		user, err := s.Store.GetUser(r.Context(), strconv.FormatInt(id, 10))
		if err != nil {
			http.Error(w, userAdminMessage(r, "load_failed"), http.StatusInternalServerError)
			return
		}
		if user == nil {
			http.NotFound(w, r)
			return
		}
		status := labels["Active"]
		if user.Disabled {
			status = labels["Disabled"]
		}
		if !user.Approved {
			status = labels["PendingApproval"]
		}
		action, actionLabel := "disable", labels["Suspend"]
		if user.Disabled {
			action, actionLabel = "enable", labels["Unsuspend"]
		}
		lastLogin := labels["Never"]
		if user.LastLogin != nil {
			lastLogin = user.LastLogin.UTC().Format(time.RFC3339)
		}
		csrf := s.issuePreferenceCSRF(w, r)
		data := map[string]any{"ID": id, "Path": base[:strings.LastIndex(base, "/")], "CSRF": csrf, "Username": user.Username, "Email": maskUserEmail(user.Email), "Status": status, "TOTP": labels["No"], "LastLogin": lastLogin, "Action": action, "ActionLabel": actionLabel, "ConfirmAction": action == "disable", "Confirm": labels["Confirm"], "Cancel": labels["Cancel"]}
		if user.TOTPEnabled {
			data["TOTP"] = labels["Yes"]
		}
		for key, value := range labels {
			data[key] = value
		}
		content := executeTemplate(userAdminDetailTemplate, data)
		title := labels["DetailsTitle"]
		s.AdminHandler.RenderContentPage(w, r, title, catalog.T("user_admin.user_details_description", nil), content)
		return
	}
	message, activationLink := "", ""
	if r.Method == http.MethodPost {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
			http.Error(w, userAdminMessage(r, "security"), http.StatusForbidden)
			return
		}
		username, emailAddress := strings.TrimSpace(r.FormValue("username")), strings.TrimSpace(r.FormValue("email"))
		if err := validateAdminUserInput(username, emailAddress); err != nil {
			http.Error(w, userAdminMessage(r, "operation_failed"), http.StatusBadRequest)
			return
		}
		link, err := s.createAdminUser(r, username, emailAddress, r.FormValue("delivery") == "direct")
		if err != nil {
			http.Error(w, userAdminMessage(r, "create_failed"), http.StatusConflict)
			return
		}
		if link != "" {
			activationLink = link
		} else {
			message = labels["SentEmail"]
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, userAdminMessage(r, "method_not_allowed"), http.StatusMethodNotAllowed)
		return
	}
	lifecycle, ok := s.userLifecycleStore()
	if !ok {
		http.Error(w, userAdminMessage(r, "unavailable"), http.StatusServiceUnavailable)
		return
	}
	page, err := parsePage(r.URL.Query().Get("page"))
	if err != nil {
		http.Error(w, userAdminMessage(r, "invalid_request"), http.StatusBadRequest)
		return
	}
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	users, total, err := lifecycle.ListUsers(r.Context(), 25, (page-1)*25, search)
	if err != nil {
		http.Error(w, userAdminMessage(r, "load_failed"), http.StatusInternalServerError)
		return
	}
	rows := make([]userAdminRow, 0, len(users))
	for _, user := range users {
		status, action, label := labels["Active"], "disable", labels["Suspend"]
		if user.Disabled {
			status, action, label = labels["Disabled"], "enable", labels["Unsuspend"]
		}
		if !user.Approved {
			status = labels["PendingApproval"]
		}
		rows = append(rows, userAdminRow{ID: user.ID, Username: user.Username, Email: maskUserEmail(user.Email), Status: status, CreatedAt: user.CreatedAt.UTC().Format(time.RFC3339), Action: action, ActionLabel: label, ConfirmAction: action == "disable"})
	}
	csrf := s.issuePreferenceCSRF(w, r)
	previous, next := "", ""
	if page > 1 {
		previous = pageURL(base, page-1, search)
	}
	if page*25 < total {
		next = pageURL(base, page+1, search)
	}
	data := map[string]any{"Path": base, "InvitesURL": base + "/invites", "Search": search, "CSRF": csrf, "Users": rows, "Message": message, "Link": activationLink, "Previous": previous, "Next": next}
	for key, value := range labels {
		data[key] = value
	}
	content := executeTemplate(userAdminTemplate, data)
	title := labels["Title"]
	s.AdminHandler.RenderContentPage(w, r, title, catalog.T("user_admin.count", map[string]string{"count": strconv.Itoa(total)}), content)
}

func (s *Server) createAdminUser(r *http.Request, username, emailAddress string, emailLink bool) (string, error) {
	lifecycle, ok := s.userLifecycleStore()
	if !ok {
		return "", fmt.Errorf("user lifecycle storage unavailable")
	}
	if user, err := s.Store.GetUserByUsername(r.Context(), username); err != nil {
		return "", err
	} else if user != nil {
		return "", fmt.Errorf("username already exists")
	}
	if user, err := s.Store.GetUserByEmail(r.Context(), emailAddress); err != nil {
		return "", err
	} else if user != nil {
		return "", fmt.Errorf("email already exists")
	}
	placeholderPassword, err := randomOpaqueValue()
	if err != nil {
		return "", err
	}
	placeholder, err := auth.HashPassword(placeholderPassword)
	if err != nil {
		return "", err
	}
	user := &model.User{Username: username, Email: emailAddress, PasswordHash: placeholder, Role: s.defaultUserRole(), Source: "local", Approved: false, Disabled: true, EmailVerified: true, Visibility: "public", Language: "en", Timezone: "UTC", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := s.Store.CreateUser(r.Context(), user); err != nil {
		return "", err
	}
	secret, err := randomOpaqueValue()
	if err != nil {
		_ = s.Store.DeleteUser(r.Context(), model.UserIDString(user.ID))
		return "", err
	}
	digest := sha256.Sum256([]byte(secret))
	expiresIn := 7 * 24 * time.Hour
	if s.Config != nil && s.Config.Server.Users.Registration.InviteExpirationDays > 0 {
		expiresIn = time.Duration(s.Config.Server.Users.Registration.InviteExpirationDays) * 24 * time.Hour
	}
	if err := lifecycle.CreateUserActivationToken(r.Context(), model.UserIDString(user.ID), hex.EncodeToString(digest[:]), time.Now().Add(expiresIn)); err != nil {
		_ = s.Store.DeleteUser(r.Context(), model.UserIDString(user.ID))
		return "", err
	}
	path := "/server/auth/invite/user/" + url.PathEscape(secret)
	activationLink := BuildURL(r, path)
	if !emailLink || s.EmailService == nil || !s.EmailService.Available() {
		return activationLink, nil
	}
	labels, catalog := userAdminLabels(r)
	_ = labels
	body := catalog.T("user_admin.activation_email_body", map[string]string{"activation_url": activationLink})
	if err := s.EmailService.SendMessage(emailAddress, "", catalog.T("user_admin.activation_email_subject", nil), body); err != nil {
		return activationLink, nil
	}
	return "", nil
}

func (s *Server) renderActivation(w http.ResponseWriter, r *http.Request, token, message string, status int) {
	labels, _ := userAdminLabels(r)
	csrf := s.issuePreferenceCSRF(w, r)
	data := map[string]string{"Action": "/server/auth/invite/user/" + url.PathEscape(token), "CSRF": csrf, "Message": message}
	for key, value := range labels {
		data[key] = value
	}
	content := executeTemplate(userActivationTemplate, data)
	title := labels["ActivateTitle"]
	page := publicPageTemplateData{Title: title, Lead: labels["ActivateLead"], NoIndex: true, CSRFToken: csrf, Sections: []renderedPageSection{{ID: "account-activation", Title: title, Content: template.HTML(content)}}}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, userAdminMessage(r, "unavailable"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, page)
}

func (s *Server) handleAdminUsersAPI(w http.ResponseWriter, r *http.Request) {
	lifecycle, ok := s.userLifecycleStore()
	if !ok {
		writeUserJSON(w, 503, map[string]any{"ok": false, "error": userAdminMessage(r, "unavailable")})
		return
	}
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/users") {
		var request struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Delivery string `json:"delivery"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&request); err != nil {
			writeUserJSON(w, 400, map[string]any{"ok": false, "error": userAdminMessage(r, "invalid_request")})
			return
		}
		request.Username = strings.TrimSpace(request.Username)
		request.Email = strings.TrimSpace(request.Email)
		if err := validateAdminUserInput(request.Username, request.Email); err != nil {
			writeUserJSON(w, 400, map[string]any{"ok": false, "error": userAdminMessage(r, "invalid_request")})
			return
		}
		link, err := s.createAdminUser(r, request.Username, request.Email, request.Delivery == "direct")
		if err != nil {
			writeUserJSON(w, 409, map[string]any{"ok": false, "error": userAdminMessage(r, "create_failed")})
			return
		}
		writeUserJSON(w, 201, map[string]any{"ok": true, "data": map[string]any{"username": request.Username, "activation_url": link, "sent_by_email": link == ""}})
		return
	}
	if r.Method == http.MethodGet {
		if rawID := chi.URLParam(r, "id"); rawID != "" {
			id, err := strconv.ParseInt(rawID, 10, 64)
			if err != nil || id < 1 {
				writeUserJSON(w, 404, map[string]any{"ok": false, "error": userAdminMessage(r, "not_found")})
				return
			}
			user, err := s.Store.GetUser(r.Context(), strconv.FormatInt(id, 10))
			if err != nil {
				writeUserJSON(w, 500, map[string]any{"ok": false, "error": userAdminMessage(r, "load_failed")})
				return
			}
			if user == nil {
				writeUserJSON(w, 404, map[string]any{"ok": false, "error": userAdminMessage(r, "not_found")})
				return
			}
			status := "active"
			if user.Disabled {
				status = "disabled"
			}
			if !user.Approved {
				status = "pending approval"
			}
			writeUserJSON(w, 200, map[string]any{"ok": true, "data": map[string]any{"id": user.ID, "username": user.Username, "email": maskUserEmail(user.Email), "status": status, "two_factor_enabled": user.TOTPEnabled, "last_login": user.LastLogin}})
			return
		}
		page, err := parsePage(r.URL.Query().Get("page"))
		if err != nil {
			writeUserJSON(w, 400, map[string]any{"ok": false, "error": userAdminMessage(r, "invalid_request")})
			return
		}
		search := strings.TrimSpace(r.URL.Query().Get("q"))
		users, total, err := lifecycle.ListUsers(r.Context(), 25, (page-1)*25, search)
		if err != nil {
			writeUserJSON(w, 500, map[string]any{"ok": false, "error": userAdminMessage(r, "load_failed")})
			return
		}
		rows := make([]map[string]any, 0, len(users))
		for _, u := range users {
			rows = append(rows, map[string]any{"id": u.ID, "username": u.Username, "display_name": u.DisplayName, "disabled": u.Disabled, "approved": u.Approved, "created_at": u.CreatedAt})
		}
		writeUserJSON(w, 200, map[string]any{"ok": true, "data": map[string]any{"users": rows, "total": total, "page": page, "per_page": 25}})
		return
	}
	if r.Method == http.MethodDelete {
		id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil || id < 1 {
			writeUserJSON(w, 404, map[string]any{"ok": false, "error": userAdminMessage(r, "not_found")})
			return
		}
		if err := s.Store.DeleteUser(r.Context(), strconv.FormatInt(id, 10)); err != nil {
			writeUserJSON(w, 500, map[string]any{"ok": false, "error": userAdminMessage(r, "delete_failed")})
			return
		}
		s.auditUserAdminAction("user.deleted", id)
		writeUserJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/disable") || r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/enable") {
		var request struct {
			ID int64 `json:"id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&request); err != nil || request.ID < 1 {
			writeUserJSON(w, 400, map[string]any{"ok": false, "error": userAdminMessage(r, "invalid_request")})
			return
		}
		user, err := s.Store.GetUser(r.Context(), strconv.FormatInt(request.ID, 10))
		if err != nil {
			writeUserJSON(w, 500, map[string]any{"ok": false, "error": userAdminMessage(r, "load_failed")})
			return
		}
		if user == nil {
			writeUserJSON(w, 404, map[string]any{"ok": false, "error": userAdminMessage(r, "not_found")})
			return
		}
		user.Disabled = strings.HasSuffix(r.URL.Path, "/disable")
		user.UpdatedAt = time.Now().UTC()
		if err := s.Store.UpdateUser(r.Context(), user); err != nil {
			writeUserJSON(w, 500, map[string]any{"ok": false, "error": userAdminMessage(r, "update_failed")})
			return
		}
		if user.Disabled {
			if err := s.revokeUserCredentials(r.Context(), user.ID); err != nil {
				writeUserJSON(w, 500, map[string]any{"ok": false, "error": userAdminMessage(r, "update_failed")})
				return
			}
		}
		event := "user.enabled"
		if user.Disabled {
			event = "user.suspended"
		}
		s.auditUserAdminAction(event, user.ID)
		writeUserJSON(w, 200, map[string]any{"ok": true, "data": map[string]any{"id": user.ID, "disabled": user.Disabled}})
		return
	}
	writeUserJSON(w, 405, map[string]any{"ok": false, "error": userAdminMessage(r, "method_not_allowed")})
}

func (s *Server) handleAdminUserAction(w http.ResponseWriter, r *http.Request) {
	if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
		http.Error(w, userAdminMessage(r, "security"), http.StatusForbidden)
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id < 1 {
		http.NotFound(w, r)
		return
	}
	userID := strconv.FormatInt(id, 10)
	action := chi.URLParam(r, "action")
	switch action {
	case "disable", "enable":
		user, err := s.Store.GetUser(r.Context(), userID)
		if err != nil || user == nil {
			http.NotFound(w, r)
			return
		}
		user.Disabled = action == "disable"
		user.UpdatedAt = time.Now().UTC()
		if err := s.Store.UpdateUser(r.Context(), user); err != nil {
			http.Error(w, userAdminMessage(r, "update_failed"), http.StatusInternalServerError)
			return
		}
		if user.Disabled {
			if err := s.revokeUserCredentials(r.Context(), user.ID); err != nil {
				http.Error(w, userAdminMessage(r, "update_failed"), http.StatusInternalServerError)
				return
			}
		}
		event := "user.enabled"
		if user.Disabled {
			event = "user.suspended"
		}
		s.auditUserAdminAction(event, user.ID)
	case "delete":
		user, err := s.Store.GetUser(r.Context(), userID)
		if err != nil || user == nil {
			http.NotFound(w, r)
			return
		}
		if r.FormValue("confirm") != user.Username {
			http.Error(w, userAdminMessage(r, "confirmation"), http.StatusBadRequest)
			return
		}
		if err := s.Store.DeleteUser(r.Context(), userID); err != nil {
			http.Error(w, userAdminMessage(r, "delete_failed"), http.StatusInternalServerError)
			return
		}
		s.auditUserAdminAction("user.deleted", user.ID)
	case "sessions":
		if err := s.Store.DeleteUserSessions(r.Context(), userID); err != nil {
			http.Error(w, userAdminMessage(r, "delete_failed"), http.StatusInternalServerError)
			return
		}
		s.auditUserAdminAction("user.sessions_revoked", id)
	default:
		http.NotFound(w, r)
		return
	}
	base := strings.TrimRight(r.URL.Path, "/")
	if strings.Contains(base, "/moderation/users/") {
		base = base[:strings.Index(base, "/moderation/users/")+len("/moderation/users")]
	} else {
		base = base[:strings.Index(base, "/users/")+len("/users")]
	}
	http.Redirect(w, r, base, http.StatusSeeOther)
}

func (s *Server) auditUserAdminAction(event string, userID int64) {
	if s.Logger == nil || s.Logger.Audit == nil {
		return
	}
	entry, err := json.Marshal(map[string]any{"event": event, "user_id": userID, "timestamp": time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return
	}
	s.Logger.Audit.Printf("%s\n", entry)
}

func (s *Server) revokeUserCredentials(ctx context.Context, userID int64) error {
	id := model.UserIDString(userID)
	tokens, err := s.Store.GetUserAPITokens(ctx, id)
	if err != nil {
		return err
	}
	for _, token := range tokens {
		if err := s.Store.DeleteAPIToken(ctx, token.ID); err != nil {
			return err
		}
	}
	return s.Store.DeleteUserSessions(ctx, id)
}

func validateAdminUserInput(username, emailAddress string) error {
	if len(username) < 2 || len(username) > 39 || strings.Trim(username, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != "" || strings.HasPrefix(username, "-") || strings.HasSuffix(username, "-") {
		return fmt.Errorf("invalid username")
	}
	address, err := mail.ParseAddress(emailAddress)
	if err != nil || address.Address != emailAddress {
		return fmt.Errorf("invalid email")
	}
	return nil
}

func maskUserEmail(address string) string {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	localRunes := []rune(parts[0])
	maskedLocal := "*"
	if len(localRunes) > 1 {
		maskedLocal = string(localRunes[0]) + strings.Repeat("*", max(1, len(localRunes)-2)) + string(localRunes[len(localRunes)-1])
	}
	domain := parts[1]
	domainParts := strings.Split(domain, ".")
	if len(domainParts) > 1 {
		labels := domainParts[:len(domainParts)-1]
		for i, label := range labels {
			if label != "" {
				first := []rune(label)[0]
				labels[i] = string(first) + "***"
			}
		}
		domain = strings.Join(append(labels, domainParts[len(domainParts)-1]), ".")
	} else if domain != "" {
		domain = string([]rune(domain)[0]) + "***"
	}
	return maskedLocal + "@" + domain
}

func userAdminLabels(r *http.Request) (map[string]string, *i18n.Catalog) {
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		catalog, _ = i18n.Resolve("en")
	}
	keys := map[string]string{
		"Title": "title", "SearchLabel": "search_label", "SearchButton": "search", "CreateTitle": "create_title",
		"UsernameLabel": "username", "EmailLabel": "email", "CreateInvite": "create_invite", "CreateDirect": "create_direct",
		"LinkLabel": "link_label", "IDLabel": "id", "StatusLabel": "status", "CreatedLabel": "created", "ActionsLabel": "actions",
		"RevokeSessions": "revoke_sessions", "Details": "details", "NoUsers": "no_users", "PageNav": "page_nav", "PreviousLabel": "previous", "NextLabel": "next",
		"DetailsTitle": "details_title", "TwoFactorLabel": "two_factor", "LastLoginLabel": "last_login", "Never": "never", "DeleteUser": "delete_user",
		"DeleteWarning": "delete_warning", "UsernameConfirmation": "username_confirmation", "Back": "back", "ActivateTitle": "activate_title",
		"ActivateLead": "activate_lead", "ChoosePassword": "choose_password", "ConfirmPassword": "confirm_password", "Activate": "activate",
		"PasswordMismatch": "password_mismatch", "ActivationPrompt": "activation_prompt", "SentEmail": "sent_email", "Active": "active",
		"Disabled": "disabled", "PendingApproval": "pending_approval", "Suspend": "suspend", "Unsuspend": "unsuspend", "Yes": "yes", "No": "no",
		"InviteCodes": "invite_codes", "GenerateTitle": "generate_title", "RoleLabel": "role_label", "RoleUser": "role_user", "RoleAdmin": "role_admin",
		"ExpiryLabel": "expiry_label", "ExpiryUTC": "expiry_utc", "MaxUsesLabel": "max_uses_label", "UnlimitedHint": "unlimited_hint",
		"GenerateInvite": "generate_invite", "InviteListTitle": "invite_list_title", "UsesLabel": "uses_label", "RevokeLabel": "revoke_label",
		"NoInvites": "no_invites", "Unlimited": "unlimited", "InviteTitle": "invite_title", "InviteLead": "invite_lead", "AcceptInvite": "accept_invite", "InviteFailure": "invite_failure",
	}
	labels := make(map[string]string, len(keys))
	for field, key := range keys {
		labels[field] = catalog.T("user_admin."+key, nil)
	}
	labels["Cancel"] = catalog.T("common.cancel", nil)
	labels["Confirm"] = catalog.T("common.confirm", nil)
	return labels, catalog
}

func randomOpaqueValue() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
func parsePage(raw string) (int, error) {
	if raw == "" {
		return 1, nil
	}
	page, err := strconv.Atoi(raw)
	if err != nil || page < 1 || page > 100000 {
		return 0, fmt.Errorf("invalid page")
	}
	return page, nil
}
func pageURL(path string, page int, search string) string {
	query := url.Values{"page": {strconv.Itoa(page)}}
	if search != "" {
		query.Set("q", search)
	}
	return path + "?" + query.Encode()
}

func (s *Server) handleUserInvitesPage(w http.ResponseWriter, r *http.Request) {
	labels, catalog := userAdminLabels(r)
	if r.Method == http.MethodPost {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
			http.Error(w, userAdminMessage(r, "security"), http.StatusForbidden)
			return
		}
		maxUses, err := strconv.Atoi(r.FormValue("max_uses"))
		if err != nil || maxUses < 0 {
			http.Error(w, userAdminMessage(r, "max_uses"), http.StatusBadRequest)
			return
		}
		expiresAt, err := time.ParseInLocation("2006-01-02T15:04", r.FormValue("expires_at"), time.UTC)
		if err != nil || !expiresAt.After(time.Now()) {
			http.Error(w, userAdminMessage(r, "expiration"), http.StatusBadRequest)
			return
		}
		link, err := s.createUserInvite(r, r.FormValue("role"), maxUses, expiresAt)
		if err != nil {
			http.Error(w, userAdminMessage(r, "create_failed"), http.StatusBadRequest)
			return
		}
		r.URL.RawQuery = url.Values{"created": {"1"}}.Encode()
		r = r.WithContext(context.WithValue(r.Context(), inviteLinkContextKey{}, link))
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, userAdminMessage(r, "method_not_allowed"), http.StatusMethodNotAllowed)
		return
	}
	inviteStore, ok := s.userInviteStore()
	if !ok {
		http.Error(w, userAdminMessage(r, "unavailable"), http.StatusServiceUnavailable)
		return
	}
	invites, err := inviteStore.ListUserInvites(r.Context())
	if err != nil {
		http.Error(w, userAdminMessage(r, "load_failed"), http.StatusInternalServerError)
		return
	}
	rows := make([]userInviteRow, 0, len(invites))
	for _, invite := range invites {
		maxUses := strconv.Itoa(invite.MaxUses)
		if invite.MaxUses == 0 {
			maxUses = labels["Unlimited"]
		}
		rows = append(rows, userInviteRow{ID: invite.ID, Role: invite.Role, UseCount: invite.UseCount, MaxUses: maxUses, ExpiresAt: invite.ExpiresAt.UTC().Format(time.RFC3339)})
	}
	csrf := s.issuePreferenceCSRF(w, r)
	defaultExpiry := time.Now().UTC().Add(7 * 24 * time.Hour).Format("2006-01-02T15:04")
	base := strings.TrimRight(r.URL.Path, "/")
	data := map[string]any{"Path": base, "BackURL": strings.TrimSuffix(base, "/invites"), "CSRF": csrf, "Invites": rows, "ExpiryDefault": defaultExpiry, "Link": inviteLinkFromContext(r), "Roles": s.userRoleOptions(labels)}
	for key, value := range userInviteLabels(labels) {
		data[key] = value
	}
	content := executeTemplate(userInvitesTemplate, data)
	title := catalog.T("user_admin.invites_title", nil)
	s.AdminHandler.RenderContentPage(w, r, title, catalog.T("user_admin.invites_description", nil), content)
}

type inviteLinkContextKey struct{}

func inviteLinkFromContext(r *http.Request) string {
	link, _ := r.Context().Value(inviteLinkContextKey{}).(string)
	return link
}

func userInviteLabels(labels map[string]string) map[string]string {
	result := map[string]string{"GenerateTitle": labels["GenerateTitle"], "RoleLabel": labels["RoleLabel"], "RoleUser": labels["RoleUser"], "RoleAdmin": labels["RoleAdmin"], "ExpiryLabel": labels["ExpiryLabel"], "ExpiryUTC": labels["ExpiryUTC"], "MaxUsesLabel": labels["MaxUsesLabel"], "UnlimitedHint": labels["UnlimitedHint"], "GenerateInvite": labels["GenerateInvite"], "InviteListTitle": labels["InviteListTitle"], "UsesLabel": labels["UsesLabel"], "ActionsLabel": labels["ActionsLabel"], "RevokeLabel": labels["RevokeLabel"], "NoInvites": labels["NoInvites"], "Back": labels["Back"], "LinkLabel": labels["LinkLabel"], "Unlimited": labels["Unlimited"], "Cancel": labels["Cancel"], "Confirm": labels["Confirm"]}
	return result
}

func (s *Server) handleRevokeUserInvite(w http.ResponseWriter, r *http.Request) {
	if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
		http.Error(w, userAdminMessage(r, "security"), http.StatusForbidden)
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id < 1 {
		http.NotFound(w, r)
		return
	}
	inviteStore, ok := s.userInviteStore()
	if !ok {
		http.Error(w, userAdminMessage(r, "unavailable"), http.StatusServiceUnavailable)
		return
	}
	if err := inviteStore.RevokeUserInvite(r.Context(), id); err != nil {
		http.Error(w, userAdminMessage(r, "delete_failed"), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, r.URL.Path[:strings.LastIndex(r.URL.Path, "/")-len(strconv.FormatInt(id, 10))-1], http.StatusSeeOther)
}

func (s *Server) createUserInvite(r *http.Request, role string, maxUses int, expiresAt time.Time) (string, error) {
	if !s.validUserRole(role) {
		return "", fmt.Errorf("invalid role")
	}
	inviteStore, ok := s.userInviteStore()
	if !ok {
		return "", fmt.Errorf("invite storage unavailable")
	}
	var createdBy int64
	if adminID, ok := admin.AdminIDFromContext(r.Context()); ok {
		createdBy = int64(adminID)
	} else if identity, ok := r.Context().Value(apiTokenContextKey{}).(apiTokenIdentity); ok && identity.Admin {
		if identity.ID != "operator" {
			id, err := strconv.ParseInt(strings.TrimPrefix(identity.ID, "admin-"), 10, 64)
			if err != nil || id < 1 {
				return "", fmt.Errorf("invalid admin identity")
			}
			createdBy = id
		}
	}
	raw, err := randomOpaqueValue()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(raw))
	invite := &model.UserInvite{CodeHash: hex.EncodeToString(hash[:]), Role: role, MaxUses: maxUses, ExpiresAt: expiresAt.UTC(), CreatedBy: createdBy, CreatedAt: time.Now().UTC()}
	if err := inviteStore.CreateUserInvite(r.Context(), invite); err != nil {
		return "", err
	}
	return BuildURL(r, "/server/auth/invite/user/"+url.PathEscape(raw)), nil
}

func (s *Server) defaultUserRole() string {
	if s.Config != nil {
		s.configMu.RLock()
		role := strings.TrimSpace(s.Config.Server.Users.Roles.Default)
		s.configMu.RUnlock()
		if role != "" && s.validUserRole(role) {
			return role
		}
	}
	return "user"
}

func (s *Server) validUserRole(role string) bool {
	if s.Config != nil {
		s.configMu.RLock()
		defer s.configMu.RUnlock()
		for _, available := range s.Config.Server.Users.Roles.Available {
			if role == available && role != "" {
				return true
			}
		}
		return false
	}
	return role == "user"
}

type userRoleOption struct {
	Value, Label string
	Selected     bool
}

func (s *Server) userRoleOptions(labels map[string]string) []userRoleOption {
	roles := []string{"user"}
	if s.Config != nil {
		s.configMu.RLock()
		if len(s.Config.Server.Users.Roles.Available) > 0 {
			roles = append([]string(nil), s.Config.Server.Users.Roles.Available...)
		}
		s.configMu.RUnlock()
	}
	defaultRole := s.defaultUserRole()
	options := make([]userRoleOption, 0, len(roles))
	for _, role := range roles {
		label := role
		if role == "user" {
			label = labels["RoleUser"]
		} else if role == "admin" {
			label = labels["RoleAdmin"]
		}
		options = append(options, userRoleOption{Value: role, Label: label, Selected: role == defaultRole})
	}
	return options
}

func (s *Server) handleUserInvitesAPI(w http.ResponseWriter, r *http.Request) {
	inviteStore, ok := s.userInviteStore()
	if !ok {
		writeUserJSON(w, 503, map[string]any{"ok": false, "error": userAdminMessage(r, "unavailable")})
		return
	}
	rawID := chi.URLParam(r, "id")
	switch r.Method {
	case http.MethodGet:
		if rawID != "" {
			id, err := strconv.ParseInt(rawID, 10, 64)
			if err != nil || id < 1 {
				writeUserJSON(w, 404, map[string]any{"ok": false, "error": userAdminMessage(r, "not_found")})
				return
			}
			invite, err := inviteStore.GetUserInvite(r.Context(), id)
			if err != nil {
				writeUserJSON(w, 500, map[string]any{"ok": false, "error": userAdminMessage(r, "load_failed")})
				return
			}
			if invite == nil {
				writeUserJSON(w, 404, map[string]any{"ok": false, "error": userAdminMessage(r, "not_found")})
				return
			}
			writeUserJSON(w, 200, map[string]any{"ok": true, "data": invite})
			return
		}
		invites, err := inviteStore.ListUserInvites(r.Context())
		if err != nil {
			writeUserJSON(w, 500, map[string]any{"ok": false, "error": userAdminMessage(r, "load_failed")})
			return
		}
		writeUserJSON(w, 200, map[string]any{"ok": true, "data": invites})
	case http.MethodPost:
		var request struct {
			Role      string    `json:"role"`
			MaxUses   int       `json:"max_uses"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&request); err != nil {
			writeUserJSON(w, 400, map[string]any{"ok": false, "error": userAdminMessage(r, "invalid_request")})
			return
		}
		if request.MaxUses < 0 || request.ExpiresAt.IsZero() || !request.ExpiresAt.After(time.Now()) || !s.validUserRole(request.Role) {
			writeUserJSON(w, 400, map[string]any{"ok": false, "error": userAdminMessage(r, "invalid_request")})
			return
		}
		link, err := s.createUserInvite(r, request.Role, request.MaxUses, request.ExpiresAt)
		if err != nil {
			writeUserJSON(w, 500, map[string]any{"ok": false, "error": userAdminMessage(r, "create_failed")})
			return
		}
		rawCode := strings.TrimPrefix(link, BuildURL(r, "/server/auth/invite/user/"))
		writeUserJSON(w, 201, map[string]any{"ok": true, "data": map[string]any{"url": link, "code": rawCode}})
	case http.MethodDelete:
		id, err := strconv.ParseInt(rawID, 10, 64)
		if err != nil || id < 1 {
			writeUserJSON(w, 404, map[string]any{"ok": false, "error": userAdminMessage(r, "not_found")})
			return
		}
		if err := inviteStore.RevokeUserInvite(r.Context(), id); err != nil {
			writeUserJSON(w, 500, map[string]any{"ok": false, "error": userAdminMessage(r, "delete_failed")})
			return
		}
		writeUserJSON(w, 200, map[string]any{"ok": true})
	default:
		writeUserJSON(w, 405, map[string]any{"ok": false, "error": userAdminMessage(r, "method_not_allowed")})
	}
}

func (s *Server) handleUserInviteAcceptance(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "token")
	if len(code) < 32 || len(code) > 256 {
		http.NotFound(w, r)
		return
	}
	inviteStore, ok := s.userInviteStore()
	if !ok {
		http.Error(w, userAdminMessage(r, "unavailable"), http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodGet {
		invite, err := inviteStore.GetUserInviteByCode(r.Context(), code, time.Now())
		if err != nil {
			http.Error(w, userAdminMessage(r, "unavailable"), http.StatusInternalServerError)
			return
		}
		if invite == nil {
			labels, _ := userAdminLabels(r)
			s.renderActivation(w, r, code, labels["ActivationPrompt"], http.StatusOK)
			return
		}
		s.renderUserInviteAcceptance(w, r, code, http.StatusOK, "")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, userAdminMessage(r, "method_not_allowed"), http.StatusMethodNotAllowed)
		return
	}
	if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
		http.Error(w, userAdminMessage(r, "security"), http.StatusForbidden)
		return
	}
	invite, err := inviteStore.GetUserInviteByCode(r.Context(), code, time.Now())
	if err != nil {
		http.Error(w, userAdminMessage(r, "unavailable"), http.StatusInternalServerError)
		return
	}
	if invite == nil {
		password, confirm := r.FormValue("password"), r.FormValue("confirm_password")
		labels, _ := userAdminLabels(r)
		if s.validateUserPassword(password) != nil || password != confirm {
			s.renderActivation(w, r, code, labels["PasswordMismatch"], http.StatusBadRequest)
			return
		}
		completed, ok := s.Store.(interface {
			CompleteUserActivationToken(context.Context, string, time.Time, string) (bool, error)
		})
		if !ok {
			http.Error(w, userAdminMessage(r, "unavailable"), http.StatusServiceUnavailable)
			return
		}
		hash := sha256.Sum256([]byte(code))
		passwordHash, err := auth.HashPassword(password)
		if err != nil {
			http.Error(w, userAdminMessage(r, "activation_failed"), http.StatusInternalServerError)
			return
		}
		activated, err := completed.CompleteUserActivationToken(r.Context(), hex.EncodeToString(hash[:]), time.Now(), passwordHash)
		if err != nil {
			http.Error(w, userAdminMessage(r, "activation_failed"), http.StatusInternalServerError)
			return
		}
		if !activated {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/server/auth/login?registered=1", http.StatusSeeOther)
		return
	}
	user, err := s.completeUserInvite(r, code, r.FormValue("username"), r.FormValue("email"), r.FormValue("password"), r.FormValue("confirm_password"))
	if user != nil {
		if err != nil {
			http.Redirect(w, r, "/server/auth/verify/resend?delivery=failed", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/server/auth/login?registered=1", http.StatusSeeOther)
		}
		return
	}
	labels, _ := userAdminLabels(r)
	s.renderUserInviteAcceptance(w, r, code, http.StatusBadRequest, labels["InviteFailure"])
}

func (s *Server) renderUserInviteAcceptance(w http.ResponseWriter, r *http.Request, code string, status int, message string) {
	labels, catalog := userAdminLabels(r)
	csrf := s.issuePreferenceCSRF(w, r)
	data := map[string]string{"Action": "/server/auth/invite/user/" + url.PathEscape(code), "CSRF": csrf, "InviteLead": catalog.T("user_admin.invite_lead", nil), "Error": message}
	for key, value := range labels {
		data[key] = value
	}
	content := executeTemplate(userInviteAcceptanceTemplate, data)
	title := catalog.T("user_admin.invite_title", nil)
	page := publicPageTemplateData{Title: title, Lead: title, NoIndex: true, CSRFToken: csrf, Sections: []renderedPageSection{{ID: "user-invite", Title: title, Content: template.HTML(content)}}}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, userAdminMessage(r, "unavailable"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, page)
}

func (s *Server) handleVerificationResend(w http.ResponseWriter, r *http.Request) {
	labels, catalog := userAdminLabels(r)
	message := ""
	if r.Method == http.MethodPost {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
			http.Error(w, userAdminMessage(r, "security"), http.StatusForbidden)
			return
		}
		var deliveryErr error
		emailAddress := strings.TrimSpace(r.FormValue("email"))
		if auth.ValidateEmail(emailAddress) == nil && s.EmailService != nil && s.EmailService.Available() {
			user, lookupErr := s.Store.GetUserByEmail(r.Context(), emailAddress)
			if lookupErr != nil {
				deliveryErr = lookupErr
			}
			if user != nil && !user.EmailVerified && deliveryErr == nil {
				if tokens, ok := s.Store.(store.EmailVerificationStore); ok {
					token, err := randomOpaqueValue()
					if err != nil {
						deliveryErr = err
					} else {
						digest := sha256.Sum256([]byte(token))
						if err := tokens.CreateEmailVerification(r.Context(), model.UserIDString(user.ID), hex.EncodeToString(digest[:]), time.Now().Add(48*time.Hour)); err != nil {
							deliveryErr = err
						} else {
							verifyURL := BuildURL(r, "/server/auth/verify/"+url.PathEscape(token))
							body := catalog.T("email.verify_body", map[string]string{"verify_url": verifyURL})
							deliveryErr = s.EmailService.SendMessage(emailAddress, "", catalog.T("email.verify_subject", nil), body)
						}
					}
				} else {
					deliveryErr = fmt.Errorf("email verification store unavailable")
				}
			}
		}
		if deliveryErr != nil && s.Logger != nil && s.Logger.Error != nil {
			s.Logger.Error.Printf("verification email resend failed: %v", deliveryErr)
		}
		message = catalog.T("user_admin.resend_message", nil)
	} else if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, userAdminMessage(r, "method_not_allowed"), http.StatusMethodNotAllowed)
		return
	}
	csrf := s.issuePreferenceCSRF(w, r)
	content := executeTemplate(verificationResendTemplate, map[string]string{"Lead": catalog.T("user_admin.resend_lead", nil), "Message": message, "CSRF": csrf, "EmailLabel": labels["EmailLabel"], "Button": catalog.T("user_admin.resend_button", nil)})
	title := catalog.T("user_admin.resend_title", nil)
	page := publicPageTemplateData{Title: title, Lead: title, NoIndex: true, CSRFToken: csrf, Sections: []renderedPageSection{{ID: "verification-resend", Title: title, Content: template.HTML(content)}}}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, userAdminMessage(r, "unavailable"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	_ = pageTemplate.Execute(w, page)
}

func (s *Server) completeUserInvite(r *http.Request, code, username, emailAddress, password, confirm string) (*model.User, error) {
	username = strings.TrimSpace(username)
	emailAddress = strings.TrimSpace(emailAddress)
	if err := auth.ValidateUsername(username); err != nil {
		return nil, err
	}
	if err := auth.ValidateEmail(emailAddress); err != nil {
		return nil, err
	}
	if err := s.validateUserPassword(password); err != nil {
		return nil, err
	}
	if password != confirm {
		return nil, fmt.Errorf("password mismatch")
	}
	if existing, err := s.Store.GetUserByUsername(r.Context(), username); err != nil {
		return nil, err
	} else if existing != nil {
		return nil, fmt.Errorf("username unavailable")
	}
	if existing, err := s.Store.GetUserByEmail(r.Context(), emailAddress); err != nil {
		return nil, err
	} else if existing != nil {
		return nil, fmt.Errorf("email unavailable")
	}
	inviteStore, ok := s.userInviteStore()
	if !ok {
		return nil, fmt.Errorf("invites unavailable")
	}
	invite, err := inviteStore.GetUserInviteByCode(r.Context(), code, time.Now())
	if err != nil || invite == nil {
		return nil, fmt.Errorf("invite invalid")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}
	requiresVerification := s.Config != nil && s.Config.Server.Users.Registration.RequireEmailVerification && s.EmailService != nil && s.EmailService.Available()
	user := &model.User{Username: username, Email: emailAddress, PasswordHash: hash, Role: invite.Role, Source: "local", EmailVerified: !requiresVerification, Visibility: "public", Language: "en", Timezone: "UTC", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := inviteStore.CompleteUserInvite(r.Context(), code, time.Now(), user); err != nil {
		return nil, err
	}
	if requiresVerification {
		tokens, ok := s.Store.(store.EmailVerificationStore)
		if !ok {
			return user, fmt.Errorf("email verification unavailable")
		}
		token, tokenErr := randomOpaqueValue()
		if tokenErr != nil {
			return user, tokenErr
		}
		digest := sha256.Sum256([]byte(token))
		if tokenErr = tokens.CreateEmailVerification(r.Context(), model.UserIDString(user.ID), hex.EncodeToString(digest[:]), time.Now().Add(48*time.Hour)); tokenErr != nil {
			return user, tokenErr
		}
		lang, _ := requestLanguage(r)
		catalog, _ := i18n.Resolve(lang)
		verifyURL := BuildURL(r, "/server/auth/verify/"+url.PathEscape(token))
		body := catalog.T("email.verify_body", map[string]string{"verify_url": verifyURL})
		if tokenErr = s.EmailService.SendMessage(emailAddress, "", catalog.T("email.verify_subject", nil), body); tokenErr != nil {
			return user, tokenErr
		}
	}
	return user, nil
}

func (s *Server) handleUserInviteAPI(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "token")
	if len(code) < 32 || len(code) > 256 {
		writeUserJSON(w, 404, map[string]any{"ok": false, "error": userAdminMessage(r, "not_found")})
		return
	}
	inviteStore, ok := s.userInviteStore()
	if !ok {
		writeUserJSON(w, 503, map[string]any{"ok": false, "error": userAdminMessage(r, "unavailable")})
		return
	}
	if r.Method == http.MethodGet {
		invite, err := inviteStore.GetUserInviteByCode(r.Context(), code, time.Now())
		if err != nil {
			writeUserJSON(w, 500, map[string]any{"ok": false, "error": userAdminMessage(r, "load_failed")})
			return
		}
		if invite == nil {
			writeUserJSON(w, 404, map[string]any{"ok": false, "error": userAdminMessage(r, "not_found")})
			return
		}
		writeUserJSON(w, 200, map[string]any{"ok": true, "data": map[string]any{"role": invite.Role, "expires_at": invite.ExpiresAt, "uses_remaining": remainingInviteUses(invite)}})
		return
	}
	if r.Method != http.MethodPost {
		writeUserJSON(w, 405, map[string]any{"ok": false, "error": userAdminMessage(r, "method_not_allowed")})
		return
	}
	var request struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Confirm  string `json:"confirm_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&request); err != nil {
		writeUserJSON(w, 400, map[string]any{"ok": false, "error": userAdminMessage(r, "invalid_request")})
		return
	}
	user, err := s.completeUserInvite(r, code, request.Username, request.Email, request.Password, request.Confirm)
	if user == nil && err != nil {
		writeUserJSON(w, 400, map[string]any{"ok": false, "error": userAdminMessage(r, "operation_failed")})
		return
	}
	writeUserJSON(w, 201, map[string]any{"ok": true, "data": map[string]any{"user_id": user.ID, "username": user.Username, "email_verified": user.EmailVerified, "verification_sent": err == nil}})
}

func remainingInviteUses(invite *model.UserInvite) any {
	if invite.MaxUses == 0 {
		return "unlimited"
	}
	remaining := invite.MaxUses - invite.UseCount
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}
