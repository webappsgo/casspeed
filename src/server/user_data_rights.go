package server

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

const userDataExportTTL = 24 * time.Hour
const userDataExportThreshold = 10
const userDataExportWindow = time.Hour

var errUserDataExportRateLimit = errors.New("user data export rate limit exceeded")

type userDataExportKey struct {
	server *Server
	id     string
}

type userDataExportRateKey struct {
	server *Server
	userID string
}

type userDataExport struct {
	ownerID string
	payload []byte
	expires time.Time
}

type userDataExportCache struct {
	sync.Mutex
	entries  map[userDataExportKey]userDataExport
	requests map[userDataExportRateKey][]time.Time
	alerts   map[userDataExportRateKey]time.Time
}

var userExports = userDataExportCache{entries: make(map[userDataExportKey]userDataExport), requests: make(map[userDataExportRateKey][]time.Time), alerts: make(map[userDataExportRateKey]time.Time)}

type userDataExportDocument struct {
	ExportedAt    time.Time             `json:"exported_at"`
	Profile       map[string]any        `json:"profile"`
	Settings      *model.UserSettings   `json:"settings,omitempty"`
	Devices       []*model.Device       `json:"devices"`
	SpeedTests    []*model.SpeedTest    `json:"speed_tests"`
	APITokens     []map[string]any      `json:"api_tokens"`
	Notifications []*model.Notification `json:"notifications,omitempty"`
}

var userDataExportPage = template.Must(template.New("user-data-export").Parse(`<p>{{.Lead}}</p>{{if .Download}}<p role="status"><a href="{{.Download}}">{{.DownloadLabel}}</a></p>{{end}}<h2>{{.DeleteTitle}}</h2><p>{{.DeleteWarning}}</p>{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}<form method="post" action="/users/data/delete"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="delete-username">{{.UsernameLabel}}</label><input id="delete-username" name="confirm_username" autocomplete="username" required><label for="delete-password">{{.PasswordLabel}}</label><input id="delete-password" name="current_password" type="password" autocomplete="current-password" required>{{if .RequireTOTP}}<label for="delete-code">{{.CodeLabel}}</label><input id="delete-code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>{{end}}<button class="btn btn-danger" type="button" popovertarget="delete-account-confirm">{{.DeleteButton}}</button><div id="delete-account-confirm" popover aria-labelledby="delete-account-confirm-title"><h3 id="delete-account-confirm-title">{{.DeleteTitle}}</h3><p>{{.DeleteWarning}}</p><button class="btn btn-secondary" type="button" popovertarget="delete-account-confirm" popovertargetaction="hide">{{.Cancel}}</button><button class="btn btn-danger" type="submit">{{.DeleteButton}}</button></div></form>`))

func (s *Server) handleUserDataExport(w http.ResponseWriter, r *http.Request) {
	identity, err := s.dataRightsIdentity(r)
	if err != nil {
		http.Error(w, "Unable to load account", http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			http.Redirect(w, r, "/server/auth/login?redirect=%2Fusers%2Fdata%2Fexport", http.StatusSeeOther)
			return
		}
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Authentication required"})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/export/"+chi.URLParam(r, "id")) && chi.URLParam(r, "id") != "" {
		s.downloadUserDataExport(w, r, identity.User)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "Method not allowed"})
			return
		}
		id, err := s.createUserDataExport(r.Context(), identity.User)
		if err != nil {
			if errors.Is(err, errUserDataExportRateLimit) {
				writeUserJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "Data export request limit exceeded"})
				return
			}
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to prepare data export"})
			return
		}
		apiPrefix := strings.TrimSuffix(r.URL.Path, "/users/data/export")
		writeUserJSON(w, http.StatusCreated, map[string]any{"ok": true, "data": map[string]any{"id": id, "download_url": apiPrefix + "/users/data/export/" + id, "expires_at": time.Now().UTC().Add(userDataExportTTL)}})
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := s.createUserDataExport(r.Context(), identity.User)
	if err != nil {
		if errors.Is(err, errUserDataExportRateLimit) {
			http.Error(w, "Data export request limit exceeded", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "Unable to prepare data export", http.StatusInternalServerError)
		return
	}
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Data page unavailable", http.StatusInternalServerError)
		return
	}
	csrf := s.issuePreferenceCSRF(w, r)
	errorMessage := ""
	if r.URL.Query().Get("error") == "identity" {
		errorMessage = catalog.T("user_admin.data_identity_failed", nil)
	}
	data := s.userDataRightsLabels(catalog, identity.User, csrf, "/users/data/export/"+id, errorMessage)
	page := publicPageTemplateData{Title: catalog.T("user_admin.data_title", nil), Lead: catalog.T("user_admin.data_lead", nil), NoIndex: true, CSRFToken: csrf, Sections: []renderedPageSection{{ID: "user-data", Title: catalog.T("user_admin.data_title", nil), Content: template.HTML(executeTemplate(userDataExportPage, data))}}}
	s.writePrivateUserPage(w, r, &page)
}

func (s *Server) handleUserDataDelete(w http.ResponseWriter, r *http.Request) {
	identity, err := s.dataRightsIdentity(r)
	if err != nil {
		http.Error(w, "Unable to load account", http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			http.Redirect(w, r, "/server/auth/login?redirect=%2Fusers%2Fdata%2Fexport", http.StatusSeeOther)
			return
		}
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Authentication required"})
		return
	}
	api := strings.HasPrefix(r.URL.Path, "/api/")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		if api {
			writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "Method not allowed"})
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if !api && (!sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r)) {
		http.Error(w, "Account deletion request failed security validation", http.StatusForbidden)
		return
	}
	username, password := strings.TrimSpace(r.FormValue("confirm_username")), r.FormValue("current_password")
	if api {
		var request struct {
			Username string `json:"confirm_username"`
			Password string `json:"current_password"`
			Code     string `json:"code"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&request); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid request"})
			return
		}
		username, password = strings.TrimSpace(request.Username), request.Password
		r = r.WithContext(context.WithValue(r.Context(), userDeletionCodeContextKey{}, request.Code))
	}
	if username != identity.User.Username || !auth.VerifyPassword(password, identity.User.PasswordHash) {
		s.userDataDeleteFailure(w, r, api)
		return
	}
	if identity.User.TOTPEnabled {
		code := r.FormValue("code")
		if api {
			code, _ = r.Context().Value(userDeletionCodeContextKey{}).(string)
		}
		valid, verifyErr := s.verifyUserTOTP(r.Context(), model.UserIDString(identity.User.ID), code)
		if verifyErr != nil || !valid {
			s.userDataDeleteFailure(w, r, api)
			return
		}
	}
	userID := model.UserIDString(identity.User.ID)
	requestID, err := randomOpaqueValue()
	if err != nil {
		if api {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to prepare account deletion"})
		} else {
			http.Error(w, "Unable to prepare account deletion", http.StatusInternalServerError)
		}
		return
	}
	s.auditUserDataEvent("compliance.data_deletion_requested", identity.User.ID, requestID, 0)
	if err := s.Store.DeleteUser(r.Context(), userID); err != nil {
		if api {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to delete account"})
		} else {
			http.Error(w, "Unable to delete account", http.StatusInternalServerError)
		}
		return
	}
	s.purgeUserDataExports(userID)
	s.auditUserDataEvent("compliance.data_deletion_completed", identity.User.ID, requestID, 0)
	if api {
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]string{"status": "deleted"}})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "user_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/server/auth/login?deleted=1", http.StatusSeeOther)
}

type userDeletionCodeContextKey struct{}

func (s *Server) dataRightsIdentity(r *http.Request) (*pageIdentity, error) {
	if identity := pageIdentityFromRequest(r); identity != nil {
		return identity, nil
	}
	if token, ok := r.Context().Value(apiTokenContextKey{}).(apiTokenIdentity); ok {
		if token.Admin || token.UserID == "" {
			return nil, nil
		}
		user, err := s.Store.GetUser(r.Context(), token.UserID)
		if err != nil || user == nil {
			return nil, err
		}
		return &pageIdentity{User: user}, nil
	}
	return s.resolvePageIdentity(r)
}

func (s *Server) createUserDataExport(ctx context.Context, user *model.User) (string, error) {
	userID := model.UserIDString(user.ID)
	now := time.Now().UTC()
	rateKey := userDataExportRateKey{server: s, userID: userID}
	userExports.Lock()
	requests := userExports.requests[rateKey]
	kept := requests[:0]
	for _, requested := range requests {
		if now.Sub(requested) < userDataExportWindow {
			kept = append(kept, requested)
		}
	}
	if len(kept) >= userDataExportThreshold {
		userExports.requests[rateKey] = kept
		lastAlert := userExports.alerts[rateKey]
		alert := lastAlert.IsZero() || now.Sub(lastAlert) >= userDataExportWindow
		if alert {
			userExports.alerts[rateKey] = now
		}
		userExports.Unlock()
		if alert {
			s.auditUserDataEvent("security.mass_data_export", user.ID, "", 0)
			s.alertMassUserDataExport(user.ID)
		}
		return "", errUserDataExportRateLimit
	}
	userExports.requests[rateKey] = append(kept, now)
	userExports.Unlock()
	document := userDataExportDocument{ExportedAt: time.Now().UTC(), Profile: map[string]any{"id": user.ID, "username": user.Username, "email": user.Email, "email_verified": user.EmailVerified, "notification_email": user.NotificationEmail, "notification_email_verified": user.NotificationEmailVerified, "display_name": user.DisplayName, "bio": user.Bio, "location": user.Location, "website": user.Website, "avatar_url": user.AvatarURL, "timezone": user.Timezone, "language": user.Language, "visibility": user.Visibility, "org_visibility": user.OrgVisibility, "role": user.Role, "source": user.Source, "external_id": user.ExternalID, "groups": user.Groups, "last_sync": user.LastSync, "approved": user.Approved, "disabled": user.Disabled, "two_factor_enabled": user.TOTPEnabled, "created_at": user.CreatedAt, "updated_at": user.UpdatedAt, "last_login": user.LastLogin}}
	devices, err := s.Store.GetUserDevices(ctx, userID)
	if err != nil {
		return "", err
	}
	document.Devices = devices
	for offset := 0; ; offset += 500 {
		page, err := s.Store.GetUserSpeedTests(ctx, userID, 500, offset)
		if err != nil {
			return "", err
		}
		document.SpeedTests = append(document.SpeedTests, page...)
		if len(page) < 500 {
			break
		}
	}
	if settingsStore, ok := s.Store.(store.UserSettingsStore); ok {
		document.Settings, err = settingsStore.GetOrCreateUserSettings(ctx, userID)
		if err != nil {
			return "", err
		}
	}
	tokens, err := s.Store.GetUserAPITokens(ctx, userID)
	if err != nil {
		return "", err
	}
	document.APITokens = make([]map[string]any, 0, len(tokens))
	for _, token := range tokens {
		document.APITokens = append(document.APITokens, map[string]any{"id": token.ID, "name": token.Name, "scope": token.Scope, "token_prefix": token.TokenPrefix, "created_at": token.CreatedAt, "last_used": token.LastUsed, "expires_at": token.ExpiresAt})
	}
	if notifications, ok := s.Store.(store.UserNotificationStore); ok {
		document.Notifications, err = notifications.GetUserNotifications(ctx, userID, 10000)
		if err != nil {
			return "", err
		}
	}
	payload, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", err
	}
	id, err := randomOpaqueValue()
	if err != nil {
		return "", err
	}
	userExports.Lock()
	for key, entry := range userExports.entries {
		if !entry.expires.After(now) {
			delete(userExports.entries, key)
		}
	}
	userExports.entries[userDataExportKey{server: s, id: id}] = userDataExport{ownerID: userID, payload: payload, expires: now.Add(userDataExportTTL)}
	userExports.Unlock()
	s.auditUserDataEvent("compliance.data_export_requested", user.ID, id, len(payload))
	return id, nil
}

func (s *Server) alertMassUserDataExport(userID int64) {
	if s.EmailService == nil || !s.EmailService.Available() || s.Config == nil {
		return
	}
	recipient := strings.TrimSpace(s.Config.Server.Contact.Admin.Email)
	if recipient == "" {
		return
	}
	if err := s.EmailService.SendMessage(recipient, "", "High data export request volume", "A user account exceeded the configured data export request threshold. User ID: "+model.UserIDString(userID)+". Review the audit log."); err != nil && s.Logger != nil && s.Logger.Error != nil {
		s.Logger.Error.Printf("mass data export alert delivery failed for user_id=%d: %v\n", userID, err)
	}
}

func (s *Server) downloadUserDataExport(w http.ResponseWriter, r *http.Request, user *model.User) {
	id := chi.URLParam(r, "id")
	key := userDataExportKey{server: s, id: id}
	userExports.Lock()
	export, ok := userExports.entries[key]
	if ok && !export.expires.After(time.Now()) {
		delete(userExports.entries, key)
		ok = false
	}
	if ok && export.ownerID != model.UserIDString(user.ID) {
		ok = false
	}
	userExports.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="casspeed-data-export.json"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(export.payload); err != nil {
		return
	}
	s.auditUserDataEvent("compliance.data_export_completed", user.ID, id, len(export.payload))
}

func (s *Server) purgeUserDataExports(userID string) {
	userExports.Lock()
	for key, export := range userExports.entries {
		if key.server == s && export.ownerID == userID {
			delete(userExports.entries, key)
		}
	}
	delete(userExports.requests, userDataExportRateKey{server: s, userID: userID})
	delete(userExports.alerts, userDataExportRateKey{server: s, userID: userID})
	userExports.Unlock()
}

func (s *Server) userDataDeleteFailure(w http.ResponseWriter, r *http.Request, api bool) {
	if api {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Identity confirmation failed"})
		return
	}
	http.Redirect(w, r, "/users/data/export?error=identity", http.StatusSeeOther)
}

func (s *Server) userDataRightsLabels(catalog *i18n.Catalog, user *model.User, csrf, download, errorMessage string) map[string]any {
	return map[string]any{"Lead": catalog.T("user_admin.data_lead", nil), "Download": download, "DownloadLabel": catalog.T("user_admin.data_download", nil), "DeleteTitle": catalog.T("user_admin.data_delete_title", nil), "DeleteWarning": catalog.T("user_admin.data_delete_warning", nil), "Error": errorMessage, "CSRF": csrf, "UsernameLabel": catalog.T("user_admin.data_confirm_username", nil), "PasswordLabel": catalog.T("user_admin.data_confirm_password", nil), "CodeLabel": catalog.T("user_admin.data_confirm_code", nil), "RequireTOTP": user.TOTPEnabled, "DeleteButton": catalog.T("user_admin.data_delete_button", nil), "Cancel": catalog.T("common.cancel", nil)}
}

func (s *Server) auditUserDataEvent(event string, userID int64, requestID string, size int) {
	if s.Logger == nil || s.Logger.Audit == nil {
		return
	}
	entry, err := json.Marshal(map[string]any{"event": event, "user_id": userID, "request_id": requestID, "file_size": size, "timestamp": time.Now().UTC().Format(time.RFC3339Nano)})
	if err == nil {
		s.Logger.Audit.Printf("%s\n", entry)
	}
}
