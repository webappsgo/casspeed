package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/admin"
	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
)

const loginCSRFCookie = "casspeed_login_csrf"

var sharedLoginFormTemplate = template.Must(template.New("shared-login-form").Parse(`{{if .Info}}<p class="alert alert-success" role="status">{{.Info}}</p>{{end}}<form action="/server/auth/login" method="post"><input type="hidden" name="csrf_token" value="{{.LoginCSRFToken}}"><input type="hidden" name="redirect" value="{{.Redirect}}">{{if .Error}}<p class="alert alert-danger" role="alert">{{.Error}}</p>{{end}}<div class="form-group"><label for="username">{{.Username}}</label><input class="form-input" id="username" name="username" autocomplete="username" required></div><div class="form-group"><label for="password">{{.Password}}</label><input class="form-input" id="password" name="password" type="password" autocomplete="current-password" required></div><div class="form-group"><label><input type="checkbox" name="remember"> {{.Remember}}</label></div><button class="btn btn-primary" type="submit">{{.SignIn}}</button></form><p><a href="/server/auth/passkey">{{.Passkey}}</a></p><p><a href="/server/auth/password/forgot">{{.Forgot}}</a></p>{{if .Register}}<p><a href="/server/auth/register">{{.Register}}</a></p>{{end}}`))

func serverAuthText(r *http.Request, key string) string {
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		catalog, _ = i18n.Resolve("en")
	}
	return catalog.T(key, nil)
}

func serverAuthError(w http.ResponseWriter, r *http.Request, status int, key string) {
	http.Error(w, serverAuthText(r, key), status)
}

func (s *Server) onlyOpenRegistration(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Config == nil || !s.Config.Server.Users.Enabled || s.Config.Server.Users.Registration.Mode != "open" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleSharedLogin(w http.ResponseWriter, r *http.Request) {
	if !admin.IsSetupComplete() {
		s.pageShellHandler(http.HandlerFunc(s.AdminHandler.Login)).ServeHTTP(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.renderSharedLogin(w, r, http.StatusOK, "")
	case http.MethodPost:
		if !sameOriginPageRequest(r) || !validLoginCSRF(r) {
			s.renderPrivatePageError(w, r, http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			s.renderSharedLogin(w, r, http.StatusBadRequest, serverAuthText(r, "errors.http_400_message"))
			return
		}
		identifier := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		if identifier == "" || password == "" {
			s.recordFailedAuthentication(r)
			s.renderSharedLogin(w, r, http.StatusUnauthorized, serverAuthText(r, "auth.pages.invalid_credentials"))
			return
		}
		if s.loginAdmin(w, r, identifier, password) {
			return
		}
		if s.Config != nil && s.Config.Server.Users.Enabled && s.loginUser(w, r, identifier, password) {
			return
		}
		s.recordFailedAuthentication(r)
		s.renderSharedLogin(w, r, http.StatusUnauthorized, serverAuthText(r, "auth.pages.invalid_credentials"))
	default:
		w.Header().Set("Allow", "GET, POST")
		s.renderPrivatePageError(w, r, http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderSharedLogin(w http.ResponseWriter, r *http.Request, status int, message string) {
	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(csrfBytes); err != nil {
		serverAuthError(w, r, http.StatusInternalServerError, "errors.http_500_message")
		return
	}
	csrfToken := base64.RawURLEncoding.EncodeToString(csrfBytes)
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookie, Value: csrfToken, Path: prefixPagePath(requestPathPrefix(r), "/server/auth/login"), MaxAge: 600, HttpOnly: false, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	redirect := safeUserLoginRedirect(r.URL.Query().Get("redirect"))
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		serverAuthError(w, r, http.StatusInternalServerError, "errors.http_500_message")
		return
	}
	content := executeTemplate(sharedLoginFormTemplate, map[string]string{
		"LoginCSRFToken": csrfToken, "Redirect": redirect, "Error": message,
		"Info": func() string {
			switch r.URL.Query().Get("registered") {
			case "1":
				if s.UserHandler != nil && s.UserHandler.RequiresEmailVerification() {
					return catalog.T("auth.check_email", nil)
				}
				return catalog.T("auth.registration_complete", nil)
			}
			if r.URL.Query().Get("verified") == "1" {
				return catalog.T("auth.email_verified_notice", nil)
			}
			return ""
		}(),
		"Username": catalog.T("auth.username", nil), "Password": catalog.T("auth.password", nil),
		"Remember": catalog.T("auth.remember_me", nil), "SignIn": catalog.T("auth.sign_in", nil),
		"Forgot": catalog.T("auth.forgot_password", nil), "Passkey": catalog.T("auth.passkey_sign_in", nil),
		"Register": func() string {
			if s.Config != nil && s.Config.Server.Users.Enabled && s.Config.Server.Users.Registration.Mode == "open" {
				return catalog.T("auth.register", nil)
			}
			return ""
		}(),
	})
	page := publicPageTemplateData{
		Title: catalog.T("auth.sign_in", nil), Lead: catalog.T("auth.login_lead", nil), NoIndex: true,
		Sections: []renderedPageSection{{ID: "sign-in", Title: catalog.T("auth.sign_in", nil), Content: template.HTML(content)}},
	}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		serverAuthError(w, r, http.StatusInternalServerError, "errors.http_500_message")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pageTemplate.Execute(w, page); err != nil {
		return
	}
}

func validLoginCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(loginCSRFCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	provided := r.FormValue("csrf_token")
	return len(provided) == len(cookie.Value) && subtle.ConstantTimeCompare([]byte(provided), []byte(cookie.Value)) == 1
}

func (s *Server) loginAdmin(w http.ResponseWriter, r *http.Request, username, password string) bool {
	account, err := s.Store.GetAdminByUsername(r.Context(), username)
	if err != nil || account == nil || !account.Enabled {
		return false
	}
	if !account.LockedUntil.IsZero() && time.Now().Before(account.LockedUntil) {
		return false
	}
	if !admin.VerifyPassword(password, account.Password) {
		attempts := account.FailedAttempts + 1
		_ = s.Store.UpdateAdminFailedAttempts(r.Context(), account.ID, attempts)
		if attempts >= 5 {
			_ = s.Store.LockAdmin(r.Context(), account.ID, time.Now().Add(15*time.Minute))
		}
		return false
	}
	if totpStore, ok := s.Store.(store.AdminTOTPStore); ok {
		totp, loadErr := totpStore.GetAdminTOTP(r.Context(), account.ID)
		if loadErr != nil {
			serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.security_verify_failed")
			return true
		}
		if totp != nil && totp.Enabled {
			partialToken, challengeErr := s.createPartialAuthentication(r.Context(), strconv.Itoa(account.ID), "admin", r.FormValue("remember") == "on")
			if challengeErr != nil {
				serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.challenge_failed")
				return true
			}
			clearLoginCSRFCookie(w, r)
			http.SetCookie(w, &http.Cookie{Name: "partial_session", Value: partialToken, Path: prefixPagePath(requestPathPrefix(r), "/server/auth"), MaxAge: 300, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/auth/2fa"), http.StatusSeeOther)
			return true
		}
	}
	if s.hasActivePasskey(r.Context(), "admin", strconv.Itoa(account.ID)) {
		partialToken, challengeErr := s.createPartialAuthentication(r.Context(), strconv.Itoa(account.ID), "admin", r.FormValue("remember") == "on")
		if challengeErr != nil {
			serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.challenge_failed")
			return true
		}
		clearLoginCSRFCookie(w, r)
		http.SetCookie(w, &http.Cookie{Name: "partial_session", Value: partialToken, Path: prefixPagePath(requestPathPrefix(r), "/server/auth"), MaxAge: 300, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/auth/2fa"), http.StatusSeeOther)
		return true
	}
	if err := s.Store.UpdateAdminLastLogin(r.Context(), account.ID); err != nil {
		return false
	}
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.session_create_failed")
		return true
	}
	sessionID := base64.RawURLEncoding.EncodeToString(sessionIDBytes)
	adminSessionLength := 8 * time.Hour
	if r.FormValue("remember") == "on" {
		adminSessionLength = 30 * 24 * time.Hour
	}
	session := &model.AdminSession{ID: sessionID, AdminID: account.ID, IPAddress: peerIP(r.RemoteAddr), UserAgent: r.UserAgent(), ExpiresAt: time.Now().Add(adminSessionLength)}
	if err := s.Store.CreateAdminSession(r.Context(), session); err != nil {
		serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.session_create_failed")
		return true
	}
	clearLoginCSRFCookie(w, r)
	http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: sessionID, Path: prefixPagePath(requestPathPrefix(r), "/"), Expires: session.ExpiresAt, MaxAge: int(adminSessionLength.Seconds()), HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	adminPath := strings.Trim(s.Config.Server.AdminPath, "/")
	if adminPath == "" {
		adminPath = "administration"
	}
	http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/"+adminPath), http.StatusSeeOther)
	return true
}

func (s *Server) loginUser(w http.ResponseWriter, r *http.Request, identifier, password string) bool {
	user, err := s.Store.GetUserByUsername(r.Context(), identifier)
	if err != nil {
		return false
	}
	if user == nil && strings.Contains(identifier, "@") {
		user, err = s.Store.GetUserByEmail(r.Context(), identifier)
		if err != nil {
			return false
		}
	}
	if user == nil || user.Disabled || !user.Approved || !user.EmailVerified || !auth.VerifyPassword(password, user.PasswordHash) {
		return false
	}
	if totpStore, ok := s.Store.(store.UserTOTPStore); ok {
		userID := model.UserIDString(user.ID)
		totp, loadErr := totpStore.GetUserTOTP(r.Context(), userID)
		if loadErr != nil {
			serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.security_verify_failed")
			return true
		}
		if totp != nil && totp.Enabled {
			partialToken, challengeErr := s.createPartialAuthentication(r.Context(), userID, "user", r.FormValue("remember") == "on")
			if challengeErr != nil {
				serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.challenge_failed")
				return true
			}
			clearLoginCSRFCookie(w, r)
			http.SetCookie(w, &http.Cookie{Name: "partial_session", Value: partialToken, Path: prefixPagePath(requestPathPrefix(r), "/server/auth"), MaxAge: 300, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/auth/2fa"), http.StatusSeeOther)
			return true
		}
	}
	if s.hasActivePasskey(r.Context(), "user", model.UserIDString(user.ID)) {
		partialToken, challengeErr := s.createPartialAuthentication(r.Context(), model.UserIDString(user.ID), "user", r.FormValue("remember") == "on")
		if challengeErr != nil {
			serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.challenge_failed")
			return true
		}
		clearLoginCSRFCookie(w, r)
		http.SetCookie(w, &http.Cookie{Name: "partial_session", Value: partialToken, Path: prefixPagePath(requestPathPrefix(r), "/server/auth"), MaxAge: 300, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/auth/2fa"), http.StatusSeeOther)
		return true
	}
	userID := model.UserIDString(user.ID)
	session := auth.NewSession(userID, peerIP(r.RemoteAddr), r.UserAgent())
	if r.FormValue("remember") == "on" {
		session.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	}
	if err := s.Store.CreateSession(r.Context(), &model.Session{ID: session.ID, UserID: session.UserID, ExpiresAt: session.ExpiresAt, CreatedAt: session.CreatedAt}); err != nil {
		serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.session_create_failed")
		return true
	}
	if err := s.Store.UpdateUserLastLogin(r.Context(), userID, time.Now().UTC()); err != nil {
		serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.login_complete_failed")
		return true
	}
	if err := s.createUserNotification(r.Context(), userID, "security", "notifications.session_started", "notifications.session_started_message", "/users/security"); err != nil {
		log.Printf("user session notification failed: %v", err)
	}
	clearLoginCSRFCookie(w, r)
	http.SetCookie(w, &http.Cookie{Name: "user_session", Value: session.ID, Path: prefixPagePath(requestPathPrefix(r), "/"), Expires: session.ExpiresAt, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	redirect := safeUserLoginRedirect(r.FormValue("redirect"))
	if redirect == "" {
		redirect = "/users"
	}
	http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), redirect), http.StatusSeeOther)
	return true
}

func clearLoginCSRFCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookie, Value: "", Path: prefixPagePath(requestPathPrefix(r), "/server/auth/login"), MaxAge: -1, HttpOnly: false, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
}

func safeUserLoginRedirect(value string) string {
	if (value == "/users" || strings.HasPrefix(value, "/users/")) && !strings.ContainsAny(value, "\\\r\n") {
		return value
	}
	return ""
}

func (s *Server) handleSharedLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		serverAuthError(w, r, http.StatusMethodNotAllowed, "auth.pages.method_not_allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		serverAuthError(w, r, http.StatusBadRequest, "auth.pages.logout_invalid")
		return
	}
	if cookie, err := r.Cookie("admin_session"); err == nil && cookie.Value != "" {
		if !validSessionCSRF(cookie.Value, r.FormValue("csrf_token")) {
			serverAuthError(w, r, http.StatusForbidden, "auth.pages.csrf_invalid")
			return
		}
		if err := s.Store.DeleteAdminSession(r.Context(), cookie.Value); err != nil {
			serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.session_end_failed")
			return
		}
	}
	if cookie, err := r.Cookie("user_session"); err == nil && cookie.Value != "" {
		if !validSessionCSRF(cookie.Value, r.FormValue("csrf_token")) {
			serverAuthError(w, r, http.StatusForbidden, "auth.pages.csrf_invalid")
			return
		}
		if err := s.Store.DeleteSession(r.Context(), cookie.Value); err != nil {
			serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.session_end_failed")
			return
		}
	}
	for _, name := range []string{"admin_session", "user_session"} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: prefixPagePath(requestPathPrefix(r), "/"), MaxAge: -1, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	}
	http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/auth/login"), http.StatusSeeOther)
}

func validSessionCSRF(sessionID, provided string) bool {
	return len(sessionID) > 0 && len(sessionID) == len(provided) && subtle.ConstantTimeCompare([]byte(sessionID), []byte(provided)) == 1
}
