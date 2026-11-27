package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

type UserHandler struct {
	store                store.Store
	buildURL             func(*http.Request, string) string
	registerPageRenderer func(http.ResponseWriter, *http.Request, string, string, int)
	languageAllowed      func(string) bool
	verificationRequired bool
	verificationSender   func(*http.Request, string, string) error
	allowedEmailDomains  []string
	blockedEmailDomains  []string
	defaultRole          string
	passwordValidator    func(string) error
}

const registerCSRFCookie = "casspeed_register_csrf"

type registerPageData struct {
	CSRFToken                                                   string
	Error                                                       string
	Lang, Dir, BasePath                                         string
	Title, Lead, Skip, Username, Email, Password, Submit, Login string
}

var registerPageTemplate = template.Must(template.New("register").Parse(`<!doctype html>
<html lang="{{.Lang}}" dir="{{.Dir}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{{.Title}} — CasSpeed</title><link rel="stylesheet" href="{{.BasePath}}/static/css/theme-dark.css"><link rel="stylesheet" href="{{.BasePath}}/static/css/theme-light.css"><link rel="stylesheet" href="{{.BasePath}}/static/css/style.css"><script src="{{.BasePath}}/static/js/theme.js" defer></script></head>
<body><a class="skip-link" href="#main-content">{{.Skip}}</a><main id="main-content" class="container container-sm"><header class="page-header"><h1 class="page-title">{{.Title}}</h1><p class="page-lead">{{.Lead}}</p></header><section class="section-card">{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}<form method="post" action="{{.BasePath}}/server/auth/register"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><div class="form-group"><label for="username">{{.Username}}</label><input id="username" name="username" type="text" autocomplete="username" minlength="2" maxlength="39" required></div><div class="form-group"><label for="email">{{.Email}}</label><input id="email" name="email" type="email" autocomplete="email" required></div><div class="form-group"><label for="password">{{.Password}}</label><input id="password" name="password" type="password" autocomplete="new-password" minlength="8" required></div><button type="submit">{{.Submit}}</button></form><p><a href="{{.BasePath}}/server/auth/login">{{.Login}}</a></p></section></main></body></html>`))

func NewUserHandler(st store.Store) *UserHandler {
	return &UserHandler{store: st, defaultRole: "user"}
}

// SetDefaultRole applies the configured role to newly registered users.
func (h *UserHandler) SetDefaultRole(role string) {
	if role != "" {
		h.defaultRole = role
	}
}

// SetPasswordValidator applies the configured account password policy.
func (h *UserHandler) SetPasswordValidator(validate func(string) error) {
	h.passwordValidator = validate
}

func (h *UserHandler) validatePassword(password string) error {
	if h.passwordValidator != nil {
		return h.passwordValidator(password)
	}
	return auth.ValidatePassword(password)
}

// SetRegisterPageRenderer installs the server's shared-shell renderer for browser registration.
func (h *UserHandler) SetRegisterPageRenderer(render func(http.ResponseWriter, *http.Request, string, string, int)) {
	h.registerPageRenderer = render
}

// SetURLBuilder applies the configured reverse-proxy path prefix to local URLs.
func (h *UserHandler) SetURLBuilder(build func(*http.Request, string) string) { h.buildURL = build }

// SetLanguageValidator applies the server's configured locale allowlist to profile updates.
func (h *UserHandler) SetLanguageValidator(allowed func(string) bool) { h.languageAllowed = allowed }

// SetEmailVerification configures one-time account verification while SMTP is available.
func (h *UserHandler) SetEmailVerification(required bool, send func(*http.Request, string, string) error) {
	h.verificationRequired = required && send != nil
	h.verificationSender = send
}

// RequiresEmailVerification reports whether registration currently waits for a verified address.
func (h *UserHandler) RequiresEmailVerification() bool { return h != nil && h.verificationRequired }

// SetRegistrationEmailDomains applies the server's open-registration domain policy.
func (h *UserHandler) SetRegistrationEmailDomains(allowed, blocked []string) {
	h.allowedEmailDomains = append([]string(nil), allowed...)
	h.blockedEmailDomains = append([]string(nil), blocked...)
}

func (h *UserHandler) emailDomainAllowed(address string) bool {
	separator := strings.LastIndexByte(address, '@')
	if separator < 1 || separator == len(address)-1 {
		return false
	}
	domain := strings.ToLower(strings.TrimSuffix(address[separator+1:], "."))
	for _, blocked := range h.blockedEmailDomains {
		if strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(blocked), "@"), domain) {
			return false
		}
	}
	if len(h.allowedEmailDomains) == 0 {
		return true
	}
	for _, allowed := range h.allowedEmailDomains {
		if strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(allowed), "@"), domain) {
			return true
		}
	}
	return false
}

func (h *UserHandler) finishRegistration(r *http.Request, user *model.User) error {
	if user.Role == "" {
		user.Role = h.defaultRole
	}
	if user.Source == "" {
		user.Source = "local"
	}
	user.Approved = true
	user.EmailVerified = !h.verificationRequired
	if err := h.store.CreateUser(r.Context(), user); err != nil {
		return err
	}
	if !h.verificationRequired {
		return nil
	}
	tokens, ok := h.store.(store.EmailVerificationStore)
	if !ok {
		_ = h.store.DeleteUser(r.Context(), model.UserIDString(user.ID))
		return fmt.Errorf("email verification storage is unavailable")
	}
	token, err := randomHex(32)
	if err != nil {
		_ = h.store.DeleteUser(r.Context(), model.UserIDString(user.ID))
		return err
	}
	digest := sha256.Sum256([]byte(token))
	if err := tokens.CreateEmailVerification(r.Context(), model.UserIDString(user.ID), hex.EncodeToString(digest[:]), time.Now().UTC().Add(48*time.Hour)); err != nil {
		if deleteErr := h.store.DeleteUser(r.Context(), model.UserIDString(user.ID)); deleteErr != nil {
			return fmt.Errorf("create verification and roll back account: %v; %w", err, deleteErr)
		}
		return err
	}
	if err := h.verificationSender(r, user.Email, token); err != nil {
		if deleteErr := h.store.DeleteUser(r.Context(), model.UserIDString(user.ID)); deleteErr != nil {
			return fmt.Errorf("send verification and roll back account: %v; %w", err, deleteErr)
		}
		return err
	}
	return nil
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	catalog := handlerCatalog(r)
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeUserError(w, http.StatusBadRequest, "INVALID_REQUEST", catalog.T("auth.pages.invalid_request", nil))
		return
	}
	if err := auth.ValidateUsername(req.Username); err != nil {
		writeUserError(w, http.StatusBadRequest, "INVALID_USERNAME", catalog.T("auth.register_failed", nil))
		return
	}
	if err := auth.ValidateEmail(req.Email); err != nil {
		writeUserError(w, http.StatusBadRequest, "INVALID_EMAIL", catalog.T("auth.register_failed", nil))
		return
	}
	if !h.emailDomainAllowed(req.Email) {
		writeUserError(w, http.StatusBadRequest, "EMAIL_DOMAIN_NOT_ALLOWED", catalog.T("auth.pages.email_domain_denied", nil))
		return
	}
	if err := h.validatePassword(req.Password); err != nil {
		writeUserError(w, http.StatusBadRequest, "INVALID_PASSWORD", catalog.T("auth.password_requirements", nil))
		return
	}
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", catalog.T("auth.pages.account_create_failed", nil))
		return
	}
	user := &model.User{Username: req.Username, Email: req.Email, PasswordHash: passwordHash, CreatedAt: time.Now().UTC()}
	if err := h.finishRegistration(r, user); err != nil {
		writeUserError(w, http.StatusConflict, "REGISTRATION_FAILED", catalog.T("auth.register_failed", nil))
		return
	}
	writeUserJSON(w, http.StatusCreated, map[string]interface{}{"ok": true, "data": map[string]any{"id": user.ID, "username": user.Username, "email": user.Email, "email_verified": user.EmailVerified}})
}

// RegisterPage handles the CSRF-protected browser registration form.
func (h *UserHandler) RegisterPage(w http.ResponseWriter, r *http.Request) {
	catalog := handlerCatalog(r)
	switch r.Method {
	case http.MethodGet:
		h.renderRegisterPage(w, r, http.StatusOK, "")
	case http.MethodPost:
		if !sameOriginFormRequest(r) || !validRegisterCSRF(r) {
			http.Error(w, catalog.T("auth.pages.registration_security", nil), http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			h.renderRegisterPage(w, r, http.StatusBadRequest, catalog.T("auth.pages.registration_input", nil))
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		email := strings.TrimSpace(r.FormValue("email"))
		password := r.FormValue("password")
		if err := auth.ValidateUsername(username); err != nil {
			h.renderRegisterPage(w, r, http.StatusBadRequest, catalog.T("auth.register_failed", nil))
			return
		}
		if err := auth.ValidateEmail(email); err != nil {
			h.renderRegisterPage(w, r, http.StatusBadRequest, catalog.T("auth.register_failed", nil))
			return
		}
		if !h.emailDomainAllowed(email) {
			h.renderRegisterPage(w, r, http.StatusBadRequest, catalog.T("auth.pages.email_domain_denied", nil))
			return
		}
		if err := h.validatePassword(password); err != nil {
			h.renderRegisterPage(w, r, http.StatusBadRequest, catalog.T("auth.password_requirements", nil))
			return
		}
		passwordHash, err := auth.HashPassword(password)
		if err != nil {
			h.renderRegisterPage(w, r, http.StatusInternalServerError, catalog.T("auth.pages.account_create_failed", nil))
			return
		}
		user := &model.User{Username: username, Email: email, PasswordHash: passwordHash, CreatedAt: time.Now().UTC()}
		if err := h.finishRegistration(r, user); err != nil {
			h.renderRegisterPage(w, r, http.StatusConflict, catalog.T("auth.register_failed", nil))
			return
		}
		h.clearRegisterCSRFCookie(w, r)
		http.Redirect(w, r, handlerPrefixPath(handlerPathPrefix(r, h.buildURL), "/server/auth/login?registered=1"), http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, catalog.T("auth.pages.method_not_allowed", nil), http.StatusMethodNotAllowed)
	}
}

// VerifyEmail consumes a single-use verification token sent to a registered user's address.
func (h *UserHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	catalog := handlerCatalog(r)
	token := ""
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var request struct {
			Token string `json:"token"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err == nil {
			token = request.Token
		}
	} else if r.ParseForm() == nil {
		token = r.FormValue("token")
	}
	if len(token) < 32 || len(token) > 256 {
		if r.Header.Get("Accept") == "text/html" || strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			http.Error(w, catalog.T("auth.pages.verification_invalid", nil), http.StatusBadRequest)
			return
		}
		writeUserError(w, http.StatusBadRequest, "INVALID_TOKEN", catalog.T("auth.pages.verification_invalid", nil))
		return
	}
	tokens, ok := h.store.(store.EmailVerificationStore)
	if !ok {
		writeUserError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", catalog.T("auth.pages.verification_unavailable", nil))
		return
	}
	digest := sha256.Sum256([]byte(token))
	verified, err := tokens.VerifyEmailAddress(r.Context(), hex.EncodeToString(digest[:]), time.Now().UTC())
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", catalog.T("auth.pages.verification_failed", nil))
		return
	}
	if !verified {
		writeUserError(w, http.StatusBadRequest, "INVALID_TOKEN", catalog.T("auth.pages.verification_invalid", nil))
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		http.Redirect(w, r, handlerPrefixPath(handlerPathPrefix(r, h.buildURL), "/server/auth/login?verified=1"), http.StatusSeeOther)
		return
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]bool{"email_verified": true}})
}

// UpdateEmail requests an account or notification address change for the authenticated user.
func (h *UserHandler) UpdateEmail(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	var request struct {
		Type            string `json:"type"`
		Email           string `json:"email"`
		CurrentPassword string `json:"current_password"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Type != "account" && request.Type != "notification" {
		writeUserError(w, http.StatusBadRequest, "INVALID_REQUEST", handlerCatalog(r).T("home.api_errors.email_settings_invalid", nil))
		return
	}
	user, err := h.store.GetUser(r.Context(), userID)
	if err != nil || user == nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.account_load_failed", nil))
		return
	}
	if request.Type == "account" && !auth.VerifyPassword(request.CurrentPassword, user.PasswordHash) {
		writeUserError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", handlerCatalog(r).T("home.api_errors.current_password_invalid", nil))
		return
	}
	newEmail := strings.TrimSpace(request.Email)
	if newEmail != "" {
		if err := auth.ValidateEmail(newEmail); err != nil {
			writeUserError(w, http.StatusBadRequest, "INVALID_EMAIL", handlerCatalog(r).T("home.api_errors.email_invalid", nil))
			return
		}
		newEmail = strings.ToLower(newEmail)
		existing, lookupErr := h.store.GetUserByEmail(r.Context(), newEmail)
		if lookupErr != nil {
			writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.email_validate_failed", nil))
			return
		}
		if existing != nil && existing.ID != user.ID {
			writeUserError(w, http.StatusConflict, "EMAIL_IN_USE", handlerCatalog(r).T("home.api_errors.email_in_use", nil))
			return
		}
	}
	if request.Type == "account" {
		if newEmail == "" {
			writeUserError(w, http.StatusBadRequest, "INVALID_EMAIL", handlerCatalog(r).T("home.api_errors.account_email_empty", nil))
			return
		}
		if strings.EqualFold(newEmail, user.Email) {
			writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]string{"status": "unchanged"}})
			return
		}
	} else if newEmail != "" && strings.EqualFold(newEmail, user.Email) {
		newEmail = ""
	}
	if !h.verificationRequired {
		if request.Type == "account" {
			user.Email, user.EmailVerified = newEmail, true
		} else {
			user.NotificationEmail, user.NotificationEmailVerified = newEmail, true
		}
		if err := h.store.UpdateUser(r.Context(), user); err != nil {
			writeUserError(w, http.StatusConflict, "EMAIL_UPDATE_FAILED", handlerCatalog(r).T("home.api_errors.email_update_failed", nil))
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]string{"status": "updated"}})
		return
	}
	if newEmail == "" && request.Type == "notification" {
		user.NotificationEmail, user.NotificationEmailVerified = "", true
		if err := h.store.UpdateUser(r.Context(), user); err != nil {
			writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.email_update_failed", nil))
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]string{"status": "removed"}})
		return
	}
	tokens, ok := h.store.(store.EmailVerificationStore)
	if !ok {
		writeUserError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", handlerCatalog(r).T("home.api_errors.verification_unavailable", nil))
		return
	}
	token, err := randomHex(32)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.email_change_prepare_failed", nil))
		return
	}
	digest := sha256.Sum256([]byte(token))
	purpose := "notification_change"
	if request.Type == "account" {
		purpose = "account_change"
	}
	if err := tokens.CreatePendingEmailVerification(r.Context(), userID, hex.EncodeToString(digest[:]), newEmail, purpose, time.Now().UTC().Add(48*time.Hour)); err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.email_change_prepare_failed", nil))
		return
	}
	if h.verificationSender == nil || h.verificationSender(r, newEmail, token) != nil {
		writeUserError(w, http.StatusServiceUnavailable, "EMAIL_UNAVAILABLE", handlerCatalog(r).T("home.api_errors.verification_send_failed", nil))
		return
	}
	writeUserJSON(w, http.StatusAccepted, map[string]any{"ok": true, "data": map[string]string{"status": "verification_sent"}})
}

func (h *UserHandler) renderRegisterPage(w http.ResponseWriter, r *http.Request, status int, message string) {
	catalog := handlerCatalog(r)
	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(csrfBytes); err != nil {
		http.Error(w, catalog.T("auth.pages.account_create_failed", nil), http.StatusInternalServerError)
		return
	}
	csrfToken := hex.EncodeToString(csrfBytes)
	prefix := handlerPathPrefix(r, h.buildURL)
	http.SetCookie(w, &http.Cookie{Name: registerCSRFCookie, Value: csrfToken, Path: handlerPrefixPath(prefix, "/server/auth/register"), MaxAge: 600, HttpOnly: false, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	if h.registerPageRenderer != nil {
		h.registerPageRenderer(w, r, csrfToken, message, status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(status)
	_ = registerPageTemplate.Execute(w, registerPageData{
		CSRFToken: csrfToken, Error: message, Lang: catalog.Meta.Language, Dir: catalog.Meta.Direction, BasePath: prefix,
		Title: catalog.T("auth.pages.register_title", nil), Lead: catalog.T("auth.pages.register_lead", nil),
		Skip: catalog.T("nav.skip_to_content", nil), Username: catalog.T("auth.pages.username", nil),
		Email: catalog.T("auth.pages.email", nil), Password: catalog.T("auth.password", nil),
		Submit: catalog.T("auth.pages.create_account", nil), Login: catalog.T("auth.pages.already_account", nil),
	})
}

func validRegisterCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(registerCSRFCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	provided := r.FormValue("csrf_token")
	return len(provided) == len(cookie.Value) && subtle.ConstantTimeCompare([]byte(provided), []byte(cookie.Value)) == 1
}

func (h *UserHandler) clearRegisterCSRFCookie(w http.ResponseWriter, r *http.Request) {
	path := handlerPrefixPath(handlerPathPrefix(r, h.buildURL), "/server/auth/register")
	http.SetCookie(w, &http.Cookie{Name: registerCSRFCookie, Value: "", Path: path, MaxAge: -1, HttpOnly: false, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	userID := h.currentUserID(r)
	if userID == "" {
		writeUserError(w, http.StatusUnauthorized, "UNAUTHORIZED", handlerCatalog(r).T("home.api_errors.auth_required", nil))
		return
	}
	user, err := h.store.GetUser(r.Context(), userID)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.profile_load_failed", nil))
		return
	}
	if user == nil {
		writeUserError(w, http.StatusNotFound, "NOT_FOUND", handlerCatalog(r).T("home.api_errors.profile_not_found", nil))
		return
	}
	writeUserJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "data": user})
}

// UpdateProfile applies an authenticated user's own public and private profile fields.
func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	var request struct {
		DisplayName       string `json:"display_name"`
		Bio               string `json:"bio"`
		Location          string `json:"location"`
		Website           string `json:"website"`
		Timezone          string `json:"timezone"`
		Language          string `json:"language"`
		Visibility        string `json:"visibility"`
		OrgVisibility     *bool  `json:"org_visibility"`
		ShareShowUsername *bool  `json:"share_show_username"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeUserError(w, http.StatusBadRequest, "INVALID_REQUEST", handlerCatalog(r).T("home.api_errors.profile_update_invalid", nil))
		return
	}
	user, err := h.store.GetUser(r.Context(), userID)
	if err != nil || user == nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.profile_load_failed", nil))
		return
	}
	user.DisplayName, user.Bio, user.Location = strings.TrimSpace(request.DisplayName), strings.TrimSpace(request.Bio), strings.TrimSpace(request.Location)
	user.Website, user.Timezone, user.Language = strings.TrimSpace(request.Website), strings.TrimSpace(request.Timezone), strings.TrimSpace(request.Language)
	if user.DisplayName == "" {
		user.DisplayName = user.Username
	}
	if utf8.RuneCountInString(user.DisplayName) > 100 || utf8.RuneCountInString(user.Bio) > 500 || utf8.RuneCountInString(user.Location) > 100 || len(user.Website) > 2048 {
		writeUserError(w, http.StatusBadRequest, "VALIDATION_FAILED", handlerCatalog(r).T("home.api_errors.profile_limits", nil))
		return
	}
	if user.Website != "" {
		parsed, parseErr := url.ParseRequestURI(user.Website)
		if parseErr != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
			writeUserError(w, http.StatusBadRequest, "VALIDATION_FAILED", handlerCatalog(r).T("home.api_errors.website_invalid", nil))
			return
		}
	}
	if user.Timezone != "" {
		if _, err := time.LoadLocation(user.Timezone); err != nil {
			writeUserError(w, http.StatusBadRequest, "VALIDATION_FAILED", handlerCatalog(r).T("home.api_errors.timezone_invalid", nil))
			return
		}
	}
	if user.Language != "" && !(h.languageAllowed != nil && h.languageAllowed(user.Language) || h.languageAllowed == nil && i18n.IsSupportedTag(user.Language)) {
		writeUserError(w, http.StatusBadRequest, "VALIDATION_FAILED", handlerCatalog(r).T("home.api_errors.language_unsupported", nil))
		return
	}
	if request.Visibility != "" {
		if request.Visibility != "public" && request.Visibility != "private" {
			writeUserError(w, http.StatusBadRequest, "VALIDATION_FAILED", handlerCatalog(r).T("home.api_errors.visibility_invalid", nil))
			return
		}
		user.Visibility = request.Visibility
	}
	if request.OrgVisibility != nil {
		user.OrgVisibility = *request.OrgVisibility
	}
	if request.ShareShowUsername != nil {
		user.ShareShowUsername = *request.ShareShowUsername
	}
	if err := h.store.UpdateUser(r.Context(), user); err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.profile_save_failed", nil))
		return
	}
	if err := h.createUserNotification(r.Context(), userID, "success", "notifications.profile_updated", "notifications.settings_saved", "/users"); err != nil {
		log.Printf("profile update notification failed: %v", err)
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": user})
}

// GetSettings returns the authenticated user's privacy, notification, and appearance preferences.
func (h *UserHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	settingsStore, ok := h.store.(store.UserSettingsStore)
	if !ok {
		writeUserError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", handlerCatalog(r).T("home.api_errors.settings_unavailable", nil))
		return
	}
	settings, err := settingsStore.GetOrCreateUserSettings(r.Context(), userID)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.settings_load_failed", nil))
		return
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": settings})
}

// GetSecurity returns non-secret account security state for the authenticated user.
func (h *UserHandler) GetSecurity(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	user, err := h.store.GetUser(r.Context(), userID)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.security_load_failed", nil))
		return
	}
	if user == nil {
		writeUserError(w, http.StatusNotFound, "NOT_FOUND", handlerCatalog(r).T("home.api_errors.account_not_found", nil))
		return
	}
	sessionCount := 0
	if sessions, ok := h.store.(store.UserSessionStore); ok {
		items, err := sessions.ListUserSessions(r.Context(), userID)
		if err != nil {
			writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.sessions_load_failed", nil))
			return
		}
		sessionCount = len(items)
	}
	passkeySummary := make([]map[string]any, 0)
	if passkeys, ok := h.store.(store.PasskeyStore); ok {
		items, err := passkeys.GetPasskeys(r.Context(), "user", userID)
		if err != nil {
			writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.passkeys_load_failed", nil))
			return
		}
		for _, item := range items {
			passkeySummary = append(passkeySummary, map[string]any{"id": item.ID, "name": item.Name, "active": item.Active, "created_at": item.CreatedAt, "last_used": item.LastUsed})
		}
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"password_configured": user.PasswordHash != "", "active_sessions": sessionCount, "password_change_url": "/users/security/password", "passkeys": passkeySummary}})
}

func (h *UserHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	devices, err := h.store.GetUserDevices(r.Context(), userID)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.devices_load_failed", nil))
		return
	}
	if devices == nil {
		devices = []*model.Device{}
	}
	writeUserJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "data": devices})
}

func (h *UserHandler) CreateDevice(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	var req struct {
		Name      string `json:"name"`
		Scope     string `json:"scope"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" || utf8.RuneCountInString(req.Name) > 64 {
		writeUserError(w, http.StatusBadRequest, "INVALID_DEVICE_NAME", handlerCatalog(r).T("home.api_errors.device_name_invalid", nil))
		return
	}
	if req.Scope == "" {
		req.Scope = "read"
	}
	if req.Scope != "read" && req.Scope != "read-write" && req.Scope != "global" {
		writeUserError(w, http.StatusBadRequest, "INVALID_TOKEN_SCOPE", handlerCatalog(r).T("home.api_errors.token_scope_invalid", nil))
		return
	}
	id, err := randomHex(16)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.device_create_failed", nil))
		return
	}
	now := time.Now().UTC()
	device := &model.Device{ID: id, UserID: userID, Name: req.Name, LastSeen: now, CreatedAt: now}
	if err := h.store.CreateDevice(r.Context(), device); err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.device_create_failed", nil))
		return
	}
	writeUserJSON(w, http.StatusCreated, map[string]interface{}{"ok": true, "data": device})
}

func (h *UserHandler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	device, err := h.store.GetDevice(r.Context(), chi.URLParam(r, "deviceId"))
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.device_load_failed", nil))
		return
	}
	if device == nil || device.UserID != userID {
		http.NotFound(w, r)
		return
	}
	if err := h.store.DeleteDevice(r.Context(), device.ID); err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.device_delete_failed", nil))
		return
	}
	writeUserJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "data": map[string]string{"status": "deleted"}})
}

func (h *UserHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	tokens, err := h.store.GetUserAPITokens(r.Context(), userID)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.tokens_load_failed", nil))
		return
	}
	if tokens == nil {
		tokens = []*model.APIToken{}
	}
	writeUserJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "data": tokens})
}

func (h *UserHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	var req struct {
		Name      string `json:"name"`
		Scope     string `json:"scope"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" || utf8.RuneCountInString(req.Name) > 64 {
		writeUserError(w, http.StatusBadRequest, "INVALID_TOKEN_NAME", handlerCatalog(r).T("home.api_errors.token_name_invalid", nil))
		return
	}
	if req.Scope == "" {
		req.Scope = "read"
	}
	if req.Scope != "read" && req.Scope != "read-write" && req.Scope != "global" {
		writeUserError(w, http.StatusBadRequest, "INVALID_TOKEN_SCOPE", handlerCatalog(r).T("home.api_errors.token_scope_invalid", nil))
		return
	}
	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		parsedExpiry, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil || !parsedExpiry.After(time.Now()) {
			writeUserError(w, http.StatusBadRequest, "INVALID_TOKEN_EXPIRY", handlerCatalog(r).T("home.api_errors.token_expiry_invalid", nil))
			return
		}
		parsedExpiry = parsedExpiry.UTC()
		expiresAt = &parsedExpiry
	}
	id, err := randomHex(16)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.token_create_failed", nil))
		return
	}
	suffix, err := randomBase62(32)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.token_create_failed", nil))
		return
	}
	secret := "usr_" + suffix
	hash := sha256.Sum256([]byte(secret))
	token := &model.APIToken{ID: id, UserID: userID, Token: hex.EncodeToString(hash[:]), TokenPrefix: secret[:8], Name: strings.TrimSpace(req.Name), Scope: req.Scope, ExpiresAt: expiresAt, CreatedAt: time.Now().UTC()}
	if err := h.store.CreateAPIToken(r.Context(), token); err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.token_create_failed", nil))
		return
	}
	if err := h.createUserNotification(r.Context(), userID, "success", "notifications.api_token_created", "notifications.api_token_created_message", "/users/tokens"); err != nil {
		log.Printf("persist user notification: %v", err)
	}
	writeUserJSON(w, http.StatusCreated, map[string]interface{}{"ok": true, "data": map[string]interface{}{"id": token.ID, "name": token.Name, "token_prefix": token.TokenPrefix, "scope": token.Scope, "expires_at": token.ExpiresAt, "token": secret, "created_at": token.CreatedAt}})
}

func (h *UserHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	token, err := h.store.GetAPIToken(r.Context(), chi.URLParam(r, "tokenId"))
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.token_load_failed", nil))
		return
	}
	if token == nil || token.UserID != userID {
		http.NotFound(w, r)
		return
	}
	if err := h.store.DeleteAPIToken(r.Context(), token.ID); err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.token_revoke_failed", nil))
		return
	}
	if err := h.createUserNotification(r.Context(), userID, "success", "notifications.api_token_revoked", "notifications.api_token_revoked_message", "/users/tokens"); err != nil {
		log.Printf("persist user notification: %v", err)
	}
	writeUserJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "data": map[string]string{"status": "revoked"}})
}

func (h *UserHandler) createUserNotification(ctx context.Context, userID, kind, title, message, link string) error {
	notificationStore, ok := h.store.(store.UserNotificationStore)
	if !ok {
		return nil
	}
	id, err := randomHex(16)
	if err != nil {
		return err
	}
	notification := &model.Notification{ID: id, UserID: userID, Type: kind, Title: title, Message: message, Link: link, CreatedAt: time.Now().UTC()}
	return notificationStore.CreateUserNotification(ctx, notification)
}

func (h *UserHandler) requireUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	userID := h.currentUserID(r)
	if userID == "" {
		writeUserError(w, http.StatusUnauthorized, "UNAUTHORIZED", handlerCatalog(r).T("home.api_errors.auth_required", nil))
		return "", false
	}
	return userID, true
}

func (h *UserHandler) currentUserID(r *http.Request) string {
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token, err := h.store.GetAPITokenByToken(r.Context(), strings.TrimPrefix(authHeader, "Bearer "))
		if err == nil && token != nil && (token.ExpiresAt == nil || token.ExpiresAt.After(time.Now())) {
			user, userErr := h.store.GetUser(r.Context(), token.UserID)
			if userErr == nil && user != nil && user.Approved && !user.Disabled && user.EmailVerified {
				return token.UserID
			}
		}
	}
	cookie, err := r.Cookie("user_session")
	if err != nil || cookie.Value == "" {
		return ""
	}
	session, err := h.store.GetSession(r.Context(), cookie.Value)
	if err != nil || session == nil || !session.ExpiresAt.After(time.Now()) {
		return ""
	}
	user, err := h.store.GetUser(r.Context(), session.UserID)
	if err != nil || user == nil || user.Disabled || !user.Approved {
		return ""
	}
	return model.UserIDString(user.ID)
}

// CurrentUserID returns the authenticated regular-user ID for shared server handlers.
func (h *UserHandler) CurrentUserID(r *http.Request) string { return h.currentUserID(r) }

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func randomBase62(length int) (string, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	limit := big.NewInt(int64(len(alphabet)))
	value := make([]byte, length)
	for i := range value {
		index, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		value[i] = alphabet[index.Int64()]
	}
	return string(value), nil
}

// GenerateTokenSuffix returns a cryptographically random base62 API token suffix.
func GenerateTokenSuffix(length int) (string, error) { return randomBase62(length) }

func writeUserJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeUserError(w http.ResponseWriter, status int, code, message string) {
	writeUserJSON(w, status, map[string]interface{}{"ok": false, "error": code, "message": message})
}
