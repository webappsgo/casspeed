package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/metrics"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
)

type AuthHandler struct {
	store             store.Store
	passwordResetSend func(recipient, resetURL string) error
	buildURL          func(*http.Request, string) string
	passwordValidator func(string) error
}

func handlerCatalog(r *http.Request) *i18n.Catalog {
	candidates := []string{r.URL.Query().Get("lang")}
	if cookie, err := r.Cookie("lang"); err == nil {
		candidates = append(candidates, cookie.Value)
	}
	for _, item := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		candidates = append(candidates, strings.TrimSpace(strings.SplitN(item, ";", 2)[0]))
	}
	for _, candidate := range candidates {
		if i18n.IsSupportedTag(candidate) {
			if catalog, err := i18n.Resolve(candidate); err == nil {
				return catalog
			}
		}
	}
	catalog, _ := i18n.Resolve("en")
	return catalog
}

func handlerPathPrefix(r *http.Request, buildURL func(*http.Request, string) string) string {
	if buildURL == nil {
		return ""
	}
	resolved, err := url.Parse(buildURL(r, "/"))
	if err != nil {
		return ""
	}
	prefix := strings.TrimSuffix(resolved.EscapedPath(), "/")
	if prefix == "/" {
		return ""
	}
	return prefix
}

func handlerPrefixPath(prefix, path string) string {
	if prefix == "" || !strings.HasPrefix(path, "/") || path == prefix || strings.HasPrefix(path, prefix+"/") {
		return path
	}
	return prefix + path
}

func handlerRequestHTTPS(r *http.Request, buildURL func(*http.Request, string) string) bool {
	if r.TLS != nil {
		return true
	}
	if buildURL == nil {
		return false
	}
	resolved, err := url.Parse(buildURL(r, "/"))
	return err == nil && strings.EqualFold(resolved.Scheme, "https")
}

func localizedHTTPError(w http.ResponseWriter, r *http.Request, status int, key string) {
	http.Error(w, handlerCatalog(r).T(key, nil), status)
}

type standaloneAuthPage struct {
	Lang, Dir, BasePath                                         string
	Title, Lead, Message, Skip                                  string
	FormAction, Token, FieldLabel, FieldName, FieldType, Submit string
	Link, LinkText                                              string
}

var standaloneAuthPageTemplate = template.Must(template.New("standalone-auth-page").Parse(`<!doctype html><html lang="{{.Lang}}" dir="{{.Dir}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{{.Title}} — CasSpeed</title><link rel="stylesheet" href="{{.BasePath}}/static/css/theme-dark.css"><link rel="stylesheet" href="{{.BasePath}}/static/css/theme-light.css"><link rel="stylesheet" href="{{.BasePath}}/static/css/style.css"><script src="{{.BasePath}}/static/js/theme.js" defer></script></head><body><a class="skip-link" href="#main-content">{{.Skip}}</a><main id="main-content" class="container container-sm"><header class="page-header"><h1 class="page-title">{{.Title}}</h1>{{if .Lead}}<p class="page-lead">{{.Lead}}</p>{{end}}</header><section class="section-card">{{if .Message}}<p>{{.Message}}</p>{{end}}{{if .FormAction}}<form method="post" action="{{.FormAction}}">{{if .Token}}<input type="hidden" name="token" value="{{.Token}}">{{end}}{{if .FieldName}}<label for="field">{{.FieldLabel}}</label><input id="field" name="{{.FieldName}}" type="{{.FieldType}}" {{if eq .FieldType "password"}}minlength="8" autocomplete="new-password"{{else}}autocomplete="email"{{end}} required>{{end}}<button type="submit">{{.Submit}}</button></form>{{end}}{{if .Link}}<p><a href="{{.Link}}">{{.LinkText}}</a></p>{{end}}</section></main></body></html>`))

func (h *AuthHandler) renderStandaloneAuthPage(w http.ResponseWriter, r *http.Request, status int, data standaloneAuthPage) {
	catalog := handlerCatalog(r)
	data.Lang, data.Dir = catalog.Meta.Language, catalog.Meta.Direction
	data.BasePath = handlerPathPrefix(r, h.buildURL)
	data.Skip = catalog.T("nav.skip_to_content", nil)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(status)
	_ = standaloneAuthPageTemplate.Execute(w, data)
}

func NewAuthHandler(st store.Store) *AuthHandler {
	return &AuthHandler{store: st}
}

func (h *AuthHandler) SetPasswordResetSender(send func(recipient, resetURL string) error) {
	h.passwordResetSend = send
}

func (h *AuthHandler) SetURLBuilder(build func(*http.Request, string) string) {
	h.buildURL = build
}

// SetPasswordValidator applies the configured account password policy to resets.
func (h *AuthHandler) SetPasswordValidator(validate func(string) error) {
	h.passwordValidator = validate
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	status := "failure"
	defer func() { metrics.RecordAuthentication("password", status) }()
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Remember bool   `json:"remember"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		localizedHTTPError(w, r, http.StatusBadRequest, "auth.pages.invalid_request")
		return
	}

	// Get user by username
	user, err := h.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil || user == nil {
		localizedHTTPError(w, r, http.StatusUnauthorized, "auth.pages.invalid_credentials")
		return
	}
	if user.Disabled || !user.Approved || !user.EmailVerified {
		localizedHTTPError(w, r, http.StatusUnauthorized, "auth.pages.invalid_credentials")
		return
	}

	// Verify password
	if !auth.VerifyPassword(req.Password, user.PasswordHash) {
		localizedHTTPError(w, r, http.StatusUnauthorized, "auth.pages.invalid_credentials")
		return
	}
	if totpStore, ok := h.store.(store.UserTOTPStore); ok {
		userID := model.UserIDString(user.ID)
		totp, loadErr := totpStore.GetUserTOTP(r.Context(), userID)
		if loadErr != nil {
			localizedHTTPError(w, r, http.StatusInternalServerError, "auth.pages.security_verify_failed")
			return
		}
		if totp != nil && totp.Enabled {
			partialStore, available := h.store.(store.PartialSessionStore)
			if !available {
				localizedHTTPError(w, r, http.StatusServiceUnavailable, "auth.pages.two_factor_unavailable")
				return
			}
			plain := make([]byte, 32)
			if _, err := rand.Read(plain); err != nil {
				localizedHTTPError(w, r, http.StatusInternalServerError, "auth.pages.challenge_failed")
				return
			}
			partialToken := base64.RawURLEncoding.EncodeToString(plain)
			digest := sha256.Sum256([]byte(partialToken))
			if err := partialStore.CreatePartialSession(r.Context(), &model.PartialSession{TokenHash: hex.EncodeToString(digest[:]), UserID: userID, UserType: "user", Remember: req.Remember, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}); err != nil {
				localizedHTTPError(w, r, http.StatusInternalServerError, "auth.pages.challenge_failed")
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{"requires_2fa": true, "partial_token": partialToken}})
			status = "challenge"
			return
		}
	}
	if passkeys, ok := h.store.(store.PasskeyStore); ok {
		rows, loadErr := passkeys.GetPasskeys(r.Context(), "user", model.UserIDString(user.ID))
		if loadErr != nil {
			localizedHTTPError(w, r, http.StatusInternalServerError, "auth.pages.security_verify_failed")
			return
		}
		for _, row := range rows {
			if row.Active {
				partialStore, available := h.store.(store.PartialSessionStore)
				if !available {
					localizedHTTPError(w, r, http.StatusServiceUnavailable, "auth.pages.two_factor_unavailable")
					return
				}
				plain := make([]byte, 32)
				if _, err := rand.Read(plain); err != nil {
					localizedHTTPError(w, r, http.StatusInternalServerError, "auth.pages.challenge_failed")
					return
				}
				partialToken := base64.RawURLEncoding.EncodeToString(plain)
				digest := sha256.Sum256([]byte(partialToken))
				if err := partialStore.CreatePartialSession(r.Context(), &model.PartialSession{TokenHash: hex.EncodeToString(digest[:]), UserID: model.UserIDString(user.ID), UserType: "user", Remember: req.Remember, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}); err != nil {
					localizedHTTPError(w, r, http.StatusInternalServerError, "auth.pages.challenge_failed")
					return
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{"requires_2fa": true, "partial_token": partialToken}})
				status = "challenge"
				return
			}
		}
	}

	// Create session
	userID := model.UserIDString(user.ID)
	session := auth.NewSession(userID, r.RemoteAddr, r.UserAgent())

	// Store session in database
	dbSession := &model.Session{
		ID:        session.ID,
		UserID:    session.UserID,
		ExpiresAt: session.ExpiresAt,
		CreatedAt: session.CreatedAt,
	}

	if err := h.store.CreateSession(r.Context(), dbSession); err != nil {
		localizedHTTPError(w, r, http.StatusInternalServerError, "auth.pages.session_create_failed")
		return
	}
	if err := h.store.UpdateUserLastLogin(r.Context(), userID, time.Now().UTC()); err != nil {
		localizedHTTPError(w, r, http.StatusInternalServerError, "auth.pages.login_complete_failed")
		return
	}

	// Set session cookie — SameSite=Strict per PART 11 CSRF requirement
	http.SetCookie(w, &http.Cookie{
		Name:     "user_session",
		Value:    session.ID,
		Path:     handlerPrefixPath(handlerPathPrefix(r, h.buildURL), "/"),
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   handlerRequestHTTPS(r, h.buildURL),
		SameSite: http.SameSiteStrictMode,
	})

	// Return canonical {"ok": true, "data": {...}} format (PART 9)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true,
		"data": map[string]any{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
	})
	status = "success"
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get session cookie
	cookie, err := r.Cookie("user_session")
	if err == nil && cookie.Value != "" {
		// Delete session from database
		h.store.DeleteSession(r.Context(), cookie.Value)
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "user_session",
		Value:    "",
		Path:     handlerPrefixPath(handlerPathPrefix(r, h.buildURL), "/"),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   handlerRequestHTTPS(r, h.buildURL),
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "data": nil})
}

// PasswordResetRequest handles password reset request
func (h *AuthHandler) PasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var req struct {
		Email string `json:"email"`
	}
	isForm := !strings.Contains(r.Header.Get("Content-Type"), "application/json")
	if isForm {
		if r.Method != http.MethodPost || !sameOriginFormRequest(r) {
			localizedHTTPError(w, r, http.StatusForbidden, "auth.pages.invalid_request")
			return
		}
		if err := r.ParseForm(); err != nil {
			localizedHTTPError(w, r, http.StatusBadRequest, "auth.pages.invalid_request")
			return
		}
		req.Email = r.FormValue("email")
	} else if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		localizedHTTPError(w, r, http.StatusBadRequest, "auth.pages.invalid_request")
		return
	}

	if h.passwordResetSend != nil && h.buildURL != nil {
		user, err := h.store.GetUserByEmail(r.Context(), strings.TrimSpace(req.Email))
		if err == nil && user != nil {
			secret := make([]byte, 32)
			if _, err := rand.Read(secret); err == nil {
				token := hex.EncodeToString(secret)
				hash := sha256.Sum256([]byte(token))
				expires := time.Now().UTC().Add(time.Hour)
				if err := h.store.CreatePasswordResetToken(r.Context(), model.UserIDString(user.ID), hex.EncodeToString(hash[:]), expires); err == nil {
					resetURL := h.buildURL(r, "/server/auth/password/reset") + "?token=" + url.QueryEscape(token)
					_ = h.passwordResetSend(user.Email, resetURL)
				}
			}
		}
	}

	// The response is identical for unknown accounts and delivery failures.
	catalog := handlerCatalog(r)
	if isForm {
		h.renderStandaloneAuthPage(w, r, http.StatusOK, standaloneAuthPage{
			Title: catalog.T("auth.pages.password_recovery_title", nil), Message: catalog.T("auth.pages.password_recovery_message", nil),
			Link: handlerPrefixPath(handlerPathPrefix(r, h.buildURL), "/server/auth/login"), LinkText: catalog.T("auth.pages.return_login", nil),
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true,
		"data": map[string]string{
			"message": catalog.T("auth.pages.password_recovery_message", nil),
		},
	})
}

func sameOriginFormRequest(r *http.Request) bool {
	wantScheme := "http"
	if r.TLS != nil {
		wantScheme = "https"
	}
	want := strings.ToLower(wantScheme + "://" + r.Host)
	for _, candidate := range []string{r.Header.Get("Origin"), r.Header.Get("Referer")} {
		if candidate == "" {
			continue
		}
		parsed, err := url.Parse(candidate)
		if err == nil && strings.ToLower(parsed.Scheme+"://"+parsed.Host) == want {
			return true
		}
		return false
	}
	return false
}

// PasswordForgotPage renders the password recovery request form.
func (h *AuthHandler) PasswordForgotPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		localizedHTTPError(w, r, http.StatusMethodNotAllowed, "auth.pages.method_not_allowed")
		return
	}
	catalog := handlerCatalog(r)
	prefix := handlerPathPrefix(r, h.buildURL)
	h.renderStandaloneAuthPage(w, r, http.StatusOK, standaloneAuthPage{
		Title:      catalog.T("auth.pages.password_forgot_title", nil),
		Lead:       catalog.T("auth.pages.password_recovery_message", nil),
		FormAction: handlerPrefixPath(prefix, "/server/auth/password/forgot"), FieldName: "email", FieldType: "email",
		FieldLabel: catalog.T("auth.pages.email_label", nil), Submit: catalog.T("auth.pages.send_recovery", nil),
		Link: handlerPrefixPath(prefix, "/server/auth/login"), LinkText: catalog.T("auth.pages.return_login", nil),
	})
}

func (h *AuthHandler) PasswordResetPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		localizedHTTPError(w, r, http.StatusMethodNotAllowed, "auth.pages.method_not_allowed")
		return
	}
	catalog := handlerCatalog(r)
	prefix := handlerPathPrefix(r, h.buildURL)
	h.renderStandaloneAuthPage(w, r, http.StatusOK, standaloneAuthPage{
		Title: catalog.T("auth.pages.password_reset_title", nil), Lead: catalog.T("auth.pages.password_reset_lead", nil),
		FormAction: handlerPrefixPath(prefix, "/server/auth/password/reset"), Token: r.URL.Query().Get("token"),
		FieldName: "password", FieldType: "password", FieldLabel: catalog.T("auth.pages.new_password", nil),
		Submit: catalog.T("auth.pages.update_password", nil),
	})
}

func (h *AuthHandler) PasswordResetComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			localizedHTTPError(w, r, http.StatusBadRequest, "auth.pages.invalid_request")
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			localizedHTTPError(w, r, http.StatusBadRequest, "auth.pages.invalid_request")
			return
		}
		req.Token = r.FormValue("token")
		req.Password = r.FormValue("password")
	}
	decoded, err := hex.DecodeString(req.Token)
	validPassword := auth.ValidatePassword(req.Password) == nil
	if h.passwordValidator != nil {
		validPassword = h.passwordValidator(req.Password) == nil
	}
	if err != nil || len(decoded) != 32 || !validPassword {
		localizedHTTPError(w, r, http.StatusBadRequest, "auth.pages.reset_invalid")
		return
	}
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		localizedHTTPError(w, r, http.StatusInternalServerError, "auth.pages.password_update_failed")
		return
	}
	hash := sha256.Sum256([]byte(req.Token))
	updated, err := h.store.CompletePasswordReset(r.Context(), hex.EncodeToString(hash[:]), time.Now().UTC(), passwordHash)
	if err != nil {
		localizedHTTPError(w, r, http.StatusInternalServerError, "auth.pages.password_update_failed")
		return
	}
	if !updated {
		localizedHTTPError(w, r, http.StatusBadRequest, "auth.pages.reset_expired")
		return
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]string{"message": handlerCatalog(r).T("auth.pages.password_updated_title", nil)}})
		return
	}
	catalog := handlerCatalog(r)
	prefix := handlerPathPrefix(r, h.buildURL)
	h.renderStandaloneAuthPage(w, r, http.StatusOK, standaloneAuthPage{
		Title: catalog.T("auth.pages.password_updated_title", nil), Message: catalog.T("auth.pages.password_updated_message", nil),
		Link: handlerPrefixPath(prefix, "/server/auth/login"), LinkText: catalog.T("auth.pages.sign_in_new_password", nil),
	})
}
