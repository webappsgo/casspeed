package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/admin"
	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/server/handler"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/skip2/go-qrcode"
)

func writeUserJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func userIDString(id int64) string { return strconv.FormatInt(id, 10) }

var mfaChallengeTemplate = template.Must(template.New("mfa-challenge").Parse(`<form method="post" action="{{.Action}}"><div class="form-group"><label for="mfa-code">{{.CodeLabel}}</label><input class="form-input" id="mfa-code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></div><button type="submit">{{.Submit}}</button></form><p><a href="/server/auth/passkey">{{.PasskeyLink}}</a></p><p><a href="/server/auth/recovery/use">{{.RecoveryLink}}</a></p>`))
var recoveryChallengeTemplate = template.Must(template.New("recovery-challenge").Parse(`<form method="post" action="/server/auth/recovery/use"><div class="form-group"><label for="recovery-key">{{.CodeLabel}}</label><input class="form-input" id="recovery-key" name="recovery_code" autocomplete="off" required></div><button type="submit">{{.Submit}}</button></form>`))
var adminSecurityContentTemplate = template.Must(template.New("admin-security").Parse(`<p><a href="{{.PasskeyPath}}">{{.PasskeyLabel}}</a></p><h2>{{.Heading}}</h2>{{if .Message}}<p role="status">{{.Message}}</p>{{end}}{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}{{if .QR}}<img alt="{{.QRLabel}}" src="data:image/png;base64,{{.QR}}"><p>{{.ManualLabel}} <code>{{.Secret}}</code></p><form method="post" action="{{.EnablePath}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><div><label for="admin-password">{{.PasswordLabel}}</label><input id="admin-password" name="current_password" type="password" autocomplete="current-password" required></div><div><label for="admin-code">{{.CodeLabel}}</label><input id="admin-code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required></div><button type="submit">{{.VerifyLabel}}</button></form>{{else if .RecoveryCodes}}<h3>{{.RecoveryTitle}}</h3><p>{{.RecoveryWarning}}</p><ul>{{range .RecoveryCodes}}<li><code>{{.}}</code></li>{{end}}</ul>{{if .RecoveryConfirm}}<form method="post" action="{{.EnablePath}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="code" value="{{.Code}}"><div><label for="admin-password">{{.PasswordLabel}}</label><input id="admin-password" name="current_password" type="password" autocomplete="current-password" required></div><div><label><input type="checkbox" name="recovery_keys_saved" value="true" required>{{.SavedLabel}}</label></div><button type="submit">{{.EnableLabel}}</button></form>{{end}}{{else if .Enabled}}<p>{{.EnabledLabel}} {{.Remaining}}</p><form method="post" action="{{.DisablePath}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><div><label for="admin-password">{{.PasswordLabel}}</label><input id="admin-password" name="current_password" type="password" autocomplete="current-password" required></div><div><label for="admin-code">{{.CodeLabel}}</label><input id="admin-code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"></div><div><label for="recovery-code">{{.RecoveryLabel}}</label><input id="recovery-code" name="recovery_code"></div><button type="submit">{{.DisableLabel}}</button></form><form method="post" action="{{.RegeneratePath}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><div><label for="regenerate-password">{{.PasswordLabel}}</label><input id="regenerate-password" name="current_password" type="password" autocomplete="current-password" required></div><div><label for="regenerate-code">{{.CodeLabel}}</label><input id="regenerate-code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required></div><button type="submit">{{.RegenerateLabel}}</button></form>{{else}}<p>{{.DisabledLabel}}</p><form method="post" action="{{.SetupPath}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><div><label for="admin-password">{{.PasswordLabel}}</label><input id="admin-password" name="current_password" type="password" autocomplete="current-password" required></div><button type="submit">{{.SetupLabel}}</button></form>{{end}}`))
var userTOTPPageTemplate = template.Must(template.New("user-totp-page").Parse(`{{if .Message}}<p role="status">{{.Message}}</p>{{end}}{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}{{if .Enabled}}<p>{{.EnabledLabel}}</p><form method="post" action="/users/security/2fa"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="disable"><div class="form-group"><label for="disable-password">{{.PasswordLabel}}</label><input class="form-input" type="password" id="disable-password" name="current_password" autocomplete="current-password" required></div><div class="form-group"><label for="disable-code">{{.CodeLabel}}</label><input class="form-input" id="disable-code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"></div><div class="form-group"><label for="disable-recovery">{{.RecoveryLabel}}</label><input class="form-input" id="disable-recovery" name="recovery_code"></div><button type="submit">{{.Disable}}</button></form>{{else}}{{if .QR}}<img alt="{{.QRLabel}}" src="data:image/png;base64,{{.QR}}"><p>{{.SecretLabel}} <code>{{.Secret}}</code></p><form method="post" action="/users/security/2fa"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="confirm"><input type="hidden" name="qr_code" value="{{.QR}}"><input type="hidden" name="secret" value="{{.Secret}}"><div class="form-group"><label for="setup-code">{{.CodeLabel}}</label><input class="form-input" id="setup-code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></div><button type="submit">{{.Verify}}</button></form>{{else}}<form method="post" action="/users/security/2fa"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="start"><div class="form-group"><label for="setup-password">{{.PasswordLabel}}</label><input class="form-input" type="password" id="setup-password" name="current_password" autocomplete="current-password" required></div><button type="submit">{{.Setup}}</button></form>{{end}}{{end}}{{if .RecoveryCodes}}<section aria-labelledby="recovery-codes-heading"><h3 id="recovery-codes-heading">{{.RecoveryTitle}}</h3><p>{{.RecoveryWarning}}</p><ul>{{range .RecoveryCodes}}<li><code>{{.}}</code></li>{{end}}</ul><form method="post" action="/users/security/2fa"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="confirm"><input type="hidden" name="qr_code" value="{{.QR}}"><input type="hidden" name="secret" value="{{.Secret}}"><div class="form-group"><label><input type="checkbox" name="recovery_keys_saved" value="true" required>{{.ConfirmSaved}}</label></div><div class="form-group"><label for="confirm-code">{{.CodeLabel}}</label><input class="form-input" id="confirm-code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required></div><button type="submit">{{.Verify}}</button></form></section>{{end}}`))

func (s *Server) createPartialAuthentication(ctx context.Context, userID, userType string, remember bool) (string, error) {
	partialStore, ok := s.Store.(store.PartialSessionStore)
	if !ok {
		return "", fmt.Errorf("partial-session storage is unavailable")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate partial-session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	if err := partialStore.CreatePartialSession(ctx, &model.PartialSession{TokenHash: hex.EncodeToString(digest[:]), UserID: userID, UserType: userType, Remember: remember, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Server) verifyUserTOTP(ctx context.Context, userID, code string) (bool, error) {
	totpStore, ok := s.Store.(store.UserTOTPStore)
	if !ok {
		return false, fmt.Errorf("TOTP storage is unavailable")
	}
	secret, err := totpStore.GetUserTOTP(ctx, userID)
	if err != nil {
		return false, err
	}
	if secret == nil || !secret.Enabled {
		return false, nil
	}
	plaintext, err := s.decryptTOTPSecret(secret.EncryptedSecret)
	if err != nil {
		return false, err
	}
	return auth.VerifyTOTP(string(plaintext), code, time.Now().UTC()), nil
}

func (s *Server) handleMFAChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.renderMFAChallenge(w, r, false)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	isAPI := strings.Contains(r.Header.Get("Content-Type"), "application/json")
	partialToken := ""
	code := ""
	if isAPI {
		var request struct {
			PartialToken string `json:"partial_token"`
			Code         string `json:"code"`
		}
		if err := decodeMFARequest(w, r, &request); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid two-factor request"})
			return
		}
		partialToken, code = request.PartialToken, request.Code
	} else {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil {
			http.Error(w, "Two-factor request failed security validation", http.StatusForbidden)
			return
		}
		partialToken, code = r.FormValue("partial_token"), r.FormValue("code")
		if cookie, err := r.Cookie("partial_session"); cookie != nil && err == nil {
			partialToken = cookie.Value
		}
	}
	partial, ok := s.loadPartialUser(r, partialToken)
	if !ok {
		s.mfaFailure(w, r, isAPI, "Invalid or expired challenge")
		return
	}
	var valid bool
	var err error
	switch partial.UserType {
	case "user":
		valid, err = s.verifyUserTOTP(r.Context(), partial.UserID, code)
	case "admin":
		adminID, parseErr := strconv.Atoi(partial.UserID)
		if parseErr != nil {
			s.mfaFailure(w, r, isAPI, "Invalid or expired challenge")
			return
		}
		valid, err = s.verifyAdminTOTP(r.Context(), adminID, code)
	default:
		s.mfaFailure(w, r, isAPI, "Invalid or expired challenge")
		return
	}
	if err != nil {
		s.mfaFailure(w, r, isAPI, "Unable to validate authenticator code")
		return
	}
	if !valid {
		s.recordFailedAuthentication(r)
		s.mfaFailure(w, r, isAPI, "Authenticator code is invalid")
		return
	}
	consumed, err := s.consumePartial(r, partialToken)
	if err != nil || consumed == nil {
		s.mfaFailure(w, r, isAPI, "Invalid or expired challenge")
		return
	}
	if isAPI {
		if consumed.UserType == "admin" {
			adminID, _ := strconv.Atoi(consumed.UserID)
			s.issueAdminLoginToken(w, r, adminID, nil)
		} else {
			s.issueUserLoginToken(w, r, consumed.UserID, nil)
		}
		return
	}
	if consumed.UserType == "admin" {
		adminID, _ := strconv.Atoi(consumed.UserID)
		s.issueAdminSession(w, r, consumed, adminID)
		return
	}
	s.issueUserSession(w, r, consumed, "/users")
}

func (s *Server) handleMFARecovery(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.renderMFAChallenge(w, r, true)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	isAPI := strings.Contains(r.Header.Get("Content-Type"), "application/json")
	partialToken, recoveryCode := "", ""
	if isAPI {
		var request struct {
			PartialToken string `json:"partial_token"`
			RecoveryCode string `json:"recovery_code"`
		}
		if err := decodeMFARequest(w, r, &request); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid recovery request"})
			return
		}
		partialToken, recoveryCode = request.PartialToken, request.RecoveryCode
	} else {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil {
			http.Error(w, "Recovery request failed security validation", http.StatusForbidden)
			return
		}
		partialToken, recoveryCode = r.FormValue("partial_token"), r.FormValue("recovery_code")
		if cookie, err := r.Cookie("partial_session"); cookie != nil && err == nil {
			partialToken = cookie.Value
		}
	}
	partial, ok := s.loadPartialUser(r, partialToken)
	if !ok {
		s.mfaFailure(w, r, isAPI, "Invalid or expired challenge")
		return
	}
	var remaining int
	var consumedCode bool
	var err error
	switch partial.UserType {
	case "user":
		totpStore, available := s.Store.(store.UserTOTPStore)
		if available {
			remaining, consumedCode, err = totpStore.ConsumeUserRecoveryCode(r.Context(), partial.UserID, recoveryCodeHash(recoveryCode))
		}
		if !consumedCode {
			if passkeyStore, passkeysAvailable := s.Store.(store.PasskeyStore); passkeysAvailable {
				remaining, consumedCode, err = passkeyStore.ConsumePasskeyRecoveryCode(r.Context(), "user", partial.UserID, recoveryCodeHash(recoveryCode))
			}
		}
		if !available {
			if _, passkeysAvailable := s.Store.(store.PasskeyStore); !passkeysAvailable {
				s.mfaFailure(w, r, isAPI, "Recovery is unavailable")
				return
			}
		}
	case "admin":
		adminID, parseErr := strconv.Atoi(partial.UserID)
		if parseErr != nil {
			s.mfaFailure(w, r, isAPI, "Invalid or expired challenge")
			return
		}
		totpStore, available := s.Store.(store.AdminTOTPStore)
		if available {
			remaining, consumedCode, err = totpStore.ConsumeAdminRecoveryCode(r.Context(), adminID, recoveryCodeHash(recoveryCode))
		}
		if !consumedCode {
			if passkeyStore, passkeysAvailable := s.Store.(store.PasskeyStore); passkeysAvailable {
				remaining, consumedCode, err = passkeyStore.ConsumePasskeyRecoveryCode(r.Context(), "admin", partial.UserID, recoveryCodeHash(recoveryCode))
			}
		}
		if !available {
			if _, passkeysAvailable := s.Store.(store.PasskeyStore); !passkeysAvailable {
				s.mfaFailure(w, r, isAPI, "Recovery is unavailable")
				return
			}
		}
	default:
		s.mfaFailure(w, r, isAPI, "Invalid or expired challenge")
		return
	}
	if err != nil {
		s.mfaFailure(w, r, isAPI, "Unable to validate recovery key")
		return
	}
	if !consumedCode {
		s.recordFailedAuthentication(r)
		s.mfaFailure(w, r, isAPI, "Recovery key is invalid")
		return
	}
	consumed, err := s.consumePartial(r, partialToken)
	if err != nil || consumed == nil {
		s.mfaFailure(w, r, isAPI, "Invalid or expired challenge")
		return
	}
	if isAPI {
		if consumed.UserType == "admin" {
			adminID, _ := strconv.Atoi(consumed.UserID)
			s.issueAdminLoginToken(w, r, adminID, &remaining)
		} else {
			s.issueUserLoginToken(w, r, consumed.UserID, &remaining)
		}
		return
	}
	if consumed.UserType == "admin" {
		adminID, _ := strconv.Atoi(consumed.UserID)
		s.issueAdminSession(w, r, consumed, adminID)
		return
	}
	s.issueUserSession(w, r, consumed, "/users/security/2fa")
}

func (s *Server) verifyAdminTOTP(ctx context.Context, adminID int, code string) (bool, error) {
	totpStore, ok := s.Store.(store.AdminTOTPStore)
	if !ok {
		return false, fmt.Errorf("admin TOTP storage is unavailable")
	}
	secret, err := totpStore.GetAdminTOTP(ctx, adminID)
	if err != nil {
		return false, err
	}
	if secret == nil || !secret.Enabled {
		return false, nil
	}
	plaintext, err := s.decryptTOTPSecret(secret.EncryptedSecret)
	if err != nil {
		return false, err
	}
	return auth.VerifyTOTP(string(plaintext), code, time.Now().UTC()), nil
}

func (s *Server) adminMFAIdentity(r *http.Request) (*model.Admin, bool) {
	cookie, err := r.Cookie("admin_session")
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	session, err := s.Store.GetAdminSession(r.Context(), cookie.Value)
	if err != nil || session == nil || !session.ExpiresAt.After(time.Now()) {
		return nil, false
	}
	names, ok := s.Store.(store.AdminUsernameStore)
	if !ok {
		return nil, false
	}
	username, err := names.GetAdminUsername(r.Context(), session.AdminID)
	if err != nil || username == "" || r.PathValue("username") != username {
		return nil, false
	}
	account, err := s.Store.GetAdminByUsername(r.Context(), username)
	if err != nil || account == nil || !account.Enabled {
		return nil, false
	}
	return account, true
}

func (s *Server) handleAdminTOTP(w http.ResponseWriter, r *http.Request) {
	account, ok := s.adminMFAIdentity(r)
	if !ok {
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Authentication required"})
		} else {
			http.Redirect(w, r, "/server/auth/login", http.StatusSeeOther)
		}
		return
	}
	totpStore, ok := s.Store.(store.AdminTOTPStore)
	if !ok {
		http.Error(w, "Two-factor authentication is unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodGet {
		secret, err := totpStore.GetAdminTOTP(r.Context(), account.ID)
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to load security status"})
			return
		}
		remaining := 0
		if secret != nil && secret.Enabled {
			remaining = len(secret.RecoveryCodeHashes)
		}
		passkeySummary := make([]map[string]any, 0)
		if passkeys, available := s.Store.(store.PasskeyStore); available {
			items, loadErr := passkeys.GetPasskeys(r.Context(), "admin", strconv.Itoa(account.ID))
			if loadErr != nil {
				writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to load passkeys"})
				return
			}
			for _, item := range items {
				passkeySummary = append(passkeySummary, map[string]any{"id": item.ID, "name": item.Name, "active": item.Active, "created_at": item.CreatedAt, "last_used": item.LastUsed})
			}
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"totp_enabled": secret != nil && secret.Enabled, "recovery_keys_remaining": remaining, "passkeys": passkeySummary}})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		CurrentPassword   string `json:"current_password"`
		Code              string `json:"code"`
		RecoveryCode      string `json:"recovery_code"`
		RecoveryKeysSaved bool   `json:"recovery_keys_saved"`
	}
	if err := decodeMFARequest(w, r, &request); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid security request"})
		return
	}
	if !admin.VerifyPassword(request.CurrentPassword, account.Password) {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Current password is invalid"})
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	if strings.HasSuffix(path, "/totp/setup") {
		current, err := totpStore.GetAdminTOTP(r.Context(), account.ID)
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to load setup"})
			return
		}
		if current != nil && current.Enabled {
			writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "Two-factor authentication is already enabled"})
			return
		}
		secret, err := auth.NewTOTPSecret()
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to start setup"})
			return
		}
		encrypted, err := s.encryptTOTPSecret([]byte(secret))
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to protect authenticator secret"})
			return
		}
		if err := totpStore.SaveAdminTOTP(r.Context(), &model.AdminTOTPSecret{AdminID: account.ID, EncryptedSecret: encrypted}); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to save setup"})
			return
		}
		uri := "otpauth://totp/" + url.PathEscape("CasSpeed:"+account.Username) + "?" + url.Values{"secret": {secret}, "issuer": {"CasSpeed"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}.Encode()
		qr, err := qrcode.Encode(uri, qrcode.Medium, 256)
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create QR code"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]string{"secret": secret, "otpauth_url": uri, "qr_code": base64.StdEncoding.EncodeToString(qr)}})
		return
	}
	if strings.HasSuffix(path, "/totp/enable") {
		current, err := totpStore.GetAdminTOTP(r.Context(), account.ID)
		if err != nil || current == nil {
			writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "Two-factor setup has not started"})
			return
		}
		plain, err := s.decryptTOTPSecret(current.EncryptedSecret)
		if err != nil || !auth.VerifyTOTP(string(plain), request.Code, time.Now().UTC()) {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Authenticator code is invalid"})
			return
		}
		if len(current.RecoveryCodeHashes) == 0 {
			codes, err := auth.NewRecoveryCodes()
			if err != nil {
				writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create recovery keys"})
				return
			}
			current.RecoveryCodeHashes = hashRecoveryCodes(codes)
			current.Enabled = false
			if err := totpStore.SaveAdminTOTP(r.Context(), current); err != nil {
				writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to save recovery keys"})
				return
			}
			writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"recovery_keys": codes, "requires_saved_confirmation": true}})
			return
		}
		if !request.RecoveryKeysSaved {
			writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "Confirm that recovery keys were saved"})
			return
		}
		current.Enabled = true
		if err := totpStore.SaveAdminTOTP(r.Context(), current); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to enable two-factor authentication"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]bool{"enabled": true}})
		return
	}
	if strings.HasSuffix(path, "/totp/disable") {
		current, err := totpStore.GetAdminTOTP(r.Context(), account.ID)
		if err != nil || current == nil || !current.Enabled {
			writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "Two-factor authentication is not enabled"})
			return
		}
		plain, err := s.decryptTOTPSecret(current.EncryptedSecret)
		valid := err == nil && auth.VerifyTOTP(string(plain), request.Code, time.Now().UTC())
		if !valid && request.RecoveryCode != "" {
			_, valid, err = totpStore.ConsumeAdminRecoveryCode(r.Context(), account.ID, recoveryCodeHash(request.RecoveryCode))
		}
		if err != nil || !valid {
			writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Authenticator or recovery key is invalid"})
			return
		}
		if err := totpStore.DeleteAdminTOTP(r.Context(), account.ID); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to disable two-factor authentication"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]bool{"enabled": false}})
		return
	}
	if strings.HasSuffix(path, "/recovery/regenerate") {
		current, err := totpStore.GetAdminTOTP(r.Context(), account.ID)
		if err != nil || current == nil || !current.Enabled {
			writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "Two-factor authentication is not enabled"})
			return
		}
		plain, err := s.decryptTOTPSecret(current.EncryptedSecret)
		if err != nil || !auth.VerifyTOTP(string(plain), request.Code, time.Now().UTC()) {
			writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Authenticator code is invalid"})
			return
		}
		codes, err := auth.NewRecoveryCodes()
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create recovery keys"})
			return
		}
		current.RecoveryCodeHashes = hashRecoveryCodes(codes)
		if err := totpStore.SaveAdminTOTP(r.Context(), current); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to save recovery keys"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"recovery_keys": codes, "count": len(codes)}})
		return
	}
	writeUserJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "Not found"})
}

func (s *Server) handleAdminSecurityPage(w http.ResponseWriter, r *http.Request) {
	account, ok := s.adminMFAIdentity(r)
	if !ok {
		http.Redirect(w, r, "/server/auth/login", http.StatusSeeOther)
		return
	}
	adminCookie, cookieErr := r.Cookie("admin_session")
	form := url.Values{}
	message, failure := "", ""
	rootPath := r.URL.Path[:strings.LastIndex(r.URL.Path, "/profile/security")]
	data := map[string]any{"CSRF": "", "SetupPath": rootPath + "/profile/security/totp/setup", "EnablePath": rootPath + "/profile/security/totp/enable", "DisablePath": rootPath + "/profile/security/totp/disable", "RegeneratePath": rootPath + "/profile/security/recovery/regenerate", "PasskeyPath": rootPath + "/profile/security/passkeys"}
	if cookieErr == nil {
		data["CSRF"] = adminCookie.Value
	}
	if r.Method == http.MethodPost {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil || cookieErr != nil || len(r.FormValue("csrf_token")) != len(adminCookie.Value) || subtle.ConstantTimeCompare([]byte(r.FormValue("csrf_token")), []byte(adminCookie.Value)) != 1 {
			http.Error(w, "Security settings request failed validation", http.StatusForbidden)
			return
		}
		for _, key := range []string{"current_password", "code", "recovery_code", "recovery_keys_saved"} {
			if value := r.FormValue(key); value != "" {
				form.Set(key, value)
			}
		}
		apiPath := "/api/v1" + r.URL.Path
		apiReq := r.Clone(r.Context())
		apiReq.URL = new(url.URL)
		*apiReq.URL = *r.URL
		apiReq.URL.Path = apiPath
		apiReq.Header = r.Header.Clone()
		apiReq.Header.Set("Content-Type", "application/json")
		payload, _ := json.Marshal(map[string]any{"current_password": form.Get("current_password"), "code": form.Get("code"), "recovery_code": form.Get("recovery_code"), "recovery_keys_saved": form.Get("recovery_keys_saved") == "true"})
		apiReq.Body = io.NopCloser(strings.NewReader(string(payload)))
		apiRecorder := httptest.NewRecorder()
		s.handleAdminTOTP(apiRecorder, apiReq)
		var response struct {
			OK    bool           `json:"ok"`
			Error string         `json:"error"`
			Data  map[string]any `json:"data"`
		}
		if err := json.Unmarshal(apiRecorder.Body.Bytes(), &response); err != nil {
			failure = "Unable to process security settings"
		} else if !response.OK {
			failure = response.Error
		} else {
			if secret, ok := response.Data["secret"].(string); ok {
				data["Secret"] = secret
				data["QR"] = response.Data["qr_code"]
			}
			if codes, ok := response.Data["recovery_keys"].([]any); ok {
				data["RecoveryCodes"] = codes
				data["Code"] = form.Get("code")
				data["RecoveryConfirm"] = strings.HasSuffix(r.URL.Path, "/totp/enable")
			}
			if enabled, _ := response.Data["enabled"].(bool); enabled {
				data["Enabled"] = true
				message = "Two-factor authentication is enabled."
			}
		}
	}
	if _, ok := data["Enabled"]; !ok {
		statusReq := r.Clone(r.Context())
		statusReq.Method = http.MethodGet
		statusReq.URL = new(url.URL)
		*statusReq.URL = *r.URL
		statusReq.URL.Path = "/api/v1" + r.URL.Path[:strings.LastIndex(r.URL.Path, "/profile/security")] + "/profile/security"
		statusRecorder := httptest.NewRecorder()
		s.handleAdminTOTP(statusRecorder, statusReq)
		var status struct {
			Data map[string]any `json:"data"`
		}
		if json.Unmarshal(statusRecorder.Body.Bytes(), &status) == nil {
			data["Enabled"] = status.Data["totp_enabled"]
			data["Remaining"] = status.Data["recovery_keys_remaining"]
		}
	}
	data["Message"], data["Error"] = message, failure
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Security settings unavailable", http.StatusInternalServerError)
		return
	}
	for key, catalogKey := range map[string]string{"Heading": "auth.admin_security_heading", "ManualLabel": "auth.admin_manual_key", "PasswordLabel": "auth.admin_password", "CodeLabel": "auth.admin_code", "VerifyLabel": "auth.admin_verify", "RecoveryTitle": "auth.admin_recovery_title", "RecoveryWarning": "auth.admin_recovery_warning", "SavedLabel": "auth.admin_saved", "EnableLabel": "auth.admin_enable", "EnabledLabel": "auth.admin_enabled", "DisableLabel": "auth.admin_disable", "RegenerateLabel": "auth.admin_regenerate", "DisabledLabel": "auth.admin_disabled", "SetupLabel": "auth.admin_setup", "QRLabel": "auth.admin_qr", "RecoveryLabel": "auth.recovery_key", "PasskeyLabel": "auth.passkeys"} {
		data[key] = catalog.T(catalogKey, nil)
	}
	content := executeTemplate(adminSecurityContentTemplate, data)
	s.AdminHandler.RenderContentPage(w, r, catalog.T("auth.security", nil), account.Username, content)
}

func (s *Server) issueAdminLoginToken(w http.ResponseWriter, r *http.Request, adminID int, remaining *int) {
	suffix, err := handler.GenerateTokenSuffix(32)
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create login token"})
		return
	}
	token := "adm_" + suffix
	digest := sha256.Sum256([]byte(token))
	if err := s.Store.UpdateAdminAPITokenHash(r.Context(), adminID, hex.EncodeToString(digest[:])); err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to save login token"})
		return
	}
	data := map[string]any{"token": token}
	if remaining != nil {
		data["remaining_keys"] = *remaining
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": data})
}

func (s *Server) issueAdminSession(w http.ResponseWriter, r *http.Request, partial *model.PartialSession, adminID int) {
	now := time.Now().UTC()
	expires := now.Add(8 * time.Hour)
	if partial.Remember {
		expires = now.Add(30 * 24 * time.Hour)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "Unable to create account session", http.StatusInternalServerError)
		return
	}
	sessionID := base64.RawURLEncoding.EncodeToString(raw)
	session := &model.AdminSession{ID: sessionID, AdminID: adminID, IPAddress: peerIP(r.RemoteAddr), UserAgent: r.UserAgent(), ExpiresAt: expires}
	if err := s.Store.CreateAdminSession(r.Context(), session); err != nil {
		http.Error(w, "Unable to create account session", http.StatusInternalServerError)
		return
	}
	if err := s.Store.UpdateAdminLastLogin(r.Context(), adminID); err != nil {
		http.Error(w, "Unable to update account login", http.StatusInternalServerError)
		return
	}
	nameStore, ok := s.Store.(store.AdminUsernameStore)
	if !ok {
		http.Error(w, "Unable to load account profile", http.StatusInternalServerError)
		return
	}
	username, err := nameStore.GetAdminUsername(r.Context(), adminID)
	if err != nil || username == "" {
		http.Error(w, "Unable to load account profile", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "partial_session", Value: "", Path: "/server/auth", MaxAge: -1, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: sessionID, Path: "/", Expires: expires, MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	adminPath := strings.Trim(s.Config.Server.AdminPath, "/")
	if adminPath == "" {
		adminPath = "administration"
	}
	http.Redirect(w, r, "/server/"+adminPath+"/"+url.PathEscape(username)+"/profile/security", http.StatusSeeOther)
}

func (s *Server) loadPartialUser(r *http.Request, token string) (*model.PartialSession, bool) {
	if len(token) < 32 || len(token) > 256 {
		return nil, false
	}
	partialStore, ok := s.Store.(store.PartialSessionStore)
	if !ok {
		return nil, false
	}
	digest := sha256.Sum256([]byte(token))
	partial, err := partialStore.GetPartialSession(r.Context(), hex.EncodeToString(digest[:]), time.Now().UTC())
	return partial, err == nil && partial != nil
}

func (s *Server) consumePartial(r *http.Request, token string) (*model.PartialSession, error) {
	partialStore, ok := s.Store.(store.PartialSessionStore)
	if !ok {
		return nil, fmt.Errorf("partial-session storage is unavailable")
	}
	digest := sha256.Sum256([]byte(token))
	return partialStore.ConsumePartialSession(r.Context(), hex.EncodeToString(digest[:]), time.Now().UTC())
}

func (s *Server) issueUserLoginToken(w http.ResponseWriter, r *http.Request, userID string, remaining *int) {
	user, err := s.Store.GetUser(r.Context(), userID)
	if err != nil || user == nil || user.Disabled || !user.Approved || !user.EmailVerified {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Invalid credentials"})
		return
	}
	apiTokenStore, ok := s.Store.(interface {
		CreateAPIToken(context.Context, *model.APIToken) error
	})
	if !ok {
		writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Token storage is unavailable"})
		return
	}
	suffix, err := handler.GenerateTokenSuffix(32)
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create login token"})
		return
	}
	secret := "usr_" + suffix
	digest := sha256.Sum256([]byte(secret))
	idRaw := make([]byte, 16)
	if _, err := rand.Read(idRaw); err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create login token"})
		return
	}
	expires := time.Now().UTC().Add(24 * time.Hour)
	token := &model.APIToken{ID: hex.EncodeToString(idRaw), UserID: userID, Token: hex.EncodeToString(digest[:]), TokenPrefix: secret[:8], Name: "login", Scope: "read-write", ExpiresAt: &expires, CreatedAt: time.Now().UTC()}
	if err := apiTokenStore.CreateAPIToken(r.Context(), token); err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create login token"})
		return
	}
	if err := s.Store.UpdateUserLastLogin(r.Context(), userID, time.Now().UTC()); err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to update account login"})
		return
	}
	data := map[string]any{"token": secret}
	if remaining != nil {
		data["remaining_keys"] = *remaining
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": data})
	if err := s.createUserNotification(r.Context(), userID, "security", "notifications.session_started", "notifications.session_started_message", "/users/security"); err != nil {
		log.Printf("user session notification failed: %v", err)
	}
}

func (s *Server) issueUserSession(w http.ResponseWriter, r *http.Request, partial *model.PartialSession, redirect string) {
	user, err := s.Store.GetUser(r.Context(), partial.UserID)
	if err != nil || user == nil || user.Disabled || !user.Approved || !user.EmailVerified {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	now := time.Now().UTC()
	expires := now.Add(7 * 24 * time.Hour)
	if partial.Remember {
		expires = now.Add(30 * 24 * time.Hour)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "Unable to create account session", http.StatusInternalServerError)
		return
	}
	sessionID := base64.RawURLEncoding.EncodeToString(raw)
	if err := s.Store.CreateSession(r.Context(), &model.Session{ID: sessionID, UserID: partial.UserID, ExpiresAt: expires, CreatedAt: now}); err != nil {
		http.Error(w, "Unable to create account session", http.StatusInternalServerError)
		return
	}
	if err := s.Store.UpdateUserLastLogin(r.Context(), partial.UserID, now); err != nil {
		http.Error(w, "Unable to update account login", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "partial_session", Value: "", Path: "/server/auth", MaxAge: -1, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: "user_session", Value: sessionID, Path: "/", Expires: expires, MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	if err := s.createUserNotification(r.Context(), partial.UserID, "security", "notifications.session_started", "notifications.session_started_message", "/users/security"); err != nil {
		log.Printf("user session notification failed: %v", err)
	}
	if redirect != "/users/security/2fa" {
		redirect = "/users"
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (s *Server) mfaFailure(w http.ResponseWriter, r *http.Request, isAPI bool, message string) {
	if isAPI {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "INVALID_CHALLENGE", "message": message})
		return
	}
	s.renderMFAChallengeWithMessage(w, r, false, message, http.StatusUnauthorized)
}

func (s *Server) renderMFAChallenge(w http.ResponseWriter, r *http.Request, recovery bool) {
	s.renderMFAChallengeWithMessage(w, r, recovery, "", http.StatusOK)
}

func (s *Server) renderMFAChallengeWithMessage(w http.ResponseWriter, r *http.Request, recovery bool, message string, status int) {
	language := "en"
	if r != nil {
		language, _ = requestLanguage(r)
	}
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Two-factor page unavailable", http.StatusInternalServerError)
		return
	}
	content := ""
	pageTitle := catalog.T("auth.two_factor", nil)
	if recovery {
		content = executeTemplate(recoveryChallengeTemplate, map[string]string{"CodeLabel": catalog.T("auth.recovery_key", nil), "Submit": catalog.T("auth.verify", nil)})
		pageTitle = catalog.T("auth.use_recovery_key", nil)
	} else {
		content = executeTemplate(mfaChallengeTemplate, map[string]string{"Action": "/server/auth/2fa", "CodeLabel": catalog.T("auth.authenticator_code", nil), "Submit": catalog.T("auth.verify", nil), "RecoveryLink": catalog.T("auth.use_recovery_key", nil), "PasskeyLink": catalog.T("auth.passkey_sign_in", nil)})
	}
	if message != "" {
		content = "<p role=\"alert\">" + template.HTMLEscapeString(message) + "</p>" + content
	}
	page := publicPageTemplateData{Title: pageTitle, Lead: catalog.T("auth.two_factor_lead", nil), NoIndex: true, Sections: []renderedPageSection{{ID: "mfa-challenge", Title: pageTitle, Content: template.HTML(content)}}}
	if r != nil {
		if err := s.preparePageChrome(w, r, &page); err != nil {
			http.Error(w, "Two-factor page unavailable", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, page)
}

func (s *Server) handleUserTOTPPage(w http.ResponseWriter, r *http.Request) {
	userID := s.UserHandler.CurrentUserID(r)
	if userID == "" {
		http.Redirect(w, r, "/server/auth/login?redirect=%2Fusers%2Fsecurity%2F2fa", http.StatusSeeOther)
		return
	}
	totpStore, ok := s.Store.(store.UserTOTPStore)
	if !ok {
		http.Error(w, "Two-factor authentication is unavailable", http.StatusServiceUnavailable)
		return
	}
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Two-factor page unavailable", http.StatusInternalServerError)
		return
	}
	message, errorMessage := "", ""
	qrCode, secretValue := "", ""
	var recoveryCodes []string
	enabled := false
	if r.Method == http.MethodPost {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
			http.Error(w, "Two-factor request failed security validation", http.StatusForbidden)
			return
		}
		action := r.FormValue("action")
		payload := map[string]any{"current_password": r.FormValue("current_password"), "code": r.FormValue("code"), "recovery_code": r.FormValue("recovery_code"), "recovery_keys_saved": r.FormValue("recovery_keys_saved") == "true"}
		encoded, _ := json.Marshal(payload)
		apiRequest := r.Clone(r.Context())
		apiRequest.Body = io.NopCloser(strings.NewReader(string(encoded)))
		apiRequest.Header = r.Header.Clone()
		apiRequest.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		switch action {
		case "start", "confirm":
			s.enableUserTOTP(response, apiRequest, userID, totpStore)
		case "disable":
			s.disableUserTOTP(response, apiRequest, userID, totpStore)
		default:
			http.Error(w, "Invalid two-factor action", http.StatusBadRequest)
			return
		}
		var body map[string]any
		if json.Unmarshal(response.Body.Bytes(), &body) != nil {
			errorMessage = catalog.T("auth.mfa_setup_failed", nil)
		} else if response.Code < 200 || response.Code >= 300 {
			errorMessage = catalog.T("auth.mfa_setup_failed", nil)
		} else {
			data, _ := body["data"].(map[string]any)
			if codeValue, ok := data["qr_code"].(string); ok {
				qrCode = codeValue
			}
			if value, ok := data["secret"].(string); ok {
				secretValue = value
			}
			if values, ok := data["recovery_keys"].([]any); ok {
				for _, value := range values {
					if code, ok := value.(string); ok {
						recoveryCodes = append(recoveryCodes, code)
					}
				}
			}
			if value, ok := data["enabled"].(bool); ok {
				enabled = value
				if value {
					message = catalog.T("auth.mfa_enabled", nil)
				}
			}
			if response.Code == http.StatusOK && action == "disable" {
				message, enabled = catalog.T("auth.mfa_disabled", nil), false
			}
			if len(recoveryCodes) > 0 {
				message = catalog.T("auth.recovery_keys_save_now", nil)
			}
			if qrCode == "" {
				qrCode, secretValue = r.FormValue("qr_code"), r.FormValue("secret")
			}
		}
		if errorMessage != "" {
			qrCode, secretValue = r.FormValue("qr_code"), r.FormValue("secret")
		}
	}
	current, err := totpStore.GetUserTOTP(r.Context(), userID)
	if err != nil {
		http.Error(w, "Unable to load two-factor status", http.StatusInternalServerError)
		return
	}
	if current != nil && current.Enabled {
		enabled = true
	}
	csrf := s.issuePreferenceCSRF(w, r)
	content := executeTemplate(userTOTPPageTemplate, map[string]any{
		"CSRF": csrf, "Enabled": enabled, "QR": qrCode, "Secret": secretValue, "RecoveryCodes": recoveryCodes,
		"Message": message, "Error": errorMessage, "EnabledLabel": catalog.T("auth.mfa_enabled", nil),
		"PasswordLabel": catalog.T("auth.current_password", nil), "CodeLabel": catalog.T("auth.authenticator_code", nil),
		"RecoveryLabel": catalog.T("auth.recovery_key", nil), "Disable": catalog.T("auth.mfa_disable", nil),
		"QRLabel": catalog.T("auth.authenticator_qr", nil), "SecretLabel": catalog.T("auth.manual_secret", nil),
		"Verify": catalog.T("auth.verify", nil), "Setup": catalog.T("auth.mfa_setup", nil),
		"RecoveryTitle": catalog.T("auth.recovery_keys", nil), "RecoveryWarning": catalog.T("auth.recovery_keys_save_now", nil),
		"ConfirmSaved": catalog.T("auth.recovery_saved_confirm", nil),
	})
	pageTitle := catalog.T("auth.two_factor", nil)
	page := publicPageTemplateData{Title: pageTitle, Lead: catalog.T("auth.two_factor_lead", nil), NoIndex: true, CSRFToken: csrf, Sections: []renderedPageSection{{ID: "two-factor-settings", Title: pageTitle, Content: template.HTML(content)}}}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, "Unable to prepare two-factor page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := pageTemplate.Execute(w, page); err != nil {
		return
	}
}

func (s *Server) encryptTOTPSecret(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("initialize TOTP encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("initialize TOTP encryption: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("create TOTP nonce: %w", err)
	}
	ciphertext := append(nonce, aead.Seal(nil, nonce, plaintext, []byte("casspeed/user/totp/v1"))...)
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func (s *Server) decryptTOTPSecret(encoded string) ([]byte, error) {
	ciphertext, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode TOTP ciphertext: %w", err)
	}
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("initialize TOTP decryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize TOTP decryption: %w", err)
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("invalid TOTP ciphertext")
	}
	nonce, body := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, body, []byte("casspeed/user/totp/v1"))
	if err != nil {
		return nil, fmt.Errorf("decrypt TOTP secret: %w", err)
	}
	return plaintext, nil
}

func (s *Server) handleUserTOTP(w http.ResponseWriter, r *http.Request) {
	userID := s.UserHandler.CurrentUserID(r)
	if userID == "" {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Authentication required"})
		return
	}
	totpStore, ok := s.Store.(store.UserTOTPStore)
	if !ok {
		writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Two-factor authentication is unavailable"})
		return
	}
	if r.Method == http.MethodGet {
		secret, err := totpStore.GetUserTOTP(r.Context(), userID)
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to load two-factor status"})
			return
		}
		remaining := 0
		if secret != nil && secret.Enabled {
			remaining = len(secret.RecoveryCodeHashes)
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"enabled": secret != nil && secret.Enabled, "recovery_keys_remaining": remaining}})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch strings.TrimSuffix(r.URL.Path, "/") {
	case "/api/v1/users/security/2fa/enable":
		s.enableUserTOTP(w, r, userID, totpStore)
	case "/api/v1/users/security/2fa/disable":
		s.disableUserTOTP(w, r, userID, totpStore)
	case "/api/v1/users/security/recovery/regenerate":
		s.regenerateUserRecoveryCodes(w, r, userID, totpStore)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) enableUserTOTP(w http.ResponseWriter, r *http.Request, userID string, totpStore store.UserTOTPStore) {
	var request struct {
		CurrentPassword   string `json:"current_password"`
		Code              string `json:"code"`
		RecoveryKeysSaved bool   `json:"recovery_keys_saved"`
	}
	if err := decodeMFARequest(w, r, &request); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid two-factor request"})
		return
	}
	user, err := s.Store.GetUser(r.Context(), userID)
	if err != nil || user == nil || request.CurrentPassword != "" && !auth.VerifyPassword(request.CurrentPassword, user.PasswordHash) {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Current password is invalid"})
		return
	}
	current, err := totpStore.GetUserTOTP(r.Context(), userID)
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to load two-factor setup"})
		return
	}
	if current == nil || !current.Enabled && request.Code == "" {
		if request.CurrentPassword == "" {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Current password is required"})
			return
		}
		secret, err := auth.NewTOTPSecret()
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to start two-factor setup"})
			return
		}
		encrypted, err := s.encryptTOTPSecret([]byte(secret))
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to protect authenticator secret"})
			return
		}
		if err := totpStore.SaveUserTOTP(r.Context(), &model.TOTPSecret{UserID: userID, EncryptedSecret: encrypted, Enabled: false, RecoveryCodeHashes: []string{}}); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to save two-factor setup"})
			return
		}
		label := url.PathEscape("CasSpeed:" + user.Username)
		uri := "otpauth://totp/" + label + "?" + url.Values{"secret": {secret}, "issuer": {"CasSpeed"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}.Encode()
		qr, err := qrcode.Encode(uri, qrcode.Medium, 256)
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create authenticator QR code"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]string{"secret": secret, "otpauth_url": uri, "qr_code": base64.StdEncoding.EncodeToString(qr), "next": "verify"}})
		return
	}
	secret, err := s.decryptTOTPSecret(current.EncryptedSecret)
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to read authenticator secret"})
		return
	}
	if !auth.VerifyTOTP(string(secret), request.Code, time.Now().UTC()) {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Authenticator code is invalid"})
		return
	}
	if !request.RecoveryKeysSaved {
		codes, err := auth.NewRecoveryCodes()
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create recovery keys"})
			return
		}
		hashes := hashRecoveryCodes(codes)
		current.Enabled = false
		current.RecoveryCodeHashes = hashes
		if err := totpStore.SaveUserTOTP(r.Context(), current); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to save recovery keys"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"recovery_keys": codes, "requires_saved_confirmation": true}})
		return
	}
	if len(current.RecoveryCodeHashes) != 10 {
		writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "Recovery keys must be generated before activation"})
		return
	}
	current.Enabled = true
	if err := totpStore.SaveUserTOTP(r.Context(), current); err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to enable two-factor authentication"})
		return
	}
	if err := s.createUserNotification(r.Context(), userID, "security", "notifications.mfa_enabled", "notifications.mfa_enabled_message", "/users/security/2fa"); err != nil {
		log.Printf("two-factor notification failed: %v", err)
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]bool{"enabled": true}})
}

func (s *Server) disableUserTOTP(w http.ResponseWriter, r *http.Request, userID string, totpStore store.UserTOTPStore) {
	var request struct {
		CurrentPassword string `json:"current_password"`
		Code            string `json:"code"`
		RecoveryCode    string `json:"recovery_code"`
	}
	if err := decodeMFARequest(w, r, &request); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid two-factor request"})
		return
	}
	user, err := s.Store.GetUser(r.Context(), userID)
	if err != nil || user == nil || !auth.VerifyPassword(request.CurrentPassword, user.PasswordHash) {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Current password is invalid"})
		return
	}
	current, err := totpStore.GetUserTOTP(r.Context(), userID)
	if err != nil || current == nil || !current.Enabled {
		writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "Two-factor authentication is not enabled"})
		return
	}
	secret, err := s.decryptTOTPSecret(current.EncryptedSecret)
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to read authenticator secret"})
		return
	}
	valid := auth.VerifyTOTP(string(secret), request.Code, time.Now().UTC())
	if !valid && request.RecoveryCode != "" {
		_, consumed, consumeErr := totpStore.ConsumeUserRecoveryCode(r.Context(), userID, recoveryCodeHash(request.RecoveryCode))
		if consumeErr != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to validate recovery key"})
			return
		}
		valid = consumed
	}
	if !valid {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Authenticator or recovery code is invalid"})
		return
	}
	if err := totpStore.DeleteUserTOTP(r.Context(), userID); err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to disable two-factor authentication"})
		return
	}
	if err := s.createUserNotification(r.Context(), userID, "security", "notifications.mfa_disabled", "notifications.mfa_disabled_message", "/users/security/2fa"); err != nil {
		log.Printf("two-factor notification failed: %v", err)
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]bool{"enabled": false}})
}

func (s *Server) regenerateUserRecoveryCodes(w http.ResponseWriter, r *http.Request, userID string, totpStore store.UserTOTPStore) {
	var request struct {
		CurrentPassword string `json:"current_password"`
		Code            string `json:"code"`
	}
	if err := decodeMFARequest(w, r, &request); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid recovery-key request"})
		return
	}
	user, err := s.Store.GetUser(r.Context(), userID)
	current, loadErr := totpStore.GetUserTOTP(r.Context(), userID)
	if err != nil || user == nil || !auth.VerifyPassword(request.CurrentPassword, user.PasswordHash) || loadErr != nil || current == nil || !current.Enabled {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Account verification failed"})
		return
	}
	secret, err := s.decryptTOTPSecret(current.EncryptedSecret)
	if err != nil || !auth.VerifyTOTP(string(secret), request.Code, time.Now().UTC()) {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Authenticator code is invalid"})
		return
	}
	codes, err := auth.NewRecoveryCodes()
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create recovery keys"})
		return
	}
	current.RecoveryCodeHashes = hashRecoveryCodes(codes)
	if err := totpStore.SaveUserTOTP(r.Context(), current); err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to save recovery keys"})
		return
	}
	if err := s.createUserNotification(r.Context(), userID, "security", "notifications.recovery_keys_regenerated", "notifications.recovery_keys_regenerated_message", "/users/security/2fa"); err != nil {
		log.Printf("recovery-key notification failed: %v", err)
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"recovery_keys": codes, "count": len(codes)}})
}

func decodeMFARequest(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func hashRecoveryCodes(codes []string) []string {
	hashes := make([]string, len(codes))
	for i, code := range codes {
		hashes[i] = recoveryCodeHash(code)
	}
	return hashes
}

func recoveryCodeHash(code string) string {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	digest := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(digest[:])
}
