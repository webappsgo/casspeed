package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/casapps/casspeed/src/admin"
	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const webAuthnCeremonyTTL = 3 * time.Minute

type passkeyAttempt struct {
	failures                 int
	windowUntil, lockedUntil time.Time
}

var passkeyAttemptState = struct {
	sync.Mutex
	users map[string]passkeyAttempt
}{users: make(map[string]passkeyAttempt)}

type passkeyOwner struct {
	userType string
	userID   string
	username string
	user     *model.User
	admin    *model.Admin
	creds    []webauthn.Credential
}

func (o *passkeyOwner) WebAuthnID() []byte {
	if o.user != nil {
		return []byte("user:" + strconv.FormatInt(o.user.ID, 10))
	}
	return []byte("admin:" + o.userID)
}
func (o *passkeyOwner) WebAuthnName() string { return o.username }
func (o *passkeyOwner) WebAuthnDisplayName() string {
	if o.user != nil && o.user.DisplayName != "" {
		return o.user.DisplayName
	}
	return o.username
}
func (o *passkeyOwner) WebAuthnCredentials() []webauthn.Credential { return o.creds }

type passkeyRequest struct {
	Username          string          `json:"username"`
	ChallengeID       string          `json:"challenge_id"`
	CurrentPassword   string          `json:"current_password"`
	Name              string          `json:"name"`
	Action            string          `json:"action"`
	Credential        json.RawMessage `json:"credential"`
	Browser           bool            `json:"browser"`
	PasskeyID         string          `json:"passkey_id"`
	RecoveryKeysSaved bool            `json:"recovery_keys_saved"`
	PartialToken      string          `json:"partial_token"`
}

type passkeyListItem struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	Active    bool       `json:"active"`
}

var passkeyPageTemplate = template.Must(template.New("passkey-page").Parse(`<section aria-labelledby="passkeys-heading"><h2 id="passkeys-heading">{{.Heading}}</h2>{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}{{if .Message}}<p role="status">{{.Message}}</p>{{end}}<form id="passkey-register" data-setup="{{.SetupURL}}" data-register="{{.RegisterURL}}" data-unsupported="{{.Unsupported}}" data-waiting="{{.Waiting}}" data-save-keys="{{.SaveKeys}}" data-failed="{{.Failed}}" data-activation-failed="{{.ActivationFailed}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="passkey-password">{{.PasswordLabel}}</label><input id="passkey-password" name="current_password" type="password" autocomplete="current-password" required><label for="passkey-name">{{.NameLabel}}</label><input id="passkey-name" name="name" maxlength="64" required><button type="submit">{{.RegisterLabel}}</button><p id="passkey-status" role="status" aria-live="polite"></p></form><section id="passkey-recovery" hidden aria-labelledby="passkey-recovery-heading"><h3 id="passkey-recovery-heading">{{.RecoveryHeading}}</h3><p>{{.RecoveryWarning}}</p><ul id="passkey-recovery-list"></ul><label><input id="passkey-recovery-saved" type="checkbox"> {{.SavedLabel}}</label><button id="passkey-activate" type="button" disabled>{{.ActivateLabel}}</button></section>{{if .Passkeys}}<ul>{{range .Passkeys}}<li>{{.Name}} {{if not .Active}}<strong>{{$.PendingLabel}}</strong>{{end}} <form method="post" action="{{$.RevokeBase}}/{{.ID}}/revoke"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><button class="btn btn-danger" type="button" popovertarget="revoke-passkey-{{.ID}}">{{$.RevokeLabel}}</button><div id="revoke-passkey-{{.ID}}" popover aria-labelledby="revoke-passkey-title-{{.ID}}"><h3 id="revoke-passkey-title-{{.ID}}">{{$.RevokeLabel}}</h3><p>{{$.RevokeLabel}}: {{.Name}}</p><button class="btn btn-secondary" type="button" popovertarget="revoke-passkey-{{.ID}}" popovertargetaction="hide">{{$.CancelLabel}}</button><button class="btn btn-danger" type="submit">{{$.ConfirmLabel}}</button></div></form></li>{{end}}</ul>{{else}}<p>{{.EmptyLabel}}</p>{{end}}<script src="/static/js/passkeys.js" defer></script></section>`))

var passkeyLoginTemplate = template.Must(template.New("passkey-login").Parse(`<form id="passkey-login" action="/server/auth/passkey/challenge" data-verify="/server/auth/passkey/verify" data-unsupported="{{.Unsupported}}" data-waiting="{{.Waiting}}" data-failed="{{.Failed}}"><label for="passkey-username">{{.Username}}</label><input id="passkey-username" name="username" autocomplete="username" {{if .RequireUsername}}required{{end}}><button type="submit">{{.SignIn}}</button><p id="passkey-status" role="status" aria-live="polite"></p></form><script src="/static/js/passkeys.js" defer></script>`))

func (s *Server) passkeyStore() (store.PasskeyStore, bool) {
	st, ok := s.Store.(store.PasskeyStore)
	return st, ok
}

func (s *Server) hasActivePasskey(ctx context.Context, userType, userID string) bool {
	st, ok := s.passkeyStore()
	if !ok {
		return false
	}
	items, err := st.GetPasskeys(ctx, userType, userID)
	if err != nil {
		return false
	}
	for _, item := range items {
		if item.Active {
			return true
		}
	}
	return false
}

func passkeyAccountLocked(owner *passkeyOwner, now time.Time) bool {
	if owner == nil || owner.userType != "user" {
		return false
	}
	key := owner.userType + ":" + owner.userID
	passkeyAttemptState.Lock()
	defer passkeyAttemptState.Unlock()
	state := passkeyAttemptState.users[key]
	if state.lockedUntil.After(now) {
		return true
	}
	if !state.lockedUntil.IsZero() && !state.lockedUntil.After(now) {
		delete(passkeyAttemptState.users, key)
	}
	return false
}

func (s *Server) recordPasskeyFailure(r *http.Request, owner *passkeyOwner) {
	s.recordFailedAuthentication(r)
	if owner == nil {
		return
	}
	now := time.Now().UTC()
	if owner.userType == "admin" && owner.admin != nil {
		attempts := owner.admin.FailedAttempts + 1
		_ = s.Store.UpdateAdminFailedAttempts(r.Context(), owner.admin.ID, attempts)
		if attempts >= 5 {
			_ = s.Store.LockAdmin(r.Context(), owner.admin.ID, now.Add(15*time.Minute))
		}
		return
	}
	if owner.userType != "user" {
		return
	}
	key := owner.userType + ":" + owner.userID
	passkeyAttemptState.Lock()
	defer passkeyAttemptState.Unlock()
	state := passkeyAttemptState.users[key]
	if state.windowUntil.Before(now) {
		state = passkeyAttempt{windowUntil: now.Add(15 * time.Minute)}
	}
	state.failures++
	if state.failures >= 5 {
		state.lockedUntil = now.Add(15 * time.Minute)
	}
	passkeyAttemptState.users[key] = state
}

func resetPasskeyFailure(owner *passkeyOwner) {
	if owner == nil || owner.userType != "user" {
		return
	}
	passkeyAttemptState.Lock()
	delete(passkeyAttemptState.users, owner.userType+":"+owner.userID)
	passkeyAttemptState.Unlock()
}

func validPasskeyCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(preferenceCSRFCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	provided := r.Header.Get("X-CSRF-Token")
	if provided == "" {
		provided = r.FormValue("csrf_token")
	}
	if provided == "" || len(provided) != len(cookie.Value) {
		return false
	}
	left, right := sha256.Sum256([]byte(cookie.Value)), sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func (s *Server) passkeyAPIUser(r *http.Request) (*model.User, bool) {
	if s.UserHandler == nil {
		return nil, false
	}
	id := s.UserHandler.CurrentUserID(r)
	if id == "" {
		return nil, false
	}
	user, err := s.Store.GetUser(r.Context(), id)
	return user, err == nil && user != nil && user.EmailVerified && user.Approved && !user.Disabled
}

func (s *Server) passkeyMutationAllowed(r *http.Request, userID string) bool {
	if token, ok := r.Context().Value(apiTokenContextKey{}).(apiTokenIdentity); ok {
		return token.UserID == userID && (token.Scope == "read-write" || token.Scope == "global")
	}
	return sameOriginPageRequest(r) && validPasskeyCSRF(r)
}

func (s *Server) passkeyAdminIdentity(r *http.Request) (*model.Admin, bool) {
	if account, ok := s.adminMFAIdentity(r); ok {
		return account, true
	}
	token, ok := r.Context().Value(apiTokenContextKey{}).(apiTokenIdentity)
	if !ok || !token.Admin || token.ID == "operator" {
		return nil, false
	}
	account, err := s.Store.GetAdminByUsername(r.Context(), r.PathValue("username"))
	if err != nil || account == nil || !account.Enabled || strconv.Itoa(account.ID) != token.ID {
		return nil, false
	}
	return account, true
}

func (s *Server) passkeyAdminMutationAllowed(r *http.Request, adminID int) bool {
	if token, ok := r.Context().Value(apiTokenContextKey{}).(apiTokenIdentity); ok {
		return token.Admin && token.ID == strconv.Itoa(adminID) && (token.Scope == "global" || token.Scope == "read-write")
	}
	return sameOriginPageRequest(r) && validPasskeyCSRF(r)
}

func (s *Server) webAuthnForRequest(r *http.Request) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(BuildURL(r, "/"))
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("invalid relying party origin")
	}
	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return nil, fmt.Errorf("WebAuthn requires HTTPS")
	}
	return webauthn.New(&webauthn.Config{RPDisplayName: "CasSpeed", RPID: u.Hostname(), RPOrigins: []string{u.Scheme + "://" + u.Host}})
}

func (s *Server) loadPasskeyOwner(ctx context.Context, userType, userID string) (*passkeyOwner, error) {
	st, ok := s.passkeyStore()
	if !ok {
		return nil, fmt.Errorf("passkey storage unavailable")
	}
	o := &passkeyOwner{userType: userType, userID: userID}
	if userType == "user" {
		user, err := s.Store.GetUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		if user == nil || !user.EmailVerified || !user.Approved || user.Disabled {
			return nil, fmt.Errorf("owner not found")
		}
		o.user, o.username = user, user.Username
	} else if userType == "admin" {
		id, err := strconv.Atoi(userID)
		if err != nil {
			return nil, err
		}
		names, ok := s.Store.(store.AdminUsernameStore)
		if !ok {
			return nil, fmt.Errorf("admin identity unavailable")
		}
		name, err := names.GetAdminUsername(ctx, id)
		if err != nil {
			return nil, err
		}
		account, err := s.Store.GetAdminByUsername(ctx, name)
		if err != nil {
			return nil, err
		}
		if account == nil || !account.Enabled {
			return nil, fmt.Errorf("owner not found")
		}
		o.admin, o.username = account, name
	} else {
		return nil, fmt.Errorf("invalid owner type")
	}
	rows, err := st.GetPasskeys(ctx, userType, userID)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if !row.Active {
			continue
		}
		var credential webauthn.Credential
		if err := json.Unmarshal([]byte(row.CredentialJSON), &credential); err != nil {
			return nil, fmt.Errorf("decode stored passkey: %w", err)
		}
		o.creds = append(o.creds, credential)
	}
	return o, nil
}

func passkeyChallengeKey() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:]), token, nil
}

func (s *Server) saveWebAuthnChallenge(r *http.Request, owner *passkeyOwner, session *webauthn.SessionData) (string, error) {
	st, ok := s.passkeyStore()
	if !ok {
		return "", fmt.Errorf("passkey storage unavailable")
	}
	digest, token, err := passkeyChallengeKey()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	err = st.CreateWebAuthnChallenge(r.Context(), &model.WebAuthnChallenge{ID: digest, UserType: owner.userType, UserID: owner.userID, SessionJSON: string(data), ExpiresAt: time.Now().UTC().Add(webAuthnCeremonyTTL)})
	return token, err
}

func decodePasskeyRequest(w http.ResponseWriter, r *http.Request, target *passkeyRequest) error {
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(target)
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	target.ChallengeID, target.CurrentPassword, target.Name = r.FormValue("challenge_id"), r.FormValue("current_password"), strings.TrimSpace(r.FormValue("name"))
	return nil
}

func (s *Server) handlePasskeyLoginChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req passkeyRequest
	if err := decodePasskeyRequest(w, r, &req); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid passkey request"})
		return
	}
	var owner *passkeyOwner
	partialToken := req.PartialToken
	if cookie, err := r.Cookie("partial_session"); err == nil && cookie.Value != "" {
		partialToken = cookie.Value
	}
	if partialToken != "" {
		if partial, valid := s.loadPartialUser(r, partialToken); valid {
			owner, _ = s.loadPasskeyOwner(r.Context(), partial.UserType, partial.UserID)
		}
	}
	if owner == nil {
		if a, err := s.Store.GetAdminByUsername(r.Context(), strings.TrimSpace(req.Username)); err == nil && a != nil && a.Enabled && (a.LockedUntil.IsZero() || time.Now().After(a.LockedUntil)) {
			owner, _ = s.loadPasskeyOwner(r.Context(), "admin", strconv.Itoa(a.ID))
		}
	}
	if owner == nil && s.Config != nil && s.Config.Server.Users.Enabled {
		u, err := s.Store.GetUserByUsername(r.Context(), strings.TrimSpace(req.Username))
		if err == nil && u == nil && strings.Contains(req.Username, "@") {
			u, err = s.Store.GetUserByEmail(r.Context(), strings.TrimSpace(req.Username))
		}
		if err == nil && u != nil && u.EmailVerified {
			owner, _ = s.loadPasskeyOwner(r.Context(), "user", model.UserIDString(u.ID))
		}
	}
	if owner == nil || len(owner.creds) == 0 || passkeyAccountLocked(owner, time.Now().UTC()) {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Invalid credentials"})
		return
	}
	wa, err := s.webAuthnForRequest(r)
	if err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Passkeys require a valid secure origin"})
		return
	}
	options, session, err := wa.BeginLogin(owner)
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to begin passkey authentication"})
		return
	}
	token, err := s.saveWebAuthnChallenge(r, owner, session)
	if err != nil {
		writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Passkey authentication unavailable"})
		return
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"challenge_id": token, "publicKey": options.Response}})
}

func (s *Server) consumeWebAuthnChallenge(r *http.Request, token string) (*model.WebAuthnChallenge, *webauthn.SessionData, error) {
	if len(token) < 40 || len(token) > 64 {
		return nil, nil, fmt.Errorf("invalid ceremony")
	}
	digest := sha256.Sum256([]byte(token))
	st, ok := s.passkeyStore()
	if !ok {
		return nil, nil, fmt.Errorf("passkey storage unavailable")
	}
	row, err := st.ConsumeWebAuthnChallenge(r.Context(), hex.EncodeToString(digest[:]), time.Now().UTC())
	if err != nil || row == nil {
		return nil, nil, fmt.Errorf("expired ceremony")
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(row.SessionJSON), &session); err != nil {
		return nil, nil, err
	}
	return row, &session, nil
}

func (s *Server) handlePasskeyLoginVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid passkey response"})
		return
	}
	var req passkeyRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.Credential) == 0 {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid passkey response"})
		return
	}
	challenge, session, err := s.consumeWebAuthnChallenge(r, req.ChallengeID)
	if err != nil {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Invalid credentials"})
		return
	}
	owner, err := s.loadPasskeyOwner(r.Context(), challenge.UserType, challenge.UserID)
	if err != nil {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Invalid credentials"})
		return
	}
	wa, err := s.webAuthnForRequest(r)
	if err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid passkey origin"})
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(req.Credential))
	credential, err := wa.FinishLogin(owner, *session, r)
	if err != nil {
		s.recordPasskeyFailure(r, owner)
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Invalid credentials"})
		return
	}
	st, _ := s.passkeyStore()
	stored, err := st.GetPasskey(r.Context(), base64.RawURLEncoding.EncodeToString(credential.ID))
	if err != nil || stored == nil || stored.UserType != owner.userType || stored.UserID != owner.userID {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Invalid credentials"})
		return
	}
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to update passkey"})
		return
	}
	stored.CredentialJSON, stored.SignCount = string(credentialJSON), credential.Authenticator.SignCount
	now := time.Now().UTC()
	stored.LastUsed = &now
	if err := st.UpdatePasskey(r.Context(), stored); err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to update passkey"})
		return
	}
	resetPasskeyFailure(owner)
	partialToken := req.PartialToken
	browser := req.Browser
	if cookie, cookieErr := r.Cookie("partial_session"); cookieErr == nil && cookie.Value != "" {
		partialToken = cookie.Value
		browser = true
	}
	if partialToken != "" {
		partial, valid := s.loadPartialUser(r, partialToken)
		if !valid || partial.UserType != owner.userType || partial.UserID != owner.userID {
			writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Invalid credentials"})
			return
		}
		consumed, consumeErr := s.consumePartial(r, partialToken)
		if consumeErr != nil || consumed == nil {
			writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Invalid credentials"})
			return
		}
		if browser {
			s.issuePasskeyBrowserSession(w, r, consumed)
			return
		}
		if consumed.UserType == "admin" {
			id, _ := strconv.Atoi(consumed.UserID)
			if err := s.Store.UpdateAdminLastLogin(r.Context(), id); err != nil {
				writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to update account login"})
				return
			}
			s.issueAdminLoginToken(w, r, id, nil)
		} else {
			s.issueUserLoginToken(w, r, consumed.UserID, nil)
		}
		return
	}
	s.completePasskeyLogin(w, r, owner, browser)
}

func (s *Server) completePasskeyLogin(w http.ResponseWriter, r *http.Request, owner *passkeyOwner, browser bool) {
	remember := false
	if owner.userType == "user" {
		if mfa, ok := s.Store.(store.UserTOTPStore); ok {
			secret, err := mfa.GetUserTOTP(r.Context(), owner.userID)
			if err != nil {
				writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to load account security"})
				return
			}
			if secret != nil && secret.Enabled {
				s.writePartialPasskeyLogin(w, r, owner, remember)
				return
			}
		}
		if !browser {
			s.issueUserLoginToken(w, r, owner.userID, nil)
			return
		}
		ss := auth.NewSession(owner.userID, peerIP(r.RemoteAddr), r.UserAgent())
		if err := s.Store.CreateSession(r.Context(), &model.Session{ID: ss.ID, UserID: ss.UserID, ExpiresAt: ss.ExpiresAt, CreatedAt: ss.CreatedAt}); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create session"})
			return
		}
		if err := s.Store.UpdateUserLastLogin(r.Context(), owner.userID, time.Now().UTC()); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to update account login"})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "user_session", Value: ss.ID, Path: "/", Expires: ss.ExpiresAt, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	} else {
		if mfa, ok := s.Store.(store.AdminTOTPStore); ok {
			id, _ := strconv.Atoi(owner.userID)
			secret, err := mfa.GetAdminTOTP(r.Context(), id)
			if err != nil {
				writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to load account security"})
				return
			}
			if secret != nil && secret.Enabled {
				s.writePartialPasskeyLogin(w, r, owner, remember)
				return
			}
		}
		id, _ := strconv.Atoi(owner.userID)
		if !browser {
			if err := s.Store.UpdateAdminLastLogin(r.Context(), id); err != nil {
				writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to update account login"})
				return
			}
			s.issueAdminLoginToken(w, r, id, nil)
			return
		}
		sid := make([]byte, 32)
		if _, err := rand.Read(sid); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create session"})
			return
		}
		token := base64.RawURLEncoding.EncodeToString(sid)
		expiry := time.Now().UTC().Add(8 * time.Hour)
		if err := s.Store.CreateAdminSession(r.Context(), &model.AdminSession{ID: token, AdminID: id, IPAddress: peerIP(r.RemoteAddr), UserAgent: r.UserAgent(), ExpiresAt: expiry}); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create session"})
			return
		}
		if err := s.Store.UpdateAdminLastLogin(r.Context(), id); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to update account login"})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: token, Path: "/", Expires: expiry, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"authenticated": true}})
}

func (s *Server) writePartialPasskeyLogin(w http.ResponseWriter, r *http.Request, owner *passkeyOwner, remember bool) {
	token, err := s.createPartialAuthentication(r.Context(), owner.userID, owner.userType, remember)
	if err != nil {
		writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Unable to start two-factor verification"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "partial_session", Value: token, Path: "/server/auth", MaxAge: 300, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"requires_2fa": true, "partial_token": token}})
}

func (s *Server) issuePasskeyBrowserSession(w http.ResponseWriter, r *http.Request, partial *model.PartialSession) {
	now := time.Now().UTC()
	if partial.UserType == "user" {
		user, err := s.Store.GetUser(r.Context(), partial.UserID)
		if err != nil || user == nil || user.Disabled || !user.Approved || !user.EmailVerified {
			writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Invalid credentials"})
			return
		}
		expires := now.Add(7 * 24 * time.Hour)
		if partial.Remember {
			expires = now.Add(30 * 24 * time.Hour)
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create session"})
			return
		}
		id := base64.RawURLEncoding.EncodeToString(raw)
		if err := s.Store.CreateSession(r.Context(), &model.Session{ID: id, UserID: partial.UserID, ExpiresAt: expires, CreatedAt: now}); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create session"})
			return
		}
		if err := s.Store.UpdateUserLastLogin(r.Context(), partial.UserID, now); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to update account login"})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "user_session", Value: id, Path: "/", Expires: expires, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	} else {
		id, err := strconv.Atoi(partial.UserID)
		if err != nil {
			writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Invalid credentials"})
			return
		}
		expires := now.Add(8 * time.Hour)
		if partial.Remember {
			expires = now.Add(30 * 24 * time.Hour)
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create session"})
			return
		}
		sid := base64.RawURLEncoding.EncodeToString(raw)
		if err := s.Store.CreateAdminSession(r.Context(), &model.AdminSession{ID: sid, AdminID: id, IPAddress: peerIP(r.RemoteAddr), UserAgent: r.UserAgent(), ExpiresAt: expires}); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create session"})
			return
		}
		if err := s.Store.UpdateAdminLastLogin(r.Context(), id); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to update account login"})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: sid, Path: "/", Expires: expires, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	}
	http.SetCookie(w, &http.Cookie{Name: "partial_session", Value: "", Path: "/server/auth", MaxAge: -1, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteStrictMode})
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]bool{"authenticated": true}})
}

func (s *Server) handleUserPasskeys(w http.ResponseWriter, r *http.Request) {
	identity, err := s.userPageIdentity(r)
	if err != nil {
		http.Error(w, "Unable to load passkeys", http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		http.Redirect(w, r, "/server/auth/login", http.StatusSeeOther)
		return
	}
	s.handlePasskeyManagement(w, r, &passkeyOwner{userType: "user", userID: model.UserIDString(identity.User.ID), username: identity.User.Username, user: identity.User}, "/api/v1/users/security/passkeys", "/api/v1/users/security/passkeys")
}

func (s *Server) handleAdminPasskeys(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.adminMFAIdentity(r)
	if !ok {
		http.Redirect(w, r, "/server/auth/login", http.StatusSeeOther)
		return
	}
	s.handlePasskeyManagement(w, r, &passkeyOwner{userType: "admin", userID: strconv.Itoa(owner.ID), username: owner.Username, admin: owner}, "/api/v1/server/"+strings.Trim(s.Config.Server.AdminPath, "/")+"/"+url.PathEscape(owner.Username)+"/profile/security/passkey/setup", "/api/v1/server/"+strings.Trim(s.Config.Server.AdminPath, "/")+"/"+url.PathEscape(owner.Username)+"/profile/security/passkey/register")
}

func (s *Server) handleUserPasskeyAPI(w http.ResponseWriter, r *http.Request) {
	user, authenticated := s.passkeyAPIUser(r)
	if r.Method == http.MethodGet {
		if !authenticated {
			writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Authentication required"})
			return
		}
		rows, err := s.passkeyRows(r, "user", model.UserIDString(user.ID))
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to load passkeys"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": rows})
		return
	}
	if r.Method == http.MethodDelete {
		if !authenticated {
			writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Authentication required"})
			return
		}
		userID := model.UserIDString(user.ID)
		if !s.passkeyMutationAllowed(r, userID) {
			writeUserJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "Request failed security validation"})
			return
		}
		st, ok := s.passkeyStore()
		if !ok {
			writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Passkeys unavailable"})
			return
		}
		if err := st.DeletePasskey(r.Context(), "user", userID, r.PathValue("passkey_id")); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to revoke passkey"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !authenticated {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Authentication required"})
		return
	}
	userID := model.UserIDString(user.ID)
	if !s.passkeyMutationAllowed(r, userID) {
		writeUserJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "Request failed security validation"})
		return
	}
	owner := &passkeyOwner{userType: "user", userID: userID, username: user.Username, user: user}
	s.handlePasskeyRegistrationAPI(w, r, owner, true)
}

func (s *Server) handleAdminPasskeyAPI(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.passkeyAdminIdentity(r)
	if !ok {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Authentication required"})
		return
	}
	account := &passkeyOwner{userType: "admin", userID: strconv.Itoa(owner.ID), username: owner.Username, admin: owner}
	if r.Method == http.MethodGet {
		rows, err := s.passkeyRows(r, "admin", account.userID)
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to load passkeys"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": rows})
		return
	}
	if r.Method == http.MethodDelete {
		if !s.passkeyAdminMutationAllowed(r, owner.ID) {
			writeUserJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "Request failed security validation"})
			return
		}
		st, ok := s.passkeyStore()
		if !ok {
			writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Passkeys unavailable"})
			return
		}
		if err := st.DeletePasskey(r.Context(), "admin", account.userID, r.PathValue("passkey_id")); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to revoke passkey"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.passkeyAdminMutationAllowed(r, owner.ID) {
		writeUserJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "Request failed security validation"})
		return
	}
	s.handlePasskeyRegistrationAPI(w, r, account, true)
}

func (s *Server) passkeyRows(r *http.Request, userType, userID string) ([]passkeyListItem, error) {
	st, ok := s.passkeyStore()
	if !ok {
		return nil, fmt.Errorf("passkeys unavailable")
	}
	rows, err := st.GetPasskeys(r.Context(), userType, userID)
	if err != nil {
		return nil, err
	}
	items := make([]passkeyListItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, passkeyListItem{ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt, LastUsed: row.LastUsed, Active: row.Active})
	}
	return items, nil
}

func (s *Server) handlePasskeyRegistrationAPI(w http.ResponseWriter, r *http.Request, owner *passkeyOwner, requirePassword bool) {
	body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if readErr != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid passkey request"})
		return
	}
	var req passkeyRequest
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(body, &req); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid passkey request"})
			return
		}
	} else {
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid passkey request"})
			return
		}
		req.Action, req.ChallengeID, req.CurrentPassword, req.Name = vals.Get("action"), vals.Get("challenge_id"), vals.Get("current_password"), vals.Get("name")
		if raw := vals.Get("credential"); raw != "" {
			req.Credential = json.RawMessage(raw)
		}
	}
	currentPassword := req.CurrentPassword
	if req.Action == "confirm" {
		if !requirePassword || !verifyPasskeySetupPassword(owner, currentPassword) || !req.RecoveryKeysSaved || req.PasskeyID == "" {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Save the recovery keys and confirm your password before activation"})
			return
		}
		st, ok := s.passkeyStore()
		if !ok {
			writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Passkeys unavailable"})
			return
		}
		if err := st.ActivatePasskey(r.Context(), owner.userType, owner.userID, req.PasskeyID); err != nil {
			writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "Pending passkey is unavailable"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]bool{"active": true}})
		return
	}
	setup := strings.HasSuffix(r.URL.Path, "/setup") || req.Action == "setup"
	if setup {
		if requirePassword && !verifyPasskeySetupPassword(owner, currentPassword) {
			writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Current password is invalid"})
			return
		}
		actualOwner, err := s.loadPasskeyOwner(r.Context(), owner.userType, owner.userID)
		if err != nil {
			writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Passkeys unavailable"})
			return
		}
		wa, err := s.webAuthnForRequest(r)
		if err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Passkeys require a valid secure origin"})
			return
		}
		options, session, err := wa.BeginRegistration(actualOwner, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementPreferred, UserVerification: protocol.VerificationPreferred}))
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to begin passkey registration"})
			return
		}
		token, err := s.saveWebAuthnChallenge(r, actualOwner, session)
		if err != nil {
			writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Passkey registration unavailable"})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"challenge_id": token, "publicKey": options.Response}})
		return
	}
	if len([]rune(strings.TrimSpace(req.Name))) > 64 || strings.TrimSpace(req.Name) == "" {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "A passkey name of 1 to 64 characters is required"})
		return
	}
	if requirePassword && !verifyPasskeySetupPassword(owner, currentPassword) {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Current password is invalid"})
		return
	}
	if req.ChallengeID == "" || len(req.Credential) == 0 || req.Name == "" {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid passkey registration"})
		return
	}
	challenge, session, err := s.consumeWebAuthnChallenge(r, req.ChallengeID)
	if err != nil || challenge.UserType != owner.userType || challenge.UserID != owner.userID {
		writeUserJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Invalid or expired registration"})
		return
	}
	wa, err := s.webAuthnForRequest(r)
	if err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid passkey origin"})
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(req.Credential))
	credential, err := wa.FinishRegistration(owner, *session, r)
	if err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Passkey registration failed"})
		return
	}
	serialized, err := json.Marshal(credential)
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to save passkey"})
		return
	}
	transports, _ := json.Marshal(credential.Transport)
	aaguid := hex.EncodeToString(credential.Authenticator.AAGUID)
	id := base64.RawURLEncoding.EncodeToString(credential.ID)
	st, _ := s.passkeyStore()
	existing, err := st.GetPasskeys(r.Context(), owner.userType, owner.userID)
	if err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to load passkeys"})
		return
	}
	active, pending := false, false
	for _, item := range existing {
		if item.Active {
			active = true
		} else {
			pending = true
		}
	}
	if pending {
		writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "Confirm or revoke the pending passkey before registering another"})
		return
	}
	var recoveryCodes []string
	if !active {
		recoveryCodes, err = auth.NewRecoveryCodes()
		if err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to create recovery keys"})
			return
		}
		if err := st.CreatePasskeyRecoveryCodes(r.Context(), owner.userType, owner.userID, hashRecoveryCodes(recoveryCodes)); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to save recovery keys"})
			return
		}
	}
	if err := st.SavePasskey(r.Context(), &model.Passkey{ID: id, UserType: owner.userType, UserID: owner.userID, Name: strings.TrimSpace(req.Name), CredentialJSON: string(serialized), SignCount: credential.Authenticator.SignCount, Transports: string(transports), AAGUID: aaguid, CreatedAt: time.Now().UTC(), Active: active}); err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to save passkey"})
		return
	}
	data := map[string]any{"id": id, "name": strings.TrimSpace(req.Name), "active": active}
	if len(recoveryCodes) > 0 {
		data["recovery_keys"] = recoveryCodes
		data["requires_saved_confirmation"] = true
	}
	writeUserJSON(w, http.StatusCreated, map[string]any{"ok": true, "data": data})
}

func (s *Server) handlePasskeyManagement(w http.ResponseWriter, r *http.Request, owner *passkeyOwner, setupPath, registerPath string) {
	st, ok := s.passkeyStore()
	if !ok {
		http.Error(w, "Passkeys unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.passkeyRows(r, owner.userType, owner.userID)
		if err != nil {
			http.Error(w, "Unable to load passkeys", http.StatusInternalServerError)
			return
		}
		csrf := s.issuePreferenceCSRF(w, r)
		language, _ := requestLanguage(r)
		catalog, _ := i18n.Resolve(language)
		data := struct {
			Heading, Error, Message, SetupURL, RegisterURL, RevokeBase, CSRF, PasswordLabel, NameLabel, RegisterLabel, RevokeLabel, ConfirmLabel, CancelLabel, EmptyLabel, RecoveryHeading, RecoveryWarning, SavedLabel, ActivateLabel, PendingLabel, Unsupported, Waiting, SaveKeys, Failed, ActivationFailed string
			Passkeys                                                                                                                                                                                                                                                                                           []passkeyListItem
		}{Heading: catalog.T("auth.passkeys", nil), SetupURL: setupPath, RegisterURL: registerPath, RevokeBase: "/users/security/passkeys", CSRF: csrf, PasswordLabel: catalog.T("auth.current_password", nil), NameLabel: catalog.T("auth.passkey_name", nil), RegisterLabel: catalog.T("auth.passkey_register", nil), RevokeLabel: catalog.T("auth.passkey_revoke", nil), ConfirmLabel: catalog.T("common.confirm", nil), CancelLabel: catalog.T("common.cancel", nil), EmptyLabel: catalog.T("auth.passkey_empty", nil), RecoveryHeading: catalog.T("auth.recovery_keys", nil), RecoveryWarning: catalog.T("auth.recovery_keys_save_now", nil), SavedLabel: catalog.T("auth.recovery_saved_confirm", nil), ActivateLabel: catalog.T("auth.passkey_activate", nil), PendingLabel: catalog.T("auth.passkey_pending", nil), Unsupported: catalog.T("auth.passkey_unsupported", nil), Waiting: catalog.T("auth.passkey_waiting", nil), SaveKeys: catalog.T("auth.passkey_save_keys", nil), Failed: catalog.T("auth.passkey_failed", nil), ActivationFailed: catalog.T("auth.passkey_activation_failed", nil), Passkeys: rows}
		if owner.userType == "admin" {
			data.RevokeBase = r.URL.Path
		}
		title := catalog.T("auth.passkeys", nil)
		content := executeTemplate(passkeyPageTemplate, data)
		if owner.userType == "admin" {
			s.AdminHandler.RenderContentPage(w, r, title, catalog.T("auth.passkeys_lead", nil), content)
			return
		}
		page := publicPageTemplateData{Title: title, Lead: catalog.T("auth.passkeys_lead", nil), NoIndex: true, Sections: []renderedPageSection{{ID: "passkeys", Title: title, Content: template.HTML(content)}}}
		if err := s.preparePageChrome(w, r, &page); err != nil {
			http.Error(w, "Page unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_ = pageTemplate.Execute(w, page)
	case http.MethodPost:
		if !sameOriginPageRequest(r) {
			http.Error(w, "Request failed security validation", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		if !validPreferenceCSRF(r) {
			http.Error(w, "Request failed security validation", http.StatusForbidden)
			return
		}
		id := r.PathValue("passkeyID")
		if id != "" {
			if err := st.DeletePasskey(r.Context(), owner.userType, owner.userID, id); err != nil {
				http.Error(w, "Unable to revoke passkey", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, strings.TrimSuffix(r.URL.Path, "/"+id+"/revoke"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePasskeyLoginPage(w http.ResponseWriter, r *http.Request) {
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Page unavailable", http.StatusInternalServerError)
		return
	}
	title := catalog.T("auth.passkey_sign_in", nil)
	_, partialErr := r.Cookie("partial_session")
	content := executeTemplate(passkeyLoginTemplate, map[string]any{"Username": catalog.T("auth.username", nil), "SignIn": title, "RequireUsername": partialErr != nil, "Unsupported": catalog.T("auth.passkey_unsupported", nil), "Waiting": catalog.T("auth.passkey_waiting", nil), "Failed": catalog.T("auth.passkey_failed", nil)})
	page := publicPageTemplateData{Title: title, Lead: catalog.T("auth.two_factor_lead", nil), NoIndex: true, Sections: []renderedPageSection{{ID: "passkey-login", Title: title, Content: template.HTML(content)}}}
	if err := s.preparePageChrome(w, r, &page); err != nil {
		http.Error(w, "Page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_ = pageTemplate.Execute(w, page)
}

// Keep the setup password check adjacent to the registration ceremony.
func verifyPasskeySetupPassword(owner *passkeyOwner, password string) bool {
	if owner.user != nil {
		return auth.VerifyPassword(password, owner.user.PasswordHash)
	}
	return owner.admin != nil && admin.VerifyPassword(password, owner.admin.Password)
}
