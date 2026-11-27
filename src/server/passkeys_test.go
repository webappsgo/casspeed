package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/server/handler"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
)

func TestPasskeyRevocationRequiresNativeConfirmationPopover(t *testing.T) {
	content := executeTemplate(passkeyPageTemplate, map[string]any{
		"Heading": "Passkeys", "RevokeBase": "/users/security/passkeys", "CSRF": "csrf-token",
		"RevokeLabel": "Revoke", "ConfirmLabel": "Confirm", "CancelLabel": "Cancel",
		"Passkeys": []map[string]any{{"ID": "credential-123", "Name": "Laptop", "Active": true}},
	})
	for _, required := range []string{
		`method="post" action="/users/security/passkeys/credential-123/revoke"`,
		`type="button" popovertarget="revoke-passkey-credential-123"`,
		`id="revoke-passkey-credential-123" popover`,
		`popovertargetaction="hide">Cancel</button>`,
		`class="btn btn-danger" type="submit">Confirm</button>`,
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("passkey confirmation page is missing %q: %s", required, content)
		}
	}
}

func TestPasskeyChallengeKeyUsesUniqueOpaqueDigest(t *testing.T) {
	firstHash, firstToken, err := passkeyChallengeKey()
	if err != nil {
		t.Fatal(err)
	}
	secondHash, secondToken, err := passkeyChallengeKey()
	if err != nil {
		t.Fatal(err)
	}
	if firstToken == secondToken || firstHash == secondHash {
		t.Fatal("independent passkey challenges reused a token or digest")
	}
	digest := sha256.Sum256([]byte(firstToken))
	if firstHash != hex.EncodeToString(digest[:]) || firstHash == firstToken {
		t.Fatal("challenge persistence key is not the SHA-256 digest of the opaque token")
	}
}

func TestPasskeyCSRFRequiresMatchingCookieAndHeader(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/v1/users/security/passkeys", nil)
	r.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "csrf-token-value"})
	r.Header.Set("X-CSRF-Token", "csrf-token-value")
	if !validPasskeyCSRF(r) {
		t.Fatal("matching CSRF header was rejected")
	}
	r.Header.Set("X-CSRF-Token", "different-token")
	if validPasskeyCSRF(r) {
		t.Fatal("mismatched CSRF header was accepted")
	}
}

func TestWebAuthnOriginRejectsPlainHTTPOutsideLocalhost(t *testing.T) {
	r := httptest.NewRequest("POST", "http://example.test/server/auth/passkey/challenge", nil)
	if _, err := (&Server{}).webAuthnForRequest(r); err == nil {
		t.Fatal("WebAuthn configuration accepted non-local HTTP")
	}
	secure := httptest.NewRequest("POST", "https://example.test/server/auth/passkey/challenge", nil)
	if _, err := (&Server{}).webAuthnForRequest(secure); err != nil {
		t.Fatalf("secure origin was rejected: %v", err)
	}
}

func TestPasskeyRegistrationSetupCreatesOpaqueChallenge(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	passwordHash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	user := &model.User{Username: "passkey-user", Email: "passkey@example.test", PasswordHash: passwordHash, Approved: true, EmailVerified: true}
	if err := st.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	user, err = st.GetUserByUsername(t.Context(), user.Username)
	if err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	s.UserHandler = handler.NewUserHandler(st)
	if err := st.CreateSession(t.Context(), &model.Session{ID: "passkey-session", UserID: model.UserIDString(user.ID), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	call := func(password, origin string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(passkeyRequest{Action: "setup", CurrentPassword: password})
		req := httptest.NewRequest(http.MethodPost, "https://casspeed.test/api/v1/users/security/passkeys", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		req.Header.Set("X-CSRF-Token", "passkey-csrf-value")
		req.AddCookie(&http.Cookie{Name: "user_session", Value: "passkey-session"})
		req.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "passkey-csrf-value"})
		response := httptest.NewRecorder()
		s.handleUserPasskeyAPI(response, req)
		return response
	}
	if response := call("correct horse battery staple", "https://attacker.test"); response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin setup returned %d: %s", response.Code, response.Body.String())
	}
	if response := call("wrong password", "https://casspeed.test"); response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid password returned %d: %s", response.Code, response.Body.String())
	}
	response := call("correct horse battery staple", "https://casspeed.test")
	if response.Code != http.StatusOK {
		t.Fatalf("setup returned %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			ChallengeID string `json:"challenge_id"`
			PublicKey   any    `json:"publicKey"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.ChallengeID) < 40 || payload.Data.PublicKey == nil {
		t.Fatalf("setup response omitted a usable challenge: %+v", payload.Data)
	}
	if _, _, err := s.consumeWebAuthnChallenge(httptest.NewRequest(http.MethodPost, "https://casspeed.test/", nil), payload.Data.ChallengeID); err != nil {
		t.Fatalf("saved registration challenge could not be consumed: %v", err)
	}
	if _, _, err := s.consumeWebAuthnChallenge(httptest.NewRequest(http.MethodPost, "https://casspeed.test/", nil), payload.Data.ChallengeID); err == nil {
		t.Fatal("WebAuthn challenge was reusable")
	}
}

func TestPasskeyManagementAPIAuthorizesMutationsAndRevokesCredential(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	user := &model.User{Username: "passkey-owner", Email: "owner@example.test", PasswordHash: "unused", Approved: true, EmailVerified: true}
	if err := st.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	user, err = st.GetUserByUsername(t.Context(), user.Username)
	if err != nil {
		t.Fatal(err)
	}
	userID := model.UserIDString(user.ID)
	if err := st.CreateSession(t.Context(), &model.Session{ID: "passkey-owner-session", UserID: userID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := st.SavePasskey(t.Context(), &model.Passkey{ID: "credential-to-revoke", UserType: "user", UserID: userID, Name: "Laptop", CredentialJSON: "{}", CreatedAt: time.Now().UTC(), Active: true}); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	s.UserHandler = handler.NewUserHandler(st)
	call := func(method, body, csrf string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "https://casspeed.test/api/v1/users/security/passkeys", strings.NewReader(body))
		request.Header.Set("Origin", "https://casspeed.test")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		request.AddCookie(&http.Cookie{Name: "user_session", Value: "passkey-owner-session"})
		request.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "matching-csrf"})
		response := httptest.NewRecorder()
		s.handleUserPasskeyAPI(response, request)
		return response
	}
	if response := call(http.MethodGet, "", ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "credential-to-revoke") {
		t.Fatalf("passkey list returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, `{"name":""}`, "matching-csrf"); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid registration returned %d", response.Code)
	}
	if response := call(http.MethodPost, `{`, "matching-csrf"); response.Code != http.StatusBadRequest {
		t.Fatalf("malformed registration returned %d", response.Code)
	}
	if response := call(http.MethodPost, `{"name":"Laptop"}`, "wrong-csrf"); response.Code != http.StatusForbidden {
		t.Fatalf("CSRF mismatch returned %d", response.Code)
	}
	deleteRequest := httptest.NewRequest(http.MethodDelete, "https://casspeed.test/api/v1/users/security/passkeys/credential-to-revoke", nil)
	deleteRequest.Header.Set("Origin", "https://casspeed.test")
	deleteRequest.Header.Set("X-CSRF-Token", "matching-csrf")
	deleteRequest.AddCookie(&http.Cookie{Name: "user_session", Value: "passkey-owner-session"})
	deleteRequest.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "matching-csrf"})
	deleteRequest.SetPathValue("passkey_id", "credential-to-revoke")
	deleted := httptest.NewRecorder()
	s.handleUserPasskeyAPI(deleted, deleteRequest)
	if deleted.Code != http.StatusOK {
		t.Fatalf("passkey revocation returned %d: %s", deleted.Code, deleted.Body.String())
	}
	if row, err := st.GetPasskey(t.Context(), "credential-to-revoke"); err != nil || row != nil {
		t.Fatalf("revoked passkey still exists: %#v, %v", row, err)
	}
	unknown := httptest.NewRecorder()
	s.handleUserPasskeyAPI(unknown, httptest.NewRequest(http.MethodGet, "/api/v1/users/security/passkeys", nil))
	if unknown.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous passkey list returned %d", unknown.Code)
	}
	method := httptest.NewRecorder()
	s.handleUserPasskeyAPI(method, callWithPasskeySession(t, "passkey-owner-session", http.MethodPut))
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported passkey method returned %d", method.Code)
	}
}

func TestPasskeyLoginAndManagementPagesRejectInvalidRequests(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := minimalServer()
	s.Store = st
	s.UserHandler = handler.NewUserHandler(st)
	page := httptest.NewRecorder()
	s.handlePasskeyLoginPage(page, httptest.NewRequest(http.MethodGet, "https://casspeed.test/server/auth/passkey", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "passkey-login") || page.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("passkey login page = %d headers=%v", page.Code, page.Header())
	}
	if !strings.Contains(page.Body.String(), "name=\"username\"") {
		t.Fatal("anonymous passkey page did not require a username")
	}

	call := func(method, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "https://casspeed.test/server/auth/passkey/challenge", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		s.handlePasskeyLoginChallenge(response, request)
		return response
	}
	if got := call(http.MethodGet, "{}"); got.Code != http.StatusMethodNotAllowed || got.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("challenge wrong-method response = %d allow=%q", got.Code, got.Header().Get("Allow"))
	}
	if got := call(http.MethodPost, "{"); got.Code != http.StatusBadRequest {
		t.Fatalf("malformed challenge response = %d", got.Code)
	}
	if got := call(http.MethodPost, `{"username":"missing-user"}`); got.Code != http.StatusUnauthorized {
		t.Fatalf("unknown passkey account response = %d", got.Code)
	}
	verify := httptest.NewRecorder()
	s.handlePasskeyLoginVerify(verify, httptest.NewRequest(http.MethodPost, "https://casspeed.test/server/auth/passkey/verify", strings.NewReader("{")))
	if verify.Code != http.StatusBadRequest {
		t.Fatalf("malformed verification response = %d", verify.Code)
	}
	verify = httptest.NewRecorder()
	s.handlePasskeyLoginVerify(verify, httptest.NewRequest(http.MethodPost, "https://casspeed.test/server/auth/passkey/verify", strings.NewReader(`{"challenge_id":"short","credential":{}}`)))
	if verify.Code != http.StatusUnauthorized {
		t.Fatalf("invalid ceremony response = %d", verify.Code)
	}
	userPage := httptest.NewRecorder()
	s.handleUserPasskeys(userPage, httptest.NewRequest(http.MethodGet, "/users/security/passkeys", nil))
	if userPage.Code != http.StatusSeeOther {
		t.Fatalf("anonymous user passkey page response = %d", userPage.Code)
	}
	adminPage := httptest.NewRecorder()
	s.handleAdminPasskeys(adminPage, httptest.NewRequest(http.MethodGet, "/server/administration/security/passkeys", nil))
	if adminPage.Code != http.StatusSeeOther {
		t.Fatalf("anonymous admin passkey page response = %d", adminPage.Code)
	}
	adminAPI := httptest.NewRecorder()
	s.handleAdminPasskeyAPI(adminAPI, httptest.NewRequest(http.MethodGet, "/api/v1/server/administration/passkeys", nil))
	if adminAPI.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous admin passkey API response = %d", adminAPI.Code)
	}
}

func callWithPasskeySession(t *testing.T, sessionID, method string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "/api/v1/users/security/passkeys", nil)
	request.AddCookie(&http.Cookie{Name: "user_session", Value: sessionID})
	return request
}
