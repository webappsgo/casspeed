package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/admin"
	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/server/handler"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
)

func TestUserTOTPEnableRecoveryAndDisableFlow(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	passwordHash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	user := &model.User{Username: "totp-user", Email: "totp@example.test", PasswordHash: passwordHash, Approved: true, EmailVerified: true}
	if err := st.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	user, err = st.GetUserByUsername(t.Context(), user.Username)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(t.Context(), &model.Session{ID: "totp-session", UserID: userIDString(user.ID), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	s.UserHandler = handler.NewUserHandler(st)
	s.encryptionKey = []byte(strings.Repeat("K", 32))
	call := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: "user_session", Value: "totp-session"})
		response := httptest.NewRecorder()
		s.handleUserTOTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("POST %s returned %d: %s", path, response.Code, response.Body.String())
		}
		return response
	}
	var setup struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(call("/api/v1/users/security/2fa/enable", `{"current_password":"correct horse battery staple"}`).Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	if setup.Data.Secret == "" {
		t.Fatal("TOTP setup did not return an authenticator secret")
	}
	code := testTOTPCode(t, setup.Data.Secret, time.Now().UTC())
	var recovery struct {
		Data struct {
			RecoveryKeys []string `json:"recovery_keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(call("/api/v1/users/security/2fa/enable", fmt.Sprintf(`{"current_password":"correct horse battery staple","code":%q}`, code)).Body.Bytes(), &recovery); err != nil {
		t.Fatal(err)
	}
	if len(recovery.Data.RecoveryKeys) != 10 {
		t.Fatalf("generated recovery-key count = %d, want 10", len(recovery.Data.RecoveryKeys))
	}
	code = testTOTPCode(t, setup.Data.Secret, time.Now().UTC())
	call("/api/v1/users/security/2fa/enable", fmt.Sprintf(`{"current_password":"correct horse battery staple","code":%q,"recovery_keys_saved":true}`, code))
	status := httptest.NewRecorder()
	get := httptest.NewRequest(http.MethodGet, "/api/v1/users/security/2fa", nil)
	get.AddCookie(&http.Cookie{Name: "user_session", Value: "totp-session"})
	s.handleUserTOTP(status, get)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"enabled":true`) {
		t.Fatalf("enabled status = %d %s", status.Code, status.Body.String())
	}
	code = testTOTPCode(t, setup.Data.Secret, time.Now().UTC())
	call("/api/v1/users/security/recovery/regenerate", fmt.Sprintf(`{"current_password":"correct horse battery staple","code":%q}`, code))
	code = testTOTPCode(t, setup.Data.Secret, time.Now().UTC())
	call("/api/v1/users/security/2fa/disable", fmt.Sprintf(`{"current_password":"correct horse battery staple","code":%q}`, code))
	status = httptest.NewRecorder()
	get = httptest.NewRequest(http.MethodGet, "/api/v1/users/security/2fa", nil)
	get.AddCookie(&http.Cookie{Name: "user_session", Value: "totp-session"})
	s.handleUserTOTP(status, get)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"enabled":false`) {
		t.Fatalf("disabled status = %d %s", status.Code, status.Body.String())
	}
}

func TestUserMFAChallengeConsumesPartialSessionAndIssuesToken(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	user := &model.User{Username: "challenge-user", Email: "challenge@example.test", PasswordHash: "unused", Approved: true, EmailVerified: true}
	if err := st.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	user, err = st.GetUserByUsername(t.Context(), user.Username)
	if err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	s.encryptionKey = []byte(strings.Repeat("M", 32))
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := s.encryptTOTPSecret([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	userID := model.UserIDString(user.ID)
	if err := st.SaveUserTOTP(t.Context(), &model.TOTPSecret{UserID: userID, EncryptedSecret: encrypted, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	partialToken, err := s.createPartialAuthentication(t.Context(), userID, "user", true)
	if err != nil {
		t.Fatal(err)
	}
	call := func(token, code string) *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"partial_token":%q,"code":%q}`, token, code)
		req := httptest.NewRequest(http.MethodPost, "/server/auth/2fa", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.handleMFAChallenge(rec, req)
		return rec
	}
	if response := call(partialToken, "000000"); response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid authenticator code returned %d: %s", response.Code, response.Body.String())
	}
	response := call(partialToken, testTOTPCode(t, secret, time.Now().UTC()))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"token":"usr_`) {
		t.Fatalf("valid authenticator code did not complete login: %d %s", response.Code, response.Body.String())
	}
	if _, ok := s.loadPartialUser(httptest.NewRequest(http.MethodPost, "/", nil), partialToken); ok {
		t.Fatal("successful authentication did not consume the partial session")
	}
	if response := call(partialToken, testTOTPCode(t, secret, time.Now().UTC())); response.Code != http.StatusUnauthorized {
		t.Fatalf("replayed partial session returned %d", response.Code)
	}
}

func TestAdminTOTPSetupChallengeAndDisableFlow(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	account := &model.Admin{Username: "mfa-admin", Password: admin.HashPassword("correct horse battery staple"), Role: "admin", Enabled: true}
	if err := st.CreateAdmin(t.Context(), account); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAdminSession(t.Context(), &model.AdminSession{ID: "mfa-admin-session", AdminID: account.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	s.encryptionKey = []byte(strings.Repeat("A", 32))
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "https://casspeed.test"+path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: "admin_session", Value: "mfa-admin-session"})
		request.SetPathValue("username", account.Username)
		response := httptest.NewRecorder()
		s.handleAdminTOTP(response, request)
		return response
	}
	path := "/api/v1/server/administration/mfa-admin/security/totp/setup"
	if response := call(http.MethodPost, path, `{"current_password":"wrong"}`); response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid admin password returned %d", response.Code)
	}
	response := call(http.MethodPost, path, `{"current_password":"correct horse battery staple"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("admin TOTP setup returned %d: %s", response.Code, response.Body.String())
	}
	var setup struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &setup); err != nil || setup.Data.Secret == "" {
		t.Fatalf("admin TOTP setup secret = %q, %v", setup.Data.Secret, err)
	}
	enablePath := "/api/v1/server/administration/mfa-admin/security/totp/enable"
	code := testTOTPCode(t, setup.Data.Secret, time.Now().UTC())
	recovery := call(http.MethodPost, enablePath, fmt.Sprintf(`{"current_password":%q,"code":%q}`, "correct horse battery staple", code))
	if recovery.Code != http.StatusOK || !strings.Contains(recovery.Body.String(), "recovery_keys") {
		t.Fatalf("recovery key generation returned %d: %s", recovery.Code, recovery.Body.String())
	}
	code = testTOTPCode(t, setup.Data.Secret, time.Now().UTC())
	if response := call(http.MethodPost, enablePath, fmt.Sprintf(`{"current_password":%q,"code":%q,"recovery_keys_saved":true}`, "correct horse battery staple", code)); response.Code != http.StatusOK {
		t.Fatalf("admin TOTP activation returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, "/api/v1/server/administration/mfa-admin/security/2fa", ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"totp_enabled":true`) {
		t.Fatalf("admin security status returned %d: %s", response.Code, response.Body.String())
	}
	partial, err := s.createPartialAuthentication(t.Context(), fmt.Sprint(account.ID), "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	challengeBody := fmt.Sprintf(`{"partial_token":%q,"code":%q}`, partial, testTOTPCode(t, setup.Data.Secret, time.Now().UTC()))
	challengeRequest := httptest.NewRequest(http.MethodPost, "/server/auth/2fa", strings.NewReader(challengeBody))
	challengeRequest.Header.Set("Content-Type", "application/json")
	challengeResponse := httptest.NewRecorder()
	s.handleMFAChallenge(challengeResponse, challengeRequest)
	if challengeResponse.Code != http.StatusOK || !strings.Contains(challengeResponse.Body.String(), `"token":"adm_`) {
		t.Fatalf("admin MFA login returned %d: %s", challengeResponse.Code, challengeResponse.Body.String())
	}
	disablePath := "/api/v1/server/administration/mfa-admin/security/totp/disable"
	if response := call(http.MethodPost, disablePath, fmt.Sprintf(`{"current_password":%q,"code":%q}`, "correct horse battery staple", testTOTPCode(t, setup.Data.Secret, time.Now().UTC()))); response.Code != http.StatusOK {
		t.Fatalf("admin TOTP disable returned %d: %s", response.Code, response.Body.String())
	}
}

func testTOTPCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	hash := hmac.New(sha1.New, key)
	_, _ = hash.Write(counter[:])
	digest := hash.Sum(nil)
	index := digest[len(digest)-1] & 0x0f
	value := (binary.BigEndian.Uint32(digest[index:index+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", value)
}
