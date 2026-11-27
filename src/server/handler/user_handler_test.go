package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

func authenticatedUserRequest(store *mockStore, method, path, body string) *http.Request {
	store.users["1"] = &model.User{ID: 1, Username: "alice", Email: "alice@example.com", Approved: true, EmailVerified: true}
	store.sessions["session-1"] = &model.Session{ID: "session-1", UserID: "1", ExpiresAt: time.Now().Add(time.Hour)}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "session-1"})
	return req
}

func TestRegistrationEmailDomainPolicy(t *testing.T) {
	h := NewUserHandler(nil)
	h.SetRegistrationEmailDomains([]string{"example.com"}, []string{"blocked.example.com"})
	for address, want := range map[string]bool{
		"alice@example.com":         true,
		"alice@EXAMPLE.COM":         true,
		"alice@blocked.example.com": false,
		"alice@other.example":       false,
	} {
		if got := h.emailDomainAllowed(address); got != want {
			t.Errorf("emailDomainAllowed(%q) = %t, want %t", address, got, want)
		}
	}
}

func TestBrowserRegistrationAndEmailVerificationLifecycle(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := NewUserHandler(st)
	h.SetPasswordValidator(func(string) error { return nil })
	h.SetRegistrationEmailDomains([]string{"example.test"}, nil)
	var sentToken string
	h.SetEmailVerification(true, func(_ *http.Request, _, token string) error {
		sentToken = token
		return nil
	})
	get := httptest.NewRecorder()
	h.RegisterPage(get, httptest.NewRequest(http.MethodGet, "http://example.test/server/auth/register", nil))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `name="csrf_token"`) {
		t.Fatalf("registration page response = %d", get.Code)
	}
	var csrf *http.Cookie
	for _, cookie := range get.Result().Cookies() {
		if cookie.Name == registerCSRFCookie {
			csrf = cookie
		}
	}
	if csrf == nil {
		t.Fatal("registration page did not set its CSRF cookie")
	}
	form := url.Values{"username": {"new-user"}, "email": {"new@example.test"}, "password": {"good password 123"}, "csrf_token": {csrf.Value}}
	post := httptest.NewRequest(http.MethodPost, "http://example.test/server/auth/register", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "http://example.test")
	post.AddCookie(csrf)
	created := httptest.NewRecorder()
	h.RegisterPage(created, post)
	if created.Code != http.StatusSeeOther || sentToken == "" || !strings.Contains(created.Header().Get("Location"), "registered=1") {
		t.Fatalf("registration response = %d location=%q body=%s", created.Code, created.Header().Get("Location"), created.Body.String())
	}
	user, err := st.GetUserByUsername(context.Background(), "new-user")
	if err != nil || user == nil || user.EmailVerified {
		t.Fatalf("pending account state = %#v, %v", user, err)
	}
	verifyBody, err := json.Marshal(map[string]string{"token": sentToken})
	if err != nil {
		t.Fatal(err)
	}
	verify := httptest.NewRecorder()
	verifyRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", bytes.NewReader(verifyBody))
	verifyRequest.Header.Set("Content-Type", "application/json")
	h.VerifyEmail(verify, verifyRequest)
	if verify.Code != http.StatusOK || !strings.Contains(verify.Body.String(), `"email_verified":true`) {
		t.Fatalf("verification response = %d: %s", verify.Code, verify.Body.String())
	}
	replay := httptest.NewRecorder()
	replayRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", strings.NewReader(`{"token":"`+sentToken+`"}`))
	replayRequest.Header.Set("Content-Type", "application/json")
	h.VerifyEmail(replay, replayRequest)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("verification replay status = %d", replay.Code)
	}
}

func TestUpdateEmailCreatesSingleUsePendingVerification(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	passwordHash, err := auth.HashPassword("Correct horse battery staple 8!")
	if err != nil {
		t.Fatal(err)
	}
	user := &model.User{ID: 0, Username: "emailchange", Email: "user@example.com", EmailVerified: true, NotificationEmailVerified: true, PasswordHash: passwordHash, Visibility: "public", CreatedAt: time.Now().UTC()}
	if err := st.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	session := &model.Session{ID: "email-change-session", UserID: model.UserIDString(user.ID), ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC()}
	if err := st.CreateSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	var sentTo, sentToken string
	h := NewUserHandler(st)
	h.SetEmailVerification(true, func(_ *http.Request, to, token string) error { sentTo, sentToken = to, token; return nil })
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/users/email", strings.NewReader(`{"type":"notification","email":"alerts@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: "user_session", Value: session.ID})
	response := httptest.NewRecorder()
	h.UpdateEmail(response, request)
	if response.Code != http.StatusAccepted || sentTo != "alerts@example.com" || sentToken == "" {
		t.Fatalf("notification email update = %d %q %t body=%s", response.Code, sentTo, sentToken != "", response.Body.String())
	}
	digest := sha256.Sum256([]byte(sentToken))
	verified, err := st.VerifyEmailAddress(context.Background(), hex.EncodeToString(digest[:]), time.Now().UTC())
	if err != nil || !verified {
		t.Fatalf("verify pending email = %t, %v", verified, err)
	}
	loaded, err := st.GetUser(context.Background(), model.UserIDString(user.ID))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Email != user.Email || loaded.NotificationEmail != "alerts@example.com" || !loaded.NotificationEmailVerified {
		t.Fatalf("verified notification address changed account fields: %#v", loaded)
	}
}

func TestUserHandlerRequiresAuthentication(t *testing.T) {
	store := newMockStore()
	handler := NewUserHandler(store)
	router := chi.NewRouter()
	router.Get("/users/{id}", handler.GetProfile)
	router.Get("/users/{id}/devices", handler.ListDevices)
	router.Post("/users/{id}/tokens", handler.CreateToken)
	for _, item := range []struct{ method, path string }{{http.MethodGet, "/users/user-1"}, {http.MethodGet, "/users/user-1/devices"}, {http.MethodPost, "/users/user-1/tokens"}} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(item.method, item.path, nil))
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s status = %d, want 401", item.path, recorder.Code)
		}
	}
}

func TestUserHandlerProfileUsesSessionOwner(t *testing.T) {
	store := newMockStore()
	handler := NewUserHandler(store)
	router := chi.NewRouter()
	router.Get("/users/{id}", handler.GetProfile)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, authenticatedUserRequest(store, http.MethodGet, "/users/another-user", ""))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "alice@example.com") {
		t.Fatalf("profile for session owner = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestUserHandlerUpdatesOwnProfileWithValidation(t *testing.T) {
	st := newMockStore()
	h := NewUserHandler(st)
	router := chi.NewRouter()
	router.Patch("/users", h.UpdateProfile)
	request := authenticatedUserRequest(st, http.MethodPatch, "/users", `{"display_name":"Alice Example","bio":"Network tester","website":"https://example.test/profile","timezone":"UTC","language":"en"}`)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || st.users["1"].DisplayName != "Alice Example" || st.users["1"].Website != "https://example.test/profile" {
		t.Fatalf("profile update = %d %s user=%#v", response.Code, response.Body.String(), st.users["1"])
	}
	badRequest := authenticatedUserRequest(st, http.MethodPatch, "/users", `{"website":"javascript:alert(1)"}`)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, badRequest)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid website status = %d, want 400", response.Code)
	}
}

func TestUserHandlerAuthenticatedDevices(t *testing.T) {
	store := newMockStore()
	handler := NewUserHandler(store)
	router := chi.NewRouter()
	router.Post("/users/{id}/devices", handler.CreateDevice)
	router.Get("/users/{id}/devices", handler.ListDevices)
	router.Delete("/devices/{deviceId}", handler.DeleteDevice)

	create := httptest.NewRecorder()
	router.ServeHTTP(create, authenticatedUserRequest(store, http.MethodPost, "/users/attacker/devices", `{"name":"laptop"}`))
	if create.Code != http.StatusCreated {
		t.Fatalf("CreateDevice status = %d: %s", create.Code, create.Body.String())
	}
	var envelope struct {
		Data model.Device `json:"data"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	device := envelope.Data
	if device.UserID != "1" || device.Name != "laptop" {
		t.Fatalf("created device = %#v", device)
	}

	list := httptest.NewRecorder()
	router.ServeHTTP(list, authenticatedUserRequest(store, http.MethodGet, "/users/attacker/devices", ""))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), device.ID) {
		t.Fatalf("ListDevices = %d %s", list.Code, list.Body.String())
	}

	store.users["2"] = &model.User{ID: 2, Approved: true, EmailVerified: true}
	store.sessions["session-2"] = &model.Session{ID: "session-2", UserID: "2", ExpiresAt: time.Now().Add(time.Hour)}
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/devices/"+device.ID, nil)
	deleteRequest.AddCookie(&http.Cookie{Name: "user_session", Value: "session-2"})
	denied := httptest.NewRecorder()
	router.ServeHTTP(denied, deleteRequest)
	if denied.Code != http.StatusNotFound {
		t.Fatalf("cross-account device delete = %d, want 404", denied.Code)
	}
}

func TestUserHandlerHashedAPIKeys(t *testing.T) {
	store := newMockStore()
	handler := NewUserHandler(store)
	router := chi.NewRouter()
	router.Post("/users/{id}/tokens", handler.CreateToken)
	router.Get("/users/{id}/tokens", handler.ListTokens)
	router.Delete("/tokens/{tokenId}", handler.RevokeToken)

	create := httptest.NewRecorder()
	router.ServeHTTP(create, authenticatedUserRequest(store, http.MethodPost, "/users/attacker/tokens", `{"name":"automation"}`))
	if create.Code != http.StatusCreated {
		t.Fatalf("CreateToken = %d: %s", create.Code, create.Body.String())
	}
	var response struct {
		Data struct {
			ID          string `json:"id"`
			Token       string `json:"token"`
			TokenPrefix string `json:"token_prefix"`
		} `json:"data"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(response.Data.Token, "usr_") || response.Data.TokenPrefix != response.Data.Token[:8] {
		t.Fatalf("created token response = %#v", response.Data)
	}
	stored := store.tokens[response.Data.ID]
	hash := sha256.Sum256([]byte(response.Data.Token))
	if stored == nil || stored.UserID != "1" || stored.Token != hex.EncodeToString(hash[:]) {
		t.Fatalf("token storage did not contain owner and SHA-256 only: %#v", stored)
	}

	list := httptest.NewRecorder()
	router.ServeHTTP(list, authenticatedUserRequest(store, http.MethodGet, "/users/attacker/tokens", ""))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), response.Data.Token) {
		t.Fatalf("ListTokens exposed raw token or failed: %d %s", list.Code, list.Body.String())
	}
	if got, err := store.GetAPITokenByToken(context.Background(), response.Data.Token); err != nil || got == nil {
		t.Fatalf("hashed lookup = %#v, %v", got, err)
	}

	store.users["2"] = &model.User{ID: 2, Approved: true, EmailVerified: true}
	store.sessions["session-2"] = &model.Session{ID: "session-2", UserID: "2", ExpiresAt: time.Now().Add(time.Hour)}
	revoke := httptest.NewRequest(http.MethodDelete, "/tokens/"+response.Data.ID, nil)
	revoke.AddCookie(&http.Cookie{Name: "user_session", Value: "session-2"})
	denied := httptest.NewRecorder()
	router.ServeHTTP(denied, revoke)
	if denied.Code != http.StatusNotFound {
		t.Fatalf("cross-account token revoke = %d, want 404", denied.Code)
	}
}
