package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/service"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

// ---- SpeedTestHandler -------------------------------------------------------

func TestStartTest_ReturnsTestID(t *testing.T) {
	st := newMockStore()
	svc := service.NewSpeedTestService(2, 65536)
	h := NewSpeedTestHandler(st, svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test/start", nil)
	rr := httptest.NewRecorder()
	h.StartTest(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("StartTest status = %d, want 200", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["ok"] != true {
		t.Errorf("ok = %v, want true", body["ok"])
	}
	var testID string
	for id := range st.tests {
		testID = id
	}
	if testID == "" || st.tests[testID].OwnerTokenHash == "" {
		t.Fatalf("StartTest did not persist the result owner: %#v", st.tests)
	}
	var ownerCookie *http.Cookie
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "casspeed_owner" {
			ownerCookie = cookie
			break
		}
	}
	if ownerCookie == nil {
		t.Fatal("StartTest must issue an anonymous owner cookie")
	}
	ownerRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	ownerRequest.AddCookie(ownerCookie)
	if got := anonymousOwnerTokenHash(ownerRequest); got != st.tests[testID].OwnerTokenHash {
		t.Fatal("stored owner hash does not match the issued owner cookie")
	}
}

func TestDownloadRejectsNonOwner(t *testing.T) {
	st := newMockStore()
	st.tests["private-test"] = &model.SpeedTest{ID: "private-test", OwnerTokenHash: "different-owner"}
	router := chi.NewRouter()
	router.Get("/tests/{id}/download", NewSpeedTestHandler(st, service.NewSpeedTestService(1, 65536)).Download)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/tests/private-test/download", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("non-owner download status = %d, want 404", recorder.Code)
	}
}

func TestTestStatusPersistsOwnerMeasurements(t *testing.T) {
	st := newMockStore()
	ownerCookie := &http.Cookie{Name: "casspeed_owner", Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	ownerRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	ownerRequest.AddCookie(ownerCookie)
	st.tests["owned-test"] = &model.SpeedTest{ID: "owned-test", OwnerTokenHash: anonymousOwnerTokenHash(ownerRequest)}
	router := chi.NewRouter()
	router.Get("/tests/{id}/status", NewSpeedTestHandler(st, service.NewSpeedTestService(1, 65536)).TestStatus)
	server := httptest.NewServer(router)
	defer server.Close()

	headers := http.Header{"Cookie": []string{ownerCookie.String()}}
	socketURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/tests/owned-test/status"
	conn, response, err := websocket.DefaultDialer.Dial(socketURL, headers)
	if err != nil {
		t.Fatalf("connect status WebSocket: %v (response: %#v)", err, response)
	}
	defer conn.Close()
	if err := conn.WriteJSON(map[string]interface{}{
		"type": "result", "download_mbps": 120.5, "upload_mbps": 23.25,
		"ping_ms": 8.5, "jitter_ms": 0.7, "packet_loss": 10.0,
	}); err != nil {
		t.Fatalf("send result: %v", err)
	}
	var update map[string]interface{}
	if err := conn.ReadJSON(&update); err != nil {
		t.Fatalf("read completion: %v", err)
	}
	if update["stage"] != "complete" || update["test_id"] != "owned-test" {
		t.Fatalf("completion update = %#v", update)
	}
	saved := st.tests["owned-test"]
	if saved.DownloadMbps != 120.5 || saved.UploadMbps != 23.25 || saved.PingMs != 8.5 || saved.JitterMs != 0.7 || saved.PacketLoss != 10 {
		t.Fatalf("saved measurement = %#v", saved)
	}
}

func TestTestStatusRejectsCrossOrigin(t *testing.T) {
	st := newMockStore()
	ownerCookie := &http.Cookie{Name: "casspeed_owner", Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	ownerRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	ownerRequest.AddCookie(ownerCookie)
	st.tests["owned-test"] = &model.SpeedTest{ID: "owned-test", OwnerTokenHash: anonymousOwnerTokenHash(ownerRequest)}
	router := chi.NewRouter()
	router.Get("/tests/{id}/status", NewSpeedTestHandler(st, service.NewSpeedTestService(1, 65536)).TestStatus)
	request := httptest.NewRequest(http.MethodGet, "/tests/owned-test/status", nil)
	request.AddCookie(ownerCookie)
	request.Header.Set("Origin", "https://attacker.example")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status request = %d, want 403", recorder.Code)
	}
}

func TestDownload_RespondsWithData(t *testing.T) {
	st := newMockStore()
	svc := service.NewSpeedTestService(1, 65536)
	h := NewSpeedTestHandler(st, svc)

	ownerCookie := &http.Cookie{Name: "casspeed_owner", Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	ownerRequest := httptest.NewRequest(http.MethodGet, "/api/v1/test/download", nil)
	ownerRequest.AddCookie(ownerCookie)
	st.tests["test-1"] = &model.SpeedTest{ID: "test-1", OwnerTokenHash: anonymousOwnerTokenHash(ownerRequest)}
	router := chi.NewRouter()
	router.Get("/api/v1/test/{id}/download", h.Download)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test/test-1/download", nil)
	req.AddCookie(ownerCookie)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Download status = %d, want 200", rr.Code)
	}
	if rr.Body.Len() == 0 {
		t.Error("Download response should contain data")
	}
}

func TestUpload_Success(t *testing.T) {
	st := newMockStore()
	svc := service.NewSpeedTestService(1, 65536)
	h := NewSpeedTestHandler(st, svc)

	payload := bytes.Repeat([]byte("x"), 1024)
	ownerCookie := &http.Cookie{Name: "casspeed_owner", Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	ownerRequest := httptest.NewRequest(http.MethodPost, "/api/v1/test/upload", nil)
	ownerRequest.AddCookie(ownerCookie)
	st.tests["test-1"] = &model.SpeedTest{ID: "test-1", OwnerTokenHash: anonymousOwnerTokenHash(ownerRequest)}
	router := chi.NewRouter()
	router.Post("/api/v1/test/{id}/uploads", h.Upload)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test/test-1/uploads", bytes.NewReader(payload))
	req.AddCookie(ownerCookie)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Upload status = %d, want 200", rr.Code)
	}
}

func TestGetResult_NotFound(t *testing.T) {
	st := newMockStore()
	svc := service.NewSpeedTestService(1, 65536)
	h := NewSpeedTestHandler(st, svc)

	// Use chi router context to supply URL param.
	r := chi.NewRouter()
	r.Get("/test/{id}", h.GetResult)

	req := httptest.NewRequest(http.MethodGet, "/test/nonexistent-id", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("GetResult (missing id) status = %d, want 404", rr.Code)
	}
}

func TestGetResult_Found(t *testing.T) {
	st := newMockStore()
	st.tests["test-123"] = &model.SpeedTest{
		ID:           "test-123",
		ShareCode:    "SHARED1",
		DownloadMbps: 100.0,
		ClientIPHash: "private-hash",
		UserAgent:    "private-agent",
		Timestamp:    time.Now(),
	}
	svc := service.NewSpeedTestService(1, 65536)
	h := NewSpeedTestHandler(st, svc)

	r := chi.NewRouter()
	r.Get("/test/{id}", h.GetResult)

	req := httptest.NewRequest(http.MethodGet, "/test/test-123", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GetResult status = %d, want 200", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "private-hash") || strings.Contains(rr.Body.String(), "private-agent") {
		t.Errorf("public result disclosed private metadata: %s", rr.Body.String())
	}
}

func TestGetResult_UnsharedIsPrivate(t *testing.T) {
	st := newMockStore()
	st.tests["private"] = &model.SpeedTest{ID: "private", DownloadMbps: 50}
	h := NewSpeedTestHandler(st, service.NewSpeedTestService(1, 65536))
	r := chi.NewRouter()
	r.Get("/test/{id}", h.GetResult)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/private", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unshared result status = %d, want 404", rec.Code)
	}
}

func TestGetResult_OwnerCanReadPrivateResult(t *testing.T) {
	st := newMockStore()
	st.users["1"] = &model.User{ID: 1, Approved: true, EmailVerified: true}
	st.sessions["session-id"] = &model.Session{ID: "session-id", UserID: "1", ExpiresAt: time.Now().Add(time.Hour)}
	st.tests["private"] = &model.SpeedTest{ID: "private", UserID: "1", DownloadMbps: 50}
	h := NewSpeedTestHandler(st, service.NewSpeedTestService(1, 65536))
	r := chi.NewRouter()
	r.Get("/test/{id}", h.GetResult)
	req := httptest.NewRequest(http.MethodGet, "/test/private", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "session-id"})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner result status = %d, want 200", rec.Code)
	}
}

func TestAnonymousOwnerCanReadAndSharePrivateResult(t *testing.T) {
	st := newMockStore()
	test := &model.SpeedTest{ID: "private", DownloadMbps: 50}
	st.tests[test.ID] = test
	h := NewSpeedTestHandler(st, service.NewSpeedTestService(1, 65536))
	r := chi.NewRouter()
	r.Get("/test/{id}", h.GetResult)
	r.Post("/test/{id}/shares", h.CreateShare)
	ownerCookie := &http.Cookie{Name: "casspeed_owner", Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	ownerReq := httptest.NewRequest(http.MethodGet, "/test/private", nil)
	ownerReq.AddCookie(ownerCookie)
	test.OwnerTokenHash = anonymousOwnerTokenHash(ownerReq)
	ownerRec := httptest.NewRecorder()
	r.ServeHTTP(ownerRec, ownerReq)
	if ownerRec.Code != http.StatusOK {
		t.Fatalf("originating session result status = %d, want 200", ownerRec.Code)
	}
	shareReq := httptest.NewRequest(http.MethodPost, "/test/private/shares", nil)
	shareReq.AddCookie(ownerCookie)
	shareRec := httptest.NewRecorder()
	r.ServeHTTP(shareRec, shareReq)
	if shareRec.Code != http.StatusOK || test.ShareCode == "" {
		t.Fatalf("share creation status = %d, code=%q body=%s", shareRec.Code, test.ShareCode, shareRec.Body.String())
	}
}

func TestGetResult_DBError(t *testing.T) {
	st := newMockStore()
	st.errGetSpeedTest = errDB
	svc := service.NewSpeedTestService(1, 65536)
	h := NewSpeedTestHandler(st, svc)

	r := chi.NewRouter()
	r.Get("/test/{id}", h.GetResult)

	req := httptest.NewRequest(http.MethodGet, "/test/any", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("GetResult (db error) status = %d, want 500", rr.Code)
	}
}

func TestGetShare_NotFound(t *testing.T) {
	st := newMockStore()
	svc := service.NewSpeedTestService(1, 65536)
	h := NewSpeedTestHandler(st, svc)

	r := chi.NewRouter()
	r.Get("/s/{code}", h.GetShare)

	req := httptest.NewRequest(http.MethodGet, "/s/ABCDE12345", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("GetShare (missing code) status = %d, want 404", rr.Code)
	}
}

func TestGetShare_Found(t *testing.T) {
	st := newMockStore()
	st.testsByCode["ABC123"] = &model.SpeedTest{
		ShareCode:    "ABC123",
		DownloadMbps: 50.0,
		UploadMbps:   20.0,
		PingMs:       10.0,
		Timestamp:    time.Now(),
	}
	svc := service.NewSpeedTestService(1, 65536)
	h := NewSpeedTestHandler(st, svc)

	r := chi.NewRouter()
	r.Get("/s/{code}", h.GetShare)

	req := httptest.NewRequest(http.MethodGet, "/s/ABC123", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GetShare status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "50.0") {
		t.Error("GetShare response should contain download speed")
	}
}

func TestGetHistory_Empty(t *testing.T) {
	st := newMockStore()
	svc := service.NewSpeedTestService(1, 65536)
	h := NewSpeedTestHandler(st, svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/history", nil)
	rr := httptest.NewRecorder()
	h.GetHistory(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("anonymous GetHistory status = %d, want 401", rr.Code)
	}
}

func TestGetHistory_OnlyAuthenticatedUser(t *testing.T) {
	st := newMockStore()
	st.users["1"] = &model.User{ID: 1, Approved: true, EmailVerified: true}
	st.sessions["session-id"] = &model.Session{ID: "session-id", UserID: "1", ExpiresAt: time.Now().Add(time.Hour)}
	st.tests["owned"] = &model.SpeedTest{ID: "owned", UserID: "1"}
	st.tests["other"] = &model.SpeedTest{ID: "other", UserID: "someone-else"}
	token := "usr_0123456789abcdefghijklmnopqrstuv"
	hash := sha256.Sum256([]byte(token))
	st.tokens["history"] = &model.APIToken{ID: "history", UserID: "1", Token: hex.EncodeToString(hash[:]), Scope: "read"}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/history", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	NewSpeedTestHandler(st, service.NewSpeedTestService(1, 65536)).GetHistory(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "someone-else") || strings.Contains(rec.Body.String(), "other") {
		t.Fatalf("owner history response status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestGetHistory_DBError(t *testing.T) {
	st := newMockStore()
	st.errGetHistory = errDB
	svc := service.NewSpeedTestService(1, 65536)
	h := NewSpeedTestHandler(st, svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/history", nil)
	st.users["1"] = &model.User{ID: 1, Approved: true, EmailVerified: true}
	token := "usr_0123456789abcdefghijklmnopqrstuv"
	hash := sha256.Sum256([]byte(token))
	st.tokens["history"] = &model.APIToken{ID: "history", UserID: "1", Token: hex.EncodeToString(hash[:]), Scope: "read"}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.GetHistory(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("GetHistory (db error) status = %d, want 500", rr.Code)
	}
}

// ---- AuthHandler --------------------------------------------------------

func TestLogin_InvalidJSON(t *testing.T) {
	st := newMockStore()
	h := NewAuthHandler(st)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("{bad json"))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Login (bad JSON) status = %d, want 400", rr.Code)
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	st := newMockStore()
	h := NewAuthHandler(st)

	body := `{"username":"nobody","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Login (no user) status = %d, want 401", rr.Code)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	st := newMockStore()
	hash, _ := auth.HashPassword("correct")
	st.users["u1"] = &model.User{ID: 0, Username: "alice", PasswordHash: hash}

	h := NewAuthHandler(st)
	body := `{"username":"alice","password":"wrong"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Login (wrong password) status = %d, want 401", rr.Code)
	}
}

func TestLogin_Success(t *testing.T) {
	st := newMockStore()
	hash, _ := auth.HashPassword("s3cr3t!")
	st.users["1"] = &model.User{
		ID:            1,
		Username:      "alice",
		Email:         "alice@example.com",
		EmailVerified: true,
		Approved:      true,
		PasswordHash:  hash,
	}

	h := NewAuthHandler(st)
	body := `{"username":"alice","password":"s3cr3t!"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Login status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["ok"] != true {
		t.Errorf("ok = %v, want true", resp["ok"])
	}

	// A session cookie should have been set.
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "user_session" {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie to be set")
	}
}

func TestLogin_SessionCreationError(t *testing.T) {
	st := newMockStore()
	hash, _ := auth.HashPassword("pass1234")
	st.users["1"] = &model.User{ID: 1, Username: "bob", PasswordHash: hash, EmailVerified: true, Approved: true}
	st.errCreateSession = errDB

	h := NewAuthHandler(st)
	body := `{"username":"bob","password":"pass1234"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Login (session error) status = %d, want 500", rr.Code)
	}
}

func TestLogout_WithCookie(t *testing.T) {
	st := newMockStore()
	st.sessions["sess-abc"] = &model.Session{ID: "sess-abc"}
	h := NewAuthHandler(st)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "sess-abc"})
	rr := httptest.NewRecorder()
	h.Logout(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Logout status = %d, want 200", rr.Code)
	}
	// Session should be cleared.
	if _, exists := st.sessions["sess-abc"]; exists {
		t.Error("session should be deleted after logout")
	}
}

func TestLogout_WithoutCookie(t *testing.T) {
	st := newMockStore()
	h := NewAuthHandler(st)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rr := httptest.NewRecorder()
	h.Logout(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Logout (no cookie) status = %d, want 200", rr.Code)
	}
}

func TestPasswordResetRequest_AlwaysOK(t *testing.T) {
	st := newMockStore()
	h := NewAuthHandler(st)

	for _, email := range []string{"exists@example.com", "nobody@example.com", ""} {
		body := `{"email":"` + email + `"}`
		req := httptest.NewRequest(http.MethodPost, "/password-reset", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.PasswordResetRequest(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("PasswordResetRequest(%q) status = %d, want 200", email, rr.Code)
		}
	}
}

func TestPasswordResetRequest_InvalidJSON(t *testing.T) {
	st := newMockStore()
	h := NewAuthHandler(st)

	req := httptest.NewRequest(http.MethodPost, "/password-reset", strings.NewReader("{bad"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PasswordResetRequest(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestPasswordRecoveryBrowserPages(t *testing.T) {
	h := NewAuthHandler(newMockStore())
	for _, page := range []struct {
		name string
		run  func(http.ResponseWriter, *http.Request)
	}{
		{name: "forgot", run: h.PasswordForgotPage},
		{name: "reset", run: h.PasswordResetPage},
	} {
		t.Run(page.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			page.run(recorder, httptest.NewRequest(http.MethodGet, "/?token=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", recorder.Code)
			}
			if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
				t.Fatalf("sensitive form headers missing: %v", recorder.Header())
			}
			for _, expected := range []string{"<main id=\"main-content\"", "theme-dark.css", "theme-light.css", "<h1"} {
				if !strings.Contains(recorder.Body.String(), expected) {
					t.Errorf("page does not contain %q", expected)
				}
			}
		})
	}
}

func TestPasswordResetRequest_BrowserFormRequiresSameOrigin(t *testing.T) {
	h := NewAuthHandler(newMockStore())
	request := httptest.NewRequest(http.MethodPost, "http://example.test/password-reset", strings.NewReader("email=person%40example.test"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.test")
	recorder := httptest.NewRecorder()
	h.PasswordResetRequest(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "If an account with that email exists") {
		t.Fatalf("same-origin form status = %d, body = %q", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "http://example.test/password-reset", strings.NewReader("email=person%40example.test"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	h.PasswordResetRequest(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("missing-origin form status = %d, want 403", recorder.Code)
	}
}

// ---- UserHandler --------------------------------------------------------

func TestRegister_InvalidJSON(t *testing.T) {
	st := newMockStore()
	h := NewUserHandler(st)

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("{bad"))
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Register (bad JSON) status = %d, want 400", rr.Code)
	}
}

func TestRegister_InvalidUsername(t *testing.T) {
	st := newMockStore()
	h := NewUserHandler(st)

	body := `{"username":"ab","email":"ok@x.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Register (short username) status = %d, want 400", rr.Code)
	}
}

func TestRegister_InvalidEmail(t *testing.T) {
	st := newMockStore()
	h := NewUserHandler(st)

	body := `{"username":"alice","email":"notanemail","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Register (bad email) status = %d, want 400", rr.Code)
	}
}

func TestRegister_ShortPassword(t *testing.T) {
	st := newMockStore()
	h := NewUserHandler(st)

	body := `{"username":"alice","email":"a@b.com","password":"short"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Register (short password) status = %d, want 400", rr.Code)
	}
}

func TestRegister_Success(t *testing.T) {
	st := newMockStore()
	h := NewUserHandler(st)

	body := `{"username":"charlie","email":"charlie@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Errorf("Register status = %d, want 200 or 201; body: %s", rr.Code, rr.Body.String())
	}
}
