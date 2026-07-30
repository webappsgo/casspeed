package handler

import (
	"bytes"
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
}

func TestDownload_RespondsWithData(t *testing.T) {
	st := newMockStore()
	svc := service.NewSpeedTestService(1, 65536)
	h := NewSpeedTestHandler(st, svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test/download", nil)
	rr := httptest.NewRecorder()
	h.Download(rr, req)

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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test/upload", bytes.NewReader(payload))
	rr := httptest.NewRecorder()
	h.Upload(rr, req)

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
		DownloadMbps: 100.0,
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

	if rr.Code != http.StatusOK {
		t.Errorf("GetHistory status = %d, want 200", rr.Code)
	}
}

func TestGetHistory_DBError(t *testing.T) {
	st := newMockStore()
	st.errGetHistory = errDB
	svc := service.NewSpeedTestService(1, 65536)
	h := NewSpeedTestHandler(st, svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/history", nil)
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
	st.users["u1"] = &model.User{ID: "u1", Username: "alice", PasswordHash: hash}

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
	st.users["u1"] = &model.User{
		ID:           "u1",
		Username:     "alice",
		Email:        "alice@example.com",
		PasswordHash: hash,
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
		if c.Name == "session" {
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
	st.users["u1"] = &model.User{ID: "u1", Username: "bob", PasswordHash: hash}
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
	req.AddCookie(&http.Cookie{Name: "session", Value: "sess-abc"})
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
	rr := httptest.NewRecorder()
	h.PasswordResetRequest(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
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
