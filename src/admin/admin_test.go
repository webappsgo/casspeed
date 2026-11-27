package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
)

// ---- HashPassword / VerifyPassword tests ---------------------------------

func TestHashPassword_Format(t *testing.T) {
	h := HashPassword("testpassword")
	if !strings.Contains(h, "$") {
		t.Errorf("hash %q missing '$' separator", h)
	}
	parts := strings.SplitN(h, "$", 2)
	if len(parts[0]) != 32 {
		t.Errorf("salt hex length = %d, want 32", len(parts[0]))
	}
	if len(parts[1]) != 64 {
		t.Errorf("hash hex length = %d, want 64", len(parts[1]))
	}
}

func TestHashPassword_Unique(t *testing.T) {
	h1 := HashPassword("same")
	h2 := HashPassword("same")
	if h1 == h2 {
		t.Error("two hashes of the same password should differ (random salt)")
	}
}

func TestVerifyPassword_Correct(t *testing.T) {
	h := HashPassword("mypassword")
	if !VerifyPassword("mypassword", h) {
		t.Error("VerifyPassword should return true for correct password")
	}
}

func TestVerifyPassword_Wrong(t *testing.T) {
	h := HashPassword("mypassword")
	if VerifyPassword("wrongpassword", h) {
		t.Error("VerifyPassword should return false for wrong password")
	}
}

func TestVerifyPassword_Empty(t *testing.T) {
	h := HashPassword("mypassword")
	if VerifyPassword("", h) {
		t.Error("empty password should not verify")
	}
}

func TestVerifyPassword_TooShort(t *testing.T) {
	// Hash string shorter than 33 bytes must return false immediately.
	if VerifyPassword("anything", "short") {
		t.Error("too-short hash should return false")
	}
}

func TestVerifyPassword_Malformed(t *testing.T) {
	// No separator.
	badHash := strings.Repeat("a", 33) // exactly 33 chars but no valid $
	if VerifyPassword("anything", badHash) {
		t.Error("malformed hash should return false")
	}
}

func TestVerifyPassword_EmptyHashIsShort(t *testing.T) {
	if VerifyPassword("anything", "") {
		t.Error("empty hash should return false")
	}
}

// ---- GenerateSetupToken / ValidateSetupToken / IsSetupComplete tests -----

func TestGenerateSetupToken_Format(t *testing.T) {
	// Reset global state for test isolation.
	SetSetupComplete(false)

	tok, err := GenerateSetupToken()
	if err != nil {
		t.Fatalf("GenerateSetupToken error: %v", err)
	}
	if len(tok) != 32 {
		t.Errorf("token length = %d, want 32", len(tok))
	}
	for _, c := range tok {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("non-hex character %q in token", c)
		}
	}
}

func TestGenerateSetupToken_Unique(t *testing.T) {
	SetSetupComplete(false)
	t1, _ := GenerateSetupToken()
	t2, _ := GenerateSetupToken()
	if t1 == t2 {
		t.Error("consecutive tokens should differ")
	}
}

func TestValidateSetupToken_Valid(t *testing.T) {
	SetSetupComplete(false)
	tok, _ := GenerateSetupToken()
	if !ValidateSetupToken(tok) {
		t.Error("valid token should pass validation")
	}
}

func TestValidateSetupToken_Wrong(t *testing.T) {
	SetSetupComplete(false)
	GenerateSetupToken()
	if ValidateSetupToken("wrongtoken") {
		t.Error("wrong token should fail validation")
	}
}

func TestValidateSetupToken_AfterMarkComplete(t *testing.T) {
	SetSetupComplete(false)
	tok, _ := GenerateSetupToken()
	MarkSetupComplete()
	if ValidateSetupToken(tok) {
		t.Error("token should be invalid after MarkSetupComplete")
	}
}

func TestIsSetupComplete_AfterSet(t *testing.T) {
	SetSetupComplete(false)
	if IsSetupComplete() {
		t.Error("should not be complete after SetSetupComplete(false)")
	}
	SetSetupComplete(true)
	if !IsSetupComplete() {
		t.Error("should be complete after SetSetupComplete(true)")
	}
	SetSetupComplete(false) // cleanup
}

func TestMarkSetupComplete_SetsTrue(t *testing.T) {
	SetSetupComplete(false)
	MarkSetupComplete()
	if !IsSetupComplete() {
		t.Error("IsSetupComplete should be true after MarkSetupComplete")
	}
	SetSetupComplete(false) // cleanup
}

func TestLoadOrCreateSetupTokenPersistsOnlyHash(t *testing.T) {
	SetSetupComplete(false)
	path := filepath.Join(t.TempDir(), "config", "setup_token.txt")
	token, created, err := LoadOrCreateSetupToken(path)
	if err != nil || !created || len(token) != 32 {
		t.Fatalf("first load = (%q, %v, %v), want generated token", token, created, err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(token))
	if string(stored) != hex.EncodeToString(want[:])+"\n" {
		t.Fatal("setup token file does not contain only the SHA-256 hash")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("token file mode = %o, want 600", info.Mode().Perm())
	}

	SetSetupComplete(false)
	reloaded, created, err := LoadOrCreateSetupToken(path)
	if err != nil || created || reloaded != "" || !ValidateSetupToken(token) {
		t.Fatalf("reload = (%q, %v, %v), token validation = %v", reloaded, created, err, ValidateSetupToken(token))
	}
	SetSetupComplete(false)
}

func TestSetupTokenExchangeIsOneTime(t *testing.T) {
	SetSetupComplete(false)
	token, err := GenerateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/setup/token", nil)
	response := httptest.NewRecorder()
	if err := IssueSetupSession(response, request); err != nil {
		t.Fatalf("first session issue: %v", err)
	}
	if err := IssueSetupSession(httptest.NewRecorder(), request); err == nil {
		t.Fatal("second session issue should fail")
	}
	if !ValidateSetupToken(token) {
		t.Fatal("one-time exchange should not invalidate token hash before setup completion")
	}
	MarkSetupComplete()
	if ValidateSetupToken(token) {
		t.Fatal("completed setup must invalidate token")
	}
	SetSetupComplete(false)
}

func TestSaveSettingsPersistsValidatedValues(t *testing.T) {
	cfg := config.Default()
	path := filepath.Join(t.TempDir(), "server.yml")
	handler := NewHandler(nil)
	handler.ConfigureSettings(cfg, path)
	port, threads, duration, concurrent := 65432, 8, 20, 5
	update := settingsUpdate{Server: serverSettingsUpdate{Port: &port, Mode: "development"}, Test: testSettingsUpdate{MaxThreads: &threads, DefaultDuration: &duration, MaxConcurrent: &concurrent}}
	if err := handler.saveSettings(update); err != nil {
		t.Fatalf("saveSettings: %v", err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if configPort(loaded) != port || loaded.Server.Mode != "development" || loaded.Test.MaxThreads != threads || loaded.Test.DefaultDuration != duration || loaded.Test.MaxConcurrent != concurrent {
		t.Fatalf("saved config = %#v, want updated server and test settings", loaded)
	}
	invalidPort := 70000
	if err := handler.saveSettings(settingsUpdate{Server: serverSettingsUpdate{Port: &invalidPort}}); err != errInvalidSettings {
		t.Fatalf("invalid setting error = %v, want validation error", err)
	}
	if configPort(cfg) != port {
		t.Fatal("invalid update changed in-memory config")
	}
}

func TestSettingsAPIAndFormHandlers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yml")
	h := NewHandler(nil)
	h.ConfigureSettings(config.Default(), path)

	get := httptest.NewRecorder()
	h.GetSettings(get, httptest.NewRequest(http.MethodGet, "/api/v1/server/admin/settings", nil))
	var settings map[string]any
	if get.Code != http.StatusOK || json.Unmarshal(get.Body.Bytes(), &settings) != nil || settings["server"] == nil || settings["test"] == nil {
		t.Fatalf("settings API response = %d %s", get.Code, get.Body.String())
	}

	invalid := httptest.NewRequest(http.MethodPut, "/api/v1/server/admin/settings", strings.NewReader(`{"unexpected":true}`))
	invalidResponse := httptest.NewRecorder()
	h.UpdateSettings(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("unknown settings field status = %d", invalidResponse.Code)
	}
	update := httptest.NewRequest(http.MethodPut, "/api/v1/server/admin/settings", strings.NewReader(`{"server":{"port":65431,"mode":"development"},"test":{"max_threads":4,"default_duration":12,"max_concurrent":3}}`))
	updateResponse := httptest.NewRecorder()
	h.UpdateSettings(updateResponse, update)
	if updateResponse.Code != http.StatusOK || !strings.Contains(updateResponse.Body.String(), `"port":65431`) {
		t.Fatalf("settings update response = %d %s", updateResponse.Code, updateResponse.Body.String())
	}

	pageRequest := httptest.NewRequest(http.MethodGet, "/server/admin/settings", nil)
	pageResponse := httptest.NewRecorder()
	h.ServerSettings(pageResponse, pageRequest)
	if pageResponse.Code != http.StatusOK || !strings.Contains(pageResponse.Body.String(), `name="csrf_token"`) {
		t.Fatalf("settings page response = %d %s", pageResponse.Code, pageResponse.Body.String())
	}
	badCSRF := httptest.NewRequest(http.MethodPost, "/server/admin/settings", strings.NewReader("port=65432"))
	badCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badCSRFResponse := httptest.NewRecorder()
	h.ServerSettings(badCSRFResponse, badCSRF)
	if badCSRFResponse.Code != http.StatusForbidden {
		t.Fatalf("settings invalid CSRF status = %d", badCSRFResponse.Code)
	}
	form := "csrf_token=session&port=65432&mode=production&max_threads=4&duration=10&max_concurrent=2"
	goodCSRF := httptest.NewRequest(http.MethodPost, "/server/admin/settings", strings.NewReader(form))
	goodCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	goodCSRF.AddCookie(&http.Cookie{Name: "admin_session", Value: "session"})
	goodCSRFResponse := httptest.NewRecorder()
	h.ServerSettings(goodCSRFResponse, goodCSRF)
	if goodCSRFResponse.Code != http.StatusSeeOther {
		t.Fatalf("settings form response = %d %s", goodCSRFResponse.Code, goodCSRFResponse.Body.String())
	}
}

func TestAdminPagesRenderDescriptionsAndDashboard(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := NewHandler(st)
	h.ConfigureSettings(config.Default(), filepath.Join(t.TempDir(), "server.yml"), "1.2.3", t.TempDir())
	pages := []struct {
		name string
		hand func(http.ResponseWriter, *http.Request)
	}{
		{"profile", h.Profile}, {"preferences", h.Preferences}, {"notifications", h.Notifications},
		{"audit", h.ServerAuditLogs}, {"backup", h.ServerBackup}, {"updates", h.ServerUpdates},
		{"ssl", h.ServerSSL}, {"email", h.ServerEmail}, {"scheduler", h.ServerScheduler},
		{"metrics", h.ServerMetrics}, {"tor", h.NetworkTor}, {"geoip", h.NetworkGeoIP},
		{"auth", h.SecurityAuth}, {"tokens", h.SecurityTokens}, {"users", h.ServerUsers},
	}
	for _, page := range pages {
		t.Run(page.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			page.hand(response, httptest.NewRequest(http.MethodGet, "/server/admin/"+page.name, nil))
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "<main") || !strings.Contains(response.Body.String(), "<h1") {
				t.Fatalf("page response = %d %s", response.Code, response.Body.String())
			}
		})
	}
	dashboard := httptest.NewRecorder()
	h.Dashboard(dashboard, httptest.NewRequest(http.MethodGet, "/server/admin/", nil))
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), "1.2.3") || !strings.Contains(dashboard.Body.String(), "Online") {
		t.Fatalf("dashboard response = %d %s", dashboard.Code, dashboard.Body.String())
	}
}

// ---- ValidateSetupData tests --------------------------------------------

func validSetupData() *SetupWizardData {
	return &SetupWizardData{
		AdminUsername: "admin",
		AdminPassword: "password123",
		Mode:          "production",
	}
}

func TestValidateSetupData_Valid(t *testing.T) {
	if err := ValidateSetupData(validSetupData()); err != nil {
		t.Errorf("valid data failed: %v", err)
	}
}

func TestValidateSetupData_EmptyUsername(t *testing.T) {
	d := validSetupData()
	d.AdminUsername = ""
	if err := ValidateSetupData(d); err == nil {
		t.Error("expected error for empty username")
	}
}

func TestValidateSetupData_ShortUsername(t *testing.T) {
	d := validSetupData()
	d.AdminUsername = "ab"
	if err := ValidateSetupData(d); err == nil {
		t.Error("expected error for 2-char username")
	}
}

func TestValidateSetupData_LongUsername(t *testing.T) {
	d := validSetupData()
	d.AdminUsername = strings.Repeat("a", 31)
	if err := ValidateSetupData(d); err == nil {
		t.Error("expected error for 31-char username")
	}
}

func TestValidateSetupData_EmptyPassword(t *testing.T) {
	d := validSetupData()
	d.AdminPassword = ""
	if err := ValidateSetupData(d); err == nil {
		t.Error("expected error for empty password")
	}
}

func TestValidateSetupData_ShortPassword(t *testing.T) {
	d := validSetupData()
	d.AdminPassword = "short"
	if err := ValidateSetupData(d); err == nil {
		t.Error("expected error for password < 8 chars")
	}
}

func TestValidateSetupData_DefaultsApplied(t *testing.T) {
	d := &SetupWizardData{
		AdminUsername: "admin",
		AdminPassword: "password123",
	}
	if err := ValidateSetupData(d); err != nil {
		t.Fatalf("error: %v", err)
	}
	if d.AppName != "casspeed" {
		t.Errorf("AppName = %q, want casspeed", d.AppName)
	}
	if d.Mode != "production" {
		t.Errorf("Mode = %q, want production", d.Mode)
	}
	if d.Timezone != "America/New_York" {
		t.Errorf("Timezone = %q, want America/New_York", d.Timezone)
	}
}

func TestValidateSetupData_InvalidMode(t *testing.T) {
	d := validSetupData()
	d.Mode = "staging"
	if err := ValidateSetupData(d); err == nil {
		t.Error("expected error for invalid mode 'staging'")
	}
}

// ---- Handler page-render tests (no store needed) -------------------------

func newTestHandler() *Handler {
	return NewHandler(nil)
}

func TestHandler_ServerSettings(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/settings", nil)
	rec := httptest.NewRecorder()
	h.ServerSettings(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unconfigured settings status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandler_ServerInfo(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/info", nil)
	rec := httptest.NewRecorder()
	h.ServerInfo(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusInternalServerError {
		t.Errorf("unexpected status %d", rec.Code)
	}
}

func TestHandler_ServerLogs(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/logs", nil)
	rec := httptest.NewRecorder()
	h.ServerLogs(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusInternalServerError {
		t.Errorf("unexpected status %d", rec.Code)
	}
}

func TestHandler_Profile(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/username/profile", nil)
	rec := httptest.NewRecorder()
	h.Profile(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Profile status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if body == "" {
		t.Error("Profile returned empty body")
	}
}

func TestHandler_Preferences(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/username/preferences", nil)
	rec := httptest.NewRecorder()
	h.Preferences(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Preferences status = %d, want 200", rec.Code)
	}
}

func TestHandler_Notifications(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/username/notifications", nil)
	rec := httptest.NewRecorder()
	h.Notifications(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Notifications status = %d, want 200", rec.Code)
	}
}

func TestHandler_ServerAuditLogs(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/logs/audit", nil)
	rec := httptest.NewRecorder()
	h.ServerAuditLogs(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ServerAuditLogs status = %d, want 200", rec.Code)
	}
}

func TestHandler_ServerBackup(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/backup", nil)
	rec := httptest.NewRecorder()
	h.ServerBackup(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ServerBackup status = %d, want 200", rec.Code)
	}
}

func TestHandler_ServerUpdates(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/updates", nil)
	rec := httptest.NewRecorder()
	h.ServerUpdates(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ServerUpdates status = %d, want 200", rec.Code)
	}
}

func TestHandler_ServerSSL(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/ssl", nil)
	rec := httptest.NewRecorder()
	h.ServerSSL(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ServerSSL status = %d, want 200", rec.Code)
	}
}

func TestHandler_ServerEmail(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/email", nil)
	rec := httptest.NewRecorder()
	h.ServerEmail(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ServerEmail status = %d, want 200", rec.Code)
	}
}

func TestHandler_ServerScheduler(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/scheduler", nil)
	rec := httptest.NewRecorder()
	h.ServerScheduler(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ServerScheduler status = %d, want 200", rec.Code)
	}
}

func TestHandler_ServerMetrics(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServerMetrics(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ServerMetrics status = %d, want 200", rec.Code)
	}
}

func TestHandler_NetworkTor(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/network/tor", nil)
	rec := httptest.NewRecorder()
	h.NetworkTor(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("NetworkTor status = %d, want 200", rec.Code)
	}
}

func TestHandler_NetworkGeoIP(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/network/geoip", nil)
	rec := httptest.NewRecorder()
	h.NetworkGeoIP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("NetworkGeoIP status = %d, want 200", rec.Code)
	}
}

func TestHandler_SecurityAuth(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/security/auth", nil)
	rec := httptest.NewRecorder()
	h.SecurityAuth(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("SecurityAuth status = %d, want 200", rec.Code)
	}
}

func TestHandler_SecurityTokens(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/security/tokens", nil)
	rec := httptest.NewRecorder()
	h.SecurityTokens(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("SecurityTokens status = %d, want 200", rec.Code)
	}
}

func TestHandler_ServerUsers(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest("GET", "/server/admin/config/users", nil)
	rec := httptest.NewRecorder()
	h.ServerUsers(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ServerUsers status = %d, want 200", rec.Code)
	}
}

func TestHandler_RequireAuth_RedirectsUnauthenticated(t *testing.T) {
	h := newTestHandler()
	handler := h.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/server/admin/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	// Without auth cookie, should redirect
	if rec.Code == http.StatusOK {
		t.Error("unauthenticated request should not return 200")
	}
}

func TestHandler_RequireAuthPassesAuthenticatedAdminContext(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	const sessionID = "valid-admin-session"
	const adminID = 42
	if err := st.CreateAdminSession(context.Background(), &model.AdminSession{
		ID:        sessionID,
		AdminID:   adminID,
		IPAddress: "127.0.0.1",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateAdminSession: %v", err)
	}

	h := NewHandler(st)
	called := false
	protected := h.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if got := r.Context().Value(adminIDContextKey); got != adminID {
			t.Errorf("admin ID in request context = %v, want %d", got, adminID)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/server/admin/", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: sessionID})
	rec := httptest.NewRecorder()
	protected(rec, req)
	if !called || rec.Code != http.StatusNoContent {
		t.Errorf("authenticated handler called=%t status=%d", called, rec.Code)
	}
}
