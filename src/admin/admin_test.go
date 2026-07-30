package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	if rec.Code != http.StatusOK && rec.Code != http.StatusInternalServerError {
		t.Errorf("unexpected status %d", rec.Code)
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
