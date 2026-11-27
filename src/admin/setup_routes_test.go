package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/server/store"
)

func TestSetupRoutesCompleteFirstRun(t *testing.T) {
	SetSetupComplete(false)
	t.Cleanup(func() { SetSetupComplete(false) })
	token, err := GenerateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := NewHandler(st)

	entry := httptest.NewRecorder()
	h.SetupWizardHandler(entry, httptest.NewRequest(http.MethodGet, "/server/admin/setup", nil))
	if entry.Code != http.StatusOK || !strings.Contains(entry.Body.String(), "setup-card") {
		t.Fatalf("unauthorized wizard response = %d", entry.Code)
	}

	form := url.Values{"token": {token}}
	request := httptest.NewRequest(http.MethodPost, "/server/admin/setup/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	exchanged := httptest.NewRecorder()
	h.SetupTokenHandler(exchanged, request)
	if exchanged.Code != http.StatusSeeOther || exchanged.Header().Get("Location") != h.adminRootPath()+"/setup" {
		t.Fatalf("token exchange = %d location=%q", exchanged.Code, exchanged.Header().Get("Location"))
	}
	var setupCookie *http.Cookie
	for _, cookie := range exchanged.Result().Cookies() {
		if cookie.Name == "casspeed_setup" {
			setupCookie = cookie
		}
	}
	if setupCookie == nil {
		t.Fatal("token exchange did not issue setup session")
	}

	wizardRequest := httptest.NewRequest(http.MethodGet, "/server/admin/setup", nil)
	wizardRequest.AddCookie(setupCookie)
	wizard := httptest.NewRecorder()
	h.SetupWizardHandler(wizard, wizardRequest)
	if wizard.Code != http.StatusOK || !strings.Contains(wizard.Body.String(), "wizard-container") {
		t.Fatalf("authorized wizard response = %d", wizard.Code)
	}

	completionRequest := httptest.NewRequest(http.MethodPost, "/server/admin/setup/complete", strings.NewReader(`{"admin_username":"root-admin","admin_password":"strong-password-123"}`))
	completionRequest.AddCookie(setupCookie)
	completion := httptest.NewRecorder()
	h.SetupCompleteHandler(completion, completionRequest)
	if completion.Code != http.StatusOK {
		t.Fatalf("setup completion = %d body=%s", completion.Code, completion.Body.String())
	}
	var response struct {
		Success  bool   `json:"success"`
		APIToken string `json:"api_token"`
	}
	if err := json.Unmarshal(completion.Body.Bytes(), &response); err != nil || !response.Success || !validAdminTokenFormat(response.APIToken) {
		t.Fatalf("setup completion response = %#v, %v", response, err)
	}
	if !IsSetupComplete() {
		t.Fatal("successful setup did not mark first run complete")
	}
	admin, err := st.GetAdminByUsername(context.Background(), "root-admin")
	if err != nil || admin == nil || admin.Role != "primary" {
		t.Fatalf("created admin = %#v, %v", admin, err)
	}
}

func TestSetupRoutesRejectInvalidAndCompletedRequests(t *testing.T) {
	SetSetupComplete(false)
	t.Cleanup(func() { SetSetupComplete(false) })
	h := NewHandler(nil)
	wrongMethod := httptest.NewRecorder()
	h.SetupTokenHandler(wrongMethod, httptest.NewRequest(http.MethodGet, "/server/admin/setup/token", nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("token wrong method status = %d", wrongMethod.Code)
	}
	invalid := httptest.NewRecorder()
	h.SetupTokenHandler(invalid, httptest.NewRequest(http.MethodPost, "/server/admin/setup/token", strings.NewReader("token=bad")))
	if invalid.Code != http.StatusOK || !strings.Contains(invalid.Body.String(), "setup-card") {
		t.Fatalf("invalid token response = %d", invalid.Code)
	}
	unauthorized := httptest.NewRecorder()
	h.SetupCompleteHandler(unauthorized, httptest.NewRequest(http.MethodPost, "/server/admin/setup/complete", strings.NewReader("{}")))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized completion status = %d", unauthorized.Code)
	}
	SetSetupComplete(true)
	completed := httptest.NewRecorder()
	h.SetupCompleteHandler(completed, httptest.NewRequest(http.MethodPost, "/server/admin/setup/complete", strings.NewReader("{}")))
	if completed.Code != http.StatusBadRequest {
		t.Fatalf("completed setup status = %d", completed.Code)
	}
}
