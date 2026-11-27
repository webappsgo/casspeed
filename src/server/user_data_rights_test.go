package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

func TestUserDataExportRequiresDeleteConfirmation(t *testing.T) {
	var page bytes.Buffer
	data := map[string]any{
		"Lead": "Export your data.", "DeleteTitle": "Delete your account", "DeleteWarning": "This cannot be undone.",
		"CSRF": "csrf", "UsernameLabel": "Username", "PasswordLabel": "Password", "DeleteButton": "Delete account",
		"Cancel": "Cancel", "RequireTOTP": true, "CodeLabel": "Authenticator code",
	}
	if err := userDataExportPage.Execute(&page, data); err != nil {
		t.Fatalf("render user data page: %v", err)
	}
	content := page.String()
	for _, required := range []string{`type="button" popovertarget="delete-account-confirm"`, `id="delete-account-confirm" popover`, `type="submit">Delete account</button>`, `name="confirm_username"`, `name="current_password"`, `name="code"`} {
		if !strings.Contains(content, required) {
			t.Errorf("account deletion page missing %q: %s", required, content)
		}
	}
}

func TestUserDataExportIsPrivateDownloadableAndPurged(t *testing.T) {
	database, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	owner := &model.User{Username: "data-owner", Email: "owner@example.test", DisplayName: "Owner", CreatedAt: time.Now().UTC()}
	other := &model.User{Username: "other-owner", Email: "other@example.test", CreatedAt: time.Now().UTC()}
	for _, user := range []*model.User{owner, other} {
		if err := database.CreateUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
	}
	s := minimalServer()
	s.Store = database
	defer s.purgeUserDataExports(model.UserIDString(owner.ID))
	defer s.purgeUserDataExports(model.UserIDString(other.ID))

	id, err := s.createUserDataExport(context.Background(), owner)
	if err != nil {
		t.Fatalf("createUserDataExport() error = %v", err)
	}
	request := withExportRouteID(httptest.NewRequest(http.MethodGet, "/api/v1/users/data/export/"+id, nil), id)
	response := httptest.NewRecorder()
	s.downloadUserDataExport(response, request, other)
	if response.Code != http.StatusNotFound {
		t.Fatalf("foreign owner download status = %d, want 404", response.Code)
	}
	request = withExportRouteID(httptest.NewRequest(http.MethodGet, "/api/v1/users/data/export/"+id, nil), id)
	response = httptest.NewRecorder()
	s.downloadUserDataExport(response, request, owner)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("owner download response = %d headers=%v", response.Code, response.Header())
	}
	var document userDataExportDocument
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("download is not a valid export document: %v", err)
	}
	if document.Profile["username"] != owner.Username || document.Settings == nil {
		t.Fatalf("export omitted account data or settings: %#v", document)
	}
	s.purgeUserDataExports(model.UserIDString(owner.ID))
	request = withExportRouteID(httptest.NewRequest(http.MethodGet, "/api/v1/users/data/export/"+id, nil), id)
	response = httptest.NewRecorder()
	s.downloadUserDataExport(response, request, owner)
	if response.Code != http.StatusNotFound {
		t.Fatalf("purged export download status = %d, want 404", response.Code)
	}
}

func withExportRouteID(request *http.Request, id string) *http.Request {
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", id)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
}

func TestUserDataExportEnforcesPerUserRateLimit(t *testing.T) {
	database, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	user := &model.User{Username: "export-limited", Email: "limited@example.test", CreatedAt: time.Now().UTC()}
	if err := database.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = database
	defer s.purgeUserDataExports(model.UserIDString(user.ID))
	for range userDataExportThreshold {
		if _, err := s.createUserDataExport(context.Background(), user); err != nil {
			t.Fatalf("allowed export request was rejected: %v", err)
		}
	}
	if _, err := s.createUserDataExport(context.Background(), user); err != errUserDataExportRateLimit {
		t.Fatalf("request after limit returned %v, want rate limit error", err)
	}
}

func TestUserDataDeleteAPIRequiresIdentityAndPasswordConfirmation(t *testing.T) {
	database, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	passwordHash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	user := &model.User{Username: "delete-me", Email: "delete@example.test", PasswordHash: passwordHash, Approved: true, EmailVerified: true, CreatedAt: time.Now().UTC()}
	if err := database.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = database
	request := func(method, body string, identity *pageIdentity) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/users/data/delete", strings.NewReader(body))
		if identity != nil {
			r = r.WithContext(context.WithValue(r.Context(), pageIdentityContextKey{}, identity))
		}
		w := httptest.NewRecorder()
		s.handleUserDataDelete(w, r)
		return w
	}
	if got := request(http.MethodPost, `{}`, nil); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", got.Code)
	}
	identity := &pageIdentity{User: user}
	if got := request(http.MethodGet, "", identity); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status = %d", got.Code)
	}
	if got := request(http.MethodPost, "{", identity); got.Code != http.StatusBadRequest {
		t.Fatalf("malformed body status = %d", got.Code)
	}
	wrongPassword := request(http.MethodPost, `{"confirm_username":"delete-me","current_password":"wrong"}`, identity)
	if wrongPassword.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d", wrongPassword.Code)
	}
	deleted := request(http.MethodPost, `{"confirm_username":"delete-me","current_password":"correct horse battery staple"}`, identity)
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"status":"deleted"`) {
		t.Fatalf("deletion response = %d: %s", deleted.Code, deleted.Body.String())
	}
	if remaining, err := database.GetUser(context.Background(), model.UserIDString(user.ID)); err != nil || remaining != nil {
		t.Fatalf("account remains after deletion: user=%v err=%v", remaining, err)
	}
}
