package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

func TestUserInviteCreationAndAcceptance(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.Default()
	s := &Server{Config: cfg, Store: st}
	r := httptest.NewRequest("POST", "https://casspeed.test/server/administration/users/invites", nil)
	link, err := s.createUserInvite(r, "user", 1, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	code := path.Base(parsed.Path)
	if len(code) != 64 || strings.Contains(link, "#") {
		t.Fatalf("invitation link did not contain an opaque code: %q", link)
	}
	invite, err := st.GetUserInviteByCode(t.Context(), code, time.Now())
	if err != nil || invite == nil || invite.Role != "user" || invite.MaxUses != 1 {
		t.Fatalf("created invitation lookup = %#v, %v", invite, err)
	}
	if remainingInviteUses(invite) != 1 {
		t.Fatalf("remaining uses = %v, want 1", remainingInviteUses(invite))
	}
	if _, err := s.completeUserInvite(r, code, " new-member ", "new@example.test", "Strong-password1!", "different"); err == nil {
		t.Fatal("mismatched invitation password confirmation was accepted")
	}
	user, err := s.completeUserInvite(r, code, " new-member ", "new@example.test", "Strong-password1!", "Strong-password1!")
	if err != nil {
		t.Fatalf("accept invitation: %v", err)
	}
	if user.Username != "new-member" || user.Email != "new@example.test" || user.Role != "user" || !user.Approved || !user.EmailVerified {
		t.Fatalf("unexpected invited account state: %#v", user)
	}
	if remainingInviteUses(&model.UserInvite{MaxUses: 1, UseCount: 3}) != 0 || remainingInviteUses(&model.UserInvite{MaxUses: 0}) != "unlimited" {
		t.Fatal("remaining invitation uses did not clamp or report unlimited use")
	}
	if _, err := st.GetUserInviteByCode(t.Context(), code, time.Now()); err != nil {
		t.Fatal(err)
	} else if exhausted, err := st.GetUserInviteByCode(t.Context(), code, time.Now()); err != nil || exhausted != nil {
		t.Fatalf("single-use invitation remained usable: %#v, %v", exhausted, err)
	}
}

func TestAdminUserActivationAndValidationHelpers(t *testing.T) {
	for _, test := range []struct {
		username, email string
		valid           bool
	}{
		{"valid-user", "valid@example.test", true},
		{"x", "valid@example.test", false},
		{"-invalid", "valid@example.test", false},
		{"valid-user", "Name <valid@example.test>", false},
	} {
		err := validateAdminUserInput(test.username, test.email)
		if (err == nil) != test.valid {
			t.Errorf("validateAdminUserInput(%q, %q) error = %v", test.username, test.email, err)
		}
	}
	if got := maskUserEmail("alice@example.test"); got != "a***e@e***.test" {
		t.Fatalf("masked email = %q", got)
	}
	if maskUserEmail("broken") != "" || maskUserEmail("@example.test") != "" {
		t.Fatal("malformed email was not hidden")
	}
	for _, test := range []struct {
		raw   string
		want  int
		valid bool
	}{{"", 1, true}, {"2", 2, true}, {"0", 0, false}, {"100001", 0, false}, {"bad", 0, false}} {
		got, err := parsePage(test.raw)
		if (err == nil) != test.valid || test.valid && got != test.want {
			t.Errorf("parsePage(%q) = %d, %v", test.raw, got, err)
		}
	}
	if got := pageURL("/admin/users", 3, "two words"); got != "/admin/users?page=3&q=two+words" {
		t.Fatalf("page URL = %q", got)
	}
	if got := pageURL("/admin/users", 1, ""); got != "/admin/users?page=1" {
		t.Fatalf("page URL without search = %q", got)
	}

	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := &Server{Config: config.Default(), Store: st}
	r := httptest.NewRequest("POST", "https://casspeed.test/server/administration/users", nil)
	link, err := s.createAdminUser(r, "pending-user", "pending@example.test", false)
	if err != nil || link == "" {
		t.Fatalf("create activation link: %q, %v", link, err)
	}
	user, err := st.GetUserByUsername(t.Context(), "pending-user")
	if err != nil || user == nil || !user.Approved || !user.Disabled {
		t.Fatalf("pending user state = %#v, %v", user, err)
	}
	if _, err := s.createAdminUser(r, "pending-user", "another@example.test", false); err == nil {
		t.Fatal("duplicate username was accepted")
	}
	if _, err := s.createAdminUser(r, "another-user", "pending@example.test", false); err == nil {
		t.Fatal("duplicate email was accepted")
	}
}

func TestAdminUserAPIListsCreatesDisablesEnablesAndDeletes(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := minimalServer()
	s.Store = st
	user := &model.User{Username: "managed-user", Email: "managed@example.test", PasswordHash: "unused", Approved: true, EmailVerified: true}
	if err := st.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	user, err = st.GetUserByUsername(t.Context(), user.Username)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(t.Context(), &model.Session{ID: "managed-session", UserID: model.UserIDString(user.ID), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	call := func(method, target, body string, params map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, target, strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		if len(params) > 0 {
			routeContext := chi.NewRouteContext()
			for key, value := range params {
				routeContext.URLParams.Add(key, value)
			}
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
		}
		response := httptest.NewRecorder()
		s.handleAdminUsersAPI(response, request)
		return response
	}
	if response := call(http.MethodGet, "/server/administration/users?page=1&q=managed", "", nil); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "managed-user") {
		t.Fatalf("user list returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, "/server/administration/users/1", "", map[string]string{"id": model.UserIDString(user.ID)}); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "@e***.test") {
		t.Fatalf("user detail returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "/server/administration/users", `{"username":"created-user","email":"created@example.test","delivery":"copy"}`, nil); response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), "activation_url") {
		t.Fatalf("admin user create returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "/server/administration/users/disable", `{"id":1}`, nil); response.Code != http.StatusOK {
		t.Fatalf("user disable returned %d: %s", response.Code, response.Body.String())
	}
	if session, err := st.GetSession(t.Context(), "managed-session"); err != nil || session != nil {
		t.Fatalf("disabled user retained a session: %#v, %v", session, err)
	}
	if response := call(http.MethodPost, "/server/administration/users/enable", `{"id":1}`, nil); response.Code != http.StatusOK {
		t.Fatalf("user enable returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodDelete, "/server/administration/users/1", "", map[string]string{"id": model.UserIDString(user.ID)}); response.Code != http.StatusOK {
		t.Fatalf("user delete returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, "/server/administration/users?page=0", "", nil); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid pagination returned %d", response.Code)
	}
	if response := call(http.MethodPatch, "/server/administration/users", "", nil); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported method returned %d", response.Code)
	}
}

func TestUserInviteAPIReportsAndAcceptsSingleUseInvite(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := minimalServer()
	s.Store = st
	link, err := s.createUserInvite(httptest.NewRequest(http.MethodPost, "https://casspeed.test/server/admin/users/invites", nil), "user", 1, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	code := path.Base(mustParseURL(t, link).Path)
	call := func(method, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "https://casspeed.test/server/auth/invite/user/"+code, strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		routeContext := chi.NewRouteContext()
		routeContext.URLParams.Add("token", code)
		request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
		response := httptest.NewRecorder()
		s.handleUserInviteAPI(response, request)
		return response
	}
	if response := call(http.MethodGet, ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"role":"user"`) {
		t.Fatalf("invite lookup returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "{"); response.Code != http.StatusBadRequest {
		t.Fatalf("malformed invite acceptance returned %d", response.Code)
	}
	body := `{"username":"invitee","email":"invitee@example.test","password":"Strong-password1!","confirm_password":"Strong-password1!"}`
	if response := call(http.MethodPost, body); response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"username":"invitee"`) {
		t.Fatalf("invite acceptance returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, ""); response.Code != http.StatusNotFound {
		t.Fatalf("spent invite remained visible with status %d", response.Code)
	}
}

func TestAdminUserPageActionsRequireOriginCSRFAndConfirmation(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := minimalServer()
	s.Store = st
	user := &model.User{Username: "action-user", Email: "action@example.test", PasswordHash: "unused", Approved: true, EmailVerified: true}
	if err := st.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	user, err = st.GetUserByUsername(t.Context(), user.Username)
	if err != nil {
		t.Fatal(err)
	}
	call := func(action, form, origin string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "https://casspeed.test/server/administration/users/1/"+action, strings.NewReader(form))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", origin)
		request.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "action-csrf"})
		routeContext := chi.NewRouteContext()
		routeContext.URLParams.Add("id", model.UserIDString(user.ID))
		routeContext.URLParams.Add("action", action)
		request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
		response := httptest.NewRecorder()
		s.handleAdminUserAction(response, request)
		return response
	}
	validForm := "csrf_token=action-csrf"
	if response := call("disable", validForm, "https://attacker.test"); response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin action returned %d", response.Code)
	}
	if response := call("disable", validForm, "https://casspeed.test"); response.Code != http.StatusSeeOther {
		t.Fatalf("disable returned %d: %s", response.Code, response.Body.String())
	}
	if current, err := st.GetUser(t.Context(), model.UserIDString(user.ID)); err != nil || current == nil || !current.Disabled {
		t.Fatalf("disabled user = %#v, %v", current, err)
	}
	if response := call("enable", validForm, "https://casspeed.test"); response.Code != http.StatusSeeOther {
		t.Fatalf("enable returned %d", response.Code)
	}
	if err := st.CreateSession(t.Context(), &model.Session{ID: "action-session", UserID: model.UserIDString(user.ID), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if response := call("sessions", validForm, "https://casspeed.test"); response.Code != http.StatusSeeOther {
		t.Fatalf("session revocation returned %d", response.Code)
	}
	if response := call("delete", validForm+"&confirm=wrong", "https://casspeed.test"); response.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed deletion returned %d", response.Code)
	}
	if response := call("delete", validForm+"&confirm=action-user", "https://casspeed.test"); response.Code != http.StatusSeeOther {
		t.Fatalf("confirmed deletion returned %d: %s", response.Code, response.Body.String())
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestUserInvitesAPIListCreateAndRevoke(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := minimalServer()
	s.Store = st
	call := func(method, body, id string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "/api/v1/server/users/invites", strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		if id != "" {
			routeContext := chi.NewRouteContext()
			routeContext.URLParams.Add("id", id)
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
		}
		response := httptest.NewRecorder()
		s.handleUserInvitesAPI(response, request)
		return response
	}
	if response := call(http.MethodGet, "", ""); response.Code != http.StatusOK {
		t.Fatalf("invite list returned %d", response.Code)
	}
	body := `{"role":"user","max_uses":2,"expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`
	created := call(http.MethodPost, body, "")
	if created.Code != http.StatusCreated {
		t.Fatalf("invite creation returned %d: %s", created.Code, created.Body.String())
	}
	invites, err := st.ListUserInvites(t.Context())
	if err != nil || len(invites) != 1 {
		t.Fatalf("created invitations = %d, %v", len(invites), err)
	}
	if response := call(http.MethodGet, "", "1"); response.Code != http.StatusOK {
		t.Fatalf("invite details returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodDelete, "", "1"); response.Code != http.StatusOK {
		t.Fatalf("invite revocation returned %d", response.Code)
	}
	if response := call(http.MethodPost, `{`, ""); response.Code != http.StatusBadRequest {
		t.Fatalf("malformed invite request returned %d", response.Code)
	}
	if response := call(http.MethodDelete, "", "bad"); response.Code != http.StatusNotFound {
		t.Fatalf("invalid invite id returned %d", response.Code)
	}
	if response := call(http.MethodPut, "", ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported invite method returned %d", response.Code)
	}
}

func TestUserInvitePageRenderingAndWebRevocation(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := minimalServer()
	s.Store = st
	base := httptest.NewRequest(http.MethodGet, "http://example.test/server/administration/users/invites", nil)
	link, err := s.createUserInvite(base, "user", 2, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	invites, err := st.ListUserInvites(context.Background())
	if err != nil || len(invites) != 1 {
		t.Fatalf("created invites = %d, %v", len(invites), err)
	}
	code := path.Base(link)
	page := httptest.NewRecorder()
	pageRequest := httptest.NewRequest(http.MethodGet, "http://example.test/server/auth/invite/user/"+code, nil)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("token", code)
	s.handleUserInviteAcceptance(page, pageRequest.WithContext(context.WithValue(pageRequest.Context(), chi.RouteCtxKey, routeContext)))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `name="confirm_password"`) || page.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("invite acceptance page = %d headers=%v", page.Code, page.Header())
	}
	invalid := httptest.NewRecorder()
	invalidRequest := httptest.NewRequest(http.MethodGet, "/server/auth/invite/user/short", nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("token", "short")
	s.handleUserInviteAcceptance(invalid, invalidRequest.WithContext(context.WithValue(invalidRequest.Context(), chi.RouteCtxKey, route)))
	if invalid.Code != http.StatusNotFound {
		t.Fatalf("short invite code status = %d", invalid.Code)
	}
	revoke := func(valid bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://example.test/server/administration/users/invites/1/revoke", strings.NewReader("csrf_token=csrf"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", "http://example.test")
		if valid {
			request.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "csrf"})
		}
		route := chi.NewRouteContext()
		route.URLParams.Add("id", "1")
		request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
		response := httptest.NewRecorder()
		s.handleRevokeUserInvite(response, request)
		return response
	}
	if response := revoke(false); response.Code != http.StatusForbidden {
		t.Fatalf("revocation without CSRF status = %d", response.Code)
	}
	if response := revoke(true); response.Code != http.StatusSeeOther {
		t.Fatalf("revocation response = %d location=%q", response.Code, response.Header().Get("Location"))
	}
	if remaining, err := st.ListUserInvites(context.Background()); err != nil || len(remaining) != 0 {
		t.Fatalf("invites after revocation = %d, %v", len(remaining), err)
	}
}

func TestAdminActivationFormCompletesOneTimeUserActivation(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := minimalServer()
	s.Store = st
	creationRequest := httptest.NewRequest(http.MethodPost, "https://casspeed.test/server/administration/users", nil)
	link, err := s.createAdminUser(creationRequest, "activation-user", "activation@example.test", false)
	if err != nil {
		t.Fatal(err)
	}
	code := path.Base(mustParseURL(t, link).Path)
	call := func(method, form string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "https://casspeed.test/server/auth/invite/user/"+code, strings.NewReader(form))
		request.Header.Set("Origin", "https://casspeed.test")
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "activation-csrf"})
		routeContext := chi.NewRouteContext()
		routeContext.URLParams.Add("token", code)
		request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
		response := httptest.NewRecorder()
		s.handleUserInviteAcceptance(response, request)
		return response
	}
	if response := call(http.MethodGet, ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "activation-password") {
		t.Fatalf("activation form returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "csrf_token=activation-csrf&password=Strong-password1%21&confirm_password=wrong"); response.Code != http.StatusBadRequest {
		t.Fatalf("password mismatch returned %d", response.Code)
	}
	form := "csrf_token=activation-csrf&password=Strong-password1%21&confirm_password=Strong-password1%21"
	if response := call(http.MethodPost, form); response.Code != http.StatusSeeOther {
		t.Fatalf("activation returned %d: %s", response.Code, response.Body.String())
	}
	user, err := st.GetUserByUsername(t.Context(), "activation-user")
	if err != nil || user == nil || user.Disabled || !user.Approved {
		t.Fatalf("activated account = %#v, %v", user, err)
	}
	if response := call(http.MethodPost, form); response.Code != http.StatusNotFound {
		t.Fatalf("activation token replay returned %d", response.Code)
	}
}

func TestVerificationResendIsUniformAndOriginChecked(t *testing.T) {
	s := minimalServer()
	for _, test := range []struct {
		method string
		origin string
		form   string
		want   int
	}{
		{method: http.MethodGet, want: http.StatusOK},
		{method: http.MethodPost, origin: "https://attacker.test", form: "csrf_token=csrf&email=missing@example.test", want: http.StatusForbidden},
		{method: http.MethodPost, origin: "https://casspeed.test", form: "csrf_token=csrf&email=missing@example.test", want: http.StatusOK},
		{method: http.MethodPut, want: http.StatusMethodNotAllowed},
	} {
		request := httptest.NewRequest(test.method, "https://casspeed.test/server/auth/verify/resend", strings.NewReader(test.form))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if test.origin != "" {
			request.Header.Set("Origin", test.origin)
		}
		request.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "csrf"})
		response := httptest.NewRecorder()
		s.handleVerificationResend(response, request)
		if response.Code != test.want {
			t.Errorf("%s resend returned %d, want %d", test.method, response.Code, test.want)
		}
	}
}
