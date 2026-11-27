package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/server/handler"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/service"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

func TestPrivateSpeedTestPageRequiresOwnerAndStaysPrivate(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	secret := []byte(strings.Repeat("s", 32))
	hash := sha256.Sum256(secret)
	test := &model.SpeedTest{ID: "private-test", Timestamp: time.Now().UTC(), DownloadMbps: 125.5, UploadMbps: 40.25, PingMs: 8, JitterMs: 1.2, PacketLoss: 0, OwnerTokenHash: hex.EncodeToString(hash[:]), ClientIPHash: "private-ip-hash", UserAgent: "private-agent"}
	if err := st.CreateSpeedTest(context.Background(), test); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	s.Handler = handlerForPages(st)

	request := httptest.NewRequest(http.MethodGet, "http://casspeed.test/speed-tests/private-test", nil)
	request.AddCookie(&http.Cookie{Name: "casspeed_owner", Value: base64.RawURLEncoding.EncodeToString(secret)})
	request = withSpeedTestRouteID(request, test.ID)
	response := httptest.NewRecorder()
	s.handleSpeedTestPage(response, request)
	if response.Code != http.StatusOK || response.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
		t.Fatalf("owner page response = %d headers=%v", response.Code, response.Header())
	}
	for _, expected := range []string{"Download", "125.50", "This result is private", "Create share link"} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("private page is missing %q", expected)
		}
	}
	for _, privateValue := range []string{"private-ip-hash", "private-agent"} {
		if strings.Contains(response.Body.String(), privateValue) {
			t.Errorf("private page exposed %q", privateValue)
		}
	}

	anonymous := httptest.NewRequest(http.MethodGet, "http://casspeed.test/speed-tests/private-test", nil)
	anonymous = withSpeedTestRouteID(anonymous, test.ID)
	denied := httptest.NewRecorder()
	s.handleSpeedTestPage(denied, anonymous)
	if denied.Code != http.StatusNotFound {
		t.Fatalf("anonymous private page status = %d, want 404", denied.Code)
	}
}

func TestHelpPageRegistryDrivesHubAndAPI(t *testing.T) {
	s := minimalServer()
	if pages := registeredPagesForHub("/server/help"); len(pages) != 1 || pages[0].Path != "/server/help/mcp" {
		t.Fatalf("registered help pages = %#v", pages)
	}

	hub := httptest.NewRecorder()
	s.handlePublicPage(hub, httptest.NewRequest(http.MethodGet, "/server/help", nil))
	if hub.Code != http.StatusOK || !strings.Contains(hub.Body.String(), `href="/server/help/mcp"`) {
		t.Fatalf("help hub did not render its registered page: status=%d body=%s", hub.Code, hub.Body.String())
	}

	api := httptest.NewRecorder()
	s.handlePublicPageAPI(api, httptest.NewRequest(http.MethodGet, "/api/v1/server/help", nil))
	if api.Code != http.StatusOK || !strings.Contains(api.Body.String(), `"path":"/server/help/mcp"`) {
		t.Fatalf("help API did not return the registry: status=%d body=%s", api.Code, api.Body.String())
	}
}

func TestLanguageMiddlewareUsesCatalogAndConsentForPersistence(t *testing.T) {
	s := minimalServer()
	var renderedLanguage, renderedDirection string
	handler := s.languageMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderedLanguage, renderedDirection = requestLanguage(r)
		s.handlePublicPage(w, r)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://casspeed.test/server/about?lang=ar", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if renderedLanguage != "ar" || renderedDirection != "rtl" {
		t.Fatalf("resolved locale = %s/%s, want ar/rtl", renderedLanguage, renderedDirection)
	}
	if !strings.Contains(response.Body.String(), `<html lang="ar" dir="rtl"`) {
		t.Fatalf("page shell did not apply Arabic direction: %s", response.Body.String())
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "lang" {
			t.Fatal("language query without preference consent persisted a language cookie")
		}
	}

	consent := url.QueryEscape(`{"preferences":true}`)
	request = httptest.NewRequest(http.MethodGet, "https://casspeed.test/server/about?lang=ar", nil)
	request.AddCookie(&http.Cookie{Name: "cookie_consent", Value: consent})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := responseCookie(t, response, "lang"); got.Value != "ar" || !got.Secure || got.HttpOnly {
		t.Fatalf("language preference cookie = %#v", got)
	}
}

func TestRegistrationPageUsesLocalizedSharedShell(t *testing.T) {
	s := minimalServer()
	handler := s.languageMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.renderUserRegistrationPage(w, r, "csrf-token", "invalid details", http.StatusBadRequest)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://casspeed.test/server/auth/register", nil)
	request.Header.Set("Accept-Language", "fr")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusBadRequest || !strings.Contains(body, `<html lang="fr" dir="ltr"`) || !strings.Contains(body, "Créer un compte") {
		t.Fatalf("registration shell did not use the requested locale: %d %s", response.Code, body)
	}
	if strings.Count(body, "<h1") != 1 || strings.Count(body, "<main") != 1 {
		t.Fatalf("registration page shell landmarks are duplicated: %s", body)
	}
}

func TestPublicProfileFiltersPrivateFieldsAndHidesPrivateProfiles(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	user := &model.User{ID: 0, Username: "ProfileUser", Email: "private@example.com", EmailVerified: true, DisplayName: "Public Name", Bio: "Public bio", Location: "Public place", Website: "https://example.com", Visibility: "public", CreatedAt: time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)}
	if err := st.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	if _, err := s.publicUserProfile(httptest.NewRequest(http.MethodGet, "/", nil), user.Username); err != nil {
		t.Fatalf("load public profile: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/users/ProfileUser", nil)
	request = withUsernameRouteParam(request, user.Username)
	response := httptest.NewRecorder()
	s.handlePublicUserProfileAPI(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("public profile status = %d, body=%s", response.Code, response.Body.String())
	}
	for _, private := range []string{"private@example.com", "password_hash", "email_verified"} {
		if strings.Contains(response.Body.String(), private) {
			t.Errorf("public profile exposed private field %q: %s", private, response.Body.String())
		}
	}
	if !strings.Contains(response.Body.String(), "Public place") {
		t.Fatal("public profile omitted the public location field")
	}

	settingsStore := store.UserSettingsStore(st)
	settings, err := settingsStore.GetOrCreateUserSettings(context.Background(), model.UserIDString(user.ID))
	if err != nil {
		t.Fatal(err)
	}
	settings.ShowEmail = true
	if err := settingsStore.UpdateUserSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	s.handlePublicUserProfileAPI(response, request)
	if !strings.Contains(response.Body.String(), user.Email) {
		t.Fatal("explicitly public email preference was not reflected")
	}
	torRequest := request.WithContext(context.WithValue(request.Context(), overlayRequestKey{}, "tor"))
	response = httptest.NewRecorder()
	s.handlePublicUserProfileAPI(response, torRequest)
	for _, clearnetValue := range []string{user.Email, user.Website, "gravatar.com"} {
		if strings.Contains(response.Body.String(), clearnetValue) {
			t.Errorf("Tor profile response exposed clearnet value %q: %s", clearnetValue, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), `"avatar"`) {
		t.Errorf("Tor profile response exposed an avatar URL: %s", response.Body.String())
	}
	torProfile, err := s.publicUserProfile(torRequest, user.Username)
	if err != nil {
		t.Fatalf("load Tor profile: %v", err)
	}
	if torProfile.CreatedAt.Location() != time.UTC {
		t.Errorf("Tor profile timestamp location = %v, want UTC", torProfile.CreatedAt.Location())
	}

	user.Visibility = "private"
	if err := st.UpdateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	s.handlePublicUserProfileAPI(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("private profile status = %d, want 404", response.Code)
	}
	localizedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/users/ProfileUser", nil)
	localizedRequest = withUsernameRouteParam(localizedRequest, user.Username)
	localizedRequest = localizedRequest.WithContext(contextWithLanguage(localizedRequest, "fr"))
	response = httptest.NewRecorder()
	s.handlePublicUserProfileAPI(response, localizedRequest)
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "Profil introuvable.") {
		t.Errorf("localized public profile error = %d %s", response.Code, response.Body.String())
	}
}

func TestSecurityAndDPOPagesUseRequestedLocale(t *testing.T) {
	s := minimalServer()
	s.Config.Server.Contact.Security.Email = "security@example.com"
	s.Config.Server.Contact.DPO.Email = ""
	s.Config.Server.Contact.General.Email = ""
	for _, test := range []struct {
		path     string
		expected []string
	}{
		{path: "/server/security", expected: []string{"Signalez les vulnérabilités", "Canaux de signalement", "Écrire au contact de sécurité"}},
		{path: "/server/dpo", expected: []string{"Aucune adresse directe", "page sécurité et signalement", "page de confidentialité"}},
	} {
		request := httptest.NewRequest(http.MethodGet, "http://casspeed.test"+test.path, nil)
		request = request.WithContext(contextWithLanguage(request, "fr"))
		response := httptest.NewRecorder()
		s.handlePublicPage(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d: %s", test.path, response.Code, response.Body.String())
		}
		for _, expected := range test.expected {
			if !strings.Contains(response.Body.String(), expected) {
				t.Errorf("%s response missing localized text %q: %s", test.path, expected, response.Body.String())
			}
		}
	}
}

func TestUserEmailSettingsUsesSharedShellAndShowsSeparateAddresses(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	user := &model.User{ID: 0, Username: "emailsettings", Email: "account@example.com", EmailVerified: true, NotificationEmail: "alerts@example.com", NotificationEmailVerified: true, PasswordHash: "hash", Visibility: "public", CreatedAt: time.Now().UTC()}
	if err := st.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	s.UserHandler = handler.NewUserHandler(st)
	request := httptest.NewRequest(http.MethodGet, "http://casspeed.test/users/settings/email", nil)
	request = request.WithContext(context.WithValue(request.Context(), pageIdentityContextKey{}, &pageIdentity{User: user, SessionID: "session-id"}))
	response := httptest.NewRecorder()
	s.handleUserEmailSettings(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `<main id="main-content">`) {
		t.Fatalf("email settings page response = %d: %s", response.Code, response.Body.String())
	}
	for _, expected := range []string{"Email settings", "account@example.com", "alerts@example.com", "current-password", `name="type" value="notification"`} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("email settings page is missing %q", expected)
		}
	}
}

func TestAccessLogRedactsVerificationToken(t *testing.T) {
	var loggedURI string
	handler := redactOneTimeTokenInAccessLog(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { loggedURI = r.RequestURI }))
	request := httptest.NewRequest(http.MethodGet, "/server/auth/verify/secret-token-value", nil)
	request.RequestURI = "/server/auth/verify/secret-token-value"
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if strings.Contains(loggedURI, "secret-token-value") || !strings.Contains(loggedURI, "[REDACTED]") {
		t.Fatalf("logged request URI = %q, token was not redacted", loggedURI)
	}
}

func withUsernameRouteParam(request *http.Request, username string) *http.Request {
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("username", username)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
}

func TestPreferencesPageUsesSharedShellAndSingleEditableForm(t *testing.T) {
	s := minimalServer()
	request := httptest.NewRequest(http.MethodGet, "http://casspeed.test/server/preferences", nil)
	response := httptest.NewRecorder()
	s.handlePreferences(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("preferences status = %d", response.Code)
	}
	if strings.Count(body, "<main ") != 1 || strings.Count(body, "<h1 ") != 1 {
		t.Fatalf("preferences shell has main=%d h1=%d", strings.Count(body, "<main "), strings.Count(body, "<h1 "))
	}
	for _, heading := range []string{`id="appearance"`, `id="language"`, `id="privacy"`, `name="theme"`, `name="lang"`, `value="automatic"`, `name="consent_form"`, `name="consent_preferences"`, `name="consent_analytics"`, `name="csrf_token"`, `popovertarget="reset-preferences"`, `href="/server/preferences/sync"`} {
		if !strings.Contains(body, heading) {
			t.Errorf("preferences page is missing %q", heading)
		}
	}
	if !strings.Contains(body, `method="post" action="/server/preferences"`) || !strings.Contains(body, `class="section-card" aria-labelledby="appearance"`) {
		t.Fatal("preferences form or labelled card is missing")
	}
	if strings.Contains(body, `name="code"`) || strings.Contains(body, `>Import<`) {
		t.Fatal("preferences page contains sync controls")
	}
	if strings.Index(body, `href="/server/preferences/sync"`) < strings.Index(body, `value="reset"`) {
		t.Fatal("More preferences card appears inside the preferences form")
	}
}

func TestPreferenceSyncPageUsesSharedShellAndOwnImportForm(t *testing.T) {
	s := minimalServer()
	request := httptest.NewRequest(http.MethodGet, "http://casspeed.test/server/preferences/sync", nil)
	response := httptest.NewRecorder()
	s.handlePreferenceSync(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("preference sync status = %d", response.Code)
	}
	if strings.Count(body, "<main ") != 1 || strings.Count(body, "<h1 ") != 1 || strings.Count(body, `class="section-card"`) != 2 {
		t.Fatalf("preference sync shell/cards are malformed: main=%d h1=%d cards=%d", strings.Count(body, "<main "), strings.Count(body, "<h1 "), strings.Count(body, `class="section-card"`))
	}
	for _, required := range []string{`aria-label="Breadcrumb"`, `id="preference-url"`, `id="preference-code"`, `data-copy="preference-url"`, `data-copy="preference-code"`, `name="code"`, `method="post" action="/server/preferences/sync"`, `name="csrf_token"`, `/static/js/copy.js`} {
		if !strings.Contains(body, required) {
			t.Errorf("preference sync page is missing %q", required)
		}
	}
}

func TestPublicErrorShellHidesRawErrorsAndPreservesStatus(t *testing.T) {
	s := minimalServer()
	handler := s.languageMiddleware(s.publicErrorShellMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "panic at /srv/private/path", http.StatusInternalServerError)
	})))
	request := httptest.NewRequest(http.MethodGet, "http://casspeed.test/server/private-page", nil)
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("error page status = %d", response.Code)
	}
	body := response.Body.String()
	if strings.Contains(body, "/srv/private/path") || !strings.Contains(body, "Service error") {
		t.Fatalf("error page exposed internal details or omitted shell: %s", body)
	}
	if strings.Count(body, "<main ") != 1 || strings.Count(body, "<h1 ") != 1 || !strings.Contains(body, "name=\"csrf_token\"") {
		t.Fatalf("error page does not satisfy the shared shell")
	}
}

func TestPublicErrorShellLeavesJSONResponsesUntouched(t *testing.T) {
	s := minimalServer()
	handler := s.publicErrorShellMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://casspeed.test/server/private-page", nil)
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"error":"NOT_FOUND"`) {
		t.Fatalf("JSON error response changed: %d %s", response.Code, response.Body.String())
	}
}

func TestDocumentationAndLegacyAuthPagesUseSharedShell(t *testing.T) {
	s := minimalServer()
	checks := []struct {
		name    string
		handler http.Handler
	}{
		{"swagger", http.HandlerFunc(s.handleSwaggerPage)},
		{"graphql", http.HandlerFunc(s.handleGraphQLPage)},
		{"legacy auth", s.pageShellHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html><body><main class="container"><h1>Reset password</h1><form><input name="token"></form></main></body></html>`))
		}))},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://casspeed.test/server/docs/"+url.PathEscape(check.name), nil)
			response := httptest.NewRecorder()
			check.handler.ServeHTTP(response, request)
			body := response.Body.String()
			if response.Code != http.StatusOK || strings.Count(body, "<main ") != 1 || strings.Count(body, "<h1 ") != 1 {
				t.Fatalf("page does not have one shared main and heading: status=%d main=%d h1=%d", response.Code, strings.Count(body, "<main "), strings.Count(body, "<h1 "))
			}
			for _, fragment := range []string{`class="site-header"`, `id="site-navigation"`, `class="site-footer"`, `href="/server/preferences#language"`, `name="csrf_token"`} {
				if !strings.Contains(body, fragment) {
					t.Errorf("page is missing common shell element %q", fragment)
				}
			}
		})
	}
}

func TestDocumentationPagesUseConfiguredAPIVersion(t *testing.T) {
	s := minimalServer()
	s.Config.Server.APIVersion = "v2"
	for _, test := range []struct {
		name     string
		path     string
		endpoint string
		handler  http.HandlerFunc
	}{
		{"swagger", "/server/docs/swagger", "/api/v2/server/swagger", s.handleSwaggerPage},
		{"graphql", "/server/docs/graphql", "/api/v2/server/graphql", s.handleGraphQLPage},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://casspeed.test"+test.path, nil))
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), test.endpoint) {
				t.Fatalf("configured endpoint %q missing from page: %d %s", test.endpoint, response.Code, response.Body.String())
			}
		})
	}
}

func TestPrivateRegistrationModeHidesPublicRoute(t *testing.T) {
	s := minimalServer()
	s.Config.Server.Users.Registration.Mode = "private"
	handler := s.onlyOpenRegistration(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://casspeed.test/server/auth/register", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("private registration status = %d, want 404", response.Code)
	}
}

func TestSignedInNotificationCenterUsesOwnedPersistentHistory(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	user := &model.User{ID: 0, Username: "reader", Email: "reader@example.test", PasswordHash: "hash", CreatedAt: time.Now().UTC()}
	if err := st.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(t.Context(), &model.Session{ID: "notification-session", UserID: model.UserIDString(user.ID), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUserNotification(t.Context(), &model.Notification{ID: "notification-item", UserID: model.UserIDString(user.ID), Type: "info", Title: "notifications.api_token_created", Message: "notifications.api_token_created_message", Link: "/users/tokens", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	request := httptest.NewRequest(http.MethodGet, "http://casspeed.test/users/notifications", nil)
	request.AddCookie(&http.Cookie{Name: "user_session", Value: "notification-session"})
	response := httptest.NewRecorder()
	s.handleUserNotifications(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || strings.Count(body, "<main ") != 1 || strings.Count(body, "<h1 ") != 1 {
		t.Fatalf("notification page shell status=%d main=%d h1=%d", response.Code, strings.Count(body, "<main "), strings.Count(body, "<h1 "))
	}
	for _, expected := range []string{"notification-bell", "profile-menu", "API token created", `href="/users/notifications"`, `aria-label="Skip to navigation"`} {
		if !strings.Contains(body, expected) {
			t.Errorf("signed-in shell is missing %q", expected)
		}
	}
	if strings.Contains(body, `href="/server/auth/register"`) || !strings.Contains(body, "reader") {
		t.Error("signed-in shell still shows guest auth links or omits profile identity")
	}
}

func TestUserTokenPageCreatesAndDisplaysTokenOnce(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	user := &model.User{ID: 0, Username: "tokenowner", Email: "tokenowner@example.test", CreatedAt: time.Now().UTC()}
	if err := st.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(t.Context(), &model.Session{ID: "token-page-session", UserID: model.UserIDString(user.ID), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	s.UserHandler = handler.NewUserHandler(st)
	form := url.Values{"csrf_token": {"token-page-csrf"}, "name": {"automation"}, "scope": {"read"}}
	request := httptest.NewRequest(http.MethodPost, "http://casspeed.test/users/tokens", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://casspeed.test")
	request.AddCookie(&http.Cookie{Name: "user_session", Value: "token-page-session"})
	request.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "token-page-csrf"})
	response := httptest.NewRecorder()
	s.handleUserTokensPage(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "token_one_time") && !strings.Contains(response.Body.String(), "usr_") {
		t.Fatalf("token creation page status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "automation") || !strings.Contains(response.Body.String(), "usr_") {
		t.Fatal("created token was not shown once with the token row")
	}
}

func TestMarkAllNotificationsRequiresSameOriginCSRFAndUpdatesOwner(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	user := &model.User{ID: 0, Username: "owner", Email: "owner@example.test", PasswordHash: "hash", CreatedAt: time.Now().UTC()}
	if err := st.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(t.Context(), &model.Session{ID: "notification-owner-session", UserID: model.UserIDString(user.ID), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUserNotification(t.Context(), &model.Notification{ID: "owner-notification", UserID: model.UserIDString(user.ID), Type: "info", Title: "notifications.api_token_created", Message: "notifications.api_token_created_message", Link: "/users/tokens", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	form := url.Values{"csrf_token": {"csrf-value"}}
	request := httptest.NewRequest(http.MethodPost, "http://casspeed.test/users/notifications/read", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://casspeed.test")
	request.AddCookie(&http.Cookie{Name: "user_session", Value: "notification-owner-session"})
	request.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "csrf-value"})
	response := httptest.NewRecorder()
	s.handleMarkAllUserNotificationsRead(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("mark-all status=%d body=%s", response.Code, response.Body.String())
	}
	if count, err := st.CountUnreadUserNotifications(t.Context(), model.UserIDString(user.ID)); err != nil || count != 0 {
		t.Fatalf("unread count=%d err=%v", count, err)
	}
}

func TestPrivateSpeedTestPageAllowsOwningAccountSession(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	user := &model.User{ID: 0, Username: "owner", Email: "owner@example.test"}
	if err := st.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(context.Background(), &model.Session{ID: "session-1", UserID: model.UserIDString(user.ID), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	test := &model.SpeedTest{ID: "account-test", UserID: model.UserIDString(user.ID), Timestamp: time.Now().UTC(), DownloadMbps: 10}
	if err := st.CreateSpeedTest(context.Background(), test); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	s.Handler = handlerForPages(st)
	request := httptest.NewRequest(http.MethodGet, "http://casspeed.test/speed-tests/account-test", nil)
	request.AddCookie(&http.Cookie{Name: "user_session", Value: "session-1"})
	request = withSpeedTestRouteID(request, test.ID)
	response := httptest.NewRecorder()
	s.handleSpeedTestPage(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("account owner page status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestSameOriginPageRequest(t *testing.T) {
	for _, test := range []struct {
		name    string
		origin  string
		referer string
		want    bool
	}{
		{name: "same origin", origin: "https://casspeed.test", want: true},
		{name: "same origin referer", referer: "https://casspeed.test/speed-tests/1", want: true},
		{name: "missing origin", want: false},
		{name: "different host", origin: "https://attacker.test", want: false},
		{name: "different scheme", origin: "http://casspeed.test", want: false},
		{name: "invalid origin", origin: "https://", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://casspeed.test/speed-tests/1", nil)
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.referer != "" {
				request.Header.Set("Referer", test.referer)
			}
			if got := sameOriginPageRequest(request); got != test.want {
				t.Fatalf("sameOriginPageRequest = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAnonymousOwnerMustExplicitlyCreateShare(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	secret := []byte(strings.Repeat("o", 32))
	hash := sha256.Sum256(secret)
	test := &model.SpeedTest{ID: "share-test", Timestamp: time.Now().UTC(), DownloadMbps: 42, OwnerTokenHash: hex.EncodeToString(hash[:])}
	if err := st.CreateSpeedTest(context.Background(), test); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = st
	s.Handler = handlerForPages(st)
	csrf := "share-test-csrf"
	request := httptest.NewRequest(http.MethodPost, "https://casspeed.test/speed-tests/share-test", strings.NewReader("csrf_token="+url.QueryEscape(csrf)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: csrf})
	origin, err := url.Parse(BuildURL(request, "/"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", origin.Scheme+"://"+origin.Host)
	request.AddCookie(&http.Cookie{Name: "casspeed_owner", Value: base64.RawURLEncoding.EncodeToString(secret)})
	request = withSpeedTestRouteID(request, test.ID)
	response := httptest.NewRecorder()
	s.createSpeedTestSharePage(response, request)
	if response.Code != http.StatusSeeOther || !strings.HasPrefix(response.Header().Get("Location"), "/shares/") {
		t.Fatalf("explicit share response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	shared, err := st.GetSpeedTest(context.Background(), test.ID)
	if err != nil || shared == nil || shared.ShareCode == "" {
		t.Fatalf("shared result = %#v, %v", shared, err)
	}
	if !strings.Contains(response.Header().Get("Location"), shared.ShareCode) {
		t.Fatalf("redirect %q does not use share code %q", response.Header().Get("Location"), shared.ShareCode)
	}
	if !sameOriginPageRequest(request) {
		t.Fatal("same-origin owner share request was rejected")
	}
	foreign := httptest.NewRequest(http.MethodPost, "https://casspeed.test/speed-tests/share-test", nil)
	foreign.Header.Set("Origin", "https://attacker.test")
	foreign.AddCookie(&http.Cookie{Name: "casspeed_owner", Value: base64.RawURLEncoding.EncodeToString(secret)})
	foreign = withSpeedTestRouteID(foreign, test.ID)
	denied := httptest.NewRecorder()
	s.createSpeedTestSharePage(denied, foreign)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("cross-origin share status = %d, want 403", denied.Code)
	}
}

func handlerForPages(st store.Store) *handler.SpeedTestHandler {
	return handler.NewSpeedTestHandler(st, service.NewSpeedTestService(1, 65536))
}

func withSpeedTestRouteID(request *http.Request, id string) *http.Request {
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", id)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
}
