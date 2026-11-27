package graphql

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/server/model"
)

type resolverStore struct {
	test       *model.SpeedTest
	shared     *model.SpeedTest
	history    []*model.SpeedTest
	session    *model.Session
	user       *model.User
	sessionErr error
	userErr    error
	testErr    error
	sharedErr  error
	historyErr error
	token      *model.APIToken
	settings   *model.UserSettings
	devices    []*model.Device
	tokens     []*model.APIToken
}

func (s *resolverStore) GetSpeedTest(context.Context, string) (*model.SpeedTest, error) {
	return s.test, s.testErr
}
func (s *resolverStore) GetSpeedTestByShareCode(context.Context, string) (*model.SpeedTest, error) {
	return s.shared, s.sharedErr
}
func (s *resolverStore) GetUserSpeedTests(context.Context, string, int, int) ([]*model.SpeedTest, error) {
	return s.history, s.historyErr
}
func (s *resolverStore) GetSession(context.Context, string) (*model.Session, error) {
	return s.session, s.sessionErr
}
func (s *resolverStore) GetUser(context.Context, string) (*model.User, error) {
	return s.user, s.userErr
}
func (s *resolverStore) GetAPITokenByToken(context.Context, string) (*model.APIToken, error) {
	return s.token, nil
}
func (s *resolverStore) GetOrCreateUserSettings(context.Context, string) (*model.UserSettings, error) {
	return s.settings, nil
}
func (s *resolverStore) GetUserDevices(context.Context, string) ([]*model.Device, error) {
	return s.devices, nil
}
func (s *resolverStore) GetUserAPITokens(context.Context, string) ([]*model.APIToken, error) {
	return s.tokens, nil
}
func (s *resolverStore) ListUserSessions(context.Context, string) ([]*model.Session, error) {
	return []*model.Session{s.session}, nil
}

func TestHealthQueryReturnsFullSharedSnapshot(t *testing.T) {
	handler := NewQueryHandler(Dependencies{Health: func(context.Context) (HealthSnapshot, error) {
		return HealthSnapshot{
			Project: HealthProjectSnapshot{Name: "CasSpeed", Tagline: "Measure", Description: "Private testing"},
			Status:  "healthy", Version: "1.2.3", GoVersion: "go1.26", Build: HealthBuildSnapshot{Commit: "abc", Date: "today"},
			Uptime: "1h", Mode: "production", Timestamp: "2026-01-01T00:00:00Z",
			Cluster:  HealthClusterSnapshot{Enabled: false, Status: "disabled"},
			Features: HealthFeaturesSnapshot{Geoip: true, Tor: HealthTorSnapshot{Enabled: true, Running: true, Status: "ready", Hostname: "example.onion"}},
			Checks:   HealthChecksSnapshot{Database: "ok", Cache: "ok", Disk: "ok", Scheduler: "ok"},
			Stats:    HealthStatsSnapshot{RequestsTotal: 10, Requests24h: 4, ActiveConnections: 2},
		}, nil
	}})
	response := executeGraphQL(t, handler, http.MethodPost, `{"query":"{health{project{name tagline description} status version goVersion build{commit date} uptime mode timestamp cluster{enabled status} features{geoip tor{enabled running status hostname}} checks{database cache disk scheduler} stats{requestsTotal requests24h activeConnections}}}"}`)
	for _, expected := range []string{`"name":"CasSpeed"`, `"commit":"abc"`, `"hostname":"example.onion"`, `"requestsTotal":10`} {
		if !strings.Contains(response, expected) {
			t.Errorf("health response missing %s: %s", expected, response)
		}
	}
}

func TestGraphQLHistoryUsesAuthenticatedSessionAndSafeFields(t *testing.T) {
	store := &resolverStore{
		token:   &model.APIToken{ID: "token", UserID: "user-1", Scope: "read"},
		user:    &model.User{ID: 0},
		history: []*model.SpeedTest{{ID: "result-1", UserID: "user-1", Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), DownloadMbps: 12.5, ClientIPHash: "private-hash", UserAgent: "private-agent"}},
	}
	handler := NewQueryHandler(Dependencies{Store: store})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/server/graphql", strings.NewReader(`{"query":"{speedTests{ id downloadMbps timestamp }}"}`))
	request.Header.Set("Authorization", "Bearer usr_0123456789abcdefghijklmnopqrstuv")
	response := executeGraphQLRequest(t, handler, request)
	for _, expected := range []string{`"id":"result-1"`, `"downloadMbps":12.5`} {
		if !strings.Contains(response, expected) {
			t.Errorf("history response missing %s: %s", expected, response)
		}
	}
	if strings.Contains(response, "private-hash") || strings.Contains(response, "private-agent") {
		t.Fatalf("private metadata was exposed: %s", response)
	}
}

func TestGraphQLAnonymousOwnerAndSharedResultPrivacy(t *testing.T) {
	secret := strings.Repeat("s", 32)
	hash := sha256.Sum256([]byte(secret))
	store := &resolverStore{test: &model.SpeedTest{ID: "owned", OwnerTokenHash: hex.EncodeToString(hash[:]), DownloadMbps: 7}}
	handler := NewQueryHandler(Dependencies{Store: store})
	request := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{speedTest(id:\"owned\"){id downloadMbps}}"}`))
	request.AddCookie(&http.Cookie{Name: "casspeed_owner", Value: base64.RawURLEncoding.EncodeToString([]byte(secret))})
	response := executeGraphQLRequest(t, handler, request)
	if !strings.Contains(response, `"id":"owned"`) {
		t.Fatalf("anonymous owner could not read result: %s", response)
	}

	request = httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{speedTest(id:\"owned\"){id}}"}`))
	response = executeGraphQLRequest(t, handler, request)
	if strings.Contains(response, `"id":"owned"`) {
		t.Fatalf("unowned private result was exposed: %s", response)
	}

	store.shared = &model.SpeedTest{ID: "public", ShareCode: "share123", UserAgent: "private-agent", ClientIPHash: "private-hash"}
	request = httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{sharedSpeedTest(code:\"share123\"){id}}"}`))
	response = executeGraphQLRequest(t, handler, request)
	if !strings.Contains(response, `"id":"public"`) || strings.Contains(response, "private-agent") || strings.Contains(response, "private-hash") {
		t.Fatalf("shared result response violated field privacy: %s", response)
	}
}

func TestGraphQLAccountReadsAreOwnerScopedAndOmitSecrets(t *testing.T) {
	store := &resolverStore{
		token:    &model.APIToken{ID: "auth-token", UserID: "1", Scope: "read"},
		user:     &model.User{ID: 1, Username: "alice", Email: "alice@example.test", PasswordHash: "private-password-hash", TOTPSecret: "private-totp"},
		settings: &model.UserSettings{Theme: "dark", EmailSecurity: true},
		devices:  []*model.Device{{ID: "device-1", UserID: "1", Name: "Laptop"}, {ID: "other", UserID: "2", Name: "Other"}},
		tokens:   []*model.APIToken{{ID: "token-1", UserID: "1", Token: "private-token", TokenPrefix: "usr_abc", Name: "Read API", Scope: "read"}, {ID: "other", UserID: "2", Token: "other-secret", Name: "Other"}},
	}
	handler := NewQueryHandler(Dependencies{Store: store})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/server/graphql", strings.NewReader(`{"query":"{userProfile{username email} userSettings{theme emailSecurity} userSecurity{passwordConfigured activeSessions} userDevices{id name} userTokens{id tokenPrefix name scope}}"}`))
	request.Header.Set("Authorization", "Bearer usr_0123456789abcdefghijklmnopqrstuv")
	response := executeGraphQLRequest(t, handler, request)
	for _, expected := range []string{`"username":"alice"`, `"theme":"dark"`, `"passwordConfigured":true`, `"id":"device-1"`, `"id":"token-1"`} {
		if !strings.Contains(response, expected) {
			t.Errorf("GraphQL account reads missing %s: %s", expected, response)
		}
	}
	for _, secret := range []string{"private-password-hash", "private-totp", "private-token", "other-secret", `"id":"other"`} {
		if strings.Contains(response, secret) {
			t.Errorf("GraphQL account reads exposed %q: %s", secret, response)
		}
	}
}

func TestGraphQLResolverRejectsUnauthenticatedAndInvalidState(t *testing.T) {
	resolver := newResolvers(Dependencies{Store: &resolverStore{
		session: &model.Session{UserID: "user-1", ExpiresAt: time.Now().Add(time.Hour)},
		user:    &model.User{ID: 0},
	}})
	if _, err := resolver.SpeedTests(context.Background(), struct{ Offset int32 }{}); err == nil {
		t.Fatal("history must require a request identity")
	}
	request := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	ctx := contextWithRequest(request)
	if _, err := resolver.SpeedTests(ctx, struct{ Offset int32 }{}); err == nil {
		t.Fatal("history must require an authenticated user")
	}
	request = httptest.NewRequest(http.MethodPost, "/graphql", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: "valid"})
	ctx = contextWithRequest(request)
	if _, err := resolver.SpeedTests(ctx, struct{ Offset int32 }{Offset: -1}); err == nil {
		t.Fatal("negative history offset must fail")
	}
	if _, err := resolver.Health(context.Background()); err == nil {
		t.Fatal("missing health provider must fail safely")
	}
	resolver.health = func(context.Context) (HealthSnapshot, error) { return HealthSnapshot{}, errors.New("database details") }
	if _, err := resolver.Health(context.Background()); err == nil || strings.Contains(err.Error(), "database details") {
		t.Fatalf("health provider error leaked internals: %v", err)
	}
}

func executeGraphQL(t *testing.T, handler http.Handler, method, body string) string {
	t.Helper()
	return executeGraphQLRequest(t, handler, httptest.NewRequest(method, "/graphql", strings.NewReader(body)))
}

func executeGraphQLRequest(t *testing.T, handler http.Handler, request *http.Request) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GraphQL status = %d: %s", recorder.Code, recorder.Body.String())
	}
	return recorder.Body.String()
}
