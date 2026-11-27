package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

func TestUserNotificationActionsAndTokenRevocation(t *testing.T) {
	database, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	user := &model.User{Username: "page-owner", Email: "page-owner@example.test", CreatedAt: time.Now().UTC()}
	other := &model.User{Username: "page-other", Email: "page-other@example.test", CreatedAt: time.Now().UTC()}
	for _, account := range []*model.User{user, other} {
		if err := database.CreateUser(context.Background(), account); err != nil {
			t.Fatal(err)
		}
	}
	ownerID, otherID := model.UserIDString(user.ID), model.UserIDString(other.ID)
	for _, notification := range []*model.Notification{
		{ID: "notice-1", UserID: ownerID, Type: "info", Title: "One", Message: "First", CreatedAt: time.Now().UTC()},
		{ID: "notice-2", UserID: ownerID, Type: "info", Title: "Two", Message: "Second", CreatedAt: time.Now().UTC()},
	} {
		if err := database.CreateUserNotification(context.Background(), notification); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.CreateAPIToken(context.Background(), &model.APIToken{ID: "owner-token", UserID: ownerID, Token: "owner-token-secret", Name: "Owner token", Scope: "read", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateAPIToken(context.Background(), &model.APIToken{ID: "other-token", UserID: otherID, Token: "other-token-secret", Name: "Other token", Scope: "read", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	s.Store = database
	call := func(handler http.HandlerFunc, path string, identity *pageIdentity, id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://example.test"+path, strings.NewReader("csrf_token=csrf&next=%2Fusers%2Fnotifications"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://example.test")
		r.AddCookie(&http.Cookie{Name: preferenceCSRFCookie, Value: "csrf"})
		r = r.WithContext(context.WithValue(r.Context(), pageIdentityContextKey{}, identity))
		if id != "" {
			route := chi.NewRouteContext()
			route.URLParams.Add("notificationID", id)
			route.URLParams.Add("tokenID", id)
			r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
		}
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}
	identity := &pageIdentity{User: user}
	if got := call(s.handleMarkUserNotificationRead, "/users/notifications/notice-1/read", identity, "notice-1"); got.Code != http.StatusSeeOther {
		t.Fatalf("mark notification read status = %d", got.Code)
	}
	if got := call(s.handleMarkAllUserNotificationsRead, "/users/notifications/read", identity, ""); got.Code != http.StatusSeeOther {
		t.Fatalf("mark all notifications status = %d", got.Code)
	}
	if unread, err := database.CountUnreadUserNotifications(context.Background(), ownerID); err != nil || unread != 0 {
		t.Fatalf("unread notification count = %d, %v", unread, err)
	}
	if got := call(s.handleClearUserNotifications, "/users/notifications/clear", identity, ""); got.Code != http.StatusSeeOther {
		t.Fatalf("clear notifications status = %d", got.Code)
	}
	if notifications, err := database.GetUserNotifications(context.Background(), ownerID, 10); err != nil || len(notifications) != 0 {
		t.Fatalf("notifications after clear = %d, %v", len(notifications), err)
	}
	if got := call(s.handleRevokeUserTokenPage, "/users/tokens/owner-token/revoke", identity, "owner-token"); got.Code != http.StatusSeeOther {
		t.Fatalf("own token revoke status = %d", got.Code)
	}
	if got := call(s.handleRevokeUserTokenPage, "/users/tokens/other-token/revoke", identity, "other-token"); got.Code != http.StatusNotFound {
		t.Fatalf("foreign token revoke status = %d", got.Code)
	}
	if got := call(s.handleMarkAllUserNotificationsRead, "/users/notifications/read", nil, ""); got.Code != http.StatusSeeOther {
		t.Fatalf("anonymous notification response = %d", got.Code)
	}
}

func TestEmailVerificationPageHidesInvalidTokensAndDisablesCaching(t *testing.T) {
	s := minimalServer()
	invalid := httptest.NewRecorder()
	badRequest := httptest.NewRequest(http.MethodGet, "/server/auth/verify/short", nil)
	badRoute := chi.NewRouteContext()
	badRoute.URLParams.Add("token", "short")
	s.handleEmailVerificationPage(invalid, badRequest.WithContext(context.WithValue(badRequest.Context(), chi.RouteCtxKey, badRoute)))
	if invalid.Code != http.StatusNotFound {
		t.Fatalf("invalid token page status = %d", invalid.Code)
	}
	token := strings.Repeat("a", 64)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/server/auth/verify/"+token, nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("token", token)
	response := httptest.NewRecorder()
	s.handleEmailVerificationPage(response, request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route)))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" || !strings.Contains(response.Body.String(), token) {
		t.Fatalf("verification page response = %d headers=%v", response.Code, response.Header())
	}
}
