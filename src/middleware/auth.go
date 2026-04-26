package middleware

import (
"context"
"net/http"
"time"

"github.com/casapps/casspeed/src/server/model"
"github.com/casapps/casspeed/src/server/store"
)

type contextKey string

const UserContextKey contextKey = "user"

// AuthMiddleware checks for valid session
func AuthMiddleware(store store.Store) func(http.Handler) http.Handler {
return func(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// Get session cookie
cookie, err := r.Cookie("session")
if err != nil {
http.Error(w, "Unauthorized", http.StatusUnauthorized)
return
}

// Get session from database
session, err := store.GetSession(r.Context(), cookie.Value)
if err != nil || session == nil {
http.Error(w, "Unauthorized", http.StatusUnauthorized)
return
}

// Check if expired
if session.ExpiresAt.Before(r.Context().Value("now").(time.Time)) {
http.Error(w, "Session expired", http.StatusUnauthorized)
return
}

// Get user
user, err := store.GetUser(r.Context(), session.UserID)
if err != nil || user == nil {
http.Error(w, "Unauthorized", http.StatusUnauthorized)
return
}

// Add user to context
ctx := context.WithValue(r.Context(), UserContextKey, user)
next.ServeHTTP(w, r.WithContext(ctx))
})
}
}

// GetUserFromContext extracts user from context
func GetUserFromContext(ctx context.Context) *model.User {
user, ok := ctx.Value(UserContextKey).(*model.User)
if !ok{
return nil
}
return user
}
