package server

import (
	"net/http"
	"strings"

	"github.com/casapps/casspeed/src/server/model"
)

func (s *Server) userPermissionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permission := requiredUserPermission(r.URL.Path, r.Method)
		if permission == "" {
			next.ServeHTTP(w, r)
			return
		}
		var userID string
		if identity, ok := r.Context().Value(apiTokenContextKey{}).(apiTokenIdentity); ok {
			if identity.Admin {
				next.ServeHTTP(w, r)
				return
			}
			userID = identity.UserID
		} else if identity := pageIdentityFromRequest(r); identity != nil && identity.User != nil {
			userID = model.UserIDString(identity.User.ID)
		}
		if userID == "" {
			next.ServeHTTP(w, r)
			return
		}
		user, err := s.Store.GetUser(r.Context(), userID)
		if err != nil || user == nil {
			next.ServeHTTP(w, r)
			return
		}
		if !s.userRoleAllows(user.Role, permission) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeUserJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "Insufficient role permissions"})
				return
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requiredUserPermission(path, method string) string {
	path = strings.TrimPrefix(path, "/api/v1")
	if path == "/users/tokens" || strings.HasPrefix(path, "/users/tokens/") {
		return "own_api_tokens"
	}
	if path == "/history" || path == "/users/data/export/download" {
		return "read"
	}
	if path == "/devices" || path == "/users/devices" || strings.HasPrefix(path, "/devices/") || strings.HasPrefix(path, "/users/devices/") {
		if method == http.MethodGet || method == http.MethodHead {
			return "read"
		}
		return "write"
	}
	if strings.HasPrefix(path, "/users/data/") {
		if method == http.MethodGet {
			return "read"
		}
		return "own_profile"
	}
	if path == "/users" || strings.HasPrefix(path, "/users/settings") || strings.HasPrefix(path, "/users/security") || strings.HasPrefix(path, "/users/notifications") {
		if method == http.MethodGet || method == http.MethodHead {
			return "read"
		}
		return "write"
	}
	return ""
}

func (s *Server) userRoleAllows(role, required string) bool {
	if role == "admin" {
		return true
	}
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	permissions := s.Config.Server.Users.Roles.Permissions[role]
	for _, permission := range permissions {
		if permission == required || permission == "admin" {
			return true
		}
		if required == "read" && permission == "own_profile" || required == "write" && permission == "own_profile" {
			return true
		}
	}
	return false
}
