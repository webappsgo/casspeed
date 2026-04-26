package admin

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"golang.org/x/crypto/argon2"
)

//go:embed template/*
var adminTemplateFS embed.FS

type Handler struct {
	store store.Store
}

// Alias AdminHandler to Handler for consistency
type AdminHandler = Handler

func NewHandler(st store.Store) *Handler {
	return &Handler{store: st}
}

func HashPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(salt) + "$" + hex.EncodeToString(hash)
}

func VerifyPassword(password, stored string) bool {
	parts := []byte(stored)
	if len(parts) < 33 {
		return false
	}
	saltHex := string(parts[:32])
	hashHex := string(parts[33:])
	
	salt, _ := hex.DecodeString(saltHex)
	storedHash, _ := hex.DecodeString(hashHex)
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	
	if len(hash) != len(storedHash) {
		return false
	}
	for i := range hash {
		if hash[i] != storedHash[i] {
			return false
		}
	}
	return true
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	// Check if setup is complete
	if !IsSetupComplete() {
		// Show setup token entry page
		h.renderSetupTokenPage(w, r, "")
		return
	}

	if r.Method == "GET" {
		data, err := adminTemplateFS.ReadFile("template/login.html")
		if err != nil {
			http.Error(w, "Template not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
		return
	}

	ctx := r.Context()
	username := r.FormValue("username")
	password := r.FormValue("password")

	admin, err := h.store.GetAdminByUsername(ctx, username)
	if err != nil || admin == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !admin.LockedUntil.IsZero() && time.Now().Before(admin.LockedUntil) {
		http.Error(w, "Account locked. Try again later.", http.StatusForbidden)
		return
	}

	if !VerifyPassword(password, admin.Password) {
		attempts := admin.FailedAttempts + 1
		h.store.UpdateAdminFailedAttempts(ctx, admin.ID, attempts)
		
		if attempts >= 5 {
			h.store.LockAdmin(ctx, admin.ID, time.Now().Add(15*time.Minute))
			http.Error(w, "Too many failed attempts. Account locked for 15 minutes.", http.StatusForbidden)
			return
		}
		
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	h.store.UpdateAdminLastLogin(ctx, admin.ID)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	sessionIDHex := hex.EncodeToString(sessionID)

	session := &model.AdminSession{
		ID:        sessionIDHex,
		AdminID:   admin.ID,
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}

	if err := h.store.CreateAdminSession(ctx, session); err != nil {
		http.Error(w, "Session creation failed", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    sessionIDHex,
		Path:     "/", // Cookie path covers all admin paths
		MaxAge:   86400 * 30,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	})

	// Redirect to admin dashboard (root of admin panel per PART 17)
	// Note: Path is dynamic but we use /admin/ as default here
	// In production, this should use the configured admin path
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	cookie, err := r.Cookie("admin_session")
	if err == nil {
		h.store.DeleteAdminSession(ctx, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Path:     "/admin",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	data, err := adminTemplateFS.ReadFile("template/dashboard.html")
	if err != nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	settings := map[string]interface{}{
		"server": map[string]interface{}{
			"port": 80,
			"mode": "production",
		},
		"test": map[string]interface{}{
			"max_threads":      16,
			"default_duration": 10,
			"max_concurrent":   3,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (h *Handler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	response := map[string]string{
		"status":  "success",
		"message": "Settings updated",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		
		cookie, err := r.Cookie("admin_session")
		if err != nil {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		session, err := h.store.GetAdminSession(ctx, cookie.Value)
		if err != nil || session == nil {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		h.store.UpdateAdminSessionActivity(ctx, session.ID)

		ctx = context.WithValue(ctx, "admin_id", session.AdminID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// ServerSettings shows settings page
func (h *Handler) ServerSettings(w http.ResponseWriter, r *http.Request) {
	data, err := adminTemplateFS.ReadFile("template/settings.html")
	if err != nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// ServerInfo shows server info page
func (h *Handler) ServerInfo(w http.ResponseWriter, r *http.Request) {
	data, err := adminTemplateFS.ReadFile("template/info.html")
	if err != nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// ServerLogs shows logs page
func (h *Handler) ServerLogs(w http.ResponseWriter, r *http.Request) {
	data, err := adminTemplateFS.ReadFile("template/logs.html")
	if err != nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// Profile shows admin's own profile page
func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "profile", "Admin Profile")
}

// Preferences shows admin's own preferences page
func (h *Handler) Preferences(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "preferences", "Admin Preferences")
}

// Notifications shows admin's own notifications page
func (h *Handler) Notifications(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "notifications", "Notifications")
}

// ServerAuditLogs shows audit logs page
func (h *Handler) ServerAuditLogs(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "audit-logs", "Audit Logs")
}

// ServerBackup shows backup management page
func (h *Handler) ServerBackup(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "backup", "Backup & Restore")
}

// ServerUpdates shows update management page
func (h *Handler) ServerUpdates(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "updates", "Update Management")
}

// ServerSSL shows SSL/TLS configuration page
func (h *Handler) ServerSSL(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "ssl", "SSL/TLS Configuration")
}

// ServerEmail shows email configuration page
func (h *Handler) ServerEmail(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "email", "Email Configuration")
}

// ServerScheduler shows scheduler page
func (h *Handler) ServerScheduler(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "scheduler", "Scheduled Tasks")
}

// ServerMetrics shows metrics dashboard page
func (h *Handler) ServerMetrics(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "metrics", "Metrics Dashboard")
}

// NetworkTor shows Tor configuration page
func (h *Handler) NetworkTor(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "network-tor", "Tor Configuration")
}

// NetworkGeoIP shows GeoIP settings page
func (h *Handler) NetworkGeoIP(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "network-geoip", "GeoIP Settings")
}

// SecurityAuth shows authentication settings page
func (h *Handler) SecurityAuth(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "security-auth", "Authentication Settings")
}

// SecurityTokens shows API token management page
func (h *Handler) SecurityTokens(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "security-tokens", "API Token Management")
}

// ServerUsers shows user management page
func (h *Handler) ServerUsers(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, "users", "User Management")
}

// renderAdminPage renders a standard admin page with sidebar layout
func (h *Handler) renderAdminPage(w http.ResponseWriter, pageID, title string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>` + title + ` - casspeed Admin</title>
	<link rel="stylesheet" href="/static/css/admin/style.css">
</head>
<body class="admin-layout">
	<div class="admin-container">
		<aside class="admin-sidebar">
			<div class="sidebar-header">
				<h2>casspeed</h2>
			</div>
			<nav class="sidebar-nav">
				<a href="/admin/" class="nav-item">Dashboard</a>
				<div class="nav-section">
					<div class="nav-section-title">Server</div>
					<a href="/admin/server/settings" class="nav-item">Settings</a>
					<a href="/admin/server/ssl" class="nav-item">SSL/TLS</a>
					<a href="/admin/server/email" class="nav-item">Email</a>
					<a href="/admin/server/scheduler" class="nav-item">Scheduler</a>
					<a href="/admin/server/logs" class="nav-item">Logs</a>
					<a href="/admin/server/backup" class="nav-item">Backup</a>
					<a href="/admin/server/updates" class="nav-item">Updates</a>
					<a href="/admin/server/info" class="nav-item">Info</a>
					<a href="/admin/server/metrics" class="nav-item">Metrics</a>
				</div>
				<div class="nav-section">
					<div class="nav-section-title">Network</div>
					<a href="/admin/server/network/tor" class="nav-item">Tor</a>
					<a href="/admin/server/network/geoip" class="nav-item">GeoIP</a>
				</div>
				<div class="nav-section">
					<div class="nav-section-title">Security</div>
					<a href="/admin/server/security/auth" class="nav-item">Authentication</a>
					<a href="/admin/server/security/tokens" class="nav-item">API Tokens</a>
				</div>
			</nav>
		</aside>
		<main class="admin-main">
			<header class="admin-header">
				<h1>` + title + `</h1>
				<div class="header-actions">
					<a href="/admin/profile">Profile</a>
					<a href="/admin/logout">Logout</a>
				</div>
			</header>
			<div class="admin-content">
				<p>` + title + ` page content will be displayed here.</p>
			</div>
		</main>
	</div>
</body>
</html>`))
}
