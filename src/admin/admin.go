package admin

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/metrics"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"golang.org/x/crypto/argon2"
)

//go:embed template/*
var adminTemplateFS embed.FS

var adminContentShell = template.Must(template.New("admin-content-shell").Parse(`<!doctype html><html lang="{{.Lang}}" dir="{{.Direction}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{.Title}} — {{index .Labels "admin.legacy.brand"}}</title><link rel="stylesheet" href="/static/css/theme-dark.css"><link rel="stylesheet" href="/static/css/theme-light.css"><link rel="stylesheet" href="/static/css/style.css"><link rel="stylesheet" href="/static/css/admin/style.css"></head><body><a class="skip-link" href="#main-content">{{index .Labels "admin.legacy.skip_content"}}</a><div class="admin-layout"><nav class="admin-nav" aria-label="{{index .Labels "admin.legacy.navigation"}}"><a class="admin-nav__brand" href="{{.Root}}">CasSpeed <span class="admin-nav__badge">{{index .Labels "admin.legacy.brand"}}</span></a><div class="admin-nav__section"><ul><li><a href="{{.Root}}">{{index .Labels "admin.legacy.dashboard"}}</a></li><li><a href="{{.Root}}settings">{{index .Labels "admin.legacy.settings"}}</a></li><li><a href="{{.Root}}pages">{{index .Labels "admin.legacy.public_pages"}}</a></li><li><a href="{{.Root}}privacy">{{index .Labels "admin.legacy.privacy"}}</a></li><li><a href="{{.Root}}tracking">{{index .Labels "admin.legacy.analytics"}}</a></li><li><a href="{{.Root}}users">{{index .Labels "admin.legacy.users"}}</a></li><li><a href="{{.Root}}roles">{{index .Labels "admin.legacy.roles"}}</a></li><li><a href="{{.Root}}logs">{{index .Labels "admin.legacy.logs"}}</a></li><li><a href="{{.Root}}backup">{{index .Labels "admin.legacy.backup"}}</a></li><li><a href="{{.Root}}security/auth">{{index .Labels "admin.legacy.security"}}</a></li></ul></div><div class="admin-nav__footer"><form action="/server/auth/logout" method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button type="submit">{{index .Labels "admin.legacy.sign_out"}}</button></form></div></nav><div class="admin-main"><main id="main-content" class="admin-content"><h1 class="admin-page-title">{{.Title}}</h1>{{if .Description}}<p>{{.Description}}</p>{{end}}{{.Content}}</main></div></div></body></html>`))

type contextKey string

const adminIDContextKey contextKey = "admin_id"

// AdminIDFromContext returns the authenticated administrator ID set by RequireAuth.
func AdminIDFromContext(ctx context.Context) (int, bool) {
	id, ok := ctx.Value(adminIDContextKey).(int)
	return id, ok && id > 0
}

type Handler struct {
	store      store.Store
	settingsMu sync.Mutex
	config     *config.Config
	configPath string
	version    string
	logDir     string
	startedAt  time.Time
}

var errInvalidSettings = errors.New("settings values are outside the allowed range")

type settingsUpdate struct {
	Server serverSettingsUpdate `json:"server"`
	Test   testSettingsUpdate   `json:"test"`
}

type serverSettingsUpdate struct {
	Port *int   `json:"port"`
	Mode string `json:"mode"`
}

type testSettingsUpdate struct {
	MaxThreads      *int `json:"max_threads"`
	DefaultDuration *int `json:"default_duration"`
	MaxConcurrent   *int `json:"max_concurrent"`
}

type settingsPageData struct {
	Mode          string
	Port          int
	MaxThreads    int
	Duration      int
	MaxConcurrent int
	Saved         bool
	AdminRoot     string
	CSRFToken     string
	Lang          string
	Direction     string
}

type adminTemplateData struct {
	AdminRoot string
	CSRFToken string
	Lang      string
	Direction string
}

func adminLocale(r *http.Request) (*i18n.Catalog, string) {
	language := strings.TrimSpace(r.URL.Query().Get("lang"))
	if language != "" {
		language = i18n.Normalize(language)
	} else if cookie, err := r.Cookie("lang"); err == nil && i18n.IsSupportedTag(cookie.Value) {
		language = cookie.Value
	} else {
		language = strings.SplitN(r.Header.Get("Accept-Language"), ",", 2)[0]
		language = strings.SplitN(language, ";", 2)[0]
		language = i18n.Normalize(language)
	}
	catalog, err := i18n.Resolve(language)
	if err != nil {
		catalog, _ = i18n.Resolve("en")
	}
	return catalog, language
}

func adminLabels(catalog *i18n.Catalog) map[string]string {
	keys := []string{"brand", "skip_content", "navigation", "dashboard", "settings", "public_pages", "privacy", "analytics", "users", "roles", "logs", "backup", "security", "sign_out"}
	labels := make(map[string]string, len(keys))
	for _, key := range keys {
		labels["admin.legacy."+key] = catalog.T("admin.legacy."+key, nil)
	}
	return labels
}

func adminText(r *http.Request, key string) string {
	catalog, _ := adminLocale(r)
	return catalog.T("admin.legacy."+key, nil)
}

func localizedAdminMode(catalog *i18n.Catalog, mode string) string {
	key := "admin.legacy." + strings.ToLower(mode)
	translated := catalog.T(key, nil)
	if translated == key {
		return mode
	}
	return translated
}

func (h *Handler) templateData(r *http.Request) adminTemplateData {
	catalog, language := adminLocale(r)
	return adminTemplateData{AdminRoot: h.adminRootPath(), CSRFToken: csrfToken(r), Lang: language, Direction: catalog.Meta.Direction}
}

type dashboardPageData struct {
	adminTemplateData
	TotalTests    string
	ActiveUsers   string
	Status        string
	Version       string
	Mode          string
	ModeLabel     string
	Port          int
	MaxThreads    int
	MaxConcurrent int
}

type serverInfoPageData struct {
	adminTemplateData
	Version   string
	Mode      string
	ModeLabel string
	GoVersion string
	Platform  string
	Uptime    string
}

type logsPageData struct {
	adminTemplateData
	Logs []string
}

// Alias AdminHandler to Handler for consistency
type AdminHandler = Handler

func NewHandler(st store.Store) *Handler {
	return &Handler{store: st}
}

func (h *Handler) ConfigureSettings(cfg *config.Config, path string, values ...string) {
	h.settingsMu.Lock()
	defer h.settingsMu.Unlock()
	h.config = cfg
	h.configPath = path
	if len(values) > 0 {
		h.version = values[0]
	}
	if len(values) > 1 {
		h.logDir = values[1]
	}
	h.startedAt = time.Now()
}

func (h *Handler) adminRootPath() string {
	h.settingsMu.Lock()
	defer h.settingsMu.Unlock()
	adminPath := "administration"
	if h.config != nil && h.config.Server.AdminPath != "" {
		adminPath = h.config.Server.AdminPath
	}
	return "/server/" + adminPath
}

func configPort(cfg *config.Config) int {
	switch value := cfg.Server.Port.(type) {
	case int:
		if value > 0 {
			return value
		}
	case string:
		if port, err := strconv.Atoi(value); err == nil && port > 0 {
			return port
		}
	}
	return 64580
}

func settingsResponse(cfg *config.Config) map[string]any {
	return map[string]any{
		"server": map[string]any{"port": configPort(cfg), "mode": cfg.Server.Mode},
		"test":   map[string]any{"max_threads": cfg.Test.MaxThreads, "default_duration": cfg.Test.DefaultDuration, "max_concurrent": cfg.Test.MaxConcurrent},
	}
}

func (h *Handler) saveSettings(update settingsUpdate) error {
	h.settingsMu.Lock()
	defer h.settingsMu.Unlock()
	if h.config == nil || h.configPath == "" {
		return errors.New("settings persistence is not configured")
	}
	if update.Server.Port != nil && (*update.Server.Port < 1 || *update.Server.Port > 65535) || update.Server.Mode != "" && update.Server.Mode != "production" && update.Server.Mode != "development" || update.Test.MaxThreads != nil && (*update.Test.MaxThreads < 1 || *update.Test.MaxThreads > 16) || update.Test.DefaultDuration != nil && (*update.Test.DefaultDuration < 1 || *update.Test.DefaultDuration > 60) || update.Test.MaxConcurrent != nil && (*update.Test.MaxConcurrent < 1 || *update.Test.MaxConcurrent > 100) {
		return errInvalidSettings
	}
	previous := *h.config
	if update.Server.Port != nil {
		h.config.Server.Port = *update.Server.Port
	}
	if update.Server.Mode != "" {
		h.config.Server.Mode = update.Server.Mode
	}
	if update.Test.MaxThreads != nil {
		h.config.Test.MaxThreads = *update.Test.MaxThreads
	}
	if update.Test.DefaultDuration != nil {
		h.config.Test.DefaultDuration = *update.Test.DefaultDuration
	}
	if update.Test.MaxConcurrent != nil {
		h.config.Test.MaxConcurrent = *update.Test.MaxConcurrent
	}
	if err := config.Save(h.config, h.configPath); err != nil {
		*h.config = previous
		return err
	}
	return nil
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

	// Constant-time comparison prevents timing attacks (PART 11)
	return subtle.ConstantTimeCompare(hash, storedHash) == 1
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	// Check if setup is complete
	if !IsSetupComplete() {
		// Show setup token entry page
		h.renderSetupTokenPage(w, r, "")
		return
	}

	if r.Method == "GET" {
		http.Redirect(w, r, "/server/auth/login", http.StatusSeeOther)
		return
	}
	status := "failure"
	defer func() { metrics.RecordAuthentication("admin_password", status) }()

	ctx := r.Context()
	username := r.FormValue("username")
	password := r.FormValue("password")

	admin, err := h.store.GetAdminByUsername(ctx, username)
	if err != nil || admin == nil {
		http.Error(w, adminText(r, "errors.invalid_credentials"), http.StatusUnauthorized)
		return
	}

	if !admin.LockedUntil.IsZero() && time.Now().Before(admin.LockedUntil) {
		http.Error(w, adminText(r, "errors.account_locked"), http.StatusForbidden)
		return
	}

	if !VerifyPassword(password, admin.Password) {
		attempts := admin.FailedAttempts + 1
		h.store.UpdateAdminFailedAttempts(ctx, admin.ID, attempts)

		if attempts >= 5 {
			h.store.LockAdmin(ctx, admin.ID, time.Now().Add(15*time.Minute))
			http.Error(w, adminText(r, "errors.rate_limited"), http.StatusForbidden)
			return
		}

		http.Error(w, adminText(r, "errors.invalid_credentials"), http.StatusUnauthorized)
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
		http.Error(w, adminText(r, "errors.session_failed"), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    sessionIDHex,
		Path:     "/", // Cookie path covers all admin paths
		MaxAge:   86400 * 30,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, h.adminRootPath()+"/", http.StatusSeeOther)
	status = "success"
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, adminText(r, "error.method_not_allowed"), http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil || !validAdminCSRF(r) {
		http.Error(w, adminText(r, "errors.csrf_invalid"), http.StatusForbidden)
		return
	}
	ctx := r.Context()

	cookie, err := r.Cookie("admin_session")
	if err == nil {
		h.store.DeleteAdminSession(ctx, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/server/auth/login", http.StatusSeeOther)
}

func validAdminCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("admin_session")
	if err != nil || cookie.Value == "" {
		return false
	}
	provided := r.FormValue("csrf_token")
	if len(provided) != len(cookie.Value) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(cookie.Value)) == 1
}

func csrfToken(r *http.Request) string {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	testCount, testErr := h.store.CountSpeedTests(r.Context())
	userCount, userErr := h.store.CountUsers(r.Context())
	catalog, _ := adminLocale(r)
	data := dashboardPageData{adminTemplateData: h.templateData(r), Version: catalog.T("admin.legacy.unknown", nil), ModeLabel: catalog.T("admin.legacy.unknown", nil)}
	data.TotalTests = catalog.T("admin.legacy.unavailable", nil)
	data.ActiveUsers = catalog.T("admin.legacy.unavailable", nil)
	data.Status = catalog.T("admin.legacy.degraded", nil)
	if testErr == nil {
		data.TotalTests = strconv.Itoa(testCount)
	}
	if userErr == nil {
		data.ActiveUsers = strconv.Itoa(userCount)
	}
	if testErr == nil && userErr == nil {
		data.Status = catalog.T("admin.legacy.online", nil)
	}
	h.settingsMu.Lock()
	if h.config != nil {
		data.Mode = h.config.Server.Mode
		data.ModeLabel = localizedAdminMode(catalog, data.Mode)
		data.Port = configPort(h.config)
		data.MaxThreads = h.config.Test.MaxThreads
		data.MaxConcurrent = h.config.Test.MaxConcurrent
	}
	if h.version != "" {
		data.Version = h.version
	}
	h.settingsMu.Unlock()
	h.renderAdminTemplate(w, r, "dashboard.html", data)
}

func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	h.settingsMu.Lock()
	defer h.settingsMu.Unlock()
	if h.config == nil {
		http.Error(w, adminText(r, "errors.settings_unavailable"), http.StatusServiceUnavailable)
		return
	}
	settings := settingsResponse(h.config)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (h *Handler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsUpdate
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, adminText(r, "errors.settings_request_invalid"), http.StatusBadRequest)
		return
	}
	if err := h.saveSettings(req); err != nil {
		if err == errInvalidSettings {
			http.Error(w, adminText(r, "errors.settings_invalid"), http.StatusBadRequest)
		} else {
			http.Error(w, adminText(r, "errors.settings_save_failed"), http.StatusInternalServerError)
		}
		return
	}
	h.settingsMu.Lock()
	currentSettings := settingsResponse(h.config)
	h.settingsMu.Unlock()
	response := map[string]any{"ok": true, "data": currentSettings}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cookie, err := r.Cookie("admin_session")
		if err != nil {
			http.Redirect(w, r, "/server/auth/login", http.StatusSeeOther)
			return
		}

		session, err := h.store.GetAdminSession(ctx, cookie.Value)
		if err != nil || session == nil {
			http.Redirect(w, r, "/server/auth/login", http.StatusSeeOther)
			return
		}

		h.store.UpdateAdminSessionActivity(ctx, session.ID)

		ctx = context.WithValue(ctx, adminIDContextKey, session.AdminID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// ServerSettings shows settings page
func (h *Handler) ServerSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, adminText(r, "errors.settings_form_invalid"), http.StatusBadRequest)
			return
		}
		if !validAdminCSRF(r) {
			http.Error(w, adminText(r, "errors.csrf_invalid"), http.StatusForbidden)
			return
		}
		port, err := strconv.Atoi(r.FormValue("port"))
		if err != nil {
			http.Error(w, adminText(r, "errors.port_number"), http.StatusBadRequest)
			return
		}
		threads, err := strconv.Atoi(r.FormValue("max_threads"))
		if err != nil {
			http.Error(w, adminText(r, "errors.threads_number"), http.StatusBadRequest)
			return
		}
		duration, err := strconv.Atoi(r.FormValue("duration"))
		if err != nil {
			http.Error(w, adminText(r, "errors.duration_number"), http.StatusBadRequest)
			return
		}
		concurrent, err := strconv.Atoi(r.FormValue("max_concurrent"))
		if err != nil {
			http.Error(w, adminText(r, "errors.concurrent_number"), http.StatusBadRequest)
			return
		}
		if err := h.saveSettings(settingsUpdate{Server: serverSettingsUpdate{Port: &port, Mode: r.FormValue("mode")}, Test: testSettingsUpdate{MaxThreads: &threads, DefaultDuration: &duration, MaxConcurrent: &concurrent}}); err != nil {
			if err == errInvalidSettings {
				http.Error(w, adminText(r, "errors.settings_invalid"), http.StatusBadRequest)
			} else {
				http.Error(w, adminText(r, "errors.settings_save_failed"), http.StatusInternalServerError)
			}
			return
		}
		h.settingsMu.Lock()
		adminPath := h.config.Server.AdminPath
		h.settingsMu.Unlock()
		if adminPath == "" {
			adminPath = "administration"
		}
		http.Redirect(w, r, "/server/"+adminPath+"/settings?saved=1", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, adminText(r, "error.method_not_allowed"), http.StatusMethodNotAllowed)
		return
	}
	h.settingsMu.Lock()
	if h.config == nil {
		h.settingsMu.Unlock()
		http.Error(w, adminText(r, "errors.settings_unavailable"), http.StatusServiceUnavailable)
		return
	}
	data, err := adminTemplateFS.ReadFile("template/settings.html")
	adminPath := h.config.Server.AdminPath
	if adminPath == "" {
		adminPath = "administration"
	}
	csrfToken := ""
	if cookie, err := r.Cookie("admin_session"); err == nil {
		csrfToken = cookie.Value
	}
	catalog, language := adminLocale(r)
	settings := settingsPageData{Mode: h.config.Server.Mode, Port: configPort(h.config), MaxThreads: h.config.Test.MaxThreads, Duration: h.config.Test.DefaultDuration, MaxConcurrent: h.config.Test.MaxConcurrent, Saved: r.URL.Query().Get("saved") == "1", AdminRoot: "/server/" + adminPath, CSRFToken: csrfToken, Lang: language, Direction: catalog.Meta.Direction}
	h.settingsMu.Unlock()
	if err != nil {
		http.Error(w, adminText(r, "errors.settings_template_unavailable"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	parsed, err := template.New("settings").Funcs(template.FuncMap{"t": func(key string) string { return catalog.T(key, nil) }}).Parse(string(data))
	if err != nil {
		http.Error(w, adminText(r, "errors.settings_template_invalid"), http.StatusInternalServerError)
		return
	}
	if err := parsed.Execute(w, settings); err != nil {
		return
	}
}

// ServerInfo shows server info page
func (h *Handler) ServerInfo(w http.ResponseWriter, r *http.Request) {
	catalog, _ := adminLocale(r)
	templateData := h.templateData(r)
	h.settingsMu.Lock()
	data := serverInfoPageData{adminTemplateData: templateData, Version: h.version, Mode: "unknown", ModeLabel: catalog.T("admin.legacy.unknown", nil), GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH, Uptime: catalog.T("admin.legacy.unknown", nil)}
	if h.config != nil {
		data.Mode = h.config.Server.Mode
		data.ModeLabel = localizedAdminMode(catalog, data.Mode)
	}
	if !h.startedAt.IsZero() {
		data.Uptime = time.Since(h.startedAt).Round(time.Second).String()
	}
	h.settingsMu.Unlock()
	h.renderAdminTemplate(w, r, "info.html", data)
}

// ServerLogs shows logs page
func (h *Handler) ServerLogs(w http.ResponseWriter, r *http.Request) {
	h.settingsMu.Lock()
	path := h.logDir
	h.settingsMu.Unlock()
	catalog, _ := adminLocale(r)
	logs := []string{catalog.T("admin.legacy.no_logs", nil)}
	if path != "" {
		if entries, err := readRecentLogLines(filepath.Join(path, "server.log"), 100); err == nil && len(entries) > 0 {
			logs = entries
		}
	}
	h.renderAdminTemplate(w, r, "logs.html", logsPageData{adminTemplateData: h.templateData(r), Logs: logs})
}

func readRecentLogLines(path string, limit int) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	start := info.Size() - 64*1024
	if start < 0 {
		start = 0
	}
	if _, err := file.Seek(start, 0); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 16*1024)
	lines := make([]string, 0, limit)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > limit {
			lines = lines[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func (h *Handler) renderAdminTemplate(w http.ResponseWriter, r *http.Request, name string, data ...any) {
	templateBytes, err := adminTemplateFS.ReadFile("template/" + name)
	if err != nil {
		http.Error(w, adminText(r, "errors.page_template_unavailable"), http.StatusInternalServerError)
		return
	}
	catalog, _ := adminLocale(r)
	page, err := template.New(name).Funcs(template.FuncMap{"t": func(key string) string { return catalog.T(key, nil) }}).Parse(string(templateBytes))
	if err != nil {
		http.Error(w, adminText(r, "errors.page_template_invalid"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	values := any(h.templateData(r))
	if len(data) > 0 {
		values = data[0]
	}
	if err := page.Execute(w, values); err != nil {
		return
	}
}

// Profile shows admin's own profile page
func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "profile")
}

// Preferences shows admin's own preferences page
func (h *Handler) Preferences(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "preferences")
}

// Notifications shows admin's own notifications page
func (h *Handler) Notifications(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "notifications")
}

// ServerAuditLogs shows audit logs page
func (h *Handler) ServerAuditLogs(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "audit-logs")
}

// ServerBackup shows backup management page
func (h *Handler) ServerBackup(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "backup")
}

// ServerUpdates shows update management page
func (h *Handler) ServerUpdates(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "updates")
}

// ServerSSL shows SSL/TLS configuration page
func (h *Handler) ServerSSL(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "ssl")
}

// ServerEmail shows email configuration page
func (h *Handler) ServerEmail(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "email")
}

// ServerScheduler shows scheduler page
func (h *Handler) ServerScheduler(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "scheduler")
}

// ServerMetrics shows metrics dashboard page
func (h *Handler) ServerMetrics(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "metrics")
}

// NetworkTor shows Tor configuration page
func (h *Handler) NetworkTor(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "network-tor")
}

// NetworkGeoIP shows GeoIP settings page
func (h *Handler) NetworkGeoIP(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "network-geoip")
}

// SecurityAuth shows authentication settings page
func (h *Handler) SecurityAuth(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "security-auth")
}

// SecurityTokens shows API token management page
func (h *Handler) SecurityTokens(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "security-tokens")
}

// ServerUsers shows user management page
func (h *Handler) ServerUsers(w http.ResponseWriter, r *http.Request) {
	h.renderAdminPage(w, r, "users")
}

// renderAdminPage renders a standard admin page with sidebar layout
func (h *Handler) renderAdminPage(w http.ResponseWriter, r *http.Request, pageID string) {
	catalog, _ := adminLocale(r)
	h.RenderContentPage(w, r, catalog.T("admin.legacy.page."+pageID, nil), catalog.T("admin.legacy.description."+pageID, nil), "")
}

// RenderContentPage places generated admin controls inside the isolated admin shell.
func (h *Handler) RenderContentPage(w http.ResponseWriter, r *http.Request, title, description, content string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	catalog, language := adminLocale(r)
	values := map[string]any{"Root": h.adminRootPath() + "/", "CSRF": csrfToken(r), "Title": title, "Description": description, "Content": template.HTML(content), "Lang": language, "Direction": catalog.Meta.Direction, "Labels": adminLabels(catalog)}
	if err := adminContentShell.Execute(w, values); err != nil {
		return
	}
}
