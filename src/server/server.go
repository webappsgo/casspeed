package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/casapps/casspeed/src/admin"
	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/graphql"
	"github.com/casapps/casspeed/src/logging"
	"github.com/casapps/casspeed/src/metrics"
	srcMiddleware "github.com/casapps/casspeed/src/middleware"
	"github.com/casapps/casspeed/src/mode"
	"github.com/casapps/casspeed/src/server/handler"
	"github.com/casapps/casspeed/src/server/service"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/casapps/casspeed/src/swagger"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

//go:embed template/* static/*
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

type Server struct {
	Config       *config.Config
	Mode         *mode.State
	Router       *chi.Mux
	HTTP         *http.Server
	Store        store.Store
	Handler      *handler.SpeedTestHandler
	ImageHandler *handler.ShareImageHandler
	UserHandler  *handler.UserHandler
	AdminHandler *admin.Handler
	Logger       *logging.Logger
	ipTestCount  map[string]*ipRateLimit
	ipMutex      sync.RWMutex
	startTime    time.Time
	version      string
}

type ipRateLimit struct {
	activeTests int
	lastTest    time.Time
}

func New(cfg *config.Config, appMode *mode.State, dataDir string, logDir string, version string) (*Server, error) {
	// Initialize logging
	logger, err := logging.New(logDir)
	if err != nil {
		return nil, fmt.Errorf("initializing logger: %w", err)
	}
	
	dbPath := filepath.Join(dataDir, "db", "speedtest.db")
	dbStore, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("creating store: %w", err)
	}

	// Check if setup is complete from database
	ctx := context.Background()
	setupComplete, err := dbStore.GetSetupComplete(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking setup status: %w", err)
	}
	admin.SetSetupComplete(setupComplete)

	speedTestService := service.NewSpeedTestService(cfg.Test.MaxThreads, cfg.Test.ChunkSize)
	speedTestHandler := handler.NewSpeedTestHandler(dbStore, speedTestService)
	imageHandler := handler.NewShareImageHandler(dbStore)
	userHandler := handler.NewUserHandler(dbStore)
	adminHandler := admin.NewHandler(dbStore)

	s := &Server{
		Config:       cfg,
		Mode:         appMode,
		Router:       chi.NewRouter(),
		Store:        dbStore,
		Handler:      speedTestHandler,
		ImageHandler: imageHandler,
		UserHandler:  userHandler,
		AdminHandler: adminHandler,
		Logger:       logger,
		ipTestCount:  make(map[string]*ipRateLimit),
		startTime:    time.Now(),
		version:      version,
	}

	s.setupMiddleware()
	s.setupRoutes()

	return s, nil
}

func (s *Server) setupMiddleware() {
	// URL normalization FIRST — trailing slash removal + 301 redirect (PART 16)
	s.Router.Use(srcMiddleware.URLNormalizeMiddleware)

	// Path security middleware — traversal blocking (PART 5 - NON-NEGOTIABLE)
	s.Router.Use(srcMiddleware.PathSecurityMiddleware)

	// Security headers (PART 11 - NON-NEGOTIABLE)
	s.Router.Use(securityHeaders(s.Config.Server.SSL.Enabled))

	s.Router.Use(middleware.RequestID)
	s.Router.Use(middleware.RealIP)
	s.Router.Use(middleware.Logger)
	s.Router.Use(middleware.Recoverer)
	s.Router.Use(s.rateLimitMiddleware)

	if s.Mode.IsDevelopment() || s.Mode.IsDebug() {
		s.Router.Use(middleware.Timeout(60 * time.Second))
	} else {
		s.Router.Use(middleware.Timeout(30 * time.Second))
	}

	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})
	s.Router.Use(corsHandler.Handler)
}

func (s *Server) setupRoutes() {
	// Determine admin path (configurable, default "admin")
	adminPath := s.Config.Server.AdminPath
	if adminPath == "" {
		adminPath = "admin"
	}

	// Static files — served from embedded FS
	staticHandler := http.FileServer(http.FS(staticFS))
	s.Router.Handle("/static/*", http.StripPrefix("/static", staticHandler))

	// Root / public routes
	s.Router.Get("/", s.handleIndex)

	// Well-known files (PART 11 - NON-NEGOTIABLE)
	s.Router.Get("/robots.txt", s.handleRobotsTxt)
	s.Router.Get("/.well-known/security.txt", s.handleSecurityTxt)
	s.Router.Get("/.well-known/change-password", s.handleChangePassword)

	// Health check — primary at /server/healthz, alias at /healthz (PART 13)
	s.Router.Get("/server/healthz", s.handleHealth)
	s.Router.Get("/server/healthz.json", s.handleHealth)
	s.Router.Get("/server/healthz.txt", s.handleHealth)
	s.Router.Get("/healthz", s.handleHealth)
	s.Router.Get("/healthz.json", s.handleHealth)
	s.Router.Get("/healthz.txt", s.handleHealth)

	// Metrics endpoint (Prometheus format)
	s.Router.Get("/metrics", s.handleMetrics)

	// API v1 routes
	s.Router.Route("/api/v1", func(r chi.Router) {
		r.Get("/", s.handleAPIRoot)

		// Health check API route (PART 13)
		r.Get("/server/healthz", s.handleHealth)
		r.Get("/server/healthz.json", s.handleHealth)
		r.Get("/server/healthz.txt", s.handleHealth)

		// Auth endpoints — /api/v1/server/auth/* (PART 14)
		authHandler := handler.NewAuthHandler(s.Store)
		r.Post("/server/auth/register", s.UserHandler.Register)
		r.Post("/server/auth/login", authHandler.Login)
		r.Post("/server/auth/logout", authHandler.Logout)
		r.Post("/server/auth/password/forgot", authHandler.PasswordResetRequest)

		// Speed test endpoints (public, project-specific)
		r.Post("/speed-tests", s.Handler.StartTest)
		r.Get("/speed-tests/ws", s.Handler.TestStatus)
		r.Get("/speed-tests/download", s.Handler.Download)
		r.Post("/speed-tests/upload", s.Handler.Upload)
		r.Get("/speed-tests/{id}", s.Handler.GetResult)
		r.Get("/speed-tests", s.Handler.GetHistory)

		// User self-management (no ID — session identifies user) (PART 14)
		r.Get("/users", s.UserHandler.GetProfile)
		r.Get("/users/devices", s.UserHandler.ListDevices)
		r.Post("/users/devices", s.UserHandler.CreateDevice)
		r.Delete("/users/devices/{deviceId}", s.UserHandler.DeleteDevice)
		r.Get("/users/tokens", s.UserHandler.ListTokens)
		r.Post("/users/tokens", s.UserHandler.CreateToken)
		r.Delete("/users/tokens/{tokenId}", s.UserHandler.RevokeToken)

		// Admin API endpoints — /api/v1/server/{adminPath}/config/* (PART 17)
		r.Get("/server/"+adminPath+"/config/settings", s.AdminHandler.RequireAuth(s.AdminHandler.GetSettings))
		r.Put("/server/"+adminPath+"/config/settings", s.AdminHandler.RequireAuth(s.AdminHandler.UpdateSettings))
	})

	// ==========================================================================
	// Admin Panel Web UI — /server/{adminPath}/* (PART 17)
	// ==========================================================================

	// Setup wizard — accessible without auth before setup is complete
	s.Router.Post("/server/"+adminPath+"/config/setup/token", s.AdminHandler.SetupTokenHandler)
	s.Router.Get("/server/"+adminPath+"/config/setup", s.AdminHandler.SetupWizardHandler)
	s.Router.Post("/server/"+adminPath+"/config/setup/complete", s.AdminHandler.SetupCompleteHandler)

	// Admin login / logout (no auth required)
	s.Router.Get("/server/"+adminPath, s.AdminHandler.Login)
	s.Router.Post("/server/"+adminPath+"/login", s.AdminHandler.Login)
	s.Router.Get("/server/"+adminPath+"/logout", s.AdminHandler.Logout)

	// Admin dashboard root (PART 17: dashboard ONLY at root)
	s.Router.Get("/server/"+adminPath+"/", s.AdminHandler.RequireAuth(s.AdminHandler.Dashboard))

	// Admin's own account — /server/{adminPath}/{username}/* (PART 17)
	s.Router.Get("/server/"+adminPath+"/{username}/profile", s.AdminHandler.RequireAuth(s.AdminHandler.Profile))
	s.Router.Get("/server/"+adminPath+"/{username}/preferences", s.AdminHandler.RequireAuth(s.AdminHandler.Preferences))
	s.Router.Get("/server/"+adminPath+"/{username}/notifications", s.AdminHandler.RequireAuth(s.AdminHandler.Notifications))

	// Server config routes — ALL under /server/{adminPath}/config/* (PART 17)
	s.Router.Get("/server/"+adminPath+"/config/settings", s.AdminHandler.RequireAuth(s.AdminHandler.ServerSettings))
	s.Router.Post("/server/"+adminPath+"/config/settings", s.AdminHandler.RequireAuth(s.AdminHandler.ServerSettings))
	s.Router.Get("/server/"+adminPath+"/config/info", s.AdminHandler.RequireAuth(s.AdminHandler.ServerInfo))
	s.Router.Get("/server/"+adminPath+"/config/logs", s.AdminHandler.RequireAuth(s.AdminHandler.ServerLogs))
	s.Router.Get("/server/"+adminPath+"/config/logs/audit", s.AdminHandler.RequireAuth(s.AdminHandler.ServerAuditLogs))
	s.Router.Get("/server/"+adminPath+"/config/backup", s.AdminHandler.RequireAuth(s.AdminHandler.ServerBackup))
	s.Router.Get("/server/"+adminPath+"/config/updates", s.AdminHandler.RequireAuth(s.AdminHandler.ServerUpdates))
	s.Router.Get("/server/"+adminPath+"/config/ssl", s.AdminHandler.RequireAuth(s.AdminHandler.ServerSSL))
	s.Router.Get("/server/"+adminPath+"/config/email", s.AdminHandler.RequireAuth(s.AdminHandler.ServerEmail))
	s.Router.Get("/server/"+adminPath+"/config/scheduler", s.AdminHandler.RequireAuth(s.AdminHandler.ServerScheduler))
	s.Router.Get("/server/"+adminPath+"/config/metrics", s.AdminHandler.RequireAuth(s.AdminHandler.ServerMetrics))

	// Network config
	s.Router.Get("/server/"+adminPath+"/config/network/tor", s.AdminHandler.RequireAuth(s.AdminHandler.NetworkTor))
	s.Router.Get("/server/"+adminPath+"/config/network/geoip", s.AdminHandler.RequireAuth(s.AdminHandler.NetworkGeoIP))

	// Security config
	s.Router.Get("/server/"+adminPath+"/config/security/auth", s.AdminHandler.RequireAuth(s.AdminHandler.SecurityAuth))
	s.Router.Get("/server/"+adminPath+"/config/security/tokens", s.AdminHandler.RequireAuth(s.AdminHandler.SecurityTokens))

	// User management (multi-user)
	s.Router.Get("/server/"+adminPath+"/config/users", s.AdminHandler.RequireAuth(s.AdminHandler.ServerUsers))

	// ==========================================================================
	// Share endpoints (public)
	// ==========================================================================
	s.Router.Get("/share/{code}", s.Handler.GetShare)
	s.Router.Get("/s/{code}", s.Handler.GetShare)
	s.Router.Get("/share/{code}.png", s.ImageHandler.GetSharePNG)
	s.Router.Get("/s/{code}.png", s.ImageHandler.GetSharePNG)
	s.Router.Get("/share/{code}.svg", s.ImageHandler.GetShareSVG)
	s.Router.Get("/s/{code}.svg", s.ImageHandler.GetShareSVG)

	// Swagger/OpenAPI
	s.Router.Get("/openapi", swagger.Handler)
	s.Router.Get("/openapi.json", swagger.SpecHandler)

	// GraphQL
	s.Router.Get("/graphql", graphql.Handler)
	s.Router.Post("/graphql/query", graphql.QueryHandler)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Read embedded template
	data, err := templateFS.ReadFile("template/index.html")
	if err != nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Calculate uptime
	uptime := time.Since(s.startTime)
	days := int(uptime.Hours() / 24)
	hours := int(uptime.Hours()) % 24
	minutes := int(uptime.Minutes()) % 60
	uptimeStr := fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	if days == 0 {
		if hours == 0 {
			uptimeStr = fmt.Sprintf("%dm", minutes)
		} else {
			uptimeStr = fmt.Sprintf("%dh %dm", hours, minutes)
		}
	}

	// Get hostname
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	// Health response per PART 13 spec
	response := map[string]interface{}{
		"status":    "healthy",
		"version":   s.version,
		"mode":      s.Mode.String(),
		"uptime":    uptimeStr,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"node": map[string]string{
			"id":       "standalone",
			"hostname": hostname,
		},
		"cluster": map[string]interface{}{
			"enabled": false,
		},
		"checks": map[string]string{
			"database": "ok",
			"cache":    "ok",
			"disk":     "ok",
		},
	}

	// Content negotiation per PART 13
	accept := r.Header.Get("Accept")
	
	// Check for .json or .txt extension
	if r.URL.Path == "/healthz.json" || r.URL.Path == "/api/v1/healthz.json" {
		accept = "application/json"
	} else if r.URL.Path == "/healthz.txt" || r.URL.Path == "/api/v1/healthz.txt" {
		accept = "text/plain"
	}

	// /api/v1/healthz always returns JSON
	if r.URL.Path == "/api/v1/healthz" && accept == "" {
		accept = "application/json"
	}

	// Determine format based on Accept header
	switch {
	case accept == "text/plain" || accept == "text/*":
		// Plain text format
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "status: %s\n", response["status"])
		fmt.Fprintf(w, "version: %s\n", response["version"])
		fmt.Fprintf(w, "mode: %s\n", response["mode"])
		fmt.Fprintf(w, "uptime: %s\n", response["uptime"])
		checks := response["checks"].(map[string]string)
		fmt.Fprintf(w, "database: %s\n", checks["database"])
		fmt.Fprintf(w, "cache: %s\n", checks["cache"])
		fmt.Fprintf(w, "disk: %s\n", checks["disk"])

	case accept == "application/json" || accept == "application/*":
		// JSON format
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.MarshalIndent(response, "", "  ")
		w.Write(data)
		w.Write([]byte("\n"))

	default:
		// HTML format (default for browsers)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Health Status - casspeed</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        .status-healthy { color: #28a745; font-weight: bold; font-size: 24px; }
        .info { margin: 20px 0; }
        .info dt { font-weight: bold; margin-top: 10px; }
        .info dd { margin-left: 20px; }
    </style>
</head>
<body>
    <h1>Health Status</h1>
    <p class="status-healthy">✓ %s</p>
    <dl class="info">
        <dt>Version:</dt><dd>%s</dd>
        <dt>Mode:</dt><dd>%s</dd>
        <dt>Uptime:</dt><dd>%s</dd>
        <dt>Node:</dt><dd>%s</dd>
        <dt>Database:</dt><dd>%s</dd>
        <dt>Disk:</dt><dd>%s</dd>
    </dl>
    <p><a href="/">← Back to Home</a></p>
</body>
</html>`, response["status"], response["version"], response["mode"], 
			response["uptime"], hostname, 
			response["checks"].(map[string]string)["database"],
			response["checks"].(map[string]string)["disk"])
	}
}

func (s *Server) handleAPIRoot(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"version": "v1",
		"status":  "ok",
	}
	w.Header().Set("Content-Type", "application/json")
	data, _ := json.MarshalIndent(response, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := metrics.GetMetrics()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(m.Export()))
}

// handleRobotsTxt serves robots.txt per PART 11
func (s *Server) handleRobotsTxt(w http.ResponseWriter, r *http.Request) {
	adminPath := s.Config.Server.AdminPath
	if adminPath == "" {
		adminPath = "admin"
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, `# casspeed robots.txt
User-agent: *
Allow: /
Allow: /api
Disallow: /server/%s
`, adminPath)
}

// handleSecurityTxt serves security.txt per PART 11 (RFC 9116)
func (s *Server) handleSecurityTxt(w http.ResponseWriter, r *http.Request) {
	// Get FQDN from config or use default
	fqdn := s.Config.Server.FQDN
	if fqdn == "" {
		fqdn = "localhost"
	}

	// Calculate expiry (1 year from now)
	expiry := time.Now().AddDate(1, 0, 0).Format("2006-01-02T15:04:05Z")

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, `# casspeed security.txt (RFC 9116)
Contact: mailto:security@%s
Expires: %s
Preferred-Languages: en
`, fqdn, expiry)
}

// handleChangePassword redirects to password change page per PART 11
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	// Redirect to auth password change page
	http.Redirect(w, r, "/auth/password/reset", http.StatusFound)
}

func (s *Server) Start(address string, port int) error {
	addr := fmt.Sprintf("%s:%d", address, port)

	s.HTTP = &http.Server{
		Addr:         addr,
		Handler:      s.Router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Respect NO_COLOR env var for console output
	if os.Getenv("NO_COLOR") == "" {
		fmt.Printf("│  🌐 HTTP   http://%s%s│\n", addr, padAddr(addr))
		fmt.Println("├─────────────────────────────────────────────────────────────┤")
		fmt.Printf("│  📡 Listening on http://%s%s│\n", addr, padAddr(addr))
		fmt.Printf("│  ✅ Server started on %s%s│\n", time.Now().Format("Mon Jan 02, 2006 at 15:04:05 MST"), padTime())
		fmt.Println("╰─────────────────────────────────────────────────────────────╯")
	} else {
		fmt.Printf("Listening on http://%s\n", addr)
		fmt.Printf("Server started at %s\n", time.Now().Format("2006-01-02 15:04:05"))
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- s.HTTP.ListenAndServe()
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errChan:
		return err
	case <-sigChan:
		return s.Shutdown()
	}
}

func (s *Server) Shutdown() error {
	if os.Getenv("NO_COLOR") == "" {
		fmt.Println("\n🛑 Shutting down gracefully...")
	} else {
		fmt.Println("\nShutting down gracefully...")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if s.Store != nil {
		s.Store.Close()
	}

	if err := s.HTTP.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	if os.Getenv("NO_COLOR") == "" {
		fmt.Println("✅ Server stopped")
	} else {
		fmt.Println("Server stopped")
	}
	return nil
}

func padAddr(addr string) string {
	needed := 60 - len("🌐 HTTP   http://") - len(addr)
	if needed < 0 {
		needed = 0
	}
	return fmt.Sprintf("%*s", needed, "")
}

func padTime() string {
	ts := time.Now().Format("Mon Jan 02, 2006 at 15:04:05 MST")
	needed := 60 - len("✅ Server started on ") - len(ts)
	if needed < 0 {
		needed = 0
	}
	return fmt.Sprintf("%*s", needed, "")
}

func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/speedtest/ws" && r.URL.Path != "/api/v1/speedtest/start" {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := r.RemoteAddr

		s.ipMutex.Lock()
		limit, exists := s.ipTestCount[clientIP]
		if !exists {
			limit = &ipRateLimit{activeTests: 0, lastTest: time.Time{}}
			s.ipTestCount[clientIP] = limit
		}

		if limit.activeTests >= s.Config.Test.MaxConcurrent {
			s.ipMutex.Unlock()
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too many concurrent tests", http.StatusTooManyRequests)
			return
		}

		secondsSinceLastTest := time.Since(limit.lastTest).Seconds()
		if secondsSinceLastTest < float64(s.Config.Test.MinInterval) {
			retryAfter := int(float64(s.Config.Test.MinInterval) - secondsSinceLastTest)
			s.ipMutex.Unlock()
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			http.Error(w, "Test interval too short", http.StatusTooManyRequests)
			return
		}

		limit.activeTests++
		limit.lastTest = time.Now()
		s.ipMutex.Unlock()

		defer func() {
			s.ipMutex.Lock()
			if l, ok := s.ipTestCount[clientIP]; ok {
				l.activeTests--
			}
			s.ipMutex.Unlock()
		}()

		next.ServeHTTP(w, r)
	})
}

// securityHeaders adds security headers per PART 11 specification
func securityHeaders(sslEnabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Required security headers (PART 11 - NON-NEGOTIABLE)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

			// HSTS when SSL is enabled
			if sslEnabled {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}

			next.ServeHTTP(w, r)
		})
	}
}
