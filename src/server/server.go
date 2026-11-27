package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/casapps/casspeed/src/admin"
	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/cache"
	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/email"
	"github.com/casapps/casspeed/src/graphql"
	"github.com/casapps/casspeed/src/i2p"
	"github.com/casapps/casspeed/src/logging"
	"github.com/casapps/casspeed/src/metrics"
	srcMiddleware "github.com/casapps/casspeed/src/middleware"
	"github.com/casapps/casspeed/src/mode"
	"github.com/casapps/casspeed/src/scheduler"
	"github.com/casapps/casspeed/src/server/handler"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/service"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/casapps/casspeed/src/swagger"
	"github.com/casapps/casspeed/src/tor"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

//go:embed template/index.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

func redactOneTimeTokenInAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logged := *r
		requestURI := r.RequestURI
		for _, prefix := range []string{"/server/auth/verify/", "/server/auth/invite/user/", "/server/auth/invite/server/", "/api/v1/server/auth/invite/user/", "/api/v1/server/auth/invite/server/"} {
			if strings.HasPrefix(requestURI, prefix) {
				remainder := requestURI[len(prefix):]
				if end := strings.IndexAny(remainder, "?/"); end >= 0 {
					remainder = remainder[:end]
				}
				if remainder != "" {
					requestURI = strings.Replace(requestURI, prefix+remainder, prefix+"[REDACTED]", 1)
				}
			}
		}
		if parsed, err := url.ParseRequestURI(requestURI); err == nil {
			query := parsed.Query()
			changed := false
			for _, key := range []string{"token", "verification_token", "invite_token"} {
				if query.Has(key) {
					query.Set(key, "[REDACTED]")
					changed = true
				}
			}
			if changed {
				parsed.RawQuery = query.Encode()
				requestURI = parsed.RequestURI()
			}
		}
		logged.RequestURI = requestURI
		next.ServeHTTP(w, &logged)
	})
}

type Server struct {
	Config             *config.Config
	ConfigPath         string
	DataDir            string
	LogDir             string
	configMu           sync.RWMutex
	Cache              cache.Client
	Mode               *mode.State
	Router             *chi.Mux
	HTTP               *http.Server
	Store              store.Store
	Handler            *handler.SpeedTestHandler
	ImageHandler       *handler.ShareImageHandler
	UserHandler        *handler.UserHandler
	ContactHandler     *ContactHandler
	EmailService       *email.Service
	SecurityReports    *SecurityReportService
	SecurityKeypair    *SecurityKeypairManager
	encryptionKey      []byte
	AdminHandler       *admin.Handler
	Scheduler          *scheduler.Scheduler
	Logger             *logging.Logger
	ipTestCount        map[string]*ipRateLimit
	fallbackRates      map[string][]time.Time
	rateFlushMu        sync.Mutex
	rateFlushNext      time.Time
	ipMutex            sync.RWMutex
	learnedOrigins     map[string]struct{}
	originMutex        sync.RWMutex
	startTime          time.Time
	version            string
	commitID           string
	buildDate          string
	operatorTokenHash  [32]byte
	metricsTokenHashes map[string][32]byte
	metricsLogDir      string
	overlayMu          sync.RWMutex
	i2pManager         *i2p.Manager
	i2pHTTP            *http.Server
	i2pState           i2p.State
	torManager         *tor.Manager
	torVanity          *tor.VanityManager
	torHTTP            *http.Server
	torState           tor.State
	cacheHealthMu      sync.Mutex
	cacheHealthStatus  string
	cacheHealthNext    time.Time
}

type ipRateLimit struct {
	activeTests int
	lastTest    time.Time
}

func New(cfg *config.Config, appMode *mode.State, configDir string, dataDir string, logDir string, version string, commitID string, buildDate string) (*Server, error) {
	sizeBuckets := make([]float64, len(cfg.Server.Metrics.SizeBuckets))
	for index, value := range cfg.Server.Metrics.SizeBuckets {
		sizeBuckets[index] = float64(value)
	}
	metrics.ConfigurePrometheus(metrics.PrometheusConfig{
		IncludeSystem: cfg.Server.Metrics.IncludeSystem, IncludeRuntime: cfg.Server.Metrics.IncludeRuntime,
		DurationBuckets: cfg.Server.Metrics.DurationBuckets, SizeBuckets: sizeBuckets,
	})
	metrics.InitPrometheusAppInfo(version, commitID, buildDate)
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
	secrets, err := config.LoadOrCreateSecrets(filepath.Join(configDir, "secrets.yml"))
	if err != nil {
		return nil, fmt.Errorf("loading server secrets: %w", err)
	}
	if secrets.ServerTokenGenerated {
		fmt.Printf("Operator token (save it now): %s\n", secrets.ServerToken)
	}
	for _, generated := range []struct {
		key       string
		generated bool
	}{{"server.token", secrets.ServerTokenGenerated}, {"server.security.encryption_key", secrets.EncryptionKeyGenerated}} {
		if generated.generated && logger.Audit != nil {
			entry, _ := json.Marshal(map[string]string{"event": "config.secret_generated", "key": generated.key, "timestamp": time.Now().UTC().Format(time.RFC3339Nano)})
			logger.Audit.Printf("%s\n", entry)
		}
	}
	for _, serviceName := range secrets.MetricsTokensGenerated {
		if logger.Audit != nil {
			entry, _ := json.Marshal(map[string]string{"event": "config.secret_generated", "key": "server.metrics.auth.tokens." + serviceName, "timestamp": time.Now().UTC().Format(time.RFC3339Nano)})
			logger.Audit.Printf("%s\n", entry)
		}
	}
	installationSecret, err := dbStore.GetOrCreateInstallationSecret(context.Background())
	if err != nil {
		return nil, fmt.Errorf("loading installation secret: %w", err)
	}
	csrfSecret, err := dbStore.GetOrCreateCSRFSecret(context.Background())
	if err != nil {
		return nil, fmt.Errorf("loading CSRF secret: %w", err)
	}
	securityReports, err := NewSecurityReportService(dbStore, installationSecret, secrets.EncryptionKey, cfg.Server.Security.Reports.RetentionDays)
	if err != nil {
		return nil, fmt.Errorf("initializing security reports: %w", err)
	}
	if err := securityReports.SetCSRFSecret(csrfSecret); err != nil {
		return nil, fmt.Errorf("configuring security-report CSRF protection: %w", err)
	}
	identityName := strings.TrimSpace(cfg.Server.Branding.Title)
	if identityName == "" {
		identityName = "CasSpeed"
	}
	securityEmail := strings.TrimSpace(cfg.Server.Contact.Security.Email)
	if securityEmail == "" {
		securityEmail = strings.TrimSpace(cfg.Server.Contact.Admin.Email)
	}
	keypairManager, err := NewSecurityKeypairManager(configDir, installationSecret, identityName+" Security", securityEmail, dbStore)
	if err != nil {
		return nil, fmt.Errorf("initializing security keypair: %w", err)
	}
	keypairManager.SetPublishEnabled(cfg.Web.Security.PublishPGPKey)
	securityReports.SetProjectKeypairManager(keypairManager)

	// Check if setup is complete from database
	ctx := context.Background()
	setupComplete, err := dbStore.GetSetupComplete(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking setup status: %w", err)
	}
	admin.SetSetupComplete(setupComplete)

	speedTestService := service.NewSpeedTestService(cfg.Test.MaxThreads, cfg.Test.ChunkSize, cfg.Test.DefaultDuration)
	speedTestHandler := handler.NewSpeedTestHandler(dbStore, speedTestService)
	speedTestHandler.SetURLBuilder(BuildURL)
	imageHandler := handler.NewShareImageHandler(dbStore)
	userHandler := handler.NewUserHandler(dbStore)
	userHandler.SetRegistrationEmailDomains(cfg.Server.Users.Registration.AllowedDomains, cfg.Server.Users.Registration.BlockedDomains)
	userHandler.SetDefaultRole(cfg.Server.Users.Roles.Default)
	userHandler.SetPasswordValidator(func(password string) error {
		policy := cfg.Server.Users.Auth
		return auth.ValidatePasswordPolicy(password, policy.PasswordMinLength, policy.PasswordRequireUppercase, policy.PasswordRequireNumber, policy.PasswordRequireSpecial)
	})
	adminHandler := admin.NewHandler(dbStore)
	adminHandler.ConfigureSettings(cfg, filepath.Join(configDir, "server.yml"), version, logDir)
	contactHandler, err := NewContactHandler(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating contact handler: %w", err)
	}
	contactHandler.SetCaptchaStore(dbStore)
	contactHandler.SetSecurityReportService(securityReports)
	var mailService *email.Service
	if smtpCfg := cfg.Server.Notifications.Email.SMTP; smtpCfg.Host != "" {
		from := cfg.Server.Notifications.Email.From
		mailService = email.NewService(&email.Config{
			Enabled:  true,
			Host:     smtpCfg.Host,
			Port:     smtpCfg.Port,
			Username: smtpCfg.Username,
			Password: smtpCfg.Password,
			From:     from.Email,
			FromName: from.Name,
			TLS:      smtpCfg.TLS,
		})
		contactHandler.SetDelivery(func(_ string, to, replyTo, subject, body string) error {
			return mailService.SendMessage(to, replyTo, subject, body)
		})
	}

	s := &Server{
		Config:            cfg,
		ConfigPath:        filepath.Join(configDir, "server.yml"),
		DataDir:           dataDir,
		LogDir:            logDir,
		Mode:              appMode,
		Router:            chi.NewRouter(),
		Store:             dbStore,
		Handler:           speedTestHandler,
		ImageHandler:      imageHandler,
		UserHandler:       userHandler,
		ContactHandler:    contactHandler,
		EmailService:      mailService,
		SecurityReports:   securityReports,
		SecurityKeypair:   keypairManager,
		encryptionKey:     append([]byte(nil), secrets.EncryptionKey...),
		AdminHandler:      adminHandler,
		Logger:            logger,
		ipTestCount:       make(map[string]*ipRateLimit),
		fallbackRates:     make(map[string][]time.Time),
		learnedOrigins:    make(map[string]struct{}),
		startTime:         time.Now(),
		version:           version,
		commitID:          commitID,
		buildDate:         buildDate,
		operatorTokenHash: sha256.Sum256([]byte(secrets.ServerToken)),
		metricsTokenHashes: map[string][32]byte{
			"prometheus": sha256.Sum256([]byte(secrets.MetricsTokens["prometheus"])),
			"grafana":    sha256.Sum256([]byte(secrets.MetricsTokens["grafana"])),
			"loki":       sha256.Sum256([]byte(secrets.MetricsTokens["loki"])),
		},
		metricsLogDir: logDir,
	}
	userHandler.SetRegisterPageRenderer(s.renderUserRegistrationPage)
	userHandler.SetURLBuilder(BuildURL)
	userHandler.SetLanguageValidator(s.isLanguageAvailable)
	verificationRequired := cfg.Server.Users.Registration.RequireEmailVerification && mailService.Available()
	userHandler.SetEmailVerification(verificationRequired, func(r *http.Request, recipient, token string) error {
		language, _ := requestLanguage(r)
		catalog, err := i18n.Resolve(language)
		if err != nil {
			return err
		}
		verifyURL := BuildURL(r, "/server/auth/verify/"+url.PathEscape(token))
		body := catalog.T("email.verify_body", map[string]string{"verify_url": verifyURL})
		return mailService.SendMessage(recipient, "", catalog.T("email.verify_subject", nil), body)
	})
	if err := s.initializeScheduler(cfg.Server.Scheduler.Timezone); err != nil {
		return nil, fmt.Errorf("initializing scheduler: %w", err)
	}
	cacheClient, err := cache.New(cfg.Server.Cache, configDir)
	if err != nil {
		if s.Scheduler != nil {
			s.Scheduler.Stop()
		}
		return nil, fmt.Errorf("initializing cache: %w", err)
	}
	s.Cache = cacheClient
	s.cacheHealthStatus = "ok"
	if cfg.Server.Cache.Type == "redis" || cfg.Server.Cache.Type == "valkey" {
		s.refreshCacheHealth(context.Background())
	}
	if counters, ok := s.Store.(store.RateCounterStore); ok {
		loaded, loadErr := counters.LoadRateCounters(context.Background())
		if loadErr != nil {
			if logger.Error != nil {
				logger.Error.Printf("unable to load persisted rate-limit counters: %v", loadErr)
			}
			s.markCacheDegraded()
		} else if loaded != nil {
			s.fallbackRates = pruneRateCounterSnapshot(loaded, time.Now().Add(-time.Hour))
		}
	}
	securityReports.SetSecurityLogger(func(event string, fields map[string]any) {
		fields["event"] = event
		fields["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
		if encoded, err := json.Marshal(fields); err == nil && logger.Security != nil {
			logger.Security.Printf("%s\n", encoded)
		}
	})

	s.setupMiddleware()
	s.setupRoutes()
	if err := s.startI2PManager(configDir, dataDir, logDir, cfg.Server.I2P); err != nil {
		return nil, fmt.Errorf("starting I2P manager: %w", err)
	}
	if err := s.startTorManager(configDir, dataDir, logDir, cfg.Server.Tor); err != nil {
		return nil, fmt.Errorf("starting Tor manager: %w", err)
	}

	return s, nil
}

func (s *Server) setupMiddleware() {
	s.Router.Use(s.prometheusMiddleware)
	s.Router.Use(s.apiVersionMiddleware)
	s.Router.Use(s.rateLimitMiddleware)
	s.Router.Use(s.apiTokenMiddleware)
	proxyConfig := s.Config.Server.TrustedProxies
	proxyConfig.ListenAddress = s.Config.Server.Address
	refreshTrustedProxyDNS(proxyConfig)
	s.Router.Use(trustedProxyMiddleware(proxyConfig))
	s.Router.Use(s.learnProxyOrigins)
	s.Router.Use(s.languageMiddleware)
	s.Router.Use(s.publicErrorShellMiddleware)
	s.Router.Use(s.pageIdentityMiddleware)
	s.Router.Use(s.userPermissionMiddleware)

	// URL normalization FIRST — trailing slash removal + 301 redirect (PART 16)
	s.Router.Use(srcMiddleware.URLNormalizeMiddleware)

	// Path security middleware — traversal blocking (PART 5 - NON-NEGOTIABLE)
	s.Router.Use(srcMiddleware.PathSecurityMiddleware)

	// Security headers (PART 11 - NON-NEGOTIABLE)
	s.Router.Use(securityHeaders(s))

	s.Router.Use(middleware.RequestID)
	s.Router.Use(redactOneTimeTokenInAccessLog)
	s.Router.Use(middleware.Logger)
	s.Router.Use(middleware.Recoverer)

	if s.Mode.IsDevelopment() || s.Mode.IsDebug() {
		s.Router.Use(middleware.Timeout(60 * time.Second))
	} else {
		s.Router.Use(middleware.Timeout(30 * time.Second))
	}

	s.Router.Use(s.corsMiddleware)

	// Debug middleware — no-op unless --debug/DEBUG=true (PART 6)
	s.Router.Use(s.debugMiddleware)
}

func (s *Server) prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metrics.HTTPRequestStarted()
		started := time.Now()
		wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(wrapped, r)
		metrics.HTTPRequestFinished()
		requestBytes := float64(0)
		if r.ContentLength > 0 {
			requestBytes = float64(r.ContentLength)
		}
		status := wrapped.Status()
		if status == 0 {
			status = http.StatusOK
		}
		metrics.RecordHTTP(r.Method, r.URL.Path, strconv.Itoa(status), time.Since(started).Seconds(), requestBytes, float64(wrapped.BytesWritten()))
	})
}

type apiTokenContextKey struct{}

func (s *Server) apiVersionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		configured := s.Config.APIBasePath()
		if configured == "/api/v1" || r.URL.Path == "/api/mcp" {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == configured || strings.HasPrefix(r.URL.Path, configured+"/") {
			internalRequest := r.Clone(r.Context())
			internalRequest.URL.Path = "/api/v1" + strings.TrimPrefix(r.URL.Path, configured)
			internalRequest.URL.RawPath = ""
			next.ServeHTTP(w, internalRequest)
			return
		}
		if r.URL.Path == "/api/v1" || strings.HasPrefix(r.URL.Path, "/api/v1/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type apiTokenIdentity struct {
	UserID string
	ID     string
	Scope  string
	Admin  bool
}

func (s *Server) apiTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1/server/mcp" {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/api/v1/server/metrics" || strings.HasPrefix(r.URL.Path, "/api/v1/server/metrics/") {
			next.ServeHTTP(w, r)
			return
		}
		header := r.Header.Get("Authorization")
		if header == "" {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(header, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")) == "" {
			s.writeBearerError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		tokenValue := strings.TrimPrefix(header, "Bearer ")
		_, identity, valid := s.validateBearerToken(r.Context(), tokenValue)
		if !valid {
			s.recordFailedAuthentication(r)
			s.writeBearerError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		adminPath := "/api/v1/server/" + s.Config.Server.AdminPath
		if strings.HasSuffix(adminPath, "/") || s.Config.Server.AdminPath == "" {
			adminPath = "/api/v1/server/administration"
		}
		if (r.URL.Path == adminPath || strings.HasPrefix(r.URL.Path, adminPath+"/")) && !identity.Admin {
			s.writeBearerError(w, http.StatusForbidden, "insufficient_scope")
			return
		}
		if identity.Scope == "read" && r.Method != http.MethodGet && r.Method != http.MethodHead || identity.Scope == "read-write" && r.Method == http.MethodDelete {
			s.writeBearerError(w, http.StatusForbidden, "insufficient_scope")
			return
		}
		ctx := context.WithValue(r.Context(), apiTokenContextKey{}, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) validateBearerToken(ctx context.Context, value string) (*model.APIToken, apiTokenIdentity, bool) {
	if s.validOperatorToken(value) {
		return &model.APIToken{ID: "operator", TokenPrefix: "adm_", Scope: "global"}, apiTokenIdentity{ID: "operator", Scope: "global", Admin: true}, true
	}
	if validAdminAPITokenFormat(value) {
		hash := sha256.Sum256([]byte(value))
		account, err := s.Store.GetAdminByAPITokenHash(ctx, fmt.Sprintf("%x", hash[:]))
		if err != nil || account == nil || !account.Enabled {
			return nil, apiTokenIdentity{}, false
		}
		id := fmt.Sprintf("admin-%d", account.ID)
		return &model.APIToken{ID: id, TokenPrefix: "adm_", Scope: "global"}, apiTokenIdentity{ID: id, Scope: "global", Admin: true}, true
	}
	if len(value) != 36 || !strings.HasPrefix(value, "usr_") {
		return nil, apiTokenIdentity{}, false
	}
	for _, character := range value[4:] {
		if !strings.ContainsRune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", character) {
			return nil, apiTokenIdentity{}, false
		}
	}
	token, err := s.Store.GetAPITokenByToken(ctx, value)
	if err != nil || token == nil || token.ExpiresAt != nil && !token.ExpiresAt.After(time.Now()) || token.Scope != "" && token.Scope != "global" && token.Scope != "read-write" && token.Scope != "read" {
		return nil, apiTokenIdentity{}, false
	}
	user, err := s.Store.GetUser(ctx, token.UserID)
	if err != nil || user == nil || !user.Approved || user.Disabled || !user.EmailVerified {
		return nil, apiTokenIdentity{}, false
	}
	scope := token.Scope
	if scope == "" {
		scope = "global"
	}
	return token, apiTokenIdentity{UserID: token.UserID, ID: token.ID, Scope: scope}, true
}

func validAdminAPITokenFormat(token string) bool {
	if len(token) != 36 || !strings.HasPrefix(token, "adm_") {
		return false
	}
	for _, character := range token[len("adm_"):] {
		if !strings.ContainsRune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", character) {
			return false
		}
	}
	return true
}

func (s *Server) validOperatorToken(token string) bool {
	if len(token) != 36 || !strings.HasPrefix(token, "adm_") {
		return false
	}
	got := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(got[:], s.operatorTokenHash[:]) == 1
}

func (s *Server) writeBearerError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="casspeed", error="`+code+`"`)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	message := "The bearer token is invalid or missing"
	if code == "insufficient_scope" {
		message = "The bearer token does not have permission for this operation"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": code, "message": message, "details": map[string]any{}})
}

func (s *Server) requireOperatorAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			s.writeBearerError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		_, identity, valid := s.validateBearerToken(r.Context(), strings.TrimPrefix(header, "Bearer "))
		if !valid || !identity.Admin {
			s.writeBearerError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (s *Server) requireOperatorDebug(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") || !s.validOperatorToken(strings.TrimPrefix(header, "Bearer ")) {
			s.writeBearerError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware applies the configured origin policy consistently to every route.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		allowed, wildcard := s.corsOriginAllowed(origin)
		if allowed {
			w.Header().Add("Vary", "Origin")
			if wildcard {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With, Authorization, X-CSRF-Token, X-XSRF-Token, MCP-Protocol-Version, Mcp-Method, Mcp-Name")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			if !allowed {
				http.Error(w, "CORS origin is not allowed", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// corsOriginAllowed resolves explicit web origins, DOMAIN entries, and the default wildcard.
func (s *Server) corsOriginAllowed(origin string) (bool, bool) {
	configured := strings.TrimSpace(s.Config.Web.CORS)
	if configured == "" {
		return false, false
	}
	if configured != "*" {
		for _, value := range strings.Split(configured, ",") {
			if strings.EqualFold(strings.TrimSpace(value), origin) {
				return true, false
			}
		}
	}
	domains := requestDomains()
	hasDomain := len(domains) > 0
	parsedOrigin, parseErr := url.Parse(origin)
	if parseErr != nil || parsedOrigin.User != nil || parsedOrigin.Host == "" || parsedOrigin.Path != "" || parsedOrigin.RawQuery != "" || parsedOrigin.Fragment != "" || parsedOrigin.Scheme != "http" && parsedOrigin.Scheme != "https" {
		return false, false
	}
	if parsedOrigin.Port() != "" && parsedOrigin.Port() != "443" {
		return false, false
	}
	if strings.EqualFold(parsedOrigin.Scheme, "https") && domainAllowed(strings.ToLower(parsedOrigin.Hostname()), domains) {
		return true, false
	}
	learned := s.learnedOriginList()
	for _, learnedOrigin := range learned {
		if strings.EqualFold(learnedOrigin, origin) {
			return true, false
		}
	}
	if configured == "*" && !hasDomain && len(learned) == 0 {
		return true, true
	}
	return false, false
}

func (s *Server) corsOriginSources() []string {
	configured := strings.TrimSpace(s.Config.Web.CORS)
	if configured == "" {
		return nil
	}
	domains := requestDomains()
	learned := s.learnedOriginList()
	sources := make([]string, 0, len(domains)+len(learned)+4)
	seen := make(map[string]struct{})
	add := func(value string) {
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			sources = append(sources, value)
		}
	}
	if configured == "*" && len(domains) == 0 && len(learned) == 0 {
		add("*")
	} else if configured != "" && configured != "*" {
		for _, value := range strings.Split(configured, ",") {
			value = strings.TrimSpace(value)
			if validCORSOrigin(value) {
				add(value)
			}
		}
	}
	for _, domain := range domains {
		add("https://" + domain)
	}
	for _, origin := range learned {
		add(origin)
	}
	return sources
}

func validCORSOrigin(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.User == nil && parsed.Host != "" && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && (parsed.Scheme == "http" || parsed.Scheme == "https")
}

func (s *Server) setupRoutes() {
	// Determine admin path (configurable, default "administration")
	adminPath := s.Config.Server.AdminPath
	if adminPath == "" {
		adminPath = "administration"
	}
	authHandler := handler.NewAuthHandler(s.Store)
	authHandler.SetURLBuilder(BuildURL)
	authHandler.SetPasswordValidator(s.validateUserPassword)
	if s.EmailService != nil {
		authHandler.SetPasswordResetSender(func(recipient, resetURL string) error {
			body := fmt.Sprintf("Use this one-time link to reset your CasSpeed password:\n\n%s\n\nThe link expires in one hour.", resetURL)
			return s.EmailService.SendMessage(recipient, "", "CasSpeed password reset", body)
		})
	}

	// Static files — served from embedded FS
	staticRoot, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	staticHandler := http.FileServer(http.FS(staticRoot))
	s.Router.Handle("/static/*", http.StripPrefix("/static", staticHandler))
	s.Router.Get("/locales/{lang}.json", s.serveLocale)

	// Root / public routes
	s.Router.Get("/", s.handleIndex)
	s.Router.Get("/speed-tests/{id}", s.handleSpeedTestPage)
	s.Router.Post("/speed-tests/{id}", s.createSpeedTestSharePage)
	s.Router.Get("/server", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/server/about", http.StatusMovedPermanently)
	})
	for _, page := range publicPageRegistry {
		if !page.Always {
			continue
		}
		if page.Path == "/server/preferences/sync" {
			s.Router.Get(page.Path, s.handlePreferenceSync)
			s.Router.Post(page.Path, s.handlePreferenceSync)
			s.Router.Get("/api/v1"+page.Path, s.handlePreferenceSyncAPI)
			continue
		}
		s.Router.Get(page.Path, s.handlePublicPage)
		s.Router.Get("/api/v1"+page.Path, s.handlePublicPageAPI)
	}
	s.Router.Get("/server/preferences", s.handlePreferences)
	s.Router.Post("/server/preferences", s.handlePreferences)
	s.Router.Post("/server/consent", s.handleConsent)
	s.Router.Get("/server/tracking.js", s.trackingScriptHandler)
	s.Router.Post("/server/ccpa", s.handleCCPA)
	s.Router.Get("/api/v1/server/preferences", s.handlePreferencesAPI)
	s.Router.Post("/api/v1/server/preferences", s.handlePreferencesAPI)
	s.Router.Get("/server/preferences/sync/import", s.handlePreferenceSyncImport)
	s.Router.Get("/api/v1/server/preferences/sync/import", s.handlePreferenceSyncAPI)
	s.Router.Method(http.MethodGet, "/server/auth/register", s.onlyOpenRegistration(s.pageShellHandler(http.HandlerFunc(s.UserHandler.RegisterPage))))
	s.Router.Method(http.MethodPost, "/server/auth/register", s.onlyOpenRegistration(s.pageShellHandler(http.HandlerFunc(s.UserHandler.RegisterPage))))
	s.Router.Get("/server/auth/verify/{token}", s.handleEmailVerificationPage)
	s.Router.Post("/server/auth/verify", s.UserHandler.VerifyEmail)
	s.Router.Method(http.MethodGet, "/server/auth/password/reset", s.pageShellHandler(http.HandlerFunc(authHandler.PasswordResetPage)))
	s.Router.Method(http.MethodPost, "/server/auth/password/reset", s.pageShellHandler(http.HandlerFunc(authHandler.PasswordResetComplete)))
	s.Router.Method(http.MethodGet, "/server/auth/password/forgot", s.pageShellHandler(http.HandlerFunc(authHandler.PasswordForgotPage)))
	s.Router.Method(http.MethodPost, "/server/auth/password/forgot", s.pageShellHandler(http.HandlerFunc(authHandler.PasswordResetRequest)))
	s.Router.HandleFunc("/server/contact", s.ContactHandler.ServeHTTP)
	s.Router.HandleFunc("/api/v1/server/contact", s.ContactHandler.API)
	s.Router.Get("/server/docs/swagger", s.handleSwaggerPage)
	s.Router.Get("/server/docs/graphql", s.handleGraphQLPage)
	s.Router.Get("/api/autodiscover", s.handleAPIAutodiscover)
	s.Router.Get("/cli/binaries/{filename}", s.handleCLIBinaryDownload)
	s.Router.Get("/api/v1/server/swagger", s.handleSwaggerSpec)
	s.Router.Get("/api/swagger", s.handleSwaggerSpec)
	graphqlHandler := graphql.NewQueryHandler(graphql.Dependencies{
		Store: s.Store,
		Health: func(context.Context) (graphql.HealthSnapshot, error) {
			response := s.buildHealthResponse()
			return graphql.HealthSnapshot{
				Project: graphql.HealthProjectSnapshot{
					Name: response.Project.Name, Tagline: response.Project.Tagline, Description: response.Project.Description,
				},
				Status: response.Status, Version: response.Version, GoVersion: response.GoVersion,
				Build:  graphql.HealthBuildSnapshot{Commit: response.Build.Commit, Date: response.Build.Date},
				Uptime: response.Uptime, Mode: response.Mode, Timestamp: response.Timestamp.UTC().Format(time.RFC3339Nano),
				Cluster: graphql.HealthClusterSnapshot{Enabled: response.Cluster.Enabled, Status: response.Cluster.Status},
				Features: graphql.HealthFeaturesSnapshot{
					Geoip: response.Features.GeoIP,
					Tor: graphql.HealthTorSnapshot{
						Enabled: response.Features.Tor.Enabled, Running: response.Features.Tor.Running,
						Status: response.Features.Tor.Status, Hostname: response.Features.Tor.Hostname,
					},
					I2P: graphql.HealthI2PSnapshot{
						Enabled: response.Features.I2P.Enabled, Running: response.Features.I2P.Running,
						State: response.Features.I2P.State, Status: response.Features.I2P.Status,
						Hostname: response.Features.I2P.Hostname, Provider: response.Features.I2P.Provider,
					},
				},
				Checks: graphql.HealthChecksSnapshot{
					Database: response.Checks.Database, Cache: response.Checks.Cache,
					Disk: response.Checks.Disk, Scheduler: response.Checks.Scheduler, I2P: response.Checks.I2P,
				},
				Stats: graphql.HealthStatsSnapshot{
					RequestsTotal: int32(response.Stats.RequestsTotal), Requests24h: int32(response.Stats.Requests24h),
					ActiveConnections: int32(response.Stats.ActiveConns),
				},
			}, nil
		},
	})
	s.Router.Handle("/api/v1/server/graphql", graphqlHandler)
	s.Router.Handle("/api/graphql", graphqlHandler)
	s.Router.Get("/api/healthz", s.handleHealth)

	// Well-known files (PART 11 - NON-NEGOTIABLE)
	s.Router.Get("/robots.txt", s.handleRobotsTxt)
	s.Router.Get("/sitemap.xml", s.handleSitemap)
	s.Router.Get("/feed.xml", s.handleAtomFeed)
	s.Router.Get("/rss.xml", s.handleRSSFeed)
	s.Router.Get("/.well-known/security.txt", s.handleSecurityTxt)
	s.Router.Get("/.well-known/pgp-key.asc", s.SecurityReports.PGPKeyHandler)
	s.Router.Get("/.well-known/change-password", s.handleChangePassword)

	// Health checks keep the canonical public route and mount the root alias only when configured.
	s.Router.Get("/server/healthz", s.handleHealth)
	s.Router.Get("/server/healthz.json", s.handleHealth)
	s.Router.Get("/server/healthz.txt", s.handleHealth)
	s.Router.Get("/server/security/report/{tracking_id}", s.SecurityReports.StatusPageHandler)
	if s.Config.Server.Healthz.Root.Enabled {
		s.Router.Get("/healthz", s.handleHealth)
		s.Router.Get("/healthz.json", s.handleHealth)
		s.Router.Get("/healthz.txt", s.handleHealth)
	}

	if s.Config.Server.Metrics.Enabled {
		s.Router.Get("/server/metrics", s.handleMetrics)
		s.Router.Get("/server/metrics/{service}", s.handleMetrics)
		s.Router.Get("/api/metrics", s.handleMetrics)
		s.Router.Get("/api/metrics/{service}", s.handleMetrics)
		if s.Config.Server.Metrics.Root.Enabled {
			s.Router.Get("/metrics", s.handleMetrics)
			s.Router.Get("/metrics/{service}", s.handleMetrics)
		}
	}

	// API v1 routes
	s.Router.HandleFunc("/api/v1/server/mcp", s.handleMCP)
	s.Router.HandleFunc("/api/mcp", s.handleMCP)
	s.Router.HandleFunc("/mcp", s.handleMCP)
	s.Router.Route("/api/v1", func(r chi.Router) {
		r.Get("/", s.handleAPIRoot)
		if s.Config.Server.Metrics.Enabled {
			r.Get("/server/metrics", s.handleMetrics)
			r.Get("/server/metrics/{service}", s.handleMetrics)
		}

		// Health check API route (PART 13)
		r.Get("/server/healthz", s.handleHealth)
		r.Get("/server/healthz.json", s.handleHealth)
		r.Get("/server/healthz.txt", s.handleHealth)

		// Auth endpoints — /api/v1/server/auth/* (PART 14)
		r.Post("/server/auth/register", s.onlyOpenRegistration(http.HandlerFunc(s.UserHandler.Register)).ServeHTTP)
		r.Post("/server/auth/login", authHandler.Login)
		r.Post("/server/auth/logout", authHandler.Logout)
		r.Post("/server/auth/password/forgot", authHandler.PasswordResetRequest)
		r.Post("/server/auth/password/reset", authHandler.PasswordResetComplete)
		r.Post("/server/auth/verify", s.UserHandler.VerifyEmail)
		r.Post("/server/auth/2fa", s.handleMFAChallenge)
		r.Post("/server/auth/recovery/use", s.handleMFARecovery)
		r.Post("/server/auth/passkey/challenge", s.handlePasskeyLoginChallenge)
		r.Post("/server/auth/passkey/verify", s.handlePasskeyLoginVerify)
		r.Get("/server/auth/invite/user/{token}", s.handleUserInviteAPI)
		r.Post("/server/auth/invite/user/{token}", s.handleUserInviteAPI)
		r.Get("/server/"+adminPath+"/{username}/profile/security/passkeys", s.handleAdminPasskeyAPI)
		r.Post("/server/"+adminPath+"/{username}/profile/security/passkey/setup", s.handleAdminPasskeyAPI)
		r.Post("/server/"+adminPath+"/{username}/profile/security/passkey/register", s.handleAdminPasskeyAPI)
		r.Delete("/server/"+adminPath+"/{username}/profile/security/passkeys/{passkey_id}", s.handleAdminPasskeyAPI)
		r.Get("/server/"+adminPath+"/{username}/profile/security", s.handleAdminTOTP)
		r.Post("/server/"+adminPath+"/{username}/profile/security/totp/setup", s.handleAdminTOTP)
		r.Post("/server/"+adminPath+"/{username}/profile/security/totp/enable", s.handleAdminTOTP)
		r.Post("/server/"+adminPath+"/{username}/profile/security/totp/disable", s.handleAdminTOTP)
		r.Post("/server/"+adminPath+"/{username}/profile/security/recovery/regenerate", s.handleAdminTOTP)
		r.Get("/users/{username}", s.handlePublicUserProfileAPI)

		// Speed test endpoints (public, project-specific)
		r.Post("/speed-tests", s.Handler.StartTest)
		r.Get("/speed-tests/{id}/status", s.Handler.TestStatus)
		r.Get("/speed-tests/{id}/download", s.Handler.Download)
		r.Post("/speed-tests/{id}/uploads", s.Handler.Upload)
		r.Get("/speed-tests/{id}", s.Handler.GetResult)
		r.Post("/speed-tests/{id}/shares", s.Handler.CreateShare)
		r.Get("/speed-tests", s.Handler.GetHistory)
		r.Get("/shares/{code}", s.Handler.GetShareAPI)
		r.Get("/shares/{code}/images/png", s.ImageHandler.GetSharePNG)
		r.Get("/shares/{code}/images/svg", s.ImageHandler.GetShareSVG)

		// User self-management (no ID — session identifies user) (PART 14)
		r.Get("/users", s.UserHandler.GetProfile)
		r.Patch("/users", s.UserHandler.UpdateProfile)
		r.Post("/users/data/export", s.handleUserDataExport)
		r.Get("/users/data/export/{id}", s.handleUserDataExport)
		r.Post("/users/data/delete", s.handleUserDataDelete)
		r.Patch("/users/email", s.UserHandler.UpdateEmail)
		r.Get("/users/settings", s.UserHandler.GetSettings)
		r.Get("/users/security", s.UserHandler.GetSecurity)
		r.Get("/users/security/2fa", s.handleUserTOTP)
		r.Post("/users/security/2fa/enable", s.handleUserTOTP)
		r.Post("/users/security/2fa/disable", s.handleUserTOTP)
		r.Get("/users/security/recovery", s.handleUserTOTP)
		r.Post("/users/security/recovery/regenerate", s.handleUserTOTP)
		r.Get("/users/security/passkeys", s.handleUserPasskeyAPI)
		r.Post("/users/security/passkeys", s.handleUserPasskeyAPI)
		r.Delete("/users/security/passkeys/{passkey_id}", s.handleUserPasskeyAPI)
		r.Get("/users/devices", s.UserHandler.ListDevices)
		r.Post("/users/devices", s.UserHandler.CreateDevice)
		r.Delete("/users/devices/{deviceId}", s.UserHandler.DeleteDevice)
		r.Get("/users/tokens", s.UserHandler.ListTokens)
		r.Post("/users/tokens", s.UserHandler.CreateToken)
		r.Delete("/users/tokens/{tokenId}", s.UserHandler.RevokeToken)

		// Admin API endpoints — /api/v1/server/{adminPath}/* (PART 17)
		r.Get("/server/"+adminPath+"/settings", s.requireOperatorAPI(s.AdminHandler.GetSettings))
		r.Put("/server/"+adminPath+"/settings", s.requireOperatorAPI(s.AdminHandler.UpdateSettings))
		r.Get("/server/"+adminPath+"/privacy", s.requireOperatorAPI(s.handlePrivacyAdminAPI))
		r.Patch("/server/"+adminPath+"/privacy", s.requireOperatorAPI(s.handlePrivacyAdminAPI))
		r.Get("/server/"+adminPath+"/pages/privacy", s.requireOperatorAPI(s.handlePrivacyAdminAPI))
		r.Patch("/server/"+adminPath+"/pages/privacy", s.requireOperatorAPI(s.handlePrivacyAdminAPI))
		r.Get("/server/"+adminPath+"/pages", s.requireOperatorAPI(s.handleAdminPagesAPI))
		r.Get("/server/"+adminPath+"/pages/{section}", s.requireOperatorAPI(s.handleAdminPagesAPI))
		r.Patch("/server/"+adminPath+"/pages/{section}", s.requireOperatorAPI(s.handleAdminPagesAPI))
		r.Get("/server/"+adminPath+"/moderation/users", s.requireOperatorAPI(s.handleAdminUsersAPI))
		r.Get("/server/"+adminPath+"/moderation/users/{id}", s.requireOperatorAPI(s.handleAdminUsersAPI))
		r.Delete("/server/"+adminPath+"/moderation/users/{id}", s.requireOperatorAPI(s.handleAdminUsersAPI))
		r.Post("/server/"+adminPath+"/moderation/users/disable", s.requireOperatorAPI(s.handleAdminUsersAPI))
		r.Post("/server/"+adminPath+"/moderation/users/enable", s.requireOperatorAPI(s.handleAdminUsersAPI))
		r.Post("/server/"+adminPath+"/users", s.requireOperatorAPI(s.handleAdminUsersAPI))
		r.Get("/server/"+adminPath+"/roles", s.requireOperatorAPI(s.handleRolesAPI))
		r.Post("/server/"+adminPath+"/roles", s.requireOperatorAPI(s.handleRolesAPI))
		r.Get("/server/"+adminPath+"/roles/{id}", s.requireOperatorAPI(s.handleRolesAPI))
		r.Patch("/server/"+adminPath+"/roles/{id}", s.requireOperatorAPI(s.handleRolesAPI))
		r.Delete("/server/"+adminPath+"/roles/{id}", s.requireOperatorAPI(s.handleRolesAPI))
		r.Get("/server/"+adminPath+"/users/invites", s.requireOperatorAPI(s.handleUserInvitesAPI))
		r.Post("/server/"+adminPath+"/users/invites", s.requireOperatorAPI(s.handleUserInvitesAPI))
		r.Get("/server/"+adminPath+"/users/invites/{id}", s.requireOperatorAPI(s.handleUserInvitesAPI))
		r.Delete("/server/"+adminPath+"/users/invites/{id}", s.requireOperatorAPI(s.handleUserInvitesAPI))
		r.Get("/server/"+adminPath+"/network/tor", s.requireOperatorAPI(s.handleTorAdminAPI))
		r.Patch("/server/"+adminPath+"/network/tor", s.requireOperatorAPI(s.handleTorAdminAPI))
		r.Post("/server/"+adminPath+"/network/tor/validate", s.requireOperatorAPI(s.handleTorAdminValidate))
		r.Post("/server/"+adminPath+"/network/tor/regenerate", s.requireOperatorAPI(s.handleTorAdminAction))
		r.Get("/server/"+adminPath+"/network/tor/vanity", s.requireOperatorAPI(s.handleTorVanityAPI))
		r.Post("/server/"+adminPath+"/network/tor/vanity", s.requireOperatorAPI(s.handleTorVanityAPI))
		r.Delete("/server/"+adminPath+"/network/tor/vanity", s.requireOperatorAPI(s.handleTorVanityAPI))
		r.Post("/server/"+adminPath+"/network/tor/vanity/apply", s.requireOperatorAPI(s.handleTorVanityApply))
		r.Post("/server/"+adminPath+"/network/tor/import", s.requireOperatorAPI(s.handleTorVanityImport))
		r.Get("/server/"+adminPath+"/network/i2p", s.requireOperatorAPI(s.handleI2PAdminAPI))
		r.Patch("/server/"+adminPath+"/network/i2p", s.requireOperatorAPI(s.handleI2PAdminAPI))
		r.Post("/server/"+adminPath+"/network/i2p/validate", s.requireOperatorAPI(s.handleI2PAdminValidate))
		r.Post("/server/"+adminPath+"/network/i2p/regenerate", s.requireOperatorAPI(s.handleI2PAdminAction))
		r.Post("/server/"+adminPath+"/network/i2p/restart", s.requireOperatorAPI(s.handleI2PAdminAction))
	})
	s.Router.Get("/api/autodiscover", s.handleAPIAutodiscover)

	// ==========================================================================
	// Admin Panel Web UI — /server/{adminPath}/* (PART 17)
	// ==========================================================================

	// Setup wizard — accessible without auth before setup is complete
	s.Router.Post("/server/"+adminPath+"/setup/token", s.AdminHandler.SetupTokenHandler)
	s.Router.Get("/server/"+adminPath+"/setup", s.AdminHandler.SetupWizardHandler)
	s.Router.Post("/server/"+adminPath+"/setup/complete", s.AdminHandler.SetupCompleteHandler)

	// Shared admin and user login, with one CSRF-protected logout route.
	s.Router.Get("/server/auth/login", s.handleSharedLogin)
	s.Router.Post("/server/auth/login", s.handleSharedLogin)
	s.Router.Get("/server/auth/passkey", s.handlePasskeyLoginPage)
	s.Router.Get("/server/auth/invite/user/{token}", s.handleUserInviteAcceptance)
	s.Router.Post("/server/auth/invite/user/{token}", s.handleUserInviteAcceptance)
	s.Router.Get("/server/auth/verify/resend", s.handleVerificationResend)
	s.Router.Post("/server/auth/verify/resend", s.handleVerificationResend)
	s.Router.Get("/server/auth/2fa", s.handleMFAChallenge)
	s.Router.Post("/server/auth/2fa", s.handleMFAChallenge)
	s.Router.Get("/server/auth/recovery/use", s.handleMFARecovery)
	s.Router.Post("/server/auth/recovery/use", s.handleMFARecovery)
	s.Router.Post("/server/auth/logout", s.handleSharedLogout)
	s.Router.Get("/users/notifications", s.handleUserNotifications)
	s.Router.Get("/users/data/export", s.handleUserDataExport)
	s.Router.Get("/users/data/export/{id}", s.handleUserDataExport)
	s.Router.Post("/users/data/delete", s.handleUserDataDelete)
	s.Router.Get("/history", s.handleUserHistoryPage)
	s.Router.Get("/devices", s.handleUserDevicesPage)
	s.Router.Post("/devices", s.handleUserDevicesPage)
	s.Router.Post("/devices/{deviceID}/delete", s.handleUserDevicesPage)
	s.Router.Get("/users/{username}", s.handlePublicUserProfilePage)
	s.Router.Get("/users", s.handleUserProfilePage)
	s.Router.Post("/users", s.handleUserProfilePage)
	s.Router.Get("/users/tokens", s.handleUserTokensPage)
	s.Router.Post("/users/tokens/create", s.handleUserTokensPage)
	s.Router.Post("/users/tokens/{tokenID}/revoke", s.handleRevokeUserTokenPage)
	s.Router.Get("/users/settings", s.handleUserSettingsPage)
	s.Router.Post("/users/settings", s.handleUserSettingsPage)
	s.Router.Get("/users/settings/email", s.handleUserEmailSettings)
	s.Router.Post("/users/settings/email", s.handleUserEmailSettings)
	for _, path := range []string{"/users/settings/privacy", "/users/settings/notifications", "/users/settings/appearance"} {
		s.Router.Get(path, s.handleUserSettingsPage)
		s.Router.Post(path, s.handleUserSettingsPage)
	}
	s.Router.Get("/users/security", s.handleUserSecurityPage)
	s.Router.Get("/users/security/password", s.handleUserSecurityPage)
	s.Router.Post("/users/security/password", s.handleUserSecurityPage)
	s.Router.Get("/users/security/2fa", s.handleUserTOTPPage)
	s.Router.Post("/users/security/2fa", s.handleUserTOTPPage)
	s.Router.Get("/users/security/passkeys", s.handleUserPasskeys)
	s.Router.Post("/users/security/passkeys/{passkeyID}/revoke", s.handleUserPasskeys)
	s.Router.Get("/users/security/sessions", s.handleUserSecurityPage)
	s.Router.Post("/users/security/sessions/{sessionID}/revoke", s.handleUserSecurityPage)
	s.Router.Post("/users/notifications/read", s.handleMarkAllUserNotificationsRead)
	s.Router.Post("/users/notifications/clear", s.handleClearUserNotifications)
	s.Router.Post("/users/notifications/{notificationID}/read", s.handleMarkUserNotificationRead)

	// Admin dashboard root (PART 17: dashboard ONLY at root)
	s.Router.Get("/server/"+adminPath, s.AdminHandler.RequireAuth(s.AdminHandler.Dashboard))
	s.Router.Get("/server/"+adminPath+"/", s.AdminHandler.RequireAuth(s.AdminHandler.Dashboard))

	// Admin's own account — /server/{adminPath}/{username}/* (PART 17)
	s.Router.Get("/server/"+adminPath+"/{username}/profile", s.AdminHandler.RequireAuth(s.AdminHandler.Profile))
	s.Router.Get("/server/"+adminPath+"/{username}/preferences", s.AdminHandler.RequireAuth(s.AdminHandler.Preferences))
	s.Router.Get("/server/"+adminPath+"/{username}/notifications", s.AdminHandler.RequireAuth(s.AdminHandler.Notifications))
	s.Router.Get("/server/"+adminPath+"/{username}/profile/security", s.AdminHandler.RequireAuth(s.handleAdminSecurityPage))
	s.Router.Get("/server/"+adminPath+"/{username}/profile/security/totp/setup", s.AdminHandler.RequireAuth(s.handleAdminSecurityPage))
	s.Router.Post("/server/"+adminPath+"/{username}/profile/security/totp/setup", s.AdminHandler.RequireAuth(s.handleAdminSecurityPage))
	s.Router.Post("/server/"+adminPath+"/{username}/profile/security/totp/enable", s.AdminHandler.RequireAuth(s.handleAdminSecurityPage))
	s.Router.Post("/server/"+adminPath+"/{username}/profile/security/totp/disable", s.AdminHandler.RequireAuth(s.handleAdminSecurityPage))
	s.Router.Post("/server/"+adminPath+"/{username}/profile/security/recovery/regenerate", s.AdminHandler.RequireAuth(s.handleAdminSecurityPage))
	s.Router.Get("/server/"+adminPath+"/{username}/profile/security/passkeys", s.AdminHandler.RequireAuth(s.handleAdminPasskeys))
	s.Router.Post("/server/"+adminPath+"/{username}/profile/security/passkeys/{passkeyID}/revoke", s.AdminHandler.RequireAuth(s.handleAdminPasskeys))
	s.Router.Post("/server/"+adminPath+"/{username}/profile/security/passkey/setup", s.AdminHandler.RequireAuth(s.handleAdminPasskeyAPI))
	s.Router.Post("/server/"+adminPath+"/{username}/profile/security/passkey/register", s.AdminHandler.RequireAuth(s.handleAdminPasskeyAPI))

	// Server management uses only declared section paths directly below adminPath.
	s.Router.Get("/server/"+adminPath+"/settings", s.AdminHandler.RequireAuth(s.AdminHandler.ServerSettings))
	s.Router.Post("/server/"+adminPath+"/settings", s.AdminHandler.RequireAuth(s.AdminHandler.ServerSettings))
	s.Router.Get("/server/"+adminPath+"/info", s.AdminHandler.RequireAuth(s.AdminHandler.ServerInfo))
	s.Router.Get("/server/"+adminPath+"/logs", s.AdminHandler.RequireAuth(s.AdminHandler.ServerLogs))
	s.Router.Get("/server/"+adminPath+"/logs/audit", s.AdminHandler.RequireAuth(s.AdminHandler.ServerAuditLogs))
	s.Router.Get("/server/"+adminPath+"/backup", s.AdminHandler.RequireAuth(s.AdminHandler.ServerBackup))
	s.Router.Get("/server/"+adminPath+"/updates", s.AdminHandler.RequireAuth(s.AdminHandler.ServerUpdates))
	s.Router.Get("/server/"+adminPath+"/ssl", s.AdminHandler.RequireAuth(s.AdminHandler.ServerSSL))
	s.Router.Get("/server/"+adminPath+"/email", s.AdminHandler.RequireAuth(s.AdminHandler.ServerEmail))
	s.Router.Get("/server/"+adminPath+"/scheduler", s.AdminHandler.RequireAuth(s.AdminHandler.ServerScheduler))
	s.Router.Get("/server/"+adminPath+"/metrics", s.AdminHandler.RequireAuth(s.AdminHandler.ServerMetrics))
	s.Router.Get("/server/"+adminPath+"/tracking", s.AdminHandler.RequireAuth(s.handleTrackingAdminPage))
	s.Router.Post("/server/"+adminPath+"/tracking", s.AdminHandler.RequireAuth(s.handleTrackingAdminPage))
	s.Router.Get("/api/v1/server/"+adminPath+"/tracking", s.AdminHandler.RequireAuth(s.handleTrackingAdminAPI))
	s.Router.Patch("/api/v1/server/"+adminPath+"/tracking", s.AdminHandler.RequireAuth(s.handleTrackingAdminAPI))

	// Network config
	s.Router.Get("/server/"+adminPath+"/network/tor", s.AdminHandler.RequireAuth(s.handleTorAdminPage))
	s.Router.Post("/server/"+adminPath+"/network/tor", s.AdminHandler.RequireAuth(s.handleTorAdminPage))
	s.Router.Post("/server/"+adminPath+"/network/tor/vanity", s.AdminHandler.RequireAuth(s.handleTorVanityPageAction))
	s.Router.Post("/server/"+adminPath+"/network/tor/import", s.AdminHandler.RequireAuth(s.handleTorVanityImport))
	s.Router.Get("/server/"+adminPath+"/network/i2p", s.AdminHandler.RequireAuth(s.handleI2PAdminPage))
	s.Router.Post("/server/"+adminPath+"/network/i2p", s.AdminHandler.RequireAuth(s.handleI2PAdminPage))
	s.Router.Get("/server/"+adminPath+"/network/geoip", s.AdminHandler.RequireAuth(s.AdminHandler.NetworkGeoIP))

	// Security config
	s.Router.Get("/server/"+adminPath+"/security/auth", s.AdminHandler.RequireAuth(s.AdminHandler.SecurityAuth))
	s.Router.Get("/server/"+adminPath+"/security/tokens", s.AdminHandler.RequireAuth(s.AdminHandler.SecurityTokens))
	s.Router.Get("/server/"+adminPath+"/security/reports", s.AdminHandler.RequireAuth(s.SecurityReports.AdminReportsHandler))
	s.Router.Get("/server/"+adminPath+"/security/reports/{tracking_id}", s.AdminHandler.RequireAuth(s.SecurityReports.AdminReportHandler))
	s.Router.Post("/server/"+adminPath+"/security/reports/{tracking_id}", s.AdminHandler.RequireAuth(s.SecurityReports.AdminReportHandler))
	s.Router.Get("/server/"+adminPath+"/security/keypair", s.AdminHandler.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		s.SecurityReports.AdminKeypairHandler(w, r, s.SecurityKeypair)
	}))
	s.Router.Post("/server/"+adminPath+"/security/keypair", s.AdminHandler.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		s.SecurityReports.AdminKeypairHandler(w, r, s.SecurityKeypair)
	}))

	// User management (multi-user)
	s.Router.Get("/server/"+adminPath+"/privacy", s.AdminHandler.RequireAuth(s.handlePrivacyAdminPage))
	s.Router.Post("/server/"+adminPath+"/privacy", s.AdminHandler.RequireAuth(s.handlePrivacyAdminPage))
	s.Router.Get("/server/"+adminPath+"/pages/privacy", s.AdminHandler.RequireAuth(s.handlePrivacyAdminPage))
	s.Router.Post("/server/"+adminPath+"/pages/privacy", s.AdminHandler.RequireAuth(s.handlePrivacyAdminPage))
	s.Router.Get("/server/"+adminPath+"/pages", s.AdminHandler.RequireAuth(s.handlePagesAdminPage))
	s.Router.Post("/server/"+adminPath+"/pages", s.AdminHandler.RequireAuth(s.handlePagesAdminPage))
	s.Router.Get("/server/"+adminPath+"/roles", s.AdminHandler.RequireAuth(s.handleRolesPage))
	s.Router.Post("/server/"+adminPath+"/roles", s.AdminHandler.RequireAuth(s.handleRolesPage))
	s.Router.Post("/server/"+adminPath+"/roles/{id}", s.AdminHandler.RequireAuth(s.handleRolesPage))
	s.Router.Post("/server/"+adminPath+"/roles/{id}/delete", s.AdminHandler.RequireAuth(s.handleDeleteRolePage))
	s.Router.Get("/server/"+adminPath+"/users", s.AdminHandler.RequireAuth(s.handleAdminUsersPage))
	s.Router.Post("/server/"+adminPath+"/users", s.AdminHandler.RequireAuth(s.handleAdminUsersPage))
	s.Router.Get("/server/"+adminPath+"/users/invites", s.AdminHandler.RequireAuth(s.handleUserInvitesPage))
	s.Router.Post("/server/"+adminPath+"/users/invites", s.AdminHandler.RequireAuth(s.handleUserInvitesPage))
	s.Router.Post("/server/"+adminPath+"/users/invites/{id}/revoke", s.AdminHandler.RequireAuth(s.handleRevokeUserInvite))
	s.Router.Get("/server/"+adminPath+"/users/{id}", s.AdminHandler.RequireAuth(s.handleAdminUsersPage))
	s.Router.Post("/server/"+adminPath+"/users/{id}/{action}", s.AdminHandler.RequireAuth(s.handleAdminUserAction))
	s.Router.Post("/server/"+adminPath+"/users/{id}/{action}/revoke", s.AdminHandler.RequireAuth(s.handleAdminUserAction))
	s.Router.Get("/server/"+adminPath+"/moderation/users", s.AdminHandler.RequireAuth(s.handleAdminUsersPage))
	s.Router.Get("/server/"+adminPath+"/moderation/users/{id}", s.AdminHandler.RequireAuth(s.handleAdminUsersPage))
	s.Router.Post("/server/"+adminPath+"/moderation/users/{id}/{action}", s.AdminHandler.RequireAuth(s.handleAdminUserAction))
	s.Router.Post("/server/"+adminPath+"/moderation/users/{id}/{action}/revoke", s.AdminHandler.RequireAuth(s.handleAdminUserAction))

	// ==========================================================================
	// Share endpoints (public)
	// ==========================================================================
	s.Router.Get("/shares/{code}", s.Handler.GetShare)
	s.Router.Get("/shares/{code}/images/png", s.ImageHandler.GetSharePNG)
	s.Router.Get("/shares/{code}/images/svg", s.ImageHandler.GetShareSVG)

	// Debug endpoints (only registered when --debug / DEBUG=true) (PART 6)
	s.registerDebugRoutes(s.Router)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("casspeed_owner"); err != nil || len(cookie.Value) < 32 {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			http.Error(w, indexTranslation(r, "errors.http_500_message"), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "casspeed_owner", Value: base64.RawURLEncoding.EncodeToString(secret),
			Path: prefixPagePath(requestPathPrefix(r), "/"), MaxAge: 30 * 24 * 60 * 60, HttpOnly: true,
			Secure: requestIsHTTPS(r), SameSite: http.SameSiteLaxMode,
		})
	}
	data, err := templateFS.ReadFile("template/index.html")
	if err != nil {
		http.Error(w, indexTranslation(r, "errors.http_500_message"), http.StatusInternalServerError)
		return
	}
	language, direction := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		catalog, _ = i18n.Resolve("en")
		language, direction = "en", "ltr"
	}
	homeMessages, err := json.Marshal(catalog.Messages["home"])
	if err != nil {
		http.Error(w, catalog.T("errors.http_500_message", nil), http.StatusInternalServerError)
		return
	}
	page, err := template.New("index").Funcs(template.FuncMap{
		"t": func(key string) string { return catalog.T("home."+key, nil) },
	}).Parse(string(data))
	if err != nil {
		http.Error(w, catalog.T("errors.http_500_message", nil), http.StatusInternalServerError)
		return
	}
	prefix := requestPathPrefix(r)
	values := struct {
		Lang, Dir, BasePath, APIBase string
		Translations                 template.JS
	}{language, direction, prefix, prefixPagePath(prefix, s.Config.APIBasePath()), template.JS(homeMessages)}
	hash := sha256.Sum256([]byte(s.version + "\x00" + s.commitID + "\x00" + s.buildDate + "\x00" + language))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", fmt.Sprintf("\"%x\"", hash[:]))
	if err := page.Execute(w, values); err != nil {
		return
	}
}

func indexTranslation(r *http.Request, key string) string {
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		catalog, _ = i18n.Resolve("en")
	}
	return catalog.T(key, nil)
}

// healthResponse is the canonical PART 13 health check response structure.
type healthResponse struct {
	Project   healthProject  `json:"project"`
	Status    string         `json:"status"`
	Version   string         `json:"version"`
	GoVersion string         `json:"go_version"`
	Build     healthBuild    `json:"build"`
	Uptime    string         `json:"uptime"`
	Mode      string         `json:"mode"`
	Timestamp time.Time      `json:"timestamp"`
	Cluster   healthCluster  `json:"cluster"`
	Features  healthFeatures `json:"features"`
	Checks    healthChecks   `json:"checks"`
	Stats     healthStats    `json:"stats"`
}

type healthProject struct {
	Name        string `json:"name"`
	Tagline     string `json:"tagline"`
	Description string `json:"description"`
}

type healthBuild struct {
	Commit string `json:"commit"`
	Date   string `json:"date"`
}

type healthCluster struct {
	Enabled bool   `json:"enabled"`
	Status  string `json:"status,omitempty"`
}

type healthFeatures struct {
	GeoIP bool      `json:"geoip"`
	Tor   healthTor `json:"tor"`
	I2P   healthI2P `json:"i2p"`
}

type healthTor struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Status   string `json:"status"`
	Hostname string `json:"hostname"`
}

type healthI2P struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	State    string `json:"state"`
	Status   string `json:"status"`
	Hostname string `json:"hostname"`
	Provider string `json:"provider"`
}

type healthChecks struct {
	Database  string `json:"database"`
	Cache     string `json:"cache"`
	Disk      string `json:"disk"`
	Scheduler string `json:"scheduler"`
	I2P       string `json:"i2p,omitempty"`
}

type healthStats struct {
	RequestsTotal int64 `json:"requests_total"`
	Requests24h   int64 `json:"requests_24h"`
	ActiveConns   int   `json:"active_connections"`
}

// formatUptime renders a duration as a human-readable string (e.g. "2d 5h 30m")
func formatUptime(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

func (s *Server) buildHealthResponse() healthResponse {
	m := metrics.GetMetrics()
	s.cacheHealthMu.Lock()
	cacheStatus := s.cacheHealthStatus
	s.cacheHealthMu.Unlock()
	if cacheStatus == "" {
		cacheStatus = "ok"
	}
	i2pInfo := s.i2PHealth()
	overallStatus := "healthy"
	i2pCheck := ""
	if i2pInfo.Status == "unavailable" {
		overallStatus = "degraded"
		i2pCheck = "degraded"
	} else if i2pInfo.Enabled {
		i2pCheck = "ok"
	}
	return healthResponse{
		Project: healthProject{
			Name:        s.Config.Server.Branding.Title,
			Tagline:     s.Config.Server.Branding.Tagline,
			Description: s.Config.Server.Branding.Description,
		},
		Status:    overallStatus,
		Version:   s.version,
		GoVersion: runtime.Version(),
		Build: healthBuild{
			Commit: s.commitID,
			Date:   s.buildDate,
		},
		Uptime:    formatUptime(time.Since(s.startTime)),
		Mode:      s.Mode.String(),
		Timestamp: time.Now().UTC(),
		Cluster: healthCluster{
			Enabled: false,
		},
		Features: healthFeatures{
			GeoIP: false,
			Tor:   s.torHealth(),
			I2P:   i2pInfo,
		},
		Checks: healthChecks{
			Database:  "ok",
			Cache:     cacheStatus,
			Disk:      "ok",
			Scheduler: "ok",
			I2P:       i2pCheck,
		},
		Stats: healthStats{
			RequestsTotal: m.TotalRequests(),
			Requests24h:   m.Requests24h(),
			ActiveConns:   m.ActiveConnections(),
		},
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.refreshCacheHealth(r.Context())
	resp := s.buildHealthResponse()

	// Content negotiation — .json/.txt extensions and Accept header (PART 13)
	path := r.URL.Path
	accept := r.Header.Get("Accept")

	// Path extension takes priority
	if len(path) > 5 && path[len(path)-5:] == ".json" {
		accept = "application/json"
	} else if len(path) > 4 && path[len(path)-4:] == ".txt" {
		accept = "text/plain"
	}

	// API routes default to JSON when no explicit Accept header
	if accept == "" && (len(path) >= 4 && path[:4] == "/api") {
		accept = "application/json"
	}

	switch accept {
	case "text/plain", "text/*":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "status: %s\n", resp.Status)
		fmt.Fprintf(w, "version: %s\n", resp.Version)
		fmt.Fprintf(w, "go_version: %s\n", resp.GoVersion)
		fmt.Fprintf(w, "mode: %s\n", resp.Mode)
		fmt.Fprintf(w, "uptime: %s\n", resp.Uptime)
		fmt.Fprintf(w, "database: %s\n", resp.Checks.Database)
		fmt.Fprintf(w, "cache: %s\n", resp.Checks.Cache)
		fmt.Fprintf(w, "disk: %s\n", resp.Checks.Disk)
		fmt.Fprintf(w, "scheduler: %s\n", resp.Checks.Scheduler)
		fmt.Fprintf(w, "features.i2p: %s", resp.Features.I2P.Status)
		if resp.Features.I2P.Hostname != "" {
			fmt.Fprintf(w, " %s", resp.Features.I2P.Hostname)
		}
		fmt.Fprintln(w)
		if resp.Checks.I2P != "" {
			fmt.Fprintf(w, "i2p: %s\n", resp.Checks.I2P)
		}

	case "application/json", "application/*":
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.MarshalIndent(resp, "", "  ")
		w.Write(data)
		w.Write([]byte("\n"))

	default:
		writeHealthPage(s, w, r, resp)
	}
}

func (s *Server) refreshCacheHealth(parent context.Context) {
	if s.Cache == nil {
		return
	}
	now := time.Now()
	s.cacheHealthMu.Lock()
	if now.Before(s.cacheHealthNext) {
		s.cacheHealthMu.Unlock()
		return
	}
	s.cacheHealthNext = now.Add(15 * time.Second)
	s.cacheHealthMu.Unlock()
	ctx, cancel := context.WithTimeout(parent, time.Second)
	err := s.Cache.Ping(ctx)
	cancel()
	s.cacheHealthMu.Lock()
	previous := s.cacheHealthStatus
	if err != nil {
		s.cacheHealthStatus = "degraded"
	} else {
		s.cacheHealthStatus = "ok"
	}
	s.cacheHealthMu.Unlock()
	if err != nil && previous != "degraded" && s.Logger != nil && s.Logger.Error != nil {
		s.Logger.Error.Printf("cache backend unavailable; counters are using the in-process fallback")
	}
}

func (s *Server) handleAPIRoot(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"version": s.Config.Server.APIVersion,
		"status":  "ok",
	}
	w.Header().Set("Content-Type", "application/json")
	data, _ := json.MarshalIndent(response, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	serviceName := chi.URLParam(r, "service")
	if serviceName == "" {
		trimmed := strings.Trim(strings.TrimSuffix(r.URL.Path, "/"), "/")
		parts := strings.Split(trimmed, "/")
		if len(parts) > 0 {
			last := parts[len(parts)-1]
			if last == "prometheus" || last == "grafana" || last == "loki" {
				serviceName = last
			}
		}
	}
	if serviceName == "" {
		serviceName = "prometheus"
	}
	s.serveMetricsService(w, r, serviceName)
}

func (s *Server) handleSwaggerSpec(w http.ResponseWriter, r *http.Request) {
	recorder := httptest.NewRecorder()
	swagger.SpecHandlerWithRoutes(recorder, r, s.openapiRouteInventory())
	for name, values := range recorder.Header() {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(recorder.Code)
	body := bytes.ReplaceAll(recorder.Body.Bytes(), []byte("/api/v1"), []byte(s.Config.APIBasePath()))
	_, _ = w.Write(body)
}

func (s *Server) openapiRouteInventory() []swagger.Route {
	routes := make([]swagger.Route, 0)
	if s.Router == nil {
		return routes
	}
	registered := make(map[string]struct{})
	_ = chi.Walk(s.Router, func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		const internalAPIBase = "/api/v1"
		if path != internalAPIBase && !strings.HasPrefix(path, internalAPIBase+"/") {
			return nil
		}
		relativePath := strings.TrimPrefix(path, internalAPIBase)
		if relativePath == "" {
			relativePath = "/"
		}
		methods := []string{method}
		if method == "*" {
			switch relativePath {
			case "/server/contact", "/server/graphql":
				methods = []string{http.MethodGet, http.MethodPost}
			case "/server/mcp":
				methods = []string{http.MethodPost}
			default:
				return nil
			}
		}
		mountedWhen := ""
		if strings.HasPrefix(relativePath, "/server/metrics") {
			mountedWhen = "server.metrics.enabled"
		}
		contentType := ""
		if strings.HasSuffix(relativePath, "/images/png") {
			contentType = "image/png"
		} else if strings.HasSuffix(relativePath, "/images/svg") {
			contentType = "image/svg+xml"
		} else if strings.HasSuffix(relativePath, "/download") {
			contentType = "application/octet-stream"
		}
		for _, routeMethod := range methods {
			key := routeMethod + " " + relativePath
			if _, exists := registered[key]; exists {
				continue
			}
			registered[key] = struct{}{}
			routes = append(routes, swagger.Route{Path: relativePath, Methods: []string{routeMethod}, MountedWhen: mountedWhen, ResponseContentType: contentType})
		}
		return nil
	})
	return routes
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
	fmt.Fprintf(w, "Sitemap: %s\n", BuildURL(r, "/sitemap.xml"))
}

type sitemapURLSet struct {
	XMLName xml.Name     `xml:"urlset"`
	XMLNS   string       `xml:"xmlns,attr"`
	URLs    []sitemapURL `xml:"url"`
}

type sitemapURL struct {
	Loc      string  `xml:"loc"`
	Priority float64 `xml:"priority,omitempty"`
}

func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	paths := []struct {
		path     string
		priority float64
	}{
		{path: "/", priority: 1.0},
		{path: "/server/about", priority: 0.6},
		{path: "/server/privacy", priority: 0.5},
		{path: "/server/help", priority: 0.5},
		{path: "/server/terms", priority: 0.4},
		{path: "/server/dpo", priority: 0.4},
		{path: "/server/security", priority: 0.5},
		{path: "/server/security/policy", priority: 0.4},
		{path: "/server/security/thanks", priority: 0.3},
		{path: "/server/docs/swagger", priority: 0.6},
		{path: "/server/docs/graphql", priority: 0.6},
	}
	set := sitemapURLSet{XMLNS: "http://www.sitemaps.org/schemas/sitemap/0.9", URLs: make([]sitemapURL, 0, len(paths))}
	for _, page := range paths {
		set.URLs = append(set.URLs, sitemapURL{Loc: BuildURL(r, page.path), Priority: page.priority})
	}
	body, err := xml.Marshal(set)
	if err != nil {
		http.Error(w, "Unable to generate sitemap", http.StatusInternalServerError)
		return
	}
	writeCachedXML(w, r, append([]byte(xml.Header), body...), "application/xml; charset=utf-8", s.startTime)
}

type atomFeed struct {
	XMLName xml.Name `xml:"http://www.w3.org/2005/Atom feed"`
	ID      string   `xml:"id"`
	Title   string   `xml:"title"`
	Updated string   `xml:"updated"`
	Link    atomLink `xml:"link"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr,omitempty"`
}

type rssFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Version string     `xml:"version,attr"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
}

func (s *Server) handleAtomFeed(w http.ResponseWriter, r *http.Request) {
	base := BuildURL(r, "/")
	updated := s.startTime
	if updated.IsZero() {
		updated = time.Now().UTC()
	}
	body, err := xml.Marshal(atomFeed{ID: base, Title: "CasSpeed", Updated: updated.UTC().Format(time.RFC3339), Link: atomLink{Href: base, Rel: "alternate"}})
	if err != nil {
		http.Error(w, "Unable to generate feed", http.StatusInternalServerError)
		return
	}
	writeCachedXML(w, r, append([]byte(xml.Header), body...), "application/atom+xml; charset=utf-8", updated)
}

func (s *Server) handleRSSFeed(w http.ResponseWriter, r *http.Request) {
	base := BuildURL(r, "/")
	body, err := xml.Marshal(rssFeed{Version: "2.0", Channel: rssChannel{Title: "CasSpeed", Link: base, Description: "Public CasSpeed updates"}})
	if err != nil {
		http.Error(w, "Unable to generate feed", http.StatusInternalServerError)
		return
	}
	writeCachedXML(w, r, append([]byte(xml.Header), body...), "application/rss+xml; charset=utf-8", s.startTime)
}

func writeCachedXML(w http.ResponseWriter, r *http.Request, body []byte, contentType string, lastModified time.Time) {
	hash := sha256.Sum256(body)
	etag := fmt.Sprintf("\"%x\"", hash[:])
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("ETag", etag)
	modified := lastModified.UTC().Truncate(time.Second)
	if modified.IsZero() {
		modified = time.Unix(0, 0).UTC()
	}
	w.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if since := r.Header.Get("If-Modified-Since"); since != "" {
		if parsed, err := http.ParseTime(since); err == nil && !modified.After(parsed) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleSecurityTxt serves security.txt per PART 11 (RFC 9116)
func (s *Server) handleSecurityTxt(w http.ResponseWriter, r *http.Request) {
	data := s.securityPageData(r)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = fmt.Fprintf(w, "# CasSpeed security.txt (RFC 9116)\n")
	for _, contact := range data.Contacts {
		_, _ = fmt.Fprintf(w, "Contact: %s\n", contact.Value)
	}
	_, _ = fmt.Fprintf(w, "Expires: %s\nPreferred-Languages: en\nPolicy: %s\n", data.Expires, data.PolicyURL)
	if pgpURL, ok := data.PGP["url"].(string); ok && pgpURL != "" {
		_, _ = fmt.Fprintf(w, "Encryption: %s\n", pgpURL)
	}
}

// handleChangePassword directs authenticated users to password management and guests to recovery.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	location := "/server/auth/password/forgot"
	if cookie, err := r.Cookie("user_session"); s.Store != nil && err == nil && cookie.Value != "" {
		if session, err := s.Store.GetSession(r.Context(), cookie.Value); err == nil && session != nil && session.ExpiresAt.After(time.Now()) {
			location = "/users/security/password"
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, location, http.StatusFound)
}

func (s *Server) Start(address string, port int) error {
	addr := fmt.Sprintf("%s:%d", address, port)
	if s.Scheduler != nil {
		s.Scheduler.Start()
	}

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

// Serve runs the HTTP server on an injected listener until the context is
// canceled or the listener exits. The ready channel closes after serving starts.
func (s *Server) Serve(ctx context.Context, listener net.Listener, ready chan<- struct{}) error {
	if listener == nil {
		return fmt.Errorf("HTTP listener is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Scheduler != nil {
		s.Scheduler.Start()
	}
	s.HTTP = &http.Server{
		Addr:         listener.Addr().String(),
		Handler:      s.Router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.HTTP.Serve(listener) }()
	if ready != nil {
		close(ready)
	}
	select {
	case err := <-serveErr:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownErr := s.Shutdown()
		serveResult := <-serveErr
		if serveResult != nil && serveResult != http.ErrServerClosed && shutdownErr == nil {
			return serveResult
		}
		return shutdownErr
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
	s.overlayMu.RLock()
	i2pManager, i2pHTTP := s.i2pManager, s.i2pHTTP
	torManager, torHTTP := s.torManager, s.torHTTP
	s.overlayMu.RUnlock()
	if i2pManager != nil {
		if err := i2pManager.Close(); err != nil && s.Logger != nil && s.Logger.Error != nil {
			s.Logger.Error.Printf("I2P shutdown failed: %v", err)
		}
	}
	if i2pHTTP != nil {
		if err := i2pHTTP.Shutdown(ctx); err != nil && s.Logger != nil && s.Logger.Error != nil {
			s.Logger.Error.Printf("I2P HTTP shutdown failed: %v", err)
		}
	}
	if torManager != nil {
		if err := torManager.Close(); err != nil && s.Logger != nil && s.Logger.Error != nil {
			s.Logger.Error.Printf("Tor shutdown failed: %v", err)
		}
	}
	s.overlayMu.RLock()
	torVanity := s.torVanity
	s.overlayMu.RUnlock()
	if torVanity != nil {
		torVanity.Close()
	}
	if torHTTP != nil {
		if err := torHTTP.Shutdown(ctx); err != nil && s.Logger != nil && s.Logger.Error != nil {
			s.Logger.Error.Printf("Tor HTTP shutdown failed: %v", err)
		}
	}

	if s.HTTP != nil {
		if err := s.HTTP.Shutdown(ctx); err != nil {
			return fmt.Errorf("server shutdown failed: %w", err)
		}
	}
	if s.Scheduler != nil {
		s.Scheduler.Stop()
	}
	if err := s.flushRateCounters(context.Background()); err != nil && s.Logger != nil && s.Logger.Error != nil {
		s.Logger.Error.Printf("unable to persist rate-limit counters during shutdown: %v", err)
	}
	if s.Store != nil {
		if err := s.Store.Close(); err != nil {
			return fmt.Errorf("store shutdown failed: %w", err)
		}
	}
	if s.Cache != nil {
		if err := s.Cache.Close(); err != nil {
			return fmt.Errorf("cache shutdown failed: %w", err)
		}
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
		if locked, retry := s.authFailureLockedOut(r); locked {
			writeRateLimited(w, retry)
			return
		}
		if allowed, retryAfter := s.allowConfiguredRequest(r); !allowed {
			writeRateLimited(w, retryAfter)
			return
		}
		isTestStart := r.Method == http.MethodPost && r.URL.Path == "/api/v1/speed-tests"
		isTestStatus := r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/speed-tests/") && strings.HasSuffix(r.URL.Path, "/status")
		if !isTestStart && !isTestStatus {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := requestRateIdentity(r)
		if s.Cache != nil {
			cacheKey := sha256.Sum256([]byte(clientIP))
			ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
			defer cancel()
			cacheUsed := false
			cacheAttempted := false
			if isTestStart && s.Config.Test.MinInterval > 0 {
				cacheAttempted = true
				window := time.Duration(s.Config.Test.MinInterval) * time.Second
				count, err := s.Cache.Increment(ctx, "speedtest:start:"+hex.EncodeToString(cacheKey[:]), window)
				if err == nil {
					cacheUsed = true
					cancel()
					if count > 1 {
						w.Header().Set("Retry-After", fmt.Sprintf("%d", s.Config.Test.MinInterval))
						http.Error(w, "Test interval too short", http.StatusTooManyRequests)
						return
					}
				}
			}
			if isTestStatus && !cacheUsed {
				cacheAttempted = true
				ttl := time.Duration(s.Config.Test.Timeout+30) * time.Second
				count, err := s.Cache.Increment(ctx, "speedtest:active:"+hex.EncodeToString(cacheKey[:]), ttl)
				if err == nil {
					cacheUsed = true
					cancel()
					if count > int64(s.Config.Test.MaxConcurrent) {
						cleanupCtx, cleanupCancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
						if _, decrementErr := s.Cache.Decrement(cleanupCtx, "speedtest:active:"+hex.EncodeToString(cacheKey[:])); decrementErr != nil {
							s.markCacheDegraded()
						}
						cleanupCancel()
						w.Header().Set("Retry-After", "60")
						http.Error(w, "Too many concurrent tests", http.StatusTooManyRequests)
						return
					}
					defer func() {
						decrementCtx, decrementCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
						defer decrementCancel()
						if _, decrementErr := s.Cache.Decrement(decrementCtx, "speedtest:active:"+hex.EncodeToString(cacheKey[:])); decrementErr != nil {
							s.markCacheDegraded()
						}
					}()
				}
			}
			if !cacheUsed {
				cancel()
				if cacheAttempted {
					s.markCacheDegraded()
				}
			} else {
				s.cacheHealthMu.Lock()
				s.cacheHealthStatus = "ok"
				s.cacheHealthMu.Unlock()
				next.ServeHTTP(w, r)
				return
			}
		}

		s.ipMutex.Lock()
		limit, exists := s.ipTestCount[clientIP]
		if !exists {
			limit = &ipRateLimit{activeTests: 0, lastTest: time.Time{}}
			s.ipTestCount[clientIP] = limit
		}

		if isTestStatus && limit.activeTests >= s.Config.Test.MaxConcurrent {
			s.ipMutex.Unlock()
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too many concurrent tests", http.StatusTooManyRequests)
			return
		}

		secondsSinceLastTest := time.Since(limit.lastTest).Seconds()
		if isTestStart && !limit.lastTest.IsZero() && secondsSinceLastTest < float64(s.Config.Test.MinInterval) {
			retryAfter := int(float64(s.Config.Test.MinInterval) - secondsSinceLastTest)
			s.ipMutex.Unlock()
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			http.Error(w, "Test interval too short", http.StatusTooManyRequests)
			return
		}

		if isTestStatus {
			limit.activeTests++
		} else {
			limit.lastTest = time.Now()
		}
		s.ipMutex.Unlock()

		if isTestStatus {
			defer func() {
				s.ipMutex.Lock()
				if l, ok := s.ipTestCount[clientIP]; ok {
					l.activeTests--
				}
				s.ipMutex.Unlock()
			}()
		}

		next.ServeHTTP(w, r)
	})
}

func writeRateLimited(w http.ResponseWriter, retryAfter int) {
	if retryAfter < 1 {
		retryAfter = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"ok":false,"error":"RATE_LIMITED","message":"Too many requests"}`))
}

func (s *Server) allowConfiguredRequest(r *http.Request) (bool, int) {
	limits := s.Config.Server.RateLimit
	path := r.URL.Path
	class := "write"
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		class = "read"
	}
	configured := limits.Write
	if class == "read" {
		configured = limits.Read
	}
	if strings.HasPrefix(path, "/server/healthz") || strings.HasPrefix(path, "/api/healthz") || path == "/healthz" || path == "/api/v1/health" || path == "/api/v1/status" {
		class = "health"
		configured = limits.Health
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && (path == "/api/v1/users/tokens/reveal" || path == "/api/v1/users/tokens/rotate" || path == "/api/v1/users/tokens/restore") {
		if allowed, retry := s.allowRateClass(r, "strict", limits.Strict); !allowed {
			return false, retry
		}
	}
	if extra := authEndpointLimit(path, limits.Auth); extra != nil {
		if allowed, retry := s.allowRateClass(r, "auth:"+path, *extra); !allowed {
			return false, retry
		}
	}
	if allowed, retry := s.allowRateClass(r, class, configured); !allowed {
		return false, retry
	}
	if limits.GlobalBurst > 0 {
		return s.allowRateClass(r, "global", config.RateWindowLimit{Requests: limits.GlobalBurst, Window: 60})
	}
	return true, 0
}

func authEndpointLimit(path string, limits config.AuthRateLimits) *config.RateWindowLimit {
	if strings.Contains(path, "login") {
		return &limits.Login
	}
	if strings.Contains(path, "password-reset") || strings.Contains(path, "password/reset") || strings.Contains(path, "password/forgot") {
		return &limits.PasswordReset
	}
	if strings.Contains(path, "register") || strings.Contains(path, "signup") {
		return &limits.Registration
	}
	return nil
}

func (s *Server) allowRateClass(r *http.Request, class string, limit config.RateWindowLimit) (bool, int) {
	if limit.Requests <= 0 || limit.Window <= 0 {
		return true, 0
	}
	identity := requestRateIdentity(r)
	if token, ok := r.Context().Value(apiTokenContextKey{}).(apiTokenIdentity); ok && token.ID != "" {
		identity = "token:" + token.ID
	} else if strings.HasPrefix(r.URL.Path, "/api/v1/") {
		if bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); bearer != r.Header.Get("Authorization") && bearer != "" {
			if _, token, valid := s.validateBearerToken(r.Context(), bearer); valid {
				identity = "token:" + token.ID
			}
		}
	}
	if strings.HasPrefix(class, "auth:") {
		if err := r.ParseForm(); err == nil {
			identifier := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
			if identifier == "" {
				identifier = strings.ToLower(strings.TrimSpace(r.FormValue("email")))
			}
			if identifier != "" {
				digest := sha256.Sum256([]byte(identifier))
				identity += ":identifier:" + hex.EncodeToString(digest[:])
			}
		}
	}
	key := "rate:" + class + ":" + identity
	window := time.Duration(limit.Window) * time.Second
	ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
	defer cancel()
	if s.Cache != nil && (s.Config.Server.Cache.Type == "redis" || s.Config.Server.Cache.Type == "valkey") {
		allowed, retry, err := s.Cache.Allow(ctx, key, limit.Requests, window)
		if err == nil {
			s.cacheHealthMu.Lock()
			s.cacheHealthStatus = "ok"
			s.cacheHealthMu.Unlock()
			if allowed {
				return true, 0
			}
			return false, retry
		}
		s.markCacheDegraded()
	}
	return s.allowFallbackRate(key, limit, time.Now())
}

func (s *Server) authFailureKey(r *http.Request) string {
	return "rate:auth_failures:" + requestRateIdentity(r)
}

func (s *Server) recordFailedAuthentication(r *http.Request) {
	limit := s.Config.Server.RateLimit.AuthFailures
	if limit.Requests <= 0 || limit.Window <= 0 {
		return
	}
	key := s.authFailureKey(r)
	window := time.Duration(limit.Window) * time.Second
	if s.Cache != nil && (s.Config.Server.Cache.Type == "redis" || s.Config.Server.Cache.Type == "valkey") {
		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		_, _, err := s.Cache.Allow(ctx, key, int(^uint(0)>>1), window)
		cancel()
		if err == nil {
			return
		}
		s.markCacheDegraded()
	}
	_, _ = s.allowFallbackRate(key, config.RateWindowLimit{Requests: int(^uint(0) >> 1), Window: limit.Window}, time.Now())
}

func (s *Server) authFailureLockedOut(r *http.Request) (bool, int) {
	limit := s.Config.Server.RateLimit.AuthFailures
	if limit.Requests <= 0 || limit.Window <= 0 {
		return false, 0
	}
	key := s.authFailureKey(r)
	window := time.Duration(limit.Window) * time.Second
	if s.Cache != nil && (s.Config.Server.Cache.Type == "redis" || s.Config.Server.Cache.Type == "valkey") {
		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		count, err := s.Cache.Count(ctx, key, window)
		if err == nil {
			if count < limit.Requests {
				cancel()
				return false, 0
			}
			retry, waitErr := s.Cache.RetryAfter(ctx, key, window)
			cancel()
			if waitErr != nil {
				return true, limit.Window
			}
			return true, retry
		}
		cancel()
		s.markCacheDegraded()
	}
	s.ipMutex.RLock()
	events := append([]time.Time(nil), s.fallbackRates[key]...)
	s.ipMutex.RUnlock()
	cutoff := time.Now().Add(-window)
	count := 0
	for _, event := range events {
		if event.After(cutoff) {
			count++
		}
	}
	if count < limit.Requests {
		return false, 0
	}
	oldest := time.Time{}
	for _, event := range events {
		if event.After(cutoff) && (oldest.IsZero() || event.Before(oldest)) {
			oldest = event
		}
	}
	retry := int(time.Until(oldest.Add(window)).Seconds())
	if retry < 1 {
		retry = 1
	}
	return true, retry
}

func (s *Server) allowFallbackRate(key string, limit config.RateWindowLimit, now time.Time) (bool, int) {
	window := time.Duration(limit.Window) * time.Second
	cutoff := now.Add(-window)
	s.ipMutex.Lock()
	if s.fallbackRates == nil {
		s.fallbackRates = make(map[string][]time.Time)
	}
	prior := s.fallbackRates[key]
	active := prior[:0]
	for _, stamp := range prior {
		if stamp.After(cutoff) {
			active = append(active, stamp)
		}
	}
	if len(active) >= limit.Requests {
		s.fallbackRates[key] = active
		retry := int(time.Until(active[0].Add(window)).Seconds())
		if retry < 1 {
			retry = 1
		}
		s.ipMutex.Unlock()
		return false, retry
	}
	s.fallbackRates[key] = append(active, now)
	flushDue := now.After(s.rateFlushNext)
	if flushDue {
		s.rateFlushNext = now.Add(30 * time.Second)
	}
	s.ipMutex.Unlock()
	if flushDue {
		if err := s.flushRateCounters(context.Background()); err != nil && s.Logger != nil && s.Logger.Error != nil {
			s.Logger.Error.Printf("unable to persist fallback rate-limit counters: %v", err)
		}
	}
	return true, 0
}

func (s *Server) flushRateCounters(ctx context.Context) error {
	storeCounters, ok := s.Store.(store.RateCounterStore)
	if !ok {
		return nil
	}
	s.rateFlushMu.Lock()
	defer s.rateFlushMu.Unlock()
	s.ipMutex.RLock()
	snapshot := make(map[string][]time.Time, len(s.fallbackRates))
	for key, events := range s.fallbackRates {
		for _, event := range events {
			if event.After(time.Now().Add(-time.Hour)) {
				snapshot[key] = append(snapshot[key], event)
			}
		}
	}
	s.ipMutex.RUnlock()
	return storeCounters.SaveRateCounters(ctx, snapshot)
}

func pruneRateCounterSnapshot(counters map[string][]time.Time, cutoff time.Time) map[string][]time.Time {
	pruned := make(map[string][]time.Time, len(counters))
	for key, events := range counters {
		for _, event := range events {
			if event.After(cutoff) {
				pruned[key] = append(pruned[key], event)
			}
		}
	}
	return pruned
}

func (s *Server) markCacheDegraded() {
	s.cacheHealthMu.Lock()
	wasHealthy := s.cacheHealthStatus == "ok"
	s.cacheHealthStatus = "degraded"
	s.cacheHealthMu.Unlock()
	if wasHealthy && s.Logger != nil && s.Logger.Error != nil {
		s.Logger.Error.Printf("cache backend unavailable; counters are using the in-process fallback")
	}
}

// securityHeaders adds security headers per PART 11 specification
func securityHeaders(servers ...*Server) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Required security headers (PART 11 - NON-NEGOTIABLE)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			connectSources := "'self'"
			resolvedURL, err := url.Parse(buildRequestURL(r, "/"))
			isHTTPS := err == nil && resolvedURL.Scheme == "https"
			if err == nil && resolvedURL.Host != "" {
				connectSources += " ws://" + resolvedURL.Host + " wss://" + resolvedURL.Host
			}
			if len(servers) > 0 && servers[0] != nil {
				for _, origin := range servers[0].corsOriginSources() {
					connectSources += " " + origin
					if strings.HasPrefix(origin, "https://") {
						connectSources += " wss://" + strings.TrimPrefix(origin, "https://")
					} else if strings.HasPrefix(origin, "http://") {
						connectSources += " ws://" + strings.TrimPrefix(origin, "http://")
					}
				}
			}
			scriptSources := "'self'"
			imageSources := "'self' data: blob: https:"
			frameSources := "'self'"
			if len(servers) > 0 && servers[0] != nil && servers[0].trackingAllowed(r) {
				provider := configuredTracking(servers[0].Config.Server.Tracking)
				if provider.scriptHost != "" {
					scriptSources += " " + provider.scriptHost
				}
				if provider.connectHost != "" {
					connectSources += " " + provider.connectHost
				}
				if provider.imageHost != "" {
					imageSources += " " + provider.imageHost
				}
			}
			if len(servers) > 0 && servers[0] != nil && servers[0].ContactHandler != nil && (r.URL.Path == "/server/contact" || r.URL.Path == "/api/v1/server/contact") {
				switch servers[0].ContactHandler.SelectedCaptchaProvider(r) {
				case "recaptcha":
					scriptSources += " https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/"
					frameSources += " https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/"
					connectSources += " https://www.google.com/recaptcha/"
				case "hcaptcha":
					scriptSources += " https://js.hcaptcha.com https://*.hcaptcha.com"
					frameSources += " https://hcaptcha.com https://*.hcaptcha.com"
					connectSources += " https://hcaptcha.com https://*.hcaptcha.com"
				}
			}
			csp := "default-src 'self'; script-src " + scriptSources + "; style-src 'self' 'unsafe-inline'; img-src " + imageSources + "; font-src 'self' https:; connect-src " + connectSources + "; media-src 'self' blob:; worker-src 'self' blob:; manifest-src 'self'; frame-src " + frameSources + "; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none'"
			if isHTTPS {
				csp += "; upgrade-insecure-requests"
			}
			w.Header().Set("Content-Security-Policy", csp)
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

			// HSTS when SSL is enabled
			if isHTTPS {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}

			next.ServeHTTP(w, r)
		})
	}
}
