package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/common/i18n"
	"gopkg.in/yaml.v3"
)

// Config represents the complete server configuration
type Config struct {
	CLI      CLIConfig    `yaml:"cli"`
	Language string       `yaml:"lang"`
	Server   ServerConfig `yaml:"server"`
	Web      WebConfig    `yaml:"web"`
	Test     TestConfig   `yaml:"test"`
	Runtime  RuntimeInfo  `yaml:"-"`
}

// RuntimeInfo carries process metadata that is not part of the user-managed YAML.
type RuntimeInfo struct {
	ConfigDir    string
	DataDir      string
	CacheDir     string
	LogDir       string
	BackupDir    string
	PIDFile      string
	Version      string
	CommitID     string
	BuildEpoch   string
	OfficialSite string
}

type CLIConfig struct {
	BinaryDownload CLIBinaryDownloadConfig `yaml:"binary_download"`
}

type CLIBinaryDownloadConfig struct {
	Dir         string `yaml:"dir"`
	RequireAuth bool   `yaml:"require_auth"`
}

// APIBasePath returns the configured versioned REST API prefix.
func (c *Config) APIBasePath() string {
	if c == nil || c.Server.APIVersion == "" {
		return "/api/v1"
	}
	return "/api/" + c.Server.APIVersion
}

// UserConfig controls regular-user registration independently of admin auth.
type UserConfig struct {
	Enabled      bool               `yaml:"enabled"`
	Registration RegistrationConfig `yaml:"registration"`
	Roles        UserRolesConfig    `yaml:"roles"`
	Auth         UserAuthConfig     `yaml:"auth"`
}

type RegistrationConfig struct {
	Mode                     string   `yaml:"mode"`
	RequireEmailVerification bool     `yaml:"require_email_verification"`
	AllowedDomains           []string `yaml:"allowed_domains"`
	BlockedDomains           []string `yaml:"blocked_domains"`
	InviteExpirationDays     int      `yaml:"invite_expiration_days"`
}

type UserRolesConfig struct {
	Available   []string            `yaml:"available"`
	Default     string              `yaml:"default"`
	Permissions map[string][]string `yaml:"permissions"`
}

type UserAuthConfig struct {
	Require2FA               bool `yaml:"require_2fa"`
	Allow2FA                 bool `yaml:"allow_2fa"`
	PasswordMinLength        int  `yaml:"password_min_length"`
	PasswordRequireUppercase bool `yaml:"password_require_uppercase"`
	PasswordRequireNumber    bool `yaml:"password_require_number"`
	PasswordRequireSpecial   bool `yaml:"password_require_special"`
}

// ServerConfig contains server settings
type ServerConfig struct {
	Port           interface{}          `yaml:"port"` // Can be int, string (for dual), or empty (random)
	FQDN           string               `yaml:"fqdn"`
	Address        string               `yaml:"address"`
	Mode           string               `yaml:"mode"`       // production or development
	AdminPath      string               `yaml:"admin_path"` // Admin panel path (default: "admin")
	APIVersion     string               `yaml:"api_version"`
	Branding       Branding             `yaml:"branding"`
	SEO            SEO                  `yaml:"seo"`
	User           string               `yaml:"user"`
	Group          string               `yaml:"group"`
	PIDFile        bool                 `yaml:"pidfile"`
	Daemonize      bool                 `yaml:"daemonize"`
	Admin          AdminConfig          `yaml:"admin"`
	Contact        ContactConfig        `yaml:"contact"`
	Pages          PagesConfig          `yaml:"pages"`
	Notifications  NotificationConfig   `yaml:"notifications"`
	SSL            SSLConfig            `yaml:"ssl"`
	TrustedProxies TrustedProxyConfig   `yaml:"trusted_proxies"`
	Scheduler      Scheduler            `yaml:"scheduler"`
	RateLimit      RateLimit            `yaml:"rate_limit"`
	Database       Database             `yaml:"database"`
	Cache          CacheConfig          `yaml:"cache"`
	I18n           I18nConfig           `yaml:"i18n"`
	Users          UserConfig           `yaml:"users"`
	Security       ServerSecurityConfig `yaml:"security"`
	Privacy        PrivacyConfig        `yaml:"privacy"`
	Tracking       TrackingConfig       `yaml:"tracking"`
	Healthz        HealthzConfig        `yaml:"healthz"`
	Metrics        MetricsConfig        `yaml:"metrics"`
	Update         ServerUpdateConfig   `yaml:"update"`
	I2P            I2PConfig            `yaml:"i2p"`
	Tor            TorConfig            `yaml:"tor"`
}

// TorConfig controls the app-managed hidden service and optional outbound client.
type TorConfig struct {
	Binary                    string `yaml:"binary" json:"binary"`
	Expose                    bool   `yaml:"expose" json:"expose"`
	ContactEmail              string `yaml:"contact_email" json:"contact_email"`
	UseNetwork                bool   `yaml:"use_network" json:"use_network"`
	AllowUserPreference       bool   `yaml:"allow_user_preference" json:"allow_user_preference"`
	MaxCircuits               int    `yaml:"max_circuits" json:"max_circuits"`
	StartupTimeout            int    `yaml:"startup_timeout" json:"startup_timeout"`
	CircuitTimeout            int    `yaml:"circuit_timeout" json:"circuit_timeout"`
	BootstrapTimeout          int    `yaml:"bootstrap_timeout" json:"bootstrap_timeout"`
	SafeLogging               bool   `yaml:"safe_logging" json:"safe_logging"`
	MaxStreamsPerCircuit      int    `yaml:"max_streams_per_circuit" json:"max_streams_per_circuit"`
	CloseCircuitOnStreamLimit bool   `yaml:"close_circuit_on_stream_limit" json:"close_circuit_on_stream_limit"`
	BandwidthRate             string `yaml:"bandwidth_rate" json:"bandwidth_rate"`
	BandwidthBurst            string `yaml:"bandwidth_burst" json:"bandwidth_burst"`
	MaxMonthlyBandwidth       string `yaml:"max_monthly_bandwidth" json:"max_monthly_bandwidth"`
	NumIntroPoints            int    `yaml:"num_intro_points" json:"num_intro_points"`
	VirtualPort               int    `yaml:"virtual_port" json:"virtual_port"`
}

// I2PConfig controls the optional eepsite provider. BootstrapTimeout is seconds.
type I2PConfig struct {
	Enabled          bool   `yaml:"enabled" json:"enabled"`
	Expose           bool   `yaml:"expose" json:"expose"`
	Binary           string `yaml:"binary" json:"binary"`
	SAMAddress       string `yaml:"sam_address" json:"sam_address"`
	VirtualPort      int    `yaml:"virtual_port" json:"virtual_port"`
	InboundLength    int    `yaml:"inbound_length" json:"inbound_length"`
	OutboundLength   int    `yaml:"outbound_length" json:"outbound_length"`
	InboundQuantity  int    `yaml:"inbound_quantity" json:"inbound_quantity"`
	OutboundQuantity int    `yaml:"outbound_quantity" json:"outbound_quantity"`
	SignatureType    int    `yaml:"signature_type" json:"signature_type"`
	BootstrapTimeout int    `yaml:"bootstrap_timeout" json:"bootstrap_timeout"`
}

type ServerUpdateConfig struct {
	CLIMinVersion   string `yaml:"cli_min_version"`
	AgentMinVersion string `yaml:"agent_min_version"`
}

type HealthzConfig struct {
	Root HealthzRootConfig `yaml:"root"`
}

type HealthzRootConfig struct {
	Enabled bool `yaml:"enabled"`
}

type MetricsConfig struct {
	Enabled         bool              `yaml:"enabled"`
	Root            MetricsRootConfig `yaml:"root"`
	Auth            MetricsAuthConfig `yaml:"auth"`
	IncludeSystem   bool              `yaml:"include_system"`
	IncludeRuntime  bool              `yaml:"include_runtime"`
	Loki            MetricsLokiConfig `yaml:"loki"`
	DurationBuckets []float64         `yaml:"duration_buckets"`
	SizeBuckets     []int64           `yaml:"size_buckets"`
}

type MetricsRootConfig struct {
	Enabled bool `yaml:"enabled"`
}

type MetricsAuthConfig struct {
	AllowUnauthenticated bool `yaml:"allow_unauthenticated"`
}

type MetricsLokiConfig struct {
	MaxEntries int    `yaml:"max_entries"`
	MaxAge     string `yaml:"max_age"`
}

// DefaultI2PEnabled returns the computed runtime default, without applying a
// config-file, environment, or command-line override.
func DefaultI2PEnabled() bool {
	return applicationContainer()
}

func applicationContainer() bool {
	parentID := os.Getppid()
	if os.Getenv("INVOCATION_ID") != "" || os.Getenv("RC_SVCNAME") != "" {
		return false
	}
	if parentID == 1 {
		if _, err := os.Stat("/run/openrc"); err == nil {
			return false
		}
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			return false
		}
	}
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv", "/dev/lxc"} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	if os.Getenv("container") != "" || os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	parent := parentProcessName(parentID)
	switch parent {
	case "tini", "dumb-init", "s6-svscan", "runsv", "runsvdir", "catatonit", "casspeed":
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") || strings.Contains(content, "kubepods") || strings.Contains(content, "lxc") {
			return true
		}
	}
	return false
}

func parentProcessName(pid int) string {
	if pid <= 0 {
		return ""
	}
	if content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm")); err == nil {
		return strings.TrimSpace(string(content))
	}
	output, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return ""
	}
	return filepath.Base(strings.TrimSpace(string(output)))
}

type TrackingConfig struct {
	Type string `yaml:"type" json:"type"`
	ID   string `yaml:"id" json:"id"`
	URL  string `yaml:"url" json:"url"`
}

type I18nConfig struct {
	DefaultLanguage    string   `yaml:"default_language"`
	AvailableLanguages []string `yaml:"available_languages"`
}

type PrivacyConfig struct {
	Data       PrivacyDataConfig       `yaml:"data" json:"data"`
	Retention  PrivacyRetentionConfig  `yaml:"retention" json:"retention"`
	Consent    PrivacyConsentConfig    `yaml:"consent" json:"consent"`
	Cookies    PrivacyCookiesConfig    `yaml:"cookies" json:"cookies"`
	ThirdParty PrivacyThirdPartyConfig `yaml:"third_party" json:"third_party"`
}

type PrivacyDataConfig struct {
	Sold           bool                 `yaml:"sold" json:"sold"`
	StoredOnServer bool                 `yaml:"stored_on_server" json:"stored_on_server"`
	Sharing        []PrivacySharingRule `yaml:"sharing" json:"sharing"`
}

type PrivacySharingRule struct {
	Condition string `yaml:"condition" json:"condition"`
	When      string `yaml:"when" json:"when"`
	Data      string `yaml:"data" json:"data"`
}

type PrivacyRetentionConfig struct {
	Period            string `yaml:"period" json:"period"`
	ExportAvailable   bool   `yaml:"export_available" json:"export_available"`
	DeletionAvailable bool   `yaml:"deletion_available" json:"deletion_available"`
}

type PrivacyConsentConfig struct {
	ShowUntilAcknowledged bool                  `yaml:"show_until_acknowledged" json:"show_until_acknowledged"`
	Message               string                `yaml:"message" json:"message"`
	MessageIfSold         string                `yaml:"message_if_sold" json:"message_if_sold"`
	Policy                PrivacyPolicyLink     `yaml:"policy" json:"policy"`
	Buttons               PrivacyConsentButtons `yaml:"buttons" json:"buttons"`
	Position              string                `yaml:"position" json:"position"`
	ShowPreferences       bool                  `yaml:"show_preferences" json:"show_preferences"`
	PreferencesText       string                `yaml:"preferences_text" json:"preferences_text"`
}

type PrivacyPolicyLink struct {
	Text    string `yaml:"text" json:"text"`
	URL     string `yaml:"url" json:"url"`
	Version string `yaml:"version" json:"version"`
}

type PrivacyConsentButtons struct {
	Decline string `yaml:"decline" json:"decline"`
	Accept  string `yaml:"accept" json:"accept"`
}

type PrivacyCookiesConfig struct {
	Essential   PrivacyCookieCategory    `yaml:"essential" json:"essential"`
	Preferences PrivacyCookieCategory    `yaml:"preferences" json:"preferences"`
	Analytics   PrivacyAnalyticsCategory `yaml:"analytics" json:"analytics"`
}

type PrivacyCookieCategory struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	Description string `yaml:"description" json:"description"`
}

type PrivacyAnalyticsCategory struct {
	Enabled                  bool   `yaml:"enabled" json:"enabled"`
	Description              string `yaml:"description" json:"description"`
	DescriptionSuffixNotSold string `yaml:"description_suffix_not_sold" json:"description_suffix_not_sold"`
	DescriptionSuffixSold    string `yaml:"description_suffix_sold" json:"description_suffix_sold"`
}

type PrivacyThirdPartyConfig struct {
	Services []PrivacyThirdPartyService `yaml:"services" json:"services"`
}

type PrivacyThirdPartyService struct {
	Name      string `yaml:"name" json:"name"`
	Purpose   string `yaml:"purpose" json:"purpose"`
	DataSent  string `yaml:"data_sent" json:"data_sent"`
	PolicyURL string `yaml:"policy_url" json:"policy_url"`
}

// TrustedProxyConfig controls which network peers may supply proxy headers.
type TrustedProxyConfig struct {
	Additional     []string `yaml:"additional"`
	ClientIPHeader string   `yaml:"client_ip_header"`
	ListenAddress  string   `yaml:"-"`
}

// Branding contains branding information
type Branding struct {
	Title       string          `yaml:"title"`
	Tagline     string          `yaml:"tagline"`
	Description string          `yaml:"description"`
	Content     BrandingContent `yaml:"content"`
}

type BrandingContent struct {
	About   string `yaml:"about"`
	Privacy string `yaml:"privacy"`
	Terms   string `yaml:"terms"`
}

// SEO contains SEO metadata
type SEO struct {
	Keywords []string `yaml:"keywords"`
}

// AdminConfig contains admin panel settings
type AdminConfig struct {
	Email string `yaml:"email"`
}

type NotificationConfig struct {
	Email EmailNotificationConfig `yaml:"email"`
}

type EmailNotificationConfig struct {
	SMTP SMTPConfig      `yaml:"smtp"`
	From EmailFromConfig `yaml:"from"`
}

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	TLS      string `yaml:"tls"`
}

type EmailFromConfig struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email"`
}

// ContactConfig contains notification recipients grouped by role.
type ContactConfig struct {
	Admin    ContactRoleConfig `yaml:"admin"`
	Security ContactRoleConfig `yaml:"security"`
	Abuse    ContactRoleConfig `yaml:"abuse"`
	General  ContactRoleConfig `yaml:"general"`
	DPO      DPOConfig         `yaml:"dpo"`
}

// ContactRoleConfig contains a role's email and webhook recipients.
type ContactRoleConfig struct {
	Email    string            `yaml:"email"`
	Webhooks map[string]string `yaml:"webhooks"`
}

// DPOConfig contains the public data protection contact.
type DPOConfig struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email"`
}

// PagesConfig contains configurable public page behavior.
type PagesConfig struct {
	Contact ContactPageConfig `yaml:"contact"`
	Help    HelpPageConfig    `yaml:"help"`
}

type HelpPageConfig struct {
	Content string `yaml:"content"`
	MCP     string `yaml:"mcp"`
}

// ContactPageConfig controls the public report form.
type ContactPageConfig struct {
	Enabled          bool                  `yaml:"enabled"`
	Captcha          string                `yaml:"captcha"`
	SuccessMessage   string                `yaml:"success_message"`
	CaptchaSiteKey   string                `yaml:"captcha_site_key"`
	CaptchaSecretKey string                `yaml:"captcha_secret_key"`
	Antispam         ContactAntispamConfig `yaml:"antispam"`
}

// ContactAntispamConfig controls the report form's server-side abuse checks.
type ContactAntispamConfig struct {
	Honeypot             bool     `yaml:"honeypot"`
	MinFillSeconds       int      `yaml:"min_fill_seconds"`
	MaxAgeSeconds        int      `yaml:"max_age_seconds"`
	ReviewMinSeconds     int      `yaml:"review_min_seconds"`
	ReviewMaxSeconds     int      `yaml:"review_max_seconds"`
	PerIP                int      `yaml:"per_ip"`
	PerEmail             int      `yaml:"per_email"`
	Global               int      `yaml:"global"`
	Window               string   `yaml:"window"`
	Strikes              int      `yaml:"strikes"`
	BanHours             int      `yaml:"ban_hours"`
	RejectMarkup         bool     `yaml:"reject_markup"`
	MaxLinks             int      `yaml:"max_links"`
	DuplicateWindowHours int      `yaml:"duplicate_window_hours"`
	BlockedWords         []string `yaml:"blocked_words"`
	BlockedEmailDomains  []string `yaml:"blocked_email_domains"`
}

// SSLConfig contains SSL/TLS settings
type SSLConfig struct {
	Enabled     bool              `yaml:"enabled"`
	Cert        string            `yaml:"cert"`
	Key         string            `yaml:"key"`
	MinVersion  string            `yaml:"min_version"`
	LetsEncrypt LetsEncryptConfig `yaml:"letsencrypt"`
}

// LetsEncryptConfig contains Let's Encrypt settings
type LetsEncryptConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Email     string `yaml:"email"`
	Challenge string `yaml:"challenge"` // http-01, tls-alpn-01, dns-01
	Staging   bool   `yaml:"staging"`
}

// Scheduler contains scheduler configuration
type Scheduler struct {
	Enabled  bool                     `yaml:"enabled"`
	Timezone string                   `yaml:"timezone"`
	Tasks    map[string]ScheduledTask `yaml:"tasks"`
}

// ScheduledTask represents a scheduled task configuration
type ScheduledTask struct {
	Enabled     bool   `yaml:"enabled"`
	Schedule    string `yaml:"schedule"`
	RetryOnFail bool   `yaml:"retry_on_fail"`
	RetryDelay  string `yaml:"retry_delay"`
	MaxAge      string `yaml:"max_age"`
	MaxSize     string `yaml:"max_size"`
	Retention   int    `yaml:"retention"`
	RenewBefore string `yaml:"renew_before"`
}

// RateLimit contains rate limiting settings
type RateLimit struct {
	Read         RateWindowLimit `yaml:"read"`
	Write        RateWindowLimit `yaml:"write"`
	Health       RateWindowLimit `yaml:"health"`
	Strict       RateWindowLimit `yaml:"strict"`
	AuthFailures RateWindowLimit `yaml:"auth_failures"`
	GlobalBurst  int             `yaml:"global_burst"`
	Auth         AuthRateLimits  `yaml:"auth"`
}

type RateWindowLimit struct {
	Requests int `yaml:"requests"`
	Window   int `yaml:"window"`
}

type AuthRateLimits struct {
	Login         RateWindowLimit `yaml:"login"`
	PasswordReset RateWindowLimit `yaml:"password_reset"`
	Registration  RateWindowLimit `yaml:"registration"`
}

// Database contains database configuration
type Database struct {
	Driver   string `yaml:"driver"` // file, sqlite, postgres, mysql, etc.
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Name     string `yaml:"name"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"sslmode"`
}

// CacheConfig describes the optional Valkey/Redis cache connection.
type CacheConfig struct {
	Type          string   `yaml:"type"`
	URL           string   `yaml:"url"`
	Host          string   `yaml:"host"`
	Port          int      `yaml:"port"`
	Username      string   `yaml:"username"`
	Password      string   `yaml:"password"`
	DB            int      `yaml:"db"`
	TLS           bool     `yaml:"tls"`
	TLSSkipVerify bool     `yaml:"tls_skip_verify"`
	TLSCA         string   `yaml:"tls_ca"`
	TLSCert       string   `yaml:"tls_cert"`
	TLSKey        string   `yaml:"tls_key"`
	PoolSize      int      `yaml:"pool_size"`
	MinIdle       int      `yaml:"min_idle"`
	Timeout       string   `yaml:"timeout"`
	Prefix        string   `yaml:"prefix"`
	TTL           string   `yaml:"ttl"`
	Cluster       bool     `yaml:"cluster"`
	ClusterNodes  []string `yaml:"cluster_nodes"`
}

// WebConfig contains web UI settings
type WebConfig struct {
	UI       UIConfig          `yaml:"ui"`
	CORS     string            `yaml:"cors"`
	Security WebSecurityConfig `yaml:"security"`
}

// ServerSecurityConfig contains server-side security report retention settings.
type ServerSecurityConfig struct {
	Reports SecurityReportsConfig `yaml:"reports"`
}

// SecurityReportsConfig controls how long closed disclosure reports are retained.
type SecurityReportsConfig struct {
	RetentionDays int `yaml:"retention_days"`
}

// WebSecurityConfig controls the public RFC 9116 security contact file.
type WebSecurityConfig struct {
	ReportURL     string `yaml:"report_url"`
	PublishPGPKey bool   `yaml:"publish_pgp_key"`
	Expires       string `yaml:"expires"`
	Policy        string `yaml:"policy"`
}

// UIConfig contains UI settings
type UIConfig struct {
	Theme string `yaml:"theme"` // light, dark, auto
}

// TestConfig contains speedtest-specific settings
type TestConfig struct {
	MaxConcurrent    int `yaml:"max_concurrent"`    // Max concurrent tests per IP
	MinInterval      int `yaml:"min_interval"`      // Minimum seconds between tests
	DefaultDuration  int `yaml:"default_duration"`  // Default test duration in seconds
	MaxThreads       int `yaml:"max_threads"`       // Max threads for multi-threaded tests
	ResultsRetention int `yaml:"results_retention"` // Days to keep test results (0=unlimited)
	ChunkSize        int `yaml:"chunk_size"`        // Data chunk size in bytes
	Timeout          int `yaml:"timeout"`           // Test timeout in seconds
}

// Default returns a config with sane defaults
func Default() *Config {
	availableLanguages := []string{"en", "es", "fr", "de", "it", "ar"}
	if registered, err := i18n.Supported(); err == nil {
		availableLanguages = make([]string, 0, len(registered))
		for _, locale := range registered {
			availableLanguages = append(availableLanguages, locale.Language)
		}
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	// Auto-detect optimal thread count based on CPU cores
	numCPU := runtime.NumCPU()
	maxThreads := numCPU
	if maxThreads < 4 {
		maxThreads = 4 // Minimum 4 threads for decent speed testing
	}
	if maxThreads > 16 {
		maxThreads = 16 // Cap at 16 per PART 36 validation
	}

	// Auto-detect chunk size based on thread count
	// More threads = smaller chunks for better parallelism
	chunkSize := 1048576 // Default 1MB
	if maxThreads <= 4 {
		chunkSize = 2097152 // 2MB for fewer threads
	} else if maxThreads >= 12 {
		chunkSize = 524288 // 512KB for many threads
	}

	return &Config{
		Server: ServerConfig{
			Port:    "", // Random port in 64xxx range
			FQDN:    hostname,
			Address: "[::]",
			Mode:    "production",
			I2P: I2PConfig{
				Enabled: DefaultI2PEnabled(), Expose: false, Binary: "", SAMAddress: "127.0.0.1:7656",
				VirtualPort: 80, InboundLength: 3, OutboundLength: 3, InboundQuantity: 5,
				OutboundQuantity: 5, SignatureType: 7, BootstrapTimeout: 300,
			},
			Tor: TorConfig{
				Expose: false, AllowUserPreference: true, MaxCircuits: 32, StartupTimeout: 60,
				CircuitTimeout: 60, BootstrapTimeout: 180, SafeLogging: true,
				MaxStreamsPerCircuit: 100, CloseCircuitOnStreamLimit: true,
				BandwidthRate: "1 MB", BandwidthBurst: "2 MB", MaxMonthlyBandwidth: "100 GB",
				NumIntroPoints: 3, VirtualPort: 80,
			},
			// Default admin path (PART 17).
			AdminPath:  "administration",
			APIVersion: "v1",
			Metrics: MetricsConfig{
				Enabled:         true,
				Root:            MetricsRootConfig{Enabled: true},
				IncludeSystem:   true,
				IncludeRuntime:  true,
				Loki:            MetricsLokiConfig{MaxEntries: 1000, MaxAge: "1h"},
				DurationBuckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
				SizeBuckets:     []int64{100, 1000, 10000, 100000, 1000000, 10000000},
			},
			Branding: Branding{
				Title:       "casspeed",
				Tagline:     "",
				Description: "",
			},
			SEO: SEO{
				Keywords: []string{},
			},
			User:           "auto",
			Group:          "auto",
			PIDFile:        true,
			Daemonize:      false,
			TrustedProxies: TrustedProxyConfig{ClientIPHeader: "auto"},
			Admin: AdminConfig{
				Email: fmt.Sprintf("admin@%s", hostname),
			},
			Contact: ContactConfig{
				Admin:    ContactRoleConfig{Email: fmt.Sprintf("admin@%s", hostname), Webhooks: map[string]string{}},
				Security: ContactRoleConfig{Email: fmt.Sprintf("security@%s", hostname), Webhooks: map[string]string{}},
				Abuse:    ContactRoleConfig{Webhooks: map[string]string{}},
				General:  ContactRoleConfig{Webhooks: map[string]string{}},
			},
			Pages: PagesConfig{Contact: ContactPageConfig{
				Enabled: true, Captcha: "simple", SuccessMessage: "Thank you for your message. We'll respond soon.",
				Antispam: ContactAntispamConfig{Honeypot: true, MinFillSeconds: 3, MaxAgeSeconds: 43200, ReviewMinSeconds: 2, ReviewMaxSeconds: 900, PerIP: 5, PerEmail: 3, Global: 60, Window: "1h", Strikes: 3, BanHours: 24, RejectMarkup: true, MaxLinks: 10, DuplicateWindowHours: 24},
			}},
			Notifications: NotificationConfig{Email: EmailNotificationConfig{
				SMTP: SMTPConfig{Port: 587, TLS: "auto"},
				From: EmailFromConfig{Name: "CasSpeed", Email: fmt.Sprintf("no-reply@%s", hostname)},
			}},
			SSL: SSLConfig{
				Enabled:    false,
				Cert:       "",
				Key:        "",
				MinVersion: "TLS1.2",
				LetsEncrypt: LetsEncryptConfig{
					Enabled:   false,
					Email:     fmt.Sprintf("admin@%s", hostname),
					Challenge: "http-01",
					Staging:   false,
				},
			},
			Scheduler: Scheduler{
				Enabled:  true,
				Timezone: "America/New_York",
				Tasks: map[string]ScheduledTask{
					"log_rotation": {
						Enabled:  true,
						Schedule: "0 0 * * *",
						MaxAge:   "30d",
						MaxSize:  "100MB",
					},
					"session_cleanup": {
						Enabled:  true,
						Schedule: "*/15 * * * *",
					},
					"token_cleanup": {
						Enabled:  true,
						Schedule: "*/15 * * * *",
					},
					"security_cleanup": {
						Enabled:  true,
						Schedule: "30 3 * * *",
					},
					"backup": {
						Enabled:   true,
						Schedule:  "0 2 * * *",
						Retention: 4,
					},
					"ssl_renewal": {
						Enabled:     true,
						Schedule:    "0 3 * * *",
						RenewBefore: "7d",
					},
					"health_check": {
						Enabled:  true,
						Schedule: "*/5 * * * *",
					},
				},
			},
			RateLimit: RateLimit{
				Read:         RateWindowLimit{Requests: 120, Window: 60},
				Write:        RateWindowLimit{Requests: 10, Window: 60},
				Health:       RateWindowLimit{Requests: 120, Window: 60},
				Strict:       RateWindowLimit{Requests: 10, Window: 900},
				AuthFailures: RateWindowLimit{Requests: 5, Window: 900},
				GlobalBurst:  240,
				Auth:         AuthRateLimits{Login: RateWindowLimit{Requests: 5, Window: 900}, PasswordReset: RateWindowLimit{Requests: 3, Window: 3600}, Registration: RateWindowLimit{Requests: 5, Window: 3600}},
			},
			Database: Database{
				Driver: "file",
			},
			Cache:    CacheConfig{Type: "memory", Host: "localhost", Port: 6379, TLS: false, TLSSkipVerify: true, PoolSize: 10, MinIdle: 2, Timeout: "5s", Prefix: "casspeed:", TTL: "1h", ClusterNodes: []string{}},
			I18n:     I18nConfig{DefaultLanguage: "en", AvailableLanguages: availableLanguages},
			Users:    UserConfig{Enabled: true, Registration: RegistrationConfig{Mode: "open", RequireEmailVerification: true, InviteExpirationDays: 7}, Roles: UserRolesConfig{Available: []string{"admin", "user"}, Default: "user", Permissions: map[string][]string{"admin": {"read", "write", "delete"}, "user": {"read", "own_profile", "own_api_tokens"}}}, Auth: UserAuthConfig{Allow2FA: true, PasswordMinLength: 8}},
			Security: ServerSecurityConfig{Reports: SecurityReportsConfig{RetentionDays: 365}},
			Privacy: PrivacyConfig{
				Data: PrivacyDataConfig{StoredOnServer: true, Sharing: []PrivacySharingRule{
					{Condition: "analytics", When: "Tracking configured (server.tracking.type set) AND user consents", Data: "Anonymized: page views, browser type, country"},
					{Condition: "email", When: "SMTP configured for sending emails", Data: "Email address, message content"},
					{Condition: "user_initiated", When: "User explicitly shares content", Data: "Whatever user chooses to share"},
				}},
				Retention:  PrivacyRetentionConfig{Period: "Account data is retained while your account is active. Upon account deletion, all personal data is permanently deleted within 30 days. Anonymized analytics data may be retained for up to 12 months.", ExportAvailable: true, DeletionAvailable: true},
				Consent:    PrivacyConsentConfig{ShowUntilAcknowledged: true, Message: "In accordance with the EU GDPR law this message is being displayed. We use cookies for essential site functionality and, with your consent, for preferences and analytics. Your data is stored on our servers and is never sold.", MessageIfSold: "In accordance with the EU GDPR law this message is being displayed. We use cookies for essential site functionality and, with your consent, for preferences and analytics. Your data may be shared with or sold to third parties as described in our Privacy Policy.", Policy: PrivacyPolicyLink{Text: "Privacy Policy", URL: "/server/privacy", Version: "1"}, Buttons: PrivacyConsentButtons{Decline: "Decline", Accept: "I Agree"}, Position: "bottom", ShowPreferences: true, PreferencesText: "Manage Preferences"},
				Cookies:    PrivacyCookiesConfig{Essential: PrivacyCookieCategory{Enabled: true, Description: "Required for the site to function. Includes session management, security tokens (CSRF), and authentication. These cookies are strictly necessary and cannot be disabled."}, Preferences: PrivacyCookieCategory{Enabled: true, Description: "Remember your settings such as theme (dark/light), language, and UI preferences. Without it nothing is saved and the defaults apply on each visit."}, Analytics: PrivacyAnalyticsCategory{Enabled: true, Description: "Help us understand how visitors use our site to improve the experience.", DescriptionSuffixNotSold: "Analytics data is anonymized and never sold.", DescriptionSuffixSold: "Analytics data may be shared with third parties."}},
				ThirdParty: PrivacyThirdPartyConfig{Services: []PrivacyThirdPartyService{}},
			},
			Tracking: TrackingConfig{Type: "none"},
		},
		Web: WebConfig{
			Security: WebSecurityConfig{
				ReportURL:     "https://github.com/webappsgo/casspeed/security/advisories/new",
				PublishPGPKey: true,
				Expires:       "1y",
			},
			UI: UIConfig{
				Theme: "dark",
			},
			CORS: "*",
		},
		Test: TestConfig{
			MaxConcurrent:    3,
			MinInterval:      5,
			DefaultDuration:  10,
			MaxThreads:       maxThreads,
			ResultsRetention: 30,
			ChunkSize:        chunkSize,
			Timeout:          60,
		},
	}
}

func applyI2PEnvironment(cfg *Config) error {
	value, exists := os.LookupEnv("I2P_ENABLED")
	if !exists {
		return nil
	}
	enabled, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("I2P_ENABLED must be a boolean")
	}
	cfg.Server.I2P.Enabled = enabled
	return nil
}

// Load reads configuration from file, merging with defaults
func Load(path string) (*Config, error) {
	cfg := Default()

	// If file doesn't exist, return defaults
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := applyI2PEnvironment(cfg); err != nil {
			return nil, err
		}
		if err := applyCacheEnvironment(cfg, filepath.Dir(path)); err != nil {
			return nil, err
		}
		applySMTPEnvironment(cfg)
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to inspect config file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("config path is not a regular file: %s", path)
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("failed to secure config directory: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, fmt.Errorf("failed to secure config file: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := applyI2PEnvironment(cfg); err != nil {
		return nil, err
	}
	if err := applyCacheEnvironment(cfg, filepath.Dir(path)); err != nil {
		return nil, err
	}
	applySMTPEnvironment(cfg)

	return cfg, nil
}

// applyCacheEnvironment seeds CACHE_URL only when no saved URL exists. A URL
// carrying credentials is persisted in secrets.yml and loaded from there.
func applyCacheEnvironment(cfg *Config, configDir string) error {
	cacheURL := strings.TrimSpace(cfg.Server.Cache.URL)
	secretsPath := filepath.Join(configDir, "secrets.yml")
	if data, err := os.ReadFile(secretsPath); err == nil {
		var secrets struct {
			Server struct {
				Cache struct {
					URL string `yaml:"url"`
				} `yaml:"cache"`
			} `yaml:"server"`
		}
		if yaml.Unmarshal(data, &secrets) == nil && secrets.Server.Cache.URL != "" {
			cacheURL = secrets.Server.Cache.URL
			cfg.Server.Cache.URL = cacheURL
		}
	}
	if cacheURL == "" {
		cacheURL = strings.TrimSpace(os.Getenv("CACHE_URL"))
		if cacheURL == "" {
			return nil
		}
		cfg.Server.Cache.URL = cacheURL
		if cacheURLHasCredential(cacheURL) {
			if err := persistSecretCacheURL(secretsPath, cacheURL); err != nil {
				return fmt.Errorf("persist cache URL in secrets.yml: %w", err)
			}
		}
	}
	if cacheURL != "" {
		if value := os.Getenv("CACHE_URL"); value != "" && value != cacheURL {
			fmt.Fprintln(os.Stderr, "CACHE_URL differs from the saved cache URL; ignoring the environment value")
		}
	}
	if parsed, err := url.Parse(cacheURL); err == nil {
		switch strings.ToLower(parsed.Scheme) {
		case "valkey", "redis":
			if cfg.Server.Cache.Type == "memory" || cfg.Server.Cache.Type == "none" || cfg.Server.Cache.Type == "" {
				cfg.Server.Cache.Type = strings.ToLower(parsed.Scheme)
			}
		case "valkeys", "rediss":
			if cfg.Server.Cache.Type == "memory" || cfg.Server.Cache.Type == "none" || cfg.Server.Cache.Type == "" {
				cfg.Server.Cache.Type = strings.TrimSuffix(strings.ToLower(parsed.Scheme), "s")
			}
			cfg.Server.Cache.TLS = true
		}
	}
	return nil
}

func cacheURLHasCredential(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if _, ok := parsed.User.Password(); ok {
		return true
	}
	query := parsed.Query()
	for _, key := range []string{"password", "pwd", "token", "authToken"} {
		if query.Get(key) != "" {
			return true
		}
	}
	return false
}

func persistSecretCacheURL(path, cacheURL string) error {
	values := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &values); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	server, ok := values["server"].(map[string]any)
	if !ok {
		server = map[string]any{}
		values["server"] = server
	}
	cache, ok := server["cache"].(map[string]any)
	if !ok {
		cache = map[string]any{}
		server["cache"] = cache
	}
	if existing, ok := cache["url"].(string); ok && existing != "" {
		return nil
	}
	cache["url"] = cacheURL
	data, err := yaml.Marshal(values)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".secrets-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func applySMTPEnvironment(cfg *Config) {
	smtp := &cfg.Server.Notifications.Email.SMTP
	from := &cfg.Server.Notifications.Email.From
	if value := os.Getenv("SMTP_HOST"); value != "" {
		smtp.Host = value
	}
	if value := os.Getenv("SMTP_PORT"); value != "" {
		if port, err := strconv.Atoi(value); err == nil && port > 0 && port <= 65535 {
			smtp.Port = port
		}
	}
	if value := os.Getenv("SMTP_USERNAME"); value != "" {
		smtp.Username = value
	}
	if value := os.Getenv("SMTP_PASSWORD"); value != "" {
		smtp.Password = value
	}
	if value := os.Getenv("SMTP_TLS"); value != "" {
		smtp.TLS = value
	}
	if value := os.Getenv("SMTP_FROM_NAME"); value != "" {
		from.Name = value
	}
	if value := os.Getenv("SMTP_FROM_EMAIL"); value != "" {
		from.Email = value
	}
}

// Save writes configuration to file
func Save(cfg *Config, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("failed to secure config directory: %w", err)
	}

	safeConfig := *cfg
	if cacheURLHasCredential(safeConfig.Server.Cache.URL) {
		safeConfig.Server.Cache.URL = ""
	}
	data, err := yaml.Marshal(&safeConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	temporary, err := os.CreateTemp(dir, ".server-config-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary config: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("failed to secure temporary config: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("failed to write config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("failed to sync config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("failed to close config: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("failed to replace config: %w", err)
	}
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

// Secrets contains generated installation secrets kept outside server.yml.
type Secrets struct {
	EncryptionKey          []byte
	EncryptionKeyVersion   int
	ServerToken            string
	MetricsTokens          map[string]string
	ServerTokenGenerated   bool
	EncryptionKeyGenerated bool
	MetricsTokensGenerated []string
}

// LoadOrCreateSecrets loads secrets.yml and atomically creates its AES key when absent.
func LoadOrCreateSecrets(path string) (*Secrets, error) {
	values := map[string]any{}
	data, err := os.ReadFile(path)
	changed := false
	if err == nil {
		if err := yaml.Unmarshal(data, &values); err != nil {
			return nil, fmt.Errorf("parse secrets file: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read secrets file: %w", err)
	}
	serverConfig, ok := values["server"].(map[string]any)
	if !ok {
		serverConfig = map[string]any{}
		values["server"] = serverConfig
	}
	serverToken, _ := serverConfig["token"].(string)
	generatedToken := false
	if serverToken == "" {
		const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		limit := big.NewInt(int64(len(alphabet)))
		var token strings.Builder
		token.WriteString("adm_")
		for range 32 {
			index, err := rand.Int(rand.Reader, limit)
			if err != nil {
				return nil, fmt.Errorf("generate operator token: %w", err)
			}
			token.WriteByte(alphabet[index.Int64()])
		}
		serverToken = token.String()
		serverConfig["token"] = serverToken
		changed = true
		generatedToken = true
	}
	if !validOperatorToken(serverToken) {
		return nil, fmt.Errorf("secrets file contains an invalid server.token")
	}
	metricsConfig, ok := serverConfig["metrics"].(map[string]any)
	if !ok {
		metricsConfig = map[string]any{}
		serverConfig["metrics"] = metricsConfig
	}
	metricsAuth, ok := metricsConfig["auth"].(map[string]any)
	if !ok {
		metricsAuth = map[string]any{}
		metricsConfig["auth"] = metricsAuth
	}
	metricsTokens, ok := metricsAuth["tokens"].(map[string]any)
	if !ok {
		metricsTokens = map[string]any{}
		metricsAuth["tokens"] = metricsTokens
	}
	resolvedMetricsTokens := make(map[string]string, 3)
	generatedMetricsTokens := make([]string, 0, 3)
	for _, name := range []string{"prometheus", "grafana", "loki"} {
		token, _ := metricsTokens[name].(string)
		if token == "" {
			var tokenErr error
			token, tokenErr = generatePrefixedToken("mtr_")
			if tokenErr != nil {
				return nil, fmt.Errorf("generate metrics %s token: %w", name, tokenErr)
			}
			metricsTokens[name] = token
			changed = true
			generatedMetricsTokens = append(generatedMetricsTokens, name)
		} else if !validMetricsToken(token) {
			return nil, fmt.Errorf("secrets file contains an invalid server.metrics.auth.tokens.%s", name)
		}
		resolvedMetricsTokens[name] = token
	}
	security, ok := values["security"].(map[string]any)
	if !ok {
		security = map[string]any{}
		values["security"] = security
	}
	encoded, _ := security["encryption_key"].(string)
	key, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	keyGenerated := false
	if encoded != "" && (decodeErr != nil || len(key) != 32) {
		return nil, fmt.Errorf("secrets file contains an invalid security.encryption_key")
	}
	if encoded == "" {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate encryption key: %w", err)
		}
		security["encryption_key"] = base64.StdEncoding.EncodeToString(key)
		changed = true
		keyGenerated = true
	}
	version := 1
	if configured, ok := security["encryption_key_version"].(int); ok && configured > 0 {
		version = configured
	} else if configured, ok := security["encryption_key_version"].(uint64); ok && configured > 0 {
		version = int(configured)
	} else {
		security["encryption_key_version"] = version
		changed = true
	}
	if changed {
		if err := writeSecretsAtomic(path, values); err != nil {
			return nil, err
		}
	} else if err := os.Chmod(path, 0600); err != nil {
		return nil, fmt.Errorf("secure secrets file permissions: %w", err)
	}
	return &Secrets{EncryptionKey: key, EncryptionKeyVersion: version, ServerToken: serverToken, MetricsTokens: resolvedMetricsTokens, ServerTokenGenerated: generatedToken, EncryptionKeyGenerated: keyGenerated, MetricsTokensGenerated: generatedMetricsTokens}, nil
}

func generatePrefixedToken(prefix string) (string, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	limit := big.NewInt(int64(len(alphabet)))
	var token strings.Builder
	token.WriteString(prefix)
	for range 32 {
		index, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		token.WriteByte(alphabet[index.Int64()])
	}
	return token.String(), nil
}

func validMetricsToken(token string) bool {
	if len(token) != len("mtr_")+32 || !strings.HasPrefix(token, "mtr_") {
		return false
	}
	for _, char := range token[len("mtr_"):] {
		if !strings.ContainsRune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", char) {
			return false
		}
	}
	return true
}

func validOperatorToken(token string) bool {
	if len(token) != len("adm_")+32 || !strings.HasPrefix(token, "adm_") {
		return false
	}
	for _, char := range token[len("adm_"):] {
		if !strings.ContainsRune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", char) {
			return false
		}
	}
	return true
}

func writeSecretsAtomic(path string, values map[string]any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create secrets directory: %w", err)
	}
	data, err := yaml.Marshal(values)
	if err != nil {
		return fmt.Errorf("encode secrets file: %w", err)
	}
	temporary, err := os.CreateTemp(dir, ".secrets-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary secrets file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary secrets file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write secrets file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync secrets file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close secrets file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install secrets file: %w", err)
	}
	return nil
}

// Validate checks configuration for errors
func (c *Config) Validate() error {
	c.normalizeI18n()
	if c.Server.APIVersion == "" {
		c.Server.APIVersion = "v1"
	}
	if c.Server.APIVersion != "v1" && c.Server.APIVersion != "v2" {
		return fmt.Errorf("server.api_version must be v1 or v2")
	}
	if err := ValidateTracking(&c.Server.Tracking); err != nil {
		return err
	}
	i2p := c.Server.I2P
	if i2p.VirtualPort < 1 || i2p.VirtualPort > 65535 {
		return fmt.Errorf("server.i2p.virtual_port must be between 1 and 65535")
	}
	if i2p.InboundLength < 0 || i2p.InboundLength > 7 || i2p.OutboundLength < 0 || i2p.OutboundLength > 7 {
		return fmt.Errorf("server.i2p inbound and outbound lengths must be between 0 and 7")
	}
	if i2p.InboundQuantity < 1 || i2p.InboundQuantity > 16 || i2p.OutboundQuantity < 1 || i2p.OutboundQuantity > 16 {
		return fmt.Errorf("server.i2p inbound and outbound quantities must be between 1 and 16")
	}
	if i2p.SignatureType != 0 && i2p.SignatureType != 7 {
		return fmt.Errorf("server.i2p.signature_type must be 0 or 7")
	}
	if i2p.BootstrapTimeout < 30 || i2p.BootstrapTimeout > 600 {
		return fmt.Errorf("server.i2p.bootstrap_timeout must be between 30 and 600 seconds")
	}
	if host, port, err := net.SplitHostPort(i2p.SAMAddress); err != nil || host == "" {
		return fmt.Errorf("server.i2p.sam_address must be a host:port address")
	} else if portNumber, err := strconv.Atoi(port); err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("server.i2p.sam_address port must be between 1 and 65535")
	}
	privacy := &c.Server.Privacy
	if privacy.Consent.Position != "top" && privacy.Consent.Position != "bottom" {
		return fmt.Errorf("server.privacy.consent.position must be top or bottom")
	}
	privacy.Cookies.Essential.Enabled = true
	if privacy.Consent.Policy.URL == "" {
		privacy.Consent.Policy.URL = "/server/privacy"
	}
	policyURL, policyErr := url.Parse(privacy.Consent.Policy.URL)
	if policyErr != nil || (policyURL.IsAbs() && policyURL.Scheme != "https" && policyURL.Scheme != "http") || (!policyURL.IsAbs() && !strings.HasPrefix(policyURL.Path, "/")) {
		return fmt.Errorf("server.privacy.consent.policy.url must be an absolute HTTP(S) URL or an absolute site path")
	}
	for index, service := range privacy.ThirdParty.Services {
		if strings.TrimSpace(service.Name) == "" || strings.TrimSpace(service.Purpose) == "" {
			return fmt.Errorf("server.privacy.third_party.services[%d] requires a name and purpose", index)
		}
		if service.PolicyURL != "" {
			serviceURL, err := url.Parse(service.PolicyURL)
			if err != nil || !serviceURL.IsAbs() || (serviceURL.Scheme != "https" && serviceURL.Scheme != "http") || serviceURL.Host == "" {
				return fmt.Errorf("server.privacy.third_party.services[%d].policy_url must be an absolute HTTP(S) URL", index)
			}
		}
	}
	if c.Server.Users.Registration.Mode != "open" && c.Server.Users.Registration.Mode != "private" {
		return fmt.Errorf("server.users.registration.mode must be open or private")
	}
	if len(c.Server.Users.Roles.Available) == 0 {
		c.Server.Users.Roles.Available = []string{"admin", "user"}
	}
	if c.Server.Users.Roles.Default == "" {
		c.Server.Users.Roles.Default = "user"
	}
	roles := make(map[string]struct{}, len(c.Server.Users.Roles.Available))
	for _, role := range c.Server.Users.Roles.Available {
		if role == "" || role != strings.ToLower(role) || strings.Trim(role, "abcdefghijklmnopqrstuvwxyz0123456789_-.") != "" {
			return fmt.Errorf("invalid server.users.roles.available value: %q", role)
		}
		if _, exists := roles[role]; exists {
			return fmt.Errorf("duplicate server.users.roles.available value: %q", role)
		}
		roles[role] = struct{}{}
	}
	if _, ok := roles[c.Server.Users.Roles.Default]; !ok {
		return fmt.Errorf("server.users.roles.default must be listed in available")
	}
	for role := range c.Server.Users.Roles.Permissions {
		if _, ok := roles[role]; !ok {
			return fmt.Errorf("permissions reference undefined user role: %q", role)
		}
	}
	if c.Server.Users.Auth.PasswordMinLength == 0 {
		c.Server.Users.Auth.PasswordMinLength = 8
	}
	if c.Server.Users.Auth.PasswordMinLength < 8 || c.Server.Users.Auth.PasswordMinLength > 1024 {
		return fmt.Errorf("server.users.auth.password_min_length must be between 8 and 1024")
	}
	// Validate mode
	if c.Server.Mode != "production" && c.Server.Mode != "development" {
		return fmt.Errorf("invalid mode: %s (must be 'production' or 'development')", c.Server.Mode)
	}
	cache := c.Server.Cache
	if cache.Type != "none" && cache.Type != "memory" && cache.Type != "valkey" && cache.Type != "redis" {
		return fmt.Errorf("invalid server.cache.type: %s", cache.Type)
	}
	if cache.URL != "" {
		parsed, err := url.Parse(cache.URL)
		if err != nil || parsed.Host == "" {
			return fmt.Errorf("invalid server.cache.url: use the URL form")
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "valkey" && scheme != "redis" && scheme != "valkeys" && scheme != "rediss" {
			return fmt.Errorf("invalid server.cache.url: use valkey://, redis://, valkeys://, or rediss://")
		}
		if (scheme == "valkeys" || scheme == "rediss") && !cache.TLS {
			c.Server.Cache.TLS = true
		}
	}
	if cache.Port < 1 || cache.Port > 65535 {
		return fmt.Errorf("server.cache.port must be between 1 and 65535")
	}
	if cache.DB < 0 || cache.PoolSize < 1 || cache.MinIdle < 0 || cache.MinIdle > cache.PoolSize {
		return fmt.Errorf("invalid server.cache pool or database settings")
	}
	if cache.Cluster && cache.DB != 0 {
		return fmt.Errorf("server.cache.db must be zero in cluster mode")
	}

	// Validate SSL min version
	if c.Server.SSL.MinVersion != "TLS1.2" && c.Server.SSL.MinVersion != "TLS1.3" {
		return fmt.Errorf("invalid ssl.min_version: %s (must be 'TLS1.2' or 'TLS1.3')", c.Server.SSL.MinVersion)
	}

	// Validate Let's Encrypt challenge
	validChallenges := map[string]bool{
		"http-01":     true,
		"tls-alpn-01": true,
		"dns-01":      true,
	}
	if !validChallenges[c.Server.SSL.LetsEncrypt.Challenge] {
		return fmt.Errorf("invalid letsencrypt.challenge: %s", c.Server.SSL.LetsEncrypt.Challenge)
	}

	// Validate test configuration
	if c.Test.MaxConcurrent < 1 {
		return fmt.Errorf("test.max_concurrent must be >= 1")
	}
	if c.Test.MinInterval < 0 {
		return fmt.Errorf("test.min_interval must be >= 0")
	}
	if c.Test.DefaultDuration < 1 {
		return fmt.Errorf("test.default_duration must be >= 1")
	}
	if c.Test.MaxThreads < 1 || c.Test.MaxThreads > 16 {
		return fmt.Errorf("test.max_threads must be between 1 and 16")
	}
	if c.Test.ChunkSize < 65536 || c.Test.ChunkSize > 10485760 {
		return fmt.Errorf("test.chunk_size must be between 64KB (65536) and 10MB (10485760)")
	}
	if c.Test.Timeout < 10 {
		return fmt.Errorf("test.timeout must be >= 10 seconds")
	}

	return nil
}

// ValidateTracking checks provider-specific analytics settings.
func ValidateTracking(cfg *TrackingConfig) error {
	if cfg.Type == "" || cfg.Type == "none" {
		cfg.Type = "none"
		return nil
	}
	switch cfg.Type {
	case "google":
		if !regexp.MustCompile(`^(UA-[0-9]+-[0-9]+|G-[A-Z0-9]+)$`).MatchString(cfg.ID) {
			return fmt.Errorf("invalid Google Analytics ID format")
		}
	case "matomo", "piwik":
		if _, err := strconv.Atoi(cfg.ID); err != nil {
			return fmt.Errorf("matomo/piwik ID must be an integer")
		}
		if cfg.URL == "" {
			return fmt.Errorf("matomo/piwik requires URL")
		}
	case "owa":
		if cfg.ID == "" || cfg.URL == "" {
			return fmt.Errorf("OWA requires site ID and URL")
		}
	case "fathom", "plausible":
		if cfg.ID == "" {
			return fmt.Errorf("%s requires an ID", cfg.Type)
		}
	case "umami":
		if !regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`).MatchString(cfg.ID) {
			return fmt.Errorf("invalid Umami website UUID")
		}
		if cfg.URL == "" {
			return fmt.Errorf("umami requires URL")
		}
	case "simple":
	case "cloudflare":
		if cfg.ID == "" {
			return fmt.Errorf("cloudflare Web Analytics requires beacon token")
		}
	default:
		return fmt.Errorf("unsupported tracking type %q", cfg.Type)
	}
	if cfg.URL != "" {
		parsed, err := url.Parse(cfg.URL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil {
			return fmt.Errorf("tracking URL must be an absolute HTTP(S) URL without credentials")
		}
	}
	return nil
}

func (c *Config) normalizeI18n() {
	locales, err := i18n.Supported()
	if err != nil {
		return
	}
	all := make([]string, 0, len(locales))
	known := make(map[string]bool, len(locales))
	for _, locale := range locales {
		all = append(all, locale.Language)
		known[locale.Language] = true
	}
	minimum := map[string]bool{"en": true, "es": true, "fr": true, "de": true, "it": true, "ar": true}
	filtered := make([]string, 0, len(c.Server.I18n.AvailableLanguages))
	seen := make(map[string]bool)
	for _, language := range c.Server.I18n.AvailableLanguages {
		if known[language] && !seen[language] {
			filtered = append(filtered, language)
			seen[language] = true
		}
	}
	valid := len(filtered) >= len(minimum)
	for language := range minimum {
		if !seen[language] {
			valid = false
		}
	}
	if !valid {
		fmt.Fprintln(os.Stderr, "invalid server.i18n.available_languages; using all embedded locales")
		filtered = all
	}
	defaultLanguage := strings.ToLower(strings.TrimSpace(c.Server.I18n.DefaultLanguage))
	if !seen[defaultLanguage] || !known[defaultLanguage] {
		fmt.Fprintln(os.Stderr, "invalid server.i18n.default_language; using en")
		defaultLanguage = "en"
	}
	c.Server.I18n.AvailableLanguages = filtered
	c.Server.I18n.DefaultLanguage = defaultLanguage
}

// ParseDuration parses duration strings like "30d", "2h", "15m"
func ParseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}

	unit := s[len(s)-1]
	value := s[:len(s)-1]

	var duration time.Duration
	switch unit {
	case 'd':
		days, err := time.ParseDuration(value + "h")
		if err != nil {
			return 0, err
		}
		duration = days * 24
	case 'h', 'm', 's':
		var err error
		duration, err = time.ParseDuration(s)
		if err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("invalid duration unit: %c", unit)
	}

	return duration, nil
}
