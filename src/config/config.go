package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete server configuration
type Config struct {
	Server ServerConfig `yaml:"server"`
	Web    WebConfig    `yaml:"web"`
	Test   TestConfig   `yaml:"test"`
}

// ServerConfig contains server settings
type ServerConfig struct {
	Port      interface{} `yaml:"port"` // Can be int, string (for dual), or empty (random)
	FQDN      string      `yaml:"fqdn"`
	Address   string      `yaml:"address"`
	Mode      string      `yaml:"mode"` // production or development
	AdminPath string      `yaml:"admin_path"` // Admin panel path (default: "admin")
	Branding  Branding    `yaml:"branding"`
	SEO       SEO         `yaml:"seo"`
	User      string      `yaml:"user"`
	Group     string      `yaml:"group"`
	PIDFile   bool        `yaml:"pidfile"`
	Daemonize bool        `yaml:"daemonize"`
	Admin     AdminConfig `yaml:"admin"`
	SSL       SSLConfig   `yaml:"ssl"`
	Scheduler Scheduler   `yaml:"scheduler"`
	RateLimit RateLimit   `yaml:"rate_limit"`
	Database  Database    `yaml:"database"`
}

// Branding contains branding information
type Branding struct {
	Title   string `yaml:"title"`
	Tagline string `yaml:"tagline"`
	Description string `yaml:"description"`
}

// SEO contains SEO metadata
type SEO struct {
	Keywords []string `yaml:"keywords"`
}

// AdminConfig contains admin panel settings
type AdminConfig struct {
	Email string `yaml:"email"`
}

// SSLConfig contains SSL/TLS settings
type SSLConfig struct {
	Enabled    bool              `yaml:"enabled"`
	Cert       string            `yaml:"cert"`
	Key        string            `yaml:"key"`
	MinVersion string            `yaml:"min_version"`
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
	Enabled bool                   `yaml:"enabled"`
	Tasks   map[string]ScheduledTask `yaml:"tasks"`
}

// ScheduledTask represents a scheduled task configuration
type ScheduledTask struct {
	Enabled      bool   `yaml:"enabled"`
	Schedule     string `yaml:"schedule"`
	RetryOnFail  bool   `yaml:"retry_on_fail"`
	RetryDelay   string `yaml:"retry_delay"`
	MaxAge       string `yaml:"max_age"`
	MaxSize      string `yaml:"max_size"`
	Retention    int    `yaml:"retention"`
	RenewBefore  string `yaml:"renew_before"`
}

// RateLimit contains rate limiting settings
type RateLimit struct {
	Enabled  bool `yaml:"enabled"`
	Requests int  `yaml:"requests"`
	Window   int  `yaml:"window"`
}

// Database contains database configuration
type Database struct {
	Driver   string `yaml:"driver"`   // file, sqlite, postgres, mysql, etc.
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Name     string `yaml:"name"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"sslmode"`
}

// WebConfig contains web UI settings
type WebConfig struct {
	UI   UIConfig `yaml:"ui"`
	CORS string   `yaml:"cors"`
}

// UIConfig contains UI settings
type UIConfig struct {
	Theme string `yaml:"theme"` // light, dark, auto
}

// TestConfig contains speedtest-specific settings
type TestConfig struct {
	MaxConcurrent    int    `yaml:"max_concurrent"`     // Max concurrent tests per IP
	MinInterval      int    `yaml:"min_interval"`       // Minimum seconds between tests
	DefaultDuration  int    `yaml:"default_duration"`   // Default test duration in seconds
	MaxThreads       int    `yaml:"max_threads"`        // Max threads for multi-threaded tests
	ResultsRetention int    `yaml:"results_retention"`  // Days to keep test results (0=unlimited)
	ChunkSize        int    `yaml:"chunk_size"`         // Data chunk size in bytes
	Timeout          int    `yaml:"timeout"`            // Test timeout in seconds
}

// Default returns a config with sane defaults
func Default() *Config {
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
			Port:      "",  // Random port in 64xxx range
			FQDN:      hostname,
			Address:   "[::]",
			Mode:      "production",
			AdminPath: "admin", // Default admin path (PART 17)
			Branding: Branding{
				Title:       "casspeed",
				Tagline:     "",
				Description: "",
			},
			SEO: SEO{
				Keywords: []string{},
			},
			User:      "auto",
			Group:     "auto",
			PIDFile:   true,
			Daemonize: false,
			Admin: AdminConfig{
				Email: fmt.Sprintf("admin@%s", hostname),
			},
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
				Enabled: true,
				Tasks: map[string]ScheduledTask{
					"log_rotation": {
						Enabled:  true,
						Schedule: "0 0 * * *",
						MaxAge:   "30d",
						MaxSize:  "100MB",
					},
					"session_cleanup": {
						Enabled:  true,
						Schedule: "@hourly",
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
				Enabled:  true,
				Requests: 120,
				Window:   60,
			},
			Database: Database{
				Driver: "file",
			},
		},
		Web: WebConfig{
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
			ResultsRetention: 90,
			ChunkSize:        chunkSize,
			Timeout:          60,
		},
	}
}

// Load reads configuration from file, merging with defaults
func Load(path string) (*Config, error) {
	cfg := Default()

	// If file doesn't exist, return defaults
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// Save writes configuration to file
func Save(cfg *Config, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// Validate checks configuration for errors
func (c *Config) Validate() error {
	// Validate mode
	if c.Server.Mode != "production" && c.Server.Mode != "development" {
		return fmt.Errorf("invalid mode: %s (must be 'production' or 'development')", c.Server.Mode)
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
