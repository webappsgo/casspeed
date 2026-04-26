package geoip

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Config holds GeoIP configuration
type Config struct {
	Enabled   bool
	DataDir   string
	DBPath    string
	UpdateURL string
}

// Location represents geographic location data
type Location struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
}

// Service manages GeoIP lookups
type Service struct {
	config *Config
	db     map[string]*Location
	mu     sync.RWMutex
}

var (
	instance *Service
	once     sync.Once
)

// GetService returns singleton GeoIP service instance
func GetService() *Service {
	once.Do(func() {
		instance = &Service{
			db: make(map[string]*Location),
		}
	})
	return instance
}

// Initialize sets up GeoIP service with configuration
func (s *Service) Initialize(cfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.config = cfg

	if !cfg.Enabled {
		return nil
	}

	// Load GeoIP database
	if err := s.loadDatabase(); err != nil {
		return fmt.Errorf("loading geoip database: %w", err)
	}

	return nil
}

// IsEnabled returns whether GeoIP functionality is available
func (s *Service) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config != nil && s.config.Enabled
}

// Lookup returns location information for an IP address
func (s *Service) Lookup(ip string) (*Location, error) {
	if !s.IsEnabled() {
		return nil, fmt.Errorf("geoip not enabled")
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Simplified lookup - real implementation would use IP ranges
	if loc, exists := s.db[ip]; exists {
		return loc, nil
	}

	// Return unknown location
	return &Location{
		IP:          ip,
		CountryCode: "XX",
		CountryName: "Unknown",
	}, nil
}

// UpdateDatabase downloads and updates the GeoIP database
func (s *Service) UpdateDatabase() error {
	if !s.IsEnabled() {
		return fmt.Errorf("geoip not enabled")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Download new database
	resp, err := http.Get(s.config.UpdateURL)
	if err != nil {
		return fmt.Errorf("downloading geoip database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Save to file
	tmpFile := s.config.DBPath + ".tmp"
	out, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("saving database: %w", err)
	}

	// Atomic replace
	if err := os.Rename(tmpFile, s.config.DBPath); err != nil {
		return fmt.Errorf("replacing database: %w", err)
	}

	// Reload database
	return s.loadDatabase()
}

// loadDatabase loads GeoIP database from disk
func (s *Service) loadDatabase() error {
	dbPath := s.config.DBPath
	if dbPath == "" {
		dbPath = filepath.Join(s.config.DataDir, "geoip", "geoip.json")
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return err
	}

	// Check if database exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// Database doesn't exist - create empty one
		s.db = make(map[string]*Location)
		return nil
	}

	data, err := os.ReadFile(dbPath)
	if err != nil {
		return err
	}

	var locations []*Location
	if err := json.Unmarshal(data, &locations); err != nil {
		return err
	}

	// Build lookup map
	s.db = make(map[string]*Location)
	for _, loc := range locations {
		s.db[loc.IP] = loc
	}

	return nil
}

// GetCountryName returns country name for country code
func GetCountryName(code string) string {
	countries := map[string]string{
		"US": "United States",
		"GB": "United Kingdom",
		"CA": "Canada",
		"AU": "Australia",
		"DE": "Germany",
		"FR": "France",
		"JP": "Japan",
		"CN": "China",
		"IN": "India",
		"BR": "Brazil",
		"XX": "Unknown",
	}

	if name, exists := countries[strings.ToUpper(code)]; exists {
		return name
	}

	return code
}

// IsPrivateIP checks if an IP is private/local
func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check for private ranges
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(parsedIP) {
			return true
		}
	}

	return false
}
