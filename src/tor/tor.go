package tor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cretz/bine/tor"
)

// Config holds Tor configuration
type Config struct {
	Enabled      bool
	TorBinary    string // Path to tor binary (optional, uses PATH if empty)
	DataDir      string
	ControlPort  int
	SocksPort    int
	HiddenPort   int  // Local port to expose via hidden service
	VanityPrefix string
}

// Service manages Tor hidden service using bine library
type Service struct {
	config    *Config
	tor       *tor.Tor
	onion     *tor.OnionService
	onionAddr string
	mu        sync.RWMutex
	running   bool
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewService creates a new Tor service
func NewService(cfg *Config) *Service {
	return &Service{
		config:  cfg,
		running: false,
	}
}

// Start starts the Tor service with bine
func (s *Service) Start() error {
	if !s.config.Enabled {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	// Create Tor data directory
	torDataDir := filepath.Join(s.config.DataDir, "tor")
	if err := os.MkdirAll(torDataDir, 0700); err != nil {
		return fmt.Errorf("creating tor data directory: %w", err)
	}

	// Create context for Tor lifecycle
	s.ctx, s.cancel = context.WithCancel(context.Background())

	// Configure Tor start options
	startConf := &tor.StartConf{
		DataDir: torDataDir,
	}

	// Use specific binary if configured
	if s.config.TorBinary != "" {
		startConf.ExePath = s.config.TorBinary
	}

	// Start Tor
	var err error
	s.tor, err = tor.Start(s.ctx, startConf)
	if err != nil {
		return fmt.Errorf("starting tor: %w", err)
	}

	// Wait for Tor to be ready
	dialCtx, dialCancel := context.WithTimeout(s.ctx, 2*time.Minute)
	defer dialCancel()

	// Create hidden service
	listenConf := &tor.ListenConf{
		LocalPort: s.config.HiddenPort,
		RemotePorts: []int{80},
	}

	s.onion, err = s.tor.Listen(dialCtx, listenConf)
	if err != nil {
		s.tor.Close()
		return fmt.Errorf("creating hidden service: %w", err)
	}

	// Get onion address
	s.onionAddr = s.onion.ID + ".onion"
	s.running = true

	return nil
}

// Stop stops the Tor service
func (s *Service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	// Close onion service
	if s.onion != nil {
		s.onion.Close()
		s.onion = nil
	}

	// Close Tor instance
	if s.tor != nil {
		s.tor.Close()
		s.tor = nil
	}

	// Cancel context
	if s.cancel != nil {
		s.cancel()
	}

	s.running = false
	return nil
}

// Restart restarts the Tor service
func (s *Service) Restart() error {
	if err := s.Stop(); err != nil {
		return err
	}
	time.Sleep(time.Second) // Brief pause before restart
	return s.Start()
}

// GetOnionAddress returns the .onion address
func (s *Service) GetOnionAddress() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.onionAddr
}

// IsRunning returns whether Tor is running
func (s *Service) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetListener returns the onion service listener for accepting connections
func (s *Service) GetListener() net.Listener {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.onion == nil {
		return nil
	}
	return s.onion
}

// Status returns Tor status information
func (s *Service) Status() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := map[string]interface{}{
		"enabled": s.config.Enabled,
		"running": s.running,
	}

	if s.running {
		status["onion_address"] = s.onionAddr
		status["hidden_port"] = s.config.HiddenPort
	}

	return status
}

// GenerateVanityAddress generates a vanity .onion address
// Note: Vanity generation for v3 onions requires significant computation
// and is typically done offline with tools like mkp224o
func (s *Service) GenerateVanityAddress(prefix string) error {
	if prefix == "" {
		return fmt.Errorf("prefix cannot be empty")
	}

	// Validate prefix (v3 onion addresses use base32)
	prefix = strings.ToLower(prefix)
	for _, c := range prefix {
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			return fmt.Errorf("invalid prefix character: %c (must be a-z or 2-7)", c)
		}
	}

	// Vanity generation is computationally intensive
	// For production use, recommend using external tool mkp224o
	return fmt.Errorf("vanity address generation requires external tool mkp224o - see docs for instructions")
}

// CheckTorAvailable checks if Tor binary is available in PATH
func CheckTorAvailable() bool {
	paths := []string{
		"tor",
		"/usr/bin/tor",
		"/usr/local/bin/tor",
		"/opt/homebrew/bin/tor",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		// Also check if it's in PATH
		if path == "tor" {
			if lookPath, err := findInPath("tor"); err == nil && lookPath != "" {
				return true
			}
		}
	}
	return false
}

// findInPath searches for executable in PATH
func findInPath(name string) (string, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return "", fmt.Errorf("PATH not set")
	}

	separator := string(os.PathListSeparator)
	paths := strings.Split(pathEnv, separator)

	for _, dir := range paths {
		fullPath := filepath.Join(dir, name)
		if info, err := os.Stat(fullPath); err == nil {
			if info.Mode()&0111 != 0 { // Check if executable
				return fullPath, nil
			}
		}
	}

	return "", fmt.Errorf("not found in PATH")
}

// ParseHiddenServiceHostname reads hostname from a standard Tor hidden service directory
func ParseHiddenServiceHostname(dataDir string) (string, error) {
	path := filepath.Join(dataDir, "hidden_service", "hostname")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
