package i2p

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Provider identifies the router that hosts the eepsite.
type Provider string

const (
	ProviderNone Provider = "none"
	ProviderI2PD Provider = "i2pd"
	ProviderSAM  Provider = "sam"
)

// State is a safe-to-serialize lifecycle snapshot. Error contains only a
// sanitized operational message and never a SAM command or destination key.
type State struct {
	Enabled        bool      `json:"enabled"`
	Running        bool      `json:"running"`
	Status         string    `json:"status"`
	Provider       Provider  `json:"provider"`
	BinaryPath     string    `json:"binary_path,omitempty"`
	SAMAddress     string    `json:"sam_address,omitempty"`
	EepsiteAddress string    `json:"eepsite_address,omitempty"`
	BackendPort    int       `json:"backend_port,omitempty"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// Config holds the server.i2p configuration and the application-owned paths.
// A caller must start serving BackendListener before SAM forwarding is enabled.
type Config struct {
	Enabled          bool
	Expose           bool
	Binary           string
	SAMAddress       string
	VirtualPort      int
	InboundLength    int
	OutboundLength   int
	InboundQuantity  int
	OutboundQuantity int
	SignatureType    int
	BootstrapTimeout time.Duration
	ConfigDir        string
	DataDir          string
	LogDir           string
	Logger           *log.Logger
	BackendReady     func(net.Listener) error
	OnState          func(State)
}

// DefaultConfig returns runtime-safe I2P defaults. Enabled remains false; the
// application config loader decides whether its container default is enabled.
func DefaultConfig() Config {
	return Config{
		SAMAddress: "127.0.0.1:7656", VirtualPort: 80,
		InboundLength: 3, OutboundLength: 3, InboundQuantity: 5, OutboundQuantity: 5,
		SignatureType: 7, BootstrapTimeout: 300 * time.Second,
	}
}

// Manager starts I2P asynchronously so router bootstrap never delays HTTP
// listener startup. It owns the resulting provider until Close is called.
type Manager struct {
	mu            sync.RWMutex
	cfg           Config
	state         State
	service       *Service
	ctx           context.Context
	cancel        context.CancelFunc
	done          chan struct{}
	restart       chan struct{}
	attemptCancel context.CancelFunc
	attemptDone   chan struct{}
	doneOnce      sync.Once
	started       bool
}

// NewManager creates a stopped I2P manager.
func NewManager(parent context.Context, cfg Config) *Manager {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	status := "disabled"
	if cfg.Enabled {
		status = "starting"
	}
	return &Manager{cfg: cfg, state: State{Enabled: cfg.Enabled, Status: status, Provider: ProviderNone}, ctx: ctx, cancel: cancel, done: make(chan struct{}), restart: make(chan struct{}, 1)}
}

// Start returns immediately. Provider startup and SAM tunnel creation run in a
// managed goroutine and are bounded by the configured bootstrap timeout.
func (m *Manager) Start() error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = true
	if !m.cfg.Enabled {
		m.state = State{Enabled: false, Status: "disabled", Provider: ProviderNone}
	} else {
		m.state.Status = "starting"
	}
	m.mu.Unlock()
	go m.run()
	return nil
}

func (m *Manager) run() {
	defer m.doneOnce.Do(func() { close(m.done) })
	backoff := 5 * time.Second
	for {
		m.mu.RLock()
		cfg := m.cfg
		m.mu.RUnlock()
		if m.ctx.Err() != nil {
			return
		}
		if !cfg.Enabled {
			m.mu.Lock()
			m.state = State{Enabled: false, Status: "disabled", Provider: ProviderNone}
			m.mu.Unlock()
			select {
			case <-m.ctx.Done():
				return
			case <-m.restart:
				continue
			}
		}
		attemptCtx, attemptCancel := context.WithCancel(m.ctx)
		attemptDone := make(chan struct{})
		m.mu.Lock()
		m.attemptCancel = attemptCancel
		m.attemptDone = attemptDone
		m.mu.Unlock()
		onState := cfg.OnState
		cfg.OnState = func(state State) {
			m.mu.Lock()
			m.state = state
			m.mu.Unlock()
			if onState != nil {
				onState(state)
			}
		}
		svc, err := StartService(attemptCtx, cfg)
		close(attemptDone)
		if err == nil {
			m.mu.Lock()
			m.service = svc
			m.state = svc.State()
			m.mu.Unlock()
			select {
			case <-m.ctx.Done():
				_ = svc.Close()
				attemptCancel()
				m.clearAttempt()
				return
			case <-m.restart:
				_ = svc.Close()
				attemptCancel()
				m.clearAttempt()
				continue
			case <-svc.Done():
				_ = svc.Close()
				attemptCancel()
				m.clearAttempt()
				m.mu.Lock()
				m.service = nil
				m.state = State{Enabled: true, Status: "error", Provider: svc.State().Provider, Error: "I2P session lost"}
				m.mu.Unlock()
			}
			backoff = 5 * time.Second
		} else {
			attemptCancel()
			m.clearAttempt()
			select {
			case <-m.restart:
				continue
			default:
			}
			status := "error"
			enabled := true
			provider := ProviderNone
			var noProvider ErrNoProvider
			if errors.As(err, &noProvider) {
				status = "no_provider"
				enabled = false
			}
			var providerErr *providerStartupError
			if errors.As(err, &providerErr) {
				provider = providerErr.provider
			}
			m.mu.Lock()
			m.state = State{Enabled: enabled, Status: status, Provider: provider, Error: safeError(err)}
			logger := m.cfg.Logger
			m.mu.Unlock()
			if logger != nil {
				logger.Printf("WARN: I2P provider unavailable: %s", safeError(err))
			} else {
				log.Printf("WARN: I2P provider unavailable: %s", safeError(err))
			}
		}
		timer := time.NewTimer(backoff)
		select {
		case <-m.ctx.Done():
			timer.Stop()
			return
		case <-m.restart:
			timer.Stop()
			backoff = 5 * time.Second
		case <-timer.C:
		}
		if backoff < 300*time.Second {
			backoff *= 2
			if backoff > 300*time.Second {
				backoff = 300 * time.Second
			}
		}
	}
}

func (m *Manager) clearAttempt() {
	m.mu.Lock()
	m.attemptCancel = nil
	m.mu.Unlock()
}

// State returns a copy of the current lifecycle state.
func (m *Manager) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// EepsiteAddress returns the current address, or empty when the service is not running.
func (m *Manager) EepsiteAddress() string { return m.State().EepsiteAddress }

// UpdateConfig stops the current provider and applies settings asynchronously.
func (m *Manager) UpdateConfig(cfg Config) error {
	if cfg.Enabled {
		if err := validateConfig(cfg); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.cfg = cfg
	service, cancel := m.service, m.attemptCancel
	if cfg.Enabled {
		m.state = State{Enabled: true, Status: "starting", Provider: ProviderNone}
	} else {
		m.state = State{Enabled: false, Status: "disabled", Provider: ProviderNone}
	}
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if service != nil {
		_ = service.Close()
	}
	m.requestRestart()
	return nil
}

// RegenerateAddress discards the saved destination and waits for a replacement address.
func (m *Manager) RegenerateAddress(ctx context.Context) (string, error) {
	m.mu.RLock()
	cfg := m.cfg
	started := m.started
	m.mu.RUnlock()
	if !cfg.Enabled {
		return "", errors.New("I2P is disabled")
	}
	if !started {
		return "", errors.New("I2P manager has not been started")
	}
	m.mu.Lock()
	service, cancel := m.service, m.attemptCancel
	attemptDone := m.attemptDone
	m.service = nil
	m.state = State{Enabled: true, Status: "starting", Provider: ProviderNone}
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if service != nil {
		_ = service.Close()
	}
	if attemptDone != nil {
		select {
		case <-attemptDone:
		case <-time.After(15 * time.Second):
			return "", errors.New("timed out stopping I2P before key regeneration")
		}
	}
	if err := os.RemoveAll(filepath.Join(cfg.DataDir, "i2p", "site")); err != nil {
		return "", fmt.Errorf("remove old I2P destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "i2p", "site"), 0700); err != nil {
		return "", fmt.Errorf("create I2P destination directory: %w", err)
	}
	if err := os.Chmod(filepath.Join(cfg.DataDir, "i2p", "site"), 0700); err != nil {
		return "", err
	}
	m.requestRestart()
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := time.NewTimer(cfg.BootstrapTimeout + 70*time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		state := m.State()
		if state.Status == "running" && state.EepsiteAddress != "" {
			return state.EepsiteAddress, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline.C:
			return "", errors.New("timed out regenerating I2P destination")
		case <-ticker.C:
		}
	}
}

func (m *Manager) requestRestart() {
	select {
	case m.restart <- struct{}{}:
	default:
	}
}

// Close stops startup/retry work and closes the active provider.
func (m *Manager) Close() error {
	m.cancel()
	m.mu.Lock()
	svc := m.service
	m.service = nil
	attemptCancel := m.attemptCancel
	started := m.started
	m.mu.Unlock()
	if attemptCancel != nil {
		attemptCancel()
	}
	if !started {
		m.doneOnce.Do(func() { close(m.done) })
	}
	var err error
	if svc != nil {
		err = svc.Close()
	}
	select {
	case <-m.done:
	case <-time.After(15 * time.Second):
		if err == nil {
			err = errors.New("timed out stopping I2P manager")
		}
	}
	return err
}

// ErrNoProvider reports that neither a managed i2pd binary nor a reachable SAM bridge exists.
type ErrNoProvider struct{ Address string }

func (e ErrNoProvider) Error() string { return "no i2pd binary or reachable SAM bridge" }

type providerStartupError struct {
	provider Provider
	err      error
}

func (e *providerStartupError) Error() string { return e.err.Error() }
func (e *providerStartupError) Unwrap() error { return e.err }

// Service owns both SAM sockets, the backend listener and (for Model A) i2pd.
type Service struct {
	mu            sync.Mutex
	state         State
	listener      net.Listener
	control       net.Conn
	forward       net.Conn
	command       *exec.Cmd
	processDone   chan struct{}
	done          chan struct{}
	closed        bool
	doneOnce      sync.Once
	cancel        context.CancelFunc
	stopControl   func() bool
	stopForward   func() bool
	controlReader *bufio.Reader
	forwardReader *bufio.Reader
}

// Done closes when either live SAM socket is lost or the owned i2pd process exits.
func (s *Service) Done() <-chan struct{} { return s.done }

// State returns the service's current state.
func (s *Service) State() State { s.mu.Lock(); defer s.mu.Unlock(); return s.state }

// BackendListener returns the dedicated plain loopback listener.
func (s *Service) BackendListener() net.Listener { s.mu.Lock(); defer s.mu.Unlock(); return s.listener }

// Close tears down the forward socket, control socket, listener and owned i2pd process.
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	forward, control, listener, cmd, processDone := s.forward, s.control, s.listener, s.command, s.processDone
	cancel, stopControl, stopForward := s.cancel, s.stopControl, s.stopForward
	s.forward, s.control, s.listener = nil, nil, nil
	s.mu.Unlock()
	if stopForward != nil {
		stopForward()
	}
	if forward != nil {
		_ = forward.Close()
	}
	if stopControl != nil {
		stopControl()
	}
	if control != nil {
		_ = control.Close()
	}
	if cancel != nil {
		cancel()
	}
	if listener != nil {
		_ = listener.Close()
	}
	if cmd != nil {
		stopProcess(cmd, processDone)
	}
	s.signalDone()
	return nil
}

func (s *Service) signalDone() { s.doneOnce.Do(func() { close(s.done) }) }

// StartService synchronously creates an eepsite. Server startup should call it
// from a goroutine (Manager does this automatically).
func StartService(parent context.Context, cfg Config) (*Service, error) {
	if !cfg.Enabled {
		return nil, errors.New("I2P disabled")
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	success := false
	defer func() {
		if !success {
			cancel()
		}
	}()
	if cfg.SAMAddress == "" {
		cfg.SAMAddress = "127.0.0.1:7656"
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	provider, binary := resolveProvider(cfg)
	if provider == ProviderNone {
		return nil, ErrNoProvider{Address: cfg.SAMAddress}
	}
	reportState(cfg, State{Enabled: true, Status: "starting", Provider: provider, BinaryPath: binary, SAMAddress: cfg.SAMAddress})
	providerError := func(err error) error {
		if err == nil {
			return nil
		}
		return &providerStartupError{provider: provider, err: err}
	}
	if err := ensureDirs(cfg); err != nil {
		return nil, providerError(err)
	}
	listener, err := allocateBackendListener()
	if err != nil {
		return nil, providerError(fmt.Errorf("allocate I2P backend listener: %w", err))
	}
	svc := &Service{listener: listener, done: make(chan struct{})}
	backendPort := listener.Addr().(*net.TCPAddr).Port
	samAddress := cfg.SAMAddress
	if provider == ProviderI2PD {
		samAddress, svc.command, svc.processDone, err = startI2PD(ctx, cfg, binary)
		if err != nil {
			listener.Close()
			return nil, providerError(err)
		}
	}
	keysPath := filepath.Join(cfg.DataDir, "i2p", "site", "site-keys.dat")
	reportState(cfg, State{Enabled: true, Status: "building", Provider: provider, BinaryPath: binary, SAMAddress: samAddress, BackendPort: backendPort})
	control, forward, controlReader, forwardReader, address, stopControl, stopForward, err := createSession(ctx, cfg, samAddress, keysPath, backendPort, listener)
	if err != nil {
		_ = svc.Close()
		return nil, providerError(err)
	}
	svc.mu.Lock()
	svc.control, svc.forward, svc.controlReader, svc.forwardReader, svc.cancel = control, forward, controlReader, forwardReader, cancel
	svc.stopControl, svc.stopForward = stopControl, stopForward
	svc.mu.Unlock()
	svc.state = State{Enabled: true, Running: true, Status: "running", Provider: provider, BinaryPath: binary, SAMAddress: samAddress, EepsiteAddress: address, BackendPort: backendPort, StartedAt: time.Now().UTC()}
	reportState(cfg, svc.state)
	go svc.monitor()
	success = true
	return svc, nil
}

func reportState(cfg Config, state State) {
	if cfg.OnState != nil {
		cfg.OnState(state)
	}
}

func (s *Service) monitor() {
	s.mu.Lock()
	control, forward := s.control, s.forward
	controlReader, forwardReader := s.controlReader, s.forwardReader
	s.mu.Unlock()
	go watchSAMSocket(control, controlReader, s.done, s.signalDone)
	go watchSAMSocket(forward, forwardReader, s.done, s.signalDone)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-s.done:
			return
		case <-s.processDone:
			if s.command != nil {
				s.signalDone()
				return
			}
		case <-ticker.C:
			state := s.State()
			if !probeSAM(state.SAMAddress) {
				failures++
			} else {
				failures = 0
			}
			if failures >= 3 {
				s.signalDone()
				return
			}
		}
	}
}

func validateConfig(cfg Config) error {
	if cfg.Binary != "" {
		if _, err := exec.LookPath(cfg.Binary); err != nil {
			return errors.New("configured i2pd binary was not found or is not executable")
		}
	}
	if cfg.SAMAddress != "" {
		host, portText, err := net.SplitHostPort(cfg.SAMAddress)
		port, portErr := strconv.Atoi(portText)
		if err != nil || strings.TrimSpace(host) == "" || portErr != nil || port < 1 || port > 65535 {
			return errors.New("invalid I2P SAM address; expected host:port")
		}
	}
	if cfg.VirtualPort < 1 || cfg.VirtualPort > 65535 {
		return errors.New("invalid I2P virtual port")
	}
	if cfg.InboundLength < 0 || cfg.InboundLength > 7 || cfg.OutboundLength < 0 || cfg.OutboundLength > 7 {
		return errors.New("invalid I2P tunnel length")
	}
	if cfg.InboundQuantity < 1 || cfg.InboundQuantity > 16 || cfg.OutboundQuantity < 1 || cfg.OutboundQuantity > 16 {
		return errors.New("invalid I2P tunnel quantity")
	}
	if cfg.SignatureType != 0 && cfg.SignatureType != 7 {
		return errors.New("invalid I2P signature type")
	}
	if cfg.BootstrapTimeout < 30*time.Second || cfg.BootstrapTimeout > 600*time.Second {
		return errors.New("invalid I2P bootstrap timeout")
	}
	if cfg.ConfigDir == "" || cfg.DataDir == "" || cfg.LogDir == "" {
		return errors.New("I2P application directories are required")
	}
	return nil
}

// ValidateConfig validates the settings accepted by the I2P admin surface.
func ValidateConfig(cfg Config) error { return validateConfig(cfg) }

func resolveProvider(cfg Config) (Provider, string) {
	if cfg.Binary != "" {
		if path, err := exec.LookPath(cfg.Binary); err == nil {
			return ProviderI2PD, path
		}
	}
	for _, path := range []string{"/usr/bin/i2pd", "/usr/sbin/i2pd", "/usr/local/bin/i2pd", "/opt/homebrew/bin/i2pd"} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return ProviderI2PD, path
		}
	}
	if path, err := exec.LookPath("i2pd"); err == nil {
		return ProviderI2PD, path
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, _, err := dialSAM(ctx, cfg.SAMAddress); err == nil {
		_ = conn.Close()
		return ProviderSAM, ""
	}
	return ProviderNone, ""
}

func ensureDirs(cfg Config) error {
	for _, path := range []string{filepath.Join(cfg.ConfigDir, "i2p"), filepath.Join(cfg.DataDir, "i2p"), filepath.Join(cfg.DataDir, "i2p", "site")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("create I2P directory: %w", err)
		}
		if err := os.Chmod(path, 0700); err != nil {
			return fmt.Errorf("secure I2P directory: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Join(cfg.LogDir), 0700); err != nil {
		return fmt.Errorf("create I2P log directory: %w", err)
	}
	return nil
}

func allocateBackendListener() (net.Listener, error) {
	permutation := make([]int, 1000)
	for i := range permutation {
		permutation[i] = 64000 + i
	}
	// Fisher-Yates avoids a fixed first-port preference while the listener remains reserved.
	for i := len(permutation) - 1; i > 0; i-- {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		j := int(binary.BigEndian.Uint32(b[:]) % uint32(i+1))
		permutation[i], permutation[j] = permutation[j], permutation[i]
	}
	var last error
	for _, port := range permutation {
		listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return listener, nil
		}
		last = err
	}
	return nil, fmt.Errorf("no available I2P backend port: %w", last)
}

func safeError(err error) string {
	var noProvider ErrNoProvider
	if errors.As(err, &noProvider) {
		return "no I2P provider available"
	}
	message := err.Error()
	for _, secret := range []string{"PRIV=", "DESTINATION="} {
		if strings.Contains(message, secret) {
			return "I2P startup failed"
		}
	}
	return message
}
