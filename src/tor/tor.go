package tor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cretz/bine/control"
	"github.com/pires/go-proxyproto"
	"golang.org/x/net/proxy"
)

type Config struct {
	Enabled          bool
	TorBinary        string
	ConfigDir        string
	DataDir          string
	LogDir           string
	StartupTimeout   time.Duration
	BootstrapTimeout time.Duration
	VirtualPort      int
	// HiddenPort supports the previous package API.
	HiddenPort                int
	MaxCircuits               int
	CircuitTimeout            int
	SafeLogging               bool
	MaxStreamsPerCircuit      int
	CloseCircuitOnStreamLimit bool
	BandwidthRate             string
	BandwidthBurst            string
	MaxMonthlyBandwidth       string
	NumIntroPoints            int
	ContactEmail              string
	UseNetwork                bool
	AllowUserPreference       bool
	VanityPrefix              string
}

type State struct {
	Enabled        bool      `json:"enabled"`
	Running        bool      `json:"running"`
	Status         string    `json:"status"`
	Hostname       string    `json:"hostname,omitempty"`
	Binary         string    `json:"binary,omitempty"`
	Version        string    `json:"version,omitempty"`
	CircuitsActive int       `json:"circuits_active"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	Error          string    `json:"error,omitempty"`
}

type Service struct {
	mu             sync.RWMutex
	cfg            Config
	cmd            *exec.Cmd
	binary         string
	version        string
	circuitsActive int
	ctrl           *control.Conn
	controlConn    net.Conn
	events         chan control.Event
	controlErr     chan error
	onionAddr      string
	backend        net.Listener
	socksAddr      string
	torHTTPClient  *http.Client
	torTransport   *http.Transport
	running        bool
	ctx            context.Context
	cancel         context.CancelFunc
	procCancel     context.CancelFunc
	done           chan struct{}
	bootstrapped   bool
}

type Manager struct {
	mu       sync.RWMutex
	cfg      Config
	service  *Service
	state    State
	callback func(State)
	closed   bool
	ctx      context.Context
	cancel   context.CancelFunc
}

// CircuitIDFromConn returns the opaque Tor rendezvous circuit identifier parsed
// from Tor's PROXY protocol header. The value is not a client IP address.
func CircuitIDFromConn(conn net.Conn) string {
	if wrapped, ok := conn.(*proxyConn); ok {
		return wrapped.CircuitID
	}
	return ""
}

func NewManager(ctx context.Context, cfg Config, callback func(State)) *Manager {
	if ctx == nil {
		ctx = context.Background()
	}
	managerCtx, cancel := context.WithCancel(ctx)
	return &Manager{cfg: cfg, callback: callback, state: State{Enabled: cfg.Enabled, Status: "disabled"}, ctx: managerCtx, cancel: cancel}
}

func (m *Manager) Start() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("tor manager is closed")
	}
	if !m.cfg.Enabled {
		m.state = State{Enabled: false, Status: "disabled"}
		state := m.state
		m.mu.Unlock()
		m.publish(state)
		return nil
	}
	m.state = State{Enabled: true, Status: "starting"}
	cfg := m.cfg
	m.mu.Unlock()
	m.publish(State{Enabled: true, Status: "starting"})
	go m.start(cfg)
	return nil
}

func (m *Manager) start(cfg Config) {
	m.mu.RLock()
	ctx := m.ctx
	m.mu.RUnlock()
	svc, err := startTor(ctx, cfg)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		if svc != nil {
			_ = svc.Close()
		}
		return
	}
	if err != nil {
		m.service = nil
		state := State{Enabled: true, Status: "unavailable", Error: safeTorError(err)}
		if strings.Contains(strings.ToLower(err.Error()), "tor binary not found") {
			state = State{Enabled: false, Status: "disabled"}
		}
		m.state = state
		m.mu.Unlock()
		log.Printf("WARN: Tor hidden service unavailable: %s", safeTorError(err))
		m.publish(state)
		return
	}
	m.service = svc
	state := State{Enabled: true, Running: true, Status: "starting", Hostname: svc.OnionAddress(), Binary: svc.binary, Version: svc.version, CircuitsActive: svc.circuitsActive, StartedAt: time.Now().UTC()}
	m.state = state
	m.mu.Unlock()
	m.publish(state)
	go m.monitorBootstrap(svc, cfg)
	go m.monitorService(svc, cfg)
}

func (m *Manager) monitorService(svc *Service, cfg Config) {
	select {
	case <-svc.done:
		if svc.ctx.Err() == nil {
			m.recoverService(svc, cfg, "Tor process stopped")
		}
	case err := <-svc.controlErr:
		if svc.ctx.Err() == nil {
			reason := "Tor control connection stopped"
			if err != nil {
				reason = safeTorError(err)
			}
			m.recoverService(svc, cfg, reason)
		}
	case <-svc.ctx.Done():
	}
}

func (m *Manager) recoverService(svc *Service, cfg Config, reason string) {
	_ = svc.Close()
	m.mu.Lock()
	if m.service != svc || m.closed {
		m.mu.Unlock()
		return
	}
	m.service = nil
	state := State{Enabled: true, Status: "unavailable", Binary: svc.binary, Version: svc.version, Error: reason}
	m.state = state
	m.mu.Unlock()
	m.publish(state)
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-m.ctx.Done():
		return
	case <-timer.C:
	}
	m.mu.Lock()
	if !m.closed {
		state = State{Enabled: true, Status: "starting"}
		m.state = state
		m.mu.Unlock()
		m.publish(state)
		go m.start(cfg)
	} else {
		m.mu.Unlock()
	}
}

func (m *Manager) monitorBootstrap(svc *Service, cfg Config) {
	type hostnameResult struct {
		address string
		err     error
	}
	hostnameReady := make(chan hostnameResult, 1)
	bootstrapReady := make(chan error, 1)
	hostnamePath := filepath.Join(cfg.DataDir, "tor", "site", "hostname")
	go func() {
		address, err := waitHostname(svc.ctx, svc.done, hostnamePath, cfg.BootstrapTimeout)
		hostnameReady <- hostnameResult{address: address, err: err}
	}()
	if svc.bootstrapped {
		bootstrapReady <- nil
	} else {
		go func() { bootstrapReady <- bootstrapTor(svc.ctx, svc.events, svc.done, cfg.BootstrapTimeout) }()
	}
	address := svc.OnionAddress()
	bootstrapped := false
	hostnameSeen := address != ""
	var bootstrapErr, hostnameErr error
	for !bootstrapped || !hostnameSeen {
		select {
		case result := <-hostnameReady:
			hostnameReady = nil
			if result.err != nil {
				hostnameErr = result.err
			} else {
				address = result.address
				hostnameSeen = true
				svc.setOnionAddress(address)
				if err := secureTorFile(filepath.Join(filepath.Dir(hostnamePath), "hostname")); err != nil {
					hostnameErr = err
				} else {
					for _, name := range []string{"hs_ed25519_secret_key", "hs_ed25519_public_key"} {
						if fileErr := secureTorFile(filepath.Join(filepath.Dir(hostnamePath), name)); fileErr != nil {
							hostnameErr = fileErr
							break
						}
					}
				}
			}
			m.updateServiceState(svc, bootstrapped, address, bootstrapErr, hostnameErr)
		case err := <-bootstrapReady:
			bootstrapReady = nil
			if err == nil {
				bootstrapped = true
				m.updateServiceState(svc, bootstrapped, address, nil, hostnameErr)
				go waitFirstDescriptor(svc.ctx, svc.events)
			} else {
				bootstrapErr = err
				m.updateServiceState(svc, false, address, bootstrapErr, hostnameErr)
			}
		case <-svc.done:
			return
		case <-svc.ctx.Done():
			return
		}
	}
	m.updateServiceState(svc, bootstrapped, address, bootstrapErr, hostnameErr)
}

func (m *Manager) updateServiceState(svc *Service, bootstrapped bool, hostname string, bootstrapErr, hostnameErr error) {
	state := State{Enabled: true, Running: true, Status: "starting", Hostname: hostname, Binary: svc.binary, Version: svc.version, CircuitsActive: svc.circuitsActive}
	if bootstrapErr != nil || hostnameErr != nil {
		state.Status = "unavailable"
		if bootstrapErr != nil {
			state.Error = safeTorError(bootstrapErr)
		} else {
			state.Error = safeTorError(hostnameErr)
		}
	} else if bootstrapped && hostname != "" {
		state.Status = "healthy"
	}
	m.mu.Lock()
	if m.closed || m.service != svc {
		m.mu.Unlock()
		return
	}
	if !m.state.StartedAt.IsZero() {
		state.StartedAt = m.state.StartedAt
	} else {
		state.StartedAt = time.Now().UTC()
	}
	m.state = state
	m.mu.Unlock()
	m.publish(state)
}

func waitFirstDescriptor(ctx context.Context, events <-chan control.Event) {
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			log.Printf("WARN: Tor hidden service descriptor was not uploaded within 60 seconds")
			return
		case event := <-events:
			if descriptor, ok := event.(*control.HSDescEvent); ok && descriptor.Action == "UPLOADED" {
				return
			}
		}
	}
}

func (m *Manager) publish(state State) {
	if m.callback != nil {
		m.callback(state)
	}
}
func (m *Manager) State() State { m.mu.RLock(); defer m.mu.RUnlock(); return m.state }
func (m *Manager) OnionAddress() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.service == nil {
		return ""
	}
	return m.service.OnionAddress()
}
func (m *Manager) Listener() net.Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.service == nil {
		return nil
	}
	return m.service.Listener()
}
func (m *Manager) GetHTTPClient(useTor bool) *http.Client {
	if !useTor {
		return &http.Client{Timeout: 30 * time.Second}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: managerRoundTripper{manager: m}}
}

type managerRoundTripper struct{ manager *Manager }

func (t managerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.manager == nil {
		return nil, errors.New("tor manager is unavailable")
	}
	t.manager.mu.RLock()
	service := t.manager.service
	t.manager.mu.RUnlock()
	if service == nil {
		return nil, errors.New("tor outbound proxy is unavailable")
	}
	client := service.GetHTTPClient(true)
	if client.Transport == nil {
		return nil, errors.New("tor outbound proxy is unavailable")
	}
	return client.Transport.RoundTrip(request)
}

func ShouldUseTor(cfg *Config, userPreference *bool) bool {
	if cfg == nil {
		return false
	}
	if !cfg.AllowUserPreference {
		return cfg.UseNetwork
	}
	if userPreference == nil {
		return cfg.UseNetwork
	}
	return *userPreference
}

func (m *Manager) RegenerateAddress() (string, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return "", errors.New("tor manager is closed")
	}
	old := m.service
	cfg := m.cfg
	m.service = nil
	ctx := m.ctx
	m.state = State{Enabled: true, Status: "starting"}
	m.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	if err := os.RemoveAll(filepath.Join(cfg.DataDir, "tor", "site")); err != nil {
		return "", fmt.Errorf("remove old Tor hidden service identity: %w", err)
	}
	svc, err := startTor(ctx, cfg)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = svc.Close()
		return "", errors.New("tor manager was closed during address regeneration")
	}
	m.service = svc
	m.state = State{Enabled: true, Running: true, Status: "starting", Hostname: svc.OnionAddress(), Binary: svc.binary, Version: svc.version, CircuitsActive: svc.circuitsActive, StartedAt: time.Now().UTC()}
	state := m.state
	m.mu.Unlock()
	m.publish(state)
	go m.monitorBootstrap(svc, cfg)
	go m.monitorService(svc, cfg)
	return svc.OnionAddress(), nil
}

func (m *Manager) ApplyVanityCandidate(vanity *VanityManager, address string) error {
	if vanity == nil {
		return errors.New("tor vanity manager is unavailable")
	}
	m.mu.RLock()
	cfg, closed := m.cfg, m.closed
	m.mu.RUnlock()
	if closed {
		return errors.New("tor manager is closed")
	}
	startTimeout := cfg.StartupTimeout + cfg.BootstrapTimeout + 30*time.Second
	if startTimeout <= 0 {
		startTimeout = 10 * time.Minute
	}
	stop := func() error {
		m.mu.Lock()
		current := m.service
		m.service = nil
		m.state = State{Enabled: true, Status: "starting"}
		m.mu.Unlock()
		if current != nil {
			return current.Close()
		}
		return nil
	}
	start := func() (string, error) {
		if err := m.Restart(); err != nil {
			return "", err
		}
		deadline := time.NewTimer(startTimeout)
		defer deadline.Stop()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			state := m.State()
			if state.Running && state.Hostname != "" {
				return state.Hostname, nil
			}
			if state.Status == "disabled" || state.Status == "unavailable" {
				return "", errors.New("tor did not become healthy with the candidate identity")
			}
			select {
			case <-m.ctx.Done():
				return "", m.ctx.Err()
			case <-deadline.C:
				return "", errors.New("timed out waiting for Tor to publish the candidate identity")
			case <-ticker.C:
			}
		}
	}
	return vanity.ApplyCandidate(address, filepath.Join(cfg.DataDir, "tor", "site"), stop, start)
}

func (m *Manager) Close() error {
	m.mu.Lock()
	m.closed = true
	svc := m.service
	m.service = nil
	cancel := m.cancel
	m.mu.Unlock()
	var err error
	if svc != nil {
		err = svc.Close()
	}
	if cancel != nil {
		cancel()
	}
	return err
}

func (m *Manager) Restart() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("tor manager is closed")
	}
	cfg, old := m.cfg, m.service
	m.service = nil
	m.state = State{Enabled: cfg.Enabled, Status: "starting"}
	m.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	if !cfg.Enabled {
		m.mu.Lock()
		m.state = State{Status: "disabled"}
		m.mu.Unlock()
		m.publish(State{Status: "disabled"})
		return nil
	}
	go m.start(cfg)
	m.publish(State{Enabled: true, Status: "starting"})
	return nil
}

func (m *Manager) UpdateConfig(cfg Config) error {
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
	return m.Restart()
}

func startTor(parent context.Context, cfg Config) (*Service, error) {
	if !cfg.Enabled {
		return nil, errors.New("tor is disabled")
	}
	binary, err := resolveTorBinary(cfg.TorBinary)
	if err != nil {
		return nil, err
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	for _, dir := range []string{filepath.Join(cfg.ConfigDir, "tor"), filepath.Join(cfg.DataDir, "tor"), filepath.Join(cfg.DataDir, "tor", "site")} {
		if dir == "tor" || dir == "" {
			return nil, errors.New("tor application directories are required")
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create Tor directory: %w", err)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return nil, fmt.Errorf("secure Tor directory: %w", err)
		}
	}
	hsDir := filepath.Join(cfg.DataDir, "tor", "site")
	if err := os.MkdirAll(cfg.LogDir, 0700); err != nil {
		return nil, fmt.Errorf("create Tor log directory: %w", err)
	}
	if err := os.Chmod(cfg.LogDir, 0700); err != nil {
		return nil, fmt.Errorf("secure Tor log directory: %w", err)
	}
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("allocate Tor backend listener: %w", err)
	}
	backendPort := backend.Addr().(*net.TCPAddr).Port
	confPath := filepath.Join(cfg.ConfigDir, "tor", "torrc")
	content := renderTorConfig(cfg, filepath.Join(cfg.DataDir, "tor"), hsDir, backendPort, os.Getpid())
	if err := writePrivateFile(confPath, []byte(content)); err != nil {
		backend.Close()
		return nil, err
	}
	controlPortPath := filepath.Join(cfg.DataDir, "tor", "control_port")
	for _, stale := range []string{controlPortPath, filepath.Join(cfg.DataDir, "tor", "control_auth_cookie"), filepath.Join(cfg.DataDir, "tor", "socks_port")} {
		if err := os.Remove(stale); err != nil && !os.IsNotExist(err) {
			backend.Close()
			return nil, fmt.Errorf("remove stale Tor runtime file: %w", err)
		}
	}
	ctx, cancel := context.WithCancel(parent)
	logFile, err := os.OpenFile(filepath.Join(cfg.LogDir, "tor.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		backend.Close()
		cancel()
		return nil, fmt.Errorf("open Tor log: %w", err)
	}
	if err := logFile.Chmod(0600); err != nil {
		logFile.Close()
		backend.Close()
		cancel()
		return nil, fmt.Errorf("secure Tor log: %w", err)
	}
	cmd := exec.CommandContext(ctx, binary, "-f", confPath)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		backend.Close()
		cancel()
		return nil, fmt.Errorf("start dedicated Tor process: %w", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); _ = logFile.Close(); close(done) }()
	timeout := cfg.StartupTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	controlAddr, cookiePath, err := waitControlPort(ctx, done, controlPortPath, timeout)
	if err != nil {
		stopProcess(cmd, done, cancel)
		backend.Close()
		return nil, fmt.Errorf("tor control port (torrc %s): %w", confPath, err)
	}
	for _, path := range []string{filepath.Join(cfg.DataDir, "tor", "control_port"), cookiePath, filepath.Join(cfg.DataDir, "tor", "tor.pid")} {
		if err := secureTorFile(path); err != nil {
			stopProcess(cmd, done, cancel)
			backend.Close()
			return nil, fmt.Errorf("secure Tor runtime file: %w", err)
		}
	}
	controlConn, torControl, events, err := dialTorControl(ctx, controlAddr, timeout)
	if err != nil {
		stopProcess(cmd, done, cancel)
		backend.Close()
		return nil, fmt.Errorf("authenticate Tor control port: %w", err)
	}
	if err := torControl.AddEventListener(events, control.EventCodeStatusClient, control.EventCodeHSDesc); err != nil {
		torControl.Close()
		stopProcess(cmd, done, cancel)
		backend.Close()
		return nil, fmt.Errorf("subscribe to Tor startup events: %w", err)
	}
	version, circuits, bootstrapped := torRuntimeDetails(torControl)
	if err := torControl.SetConf(&control.KeyVal{Key: "DisableNetwork", Val: "0"}); err != nil {
		torControl.Close()
		stopProcess(cmd, done, cancel)
		backend.Close()
		return nil, fmt.Errorf("enable Tor network: %w", err)
	}
	_ = controlConn.SetDeadline(time.Time{})
	hostname, _ := readHostname(filepath.Join(hsDir, "hostname"))
	if hostname != "" {
		for _, name := range []string{"hostname", "hs_ed25519_secret_key", "hs_ed25519_public_key"} {
			if err := secureTorFile(filepath.Join(hsDir, name)); err != nil {
				torControl.Close()
				stopProcess(cmd, done, cancel)
				backend.Close()
				return nil, fmt.Errorf("secure Tor hidden-service file: %w", err)
			}
		}
	}
	socksAddr := ""
	if cfg.UseNetwork || cfg.AllowUserPreference {
		socksAddr, _ = torSocksAddress(torControl)
	}
	svcCtx, svcCancel := context.WithCancel(ctx)
	controlErr := make(chan error, 1)
	svc := &Service{cfg: cfg, cmd: cmd, binary: binary, version: version, circuitsActive: circuits, ctrl: torControl, controlConn: controlConn, events: events, controlErr: controlErr, onionAddr: hostname, backend: backend, socksAddr: socksAddr, running: true, ctx: svcCtx, cancel: svcCancel, procCancel: cancel, done: done, bootstrapped: bootstrapped}
	go func() { controlErr <- torControl.HandleEvents(svcCtx) }()
	return svc, nil
}

func torSocksAddress(client *control.Conn) (string, error) {
	values, err := client.GetInfo("net/listeners/socks")
	if err != nil {
		return "", err
	}
	for _, value := range values {
		if value == nil || value.Key != "net/listeners/socks" {
			continue
		}
		if address, err := parseTorSocksListeners(value.Val); err == nil {
			return address, nil
		}
	}
	return "", errors.New("tor did not report a loopback SOCKS listener")
}

func parseTorSocksListeners(value string) (string, error) {
	for _, candidate := range strings.Split(value, `"`) {
		candidate = strings.Trim(candidate, " \t\r\n,")
		if candidate == "" || candidate == "[" || candidate == "]" {
			continue
		}
		host, port, err := net.SplitHostPort(candidate)
		if err == nil && (host == "127.0.0.1" || host == "::1") {
			if number, err := strconv.Atoi(port); err == nil && number > 0 && number <= 65535 {
				return net.JoinHostPort(host, port), nil
			}
		}
	}
	return "", errors.New("tor did not report a loopback SOCKS listener")
}

func validateConfig(c Config) error {
	if c.ConfigDir == "" || c.DataDir == "" || c.LogDir == "" {
		return errors.New("tor application directories are required")
	}
	if c.TorBinary != "" {
		if _, err := resolveTorBinary(c.TorBinary); err != nil {
			return errors.New("configured Tor binary was not found or is not executable")
		}
	}
	if c.ContactEmail != "" {
		if _, err := mail.ParseAddress(c.ContactEmail); err != nil {
			return errors.New("invalid Tor contact email")
		}
	}
	if c.StartupTimeout < 10*time.Second || c.StartupTimeout > 300*time.Second {
		return errors.New("tor startup timeout must be between 10 and 300 seconds")
	}
	if c.BootstrapTimeout < 30*time.Second || c.BootstrapTimeout > 600*time.Second {
		return errors.New("tor bootstrap timeout must be between 30 and 600 seconds")
	}
	if c.VirtualPort < 1 || c.VirtualPort > 65535 {
		return errors.New("tor virtual port must be between 1 and 65535")
	}
	if c.MaxCircuits < 1 || c.MaxCircuits > 128 {
		return errors.New("tor max circuits must be between 1 and 128")
	}
	if c.CircuitTimeout < 10 || c.CircuitTimeout > 300 {
		return errors.New("tor circuit timeout must be between 10 and 300 seconds")
	}
	if c.MaxStreamsPerCircuit < 10 || c.MaxStreamsPerCircuit > 500 {
		return errors.New("tor max streams must be between 10 and 500")
	}
	if c.NumIntroPoints < 3 || c.NumIntroPoints > 10 {
		return errors.New("tor introduction points must be between 3 and 10")
	}
	bandwidth := regexp.MustCompile(`^\d+\s*(KB|MB)$`)
	if !bandwidth.MatchString(strings.TrimSpace(c.BandwidthRate)) || !bandwidth.MatchString(strings.TrimSpace(c.BandwidthBurst)) {
		return errors.New("invalid Tor bandwidth value")
	}
	monthly := regexp.MustCompile(`^(\d+\s*(?:GB|TB)|unlimited)$`)
	if !monthly.MatchString(strings.TrimSpace(c.MaxMonthlyBandwidth)) {
		return errors.New("monthly Tor bandwidth must be a number with GB or TB, or unlimited")
	}
	rate, _ := parseTorBandwidth(c.BandwidthRate)
	burst, _ := parseTorBandwidth(c.BandwidthBurst)
	if burst < rate {
		return errors.New("tor bandwidth burst must be greater than or equal to the rate")
	}
	return nil
}

func parseTorBandwidth(value string) (uint64, error) {
	fields := strings.Fields(strings.ToUpper(strings.TrimSpace(value)))
	if len(fields) != 2 {
		return 0, errors.New("invalid bandwidth value")
	}
	amount, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, err
	}
	switch fields[1] {
	case "KB":
		return amount * 1024, nil
	case "MB":
		return amount * 1024 * 1024, nil
	default:
		return 0, errors.New("invalid bandwidth unit")
	}
}

func ValidateConfig(c Config) error { return validateConfig(c) }

func renderTorConfig(c Config, dataDir, hsDir string, backendPort, ownerPID int) string {
	safe := "1"
	if !c.SafeLogging {
		safe = "0"
	}
	closeOnLimit := "0"
	if c.CloseCircuitOnStreamLimit {
		closeOnLimit = "1"
	}
	socks := "SocksPort 0\n"
	if c.UseNetwork || c.AllowUserPreference {
		socks = "SocksPort 127.0.0.1:auto\n"
	}
	accounting := ""
	if c.MaxMonthlyBandwidth != "" && !strings.EqualFold(c.MaxMonthlyBandwidth, "unlimited") {
		accounting = fmt.Sprintf("AccountingStart month 1 00:00\nAccountingMax %s\n", c.MaxMonthlyBandwidth)
	}
	return fmt.Sprintf(`DataDirectory %s
PidFile %s
ControlPort 127.0.0.1:auto
ControlPortWriteToFile %s
CookieAuthentication 1
DisableNetwork 1
__OwningControllerProcess %d
%sSafeLogging %s
MaxCircuitDirtiness 600
MaxClientCircuitsPending %d
LearnCircuitBuildTimeout 0
CircuitBuildTimeout %d
BandwidthRate %s
BandwidthBurst %s
%sExitRelay 0
ExitPolicy reject *:*
ORPort 0
DirPort 0
PublishServerDescriptor 0
SocksPolicy accept 127.0.0.1
VanguardsLiteEnabled 1
HiddenServiceSingleHopMode 0
FetchDirInfoEarly 1
FetchDirInfoExtraEarly 1
DisableDebuggerAttachment 1
HiddenServiceDir %s
HiddenServiceVersion 3
HiddenServiceNumIntroductionPoints %d
HiddenServiceMaxStreams %d
HiddenServiceMaxStreamsCloseCircuit %s
HiddenServicePort %d 127.0.0.1:%d
HiddenServiceExportCircuitID haproxy
`, torrcPath(dataDir), torrcPath(filepath.Join(dataDir, "tor.pid")), torrcPath(filepath.Join(dataDir, "control_port")), ownerPID, socks, safe, c.MaxCircuits, c.CircuitTimeout, torBandwidth(c.BandwidthRate, "1 MB"), torBandwidth(c.BandwidthBurst, "2 MB"), accounting, torrcPath(hsDir), c.NumIntroPoints, c.MaxStreamsPerCircuit, closeOnLimit, c.VirtualPort, backendPort)
}

func torrcPath(value string) string {
	if strings.ContainsAny(value, " \t#\"\\") {
		return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	return value
}

func torBandwidth(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}
func writePrivateFile(path string, value []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create Tor config: %w", err)
	}
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(value)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("write Tor config: %w", err)
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

func secureTorFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	return nil
}

func waitControlPort(ctx context.Context, done <-chan struct{}, path string, timeout time.Duration) (string, string, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	pattern := regexp.MustCompile(`^PORT=127\.0\.0\.1:([0-9]+)\n$`)
	for {
		if data, err := os.ReadFile(path); err == nil {
			if match := pattern.FindSubmatch(data); match != nil {
				if p, e := strconv.Atoi(string(match[1])); e == nil && p > 0 && p <= 65535 {
					return net.JoinHostPort("127.0.0.1", string(match[1])), filepath.Join(filepath.Dir(path), "control_auth_cookie"), nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-done:
			return "", "", errors.New("tor process exited before publishing its control port")
		case <-deadline.C:
			return "", "", errors.New("timed out waiting for Tor control port")
		case <-tick.C:
		}
	}
}

func dialTorControl(ctx context.Context, address string, timeout time.Duration) (net.Conn, *control.Conn, chan control.Event, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	client := control.NewConn(textproto.NewConn(conn))
	if err := client.Authenticate(""); err != nil {
		_ = client.Close()
		return nil, nil, nil, fmt.Errorf("tor control authentication failed: %w", err)
	}
	events := make(chan control.Event, 256)
	return conn, client, events, nil
}

func readTorPortFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	match := regexp.MustCompile(`^PORT=127\.0\.0\.1:([0-9]+)\n$`).FindSubmatch(data)
	if match == nil {
		return "", errors.New("invalid Tor port file")
	}
	port, err := strconv.Atoi(string(match[1]))
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("invalid Tor port")
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
}

func waitSocksPort(ctx context.Context, done <-chan struct{}, path string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 180 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		if data, err := os.ReadFile(path); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "PORT=127.0.0.1:") {
					port := strings.TrimPrefix(line, "PORT=127.0.0.1:")
					if p, e := strconv.Atoi(port); e == nil && p > 0 && p <= 65535 {
						return net.JoinHostPort("127.0.0.1", port), nil
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-done:
			return "", errors.New("tor exited before publishing its SOCKS port")
		case <-deadline.C:
			return "", errors.New("timed out waiting for Tor SOCKS port")
		case <-tick.C:
		}
	}
}

func bootstrapTor(ctx context.Context, events <-chan control.Event, done <-chan struct{}, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 180 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case event := <-events:
			status, ok := event.(*control.StatusEvent)
			if !ok || status.Action != "BOOTSTRAP" {
				continue
			}
			if status.Severity == "WARN" || status.Severity == "ERR" {
				if reason := status.Arguments["REASON"]; reason != "" {
					log.Printf("DEBUG: Tor bootstrap warning: %s", reason)
				}
				continue
			}
			if status.Arguments["PROGRESS"] == "100" {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return errors.New("tor process exited during bootstrap")
		case <-deadline.C:
			return errors.New("tor bootstrap timed out")
		}
	}
}

func torRuntimeDetails(client *control.Conn) (string, int, bool) {
	version := ""
	circuits := 0
	bootstrapped := false
	if values, err := client.GetInfo("version", "circuit-status", "status/bootstrap-phase"); err == nil {
		for _, value := range values {
			switch value.Key {
			case "version":
				version = value.Val
			case "circuit-status":
				for _, line := range strings.Split(strings.TrimSpace(value.Val), "\n") {
					if strings.TrimSpace(line) != "" {
						circuits++
					}
				}
			case "status/bootstrap-phase":
				bootstrapped = strings.Contains(value.Val, "PROGRESS=100")
			}
		}
	}
	return version, circuits, bootstrapped
}

func readHostname(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	host := strings.TrimSpace(string(data))
	if !strings.HasSuffix(host, ".onion") || len(strings.TrimSuffix(host, ".onion")) != 56 {
		return "", errors.New("invalid Tor onion hostname")
	}
	return host, nil
}

func waitHostname(ctx context.Context, done <-chan struct{}, path string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 180 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		if host, err := readHostname(path); err == nil {
			return host, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-done:
			return "", errors.New("tor process exited before publishing its onion hostname")
		case <-deadline.C:
			return "", errors.New("timed out waiting for Tor onion hostname")
		case <-tick.C:
		}
	}
}

func (s *Service) OnionAddress() string           { s.mu.RLock(); defer s.mu.RUnlock(); return s.onionAddr }
func (s *Service) GetOnionAddress() string        { return s.OnionAddress() }
func (s *Service) setOnionAddress(address string) { s.mu.Lock(); s.onionAddr = address; s.mu.Unlock() }
func (s *Service) Listener() net.Listener {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.running {
		return nil
	}
	return &proxyListener{Listener: &proxyproto.Listener{Listener: s.backend, ReadHeaderTimeout: 3 * time.Second}}
}
func (s *Service) IsRunning() bool           { s.mu.RLock(); defer s.mu.RUnlock(); return s.running }
func (s *Service) GetListener() net.Listener { return s.Listener() }
func (s *Service) Status() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{"enabled": s.cfg.Enabled, "running": s.running, "status": map[bool]string{true: "healthy", false: "unavailable"}[s.running], "onion_address": s.onionAddr}
}
func (s *Service) GetHTTPClient(useTor bool) *http.Client {
	if !useTor {
		return &http.Client{Timeout: 30 * time.Second}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.torHTTPClient != nil {
		return s.torHTTPClient
	}
	addr := s.socksAddr
	if addr == "" {
		return &http.Client{Timeout: 30 * time.Second, Transport: errorRoundTripper{err: errors.New("tor outbound proxy is unavailable")}}
	}
	dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		return &http.Client{Timeout: 30 * time.Second, Transport: errorRoundTripper{err: err}}
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return &http.Client{Timeout: 30 * time.Second, Transport: errorRoundTripper{err: errors.New("tor SOCKS dialer does not support request cancellation")}}
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Client{Timeout: 30 * time.Second, Transport: errorRoundTripper{err: errors.New("default HTTP transport cannot be cloned for Tor")}}
	}
	transport := defaultTransport.Clone()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return contextDialer.DialContext(ctx, network, address)
	}
	s.torTransport = transport
	s.torHTTPClient = &http.Client{Timeout: 30 * time.Second, Transport: transport}
	return s.torHTTPClient
}

type errorRoundTripper struct{ err error }

func (t errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }
func (s *Service) Stop() error                                              { return s.Close() }
func (s *Service) Restart() error                                           { return errors.New("restart Tor through its manager") }
func (s *Service) Close() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	cancel, procCancel, ctrl, backend, cmd, done := s.cancel, s.procCancel, s.ctrl, s.backend, s.cmd, s.done
	transport := s.torTransport
	s.mu.Unlock()
	if transport != nil {
		transport.CloseIdleConnections()
	}
	if ctrl != nil {
		_ = ctrl.Signal("SHUTDOWN")
		_ = ctrl.Close()
	}
	if cancel != nil {
		cancel()
	}
	if backend != nil {
		_ = backend.Close()
	}
	stopProcess(cmd, done, procCancel)
	return nil
}

func stopProcess(cmd *exec.Cmd, done <-chan struct{}, cancel context.CancelFunc) {
	if cmd != nil && cmd.Process != nil {
		_ = terminateTorProcess(cmd, done)
	}
	if cancel != nil {
		cancel()
	}
}

type proxyListener struct{ net.Listener }
type proxyConn struct {
	net.Conn
	CircuitID string
}

func (l *proxyListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	parsed, ok := conn.(*proxyproto.Conn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("tor connection has no parsed PROXY protocol header")
	}
	header := parsed.ProxyHeader()
	if header == nil {
		_ = conn.Close()
		return nil, errors.New("tor connection has no PROXY protocol header")
	}
	source, ok := header.SourceAddr.(*net.TCPAddr)
	if !ok || source.IP.To4() != nil || source.IP.To16() == nil {
		_ = conn.Close()
		return nil, errors.New("invalid Tor PROXY circuit source address")
	}
	id := binary.BigEndian.Uint32(source.IP.To16()[12:16])
	return &proxyConn{Conn: conn, CircuitID: strconv.FormatUint(uint64(id), 10)}, nil
}

func ParseHiddenServiceHostname(dataDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, "hidden_service", "hostname"))
	if err != nil {
		return "", err
	}
	host := strings.TrimSpace(string(data))
	if !strings.HasSuffix(host, ".onion") {
		return "", errors.New("invalid Tor hostname")
	}
	return host, nil
}
func resolveTorBinary(configured string) (string, error) {
	if configured != "" {
		info, err := os.Stat(configured)
		if err != nil || info.IsDir() || !isExecutable(info) {
			return "", fmt.Errorf("configured tor binary is not executable: %s", configured)
		}
		return configured, nil
	}
	for _, path := range []string{"/usr/bin/tor", "/usr/sbin/tor", "/usr/local/bin/tor", "/opt/homebrew/bin/tor"} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() && isExecutable(info) {
			return path, nil
		}
	}
	if path, err := exec.LookPath("tor"); err == nil {
		return path, nil
	}
	return "", errors.New("tor binary not found")
}
func CheckTorAvailable() bool { _, err := resolveTorBinary(""); return err == nil }
func findInPath(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || !isExecutable(info) {
		return "", fmt.Errorf("%s is not executable", name)
	}
	return path, nil
}
func isExecutable(info os.FileInfo) bool { return info.Mode().Perm()&0111 != 0 }
func safeTorError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.ToLower(err.Error())
	for _, secret := range []string{"cookie", "control_auth_cookie", "hs_ed25519", "secret_key", "private key"} {
		if strings.Contains(value, secret) {
			return "Tor startup failed"
		}
	}
	return err.Error()
}

// GenerateVanityAddress is retained as a compatibility API; address search is
// performed offline with a dedicated Tor vanity generator.
func (s *Service) GenerateVanityAddress(prefix string) error {
	if prefix == "" {
		return errors.New("prefix cannot be empty")
	}
	for _, c := range strings.ToLower(prefix) {
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return fmt.Errorf("invalid prefix character: %c (must be a-z or 2-7)", c)
		}
	}
	return errors.New("vanity address generation requires external tool mkp224o - see docs for instructions")
}

// NewService creates the compatibility service wrapper. New server code should
// use Manager so Tor startup never blocks HTTP startup.
func NewService(cfg *Config) *Service {
	if cfg == nil {
		return &Service{}
	}
	return &Service{cfg: *cfg}
}

// Start synchronously starts the dedicated service for legacy callers.
func (s *Service) Start() error {
	s.mu.RLock()
	if s.running {
		s.mu.RUnlock()
		return nil
	}
	cfg := s.cfg
	s.mu.RUnlock()
	if !cfg.Enabled {
		return nil
	}
	if cfg.VirtualPort == 0 {
		cfg.VirtualPort = cfg.HiddenPort
	}
	service, err := startTor(context.Background(), cfg)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cmd = service.cmd
	s.binary = service.binary
	s.ctrl = service.ctrl
	s.onionAddr = service.onionAddr
	s.backend = service.backend
	s.socksAddr = service.socksAddr
	s.running = true
	s.ctx = service.ctx
	s.cancel = service.cancel
	s.procCancel = service.procCancel
	s.done = service.done
	s.mu.Unlock()
	return nil
}
