package tor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

const (
	vanitySecretHeader = "== ed25519v1-secret: type0 ==\x00"
	vanityPublicHeader = "== ed25519v1-public: type0 ==\x00"
)

// VanityStatus describes the current in-process search and the durable
// candidates available to apply.
type VanityStatus struct {
	State          string   `json:"state"`
	Prefix         string   `json:"prefix,omitempty"`
	Workers        int      `json:"workers,omitempty"`
	Attempts       uint64   `json:"attempts"`
	Rate           uint64   `json:"rate"`
	ElapsedSeconds int64    `json:"elapsed_seconds"`
	Candidates     []string `json:"candidates"`
}

// VanityManager owns one cancellable vanity search and its durable candidate
// directories. Candidate keys are never written into the live hidden-service
// directory by the search.
type VanityManager struct {
	mu        sync.Mutex
	applyMu   sync.Mutex
	root      string
	state     string
	prefix    string
	workers   int
	startedAt time.Time
	attempts  atomic.Uint64
	cancel    context.CancelFunc
	done      chan struct{}
}

// NewVanityManager creates a manager whose candidates live below
// {dataDir}/tor/vanity.
func NewVanityManager(dataDir string) *VanityManager {
	return &VanityManager{root: filepath.Join(dataDir, "tor", "vanity"), state: "idle"}
}

// ValidateVanityPrefix applies the v3 onion alphabet and built-in length cap.
func ValidateVanityPrefix(prefix string) error {
	if len(prefix) < 1 || len(prefix) > 6 {
		return errors.New("prefix must contain between 1 and 6 characters")
	}
	for _, char := range prefix {
		if (char < 'a' || char > 'z') && (char < '2' || char > '7') {
			return errors.New("prefix may contain only lowercase base32 characters a-z and 2-7")
		}
	}
	return nil
}

// DefaultVanityWorkers leaves one logical CPU available when possible.
func DefaultVanityWorkers() int {
	workers := runtime.NumCPU() - 1
	if workers < 1 {
		return 1
	}
	return workers
}

// Start begins a background brute-force search. A zero worker count selects
// DefaultVanityWorkers. Only one search may run at a time.
func (m *VanityManager) Start(parent context.Context, prefix string, workers int) error {
	if err := ValidateVanityPrefix(prefix); err != nil {
		return err
	}
	maxWorkers := runtime.NumCPU()
	if workers == 0 {
		workers = DefaultVanityWorkers()
	}
	if workers < 1 || workers > maxWorkers {
		return fmt.Errorf("workers must be between 1 and %d", maxWorkers)
	}
	if parent == nil {
		parent = context.Background()
	}
	if err := os.MkdirAll(m.root, 0700); err != nil {
		return fmt.Errorf("create Tor vanity candidate directory: %w", err)
	}
	if err := os.Chmod(m.root, 0700); err != nil {
		return fmt.Errorf("secure Tor vanity candidate directory: %w", err)
	}

	m.mu.Lock()
	if m.state == "running" {
		activePrefix := m.prefix
		m.mu.Unlock()
		return fmt.Errorf("vanity search for prefix %q is already running", activePrefix)
	}
	if m.done != nil {
		select {
		case <-m.done:
		default:
			activePrefix := m.prefix
			m.mu.Unlock()
			return fmt.Errorf("vanity search for prefix %q is still stopping", activePrefix)
		}
	}
	ctx, cancel := context.WithCancel(parent)
	m.state = "running"
	m.prefix = prefix
	m.workers = workers
	m.startedAt = time.Now()
	m.attempts.Store(0)
	m.cancel = cancel
	m.done = make(chan struct{})
	done := m.done
	m.mu.Unlock()

	go m.search(ctx, done, prefix, workers)
	return nil
}

func (m *VanityManager) search(ctx context.Context, done chan struct{}, prefix string, workers int) {
	var workerGroup sync.WaitGroup
	var found sync.Once
	for index := 0; index < workers; index++ {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()
			for ctx.Err() == nil {
				publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					m.mu.Lock()
					m.state = "idle"
					if m.cancel != nil {
						m.cancel()
					}
					m.mu.Unlock()
					return
				}
				m.attempts.Add(1)
				address := onionV3Address(publicKey)
				if !strings.HasPrefix(address, prefix) {
					continue
				}
				found.Do(func() {
					if err := writeVanityCandidate(m.root, address, privateKey, publicKey); err != nil {
						m.mu.Lock()
						m.state = "idle"
						if m.cancel != nil {
							m.cancel()
						}
						m.mu.Unlock()
						return
					}
					m.mu.Lock()
					m.state = "found"
					if m.cancel != nil {
						m.cancel()
					}
					m.mu.Unlock()
				})
				return
			}
		}()
	}
	workerGroup.Wait()
	m.mu.Lock()
	if m.done == done {
		if m.state == "running" {
			m.state = "idle"
		}
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
	}
	close(done)
	m.mu.Unlock()
}

// Cancel stops the active search. Any candidate already found remains on disk.
func (m *VanityManager) Cancel() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != "running" || m.cancel == nil {
		return false
	}
	m.cancel()
	return true
}

// Close cancels an active search and waits for its workers to finish.
func (m *VanityManager) Close() {
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	if cancel != nil {
		cancel()
	}
	m.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Status reports progress and candidate addresses found on disk.
func (m *VanityManager) Status() VanityStatus {
	m.mu.Lock()
	state, prefix, workers, startedAt := m.state, m.prefix, m.workers, m.startedAt
	m.mu.Unlock()
	status := VanityStatus{State: state, Prefix: prefix, Workers: workers, Attempts: m.attempts.Load(), Candidates: m.Candidates()}
	if !startedAt.IsZero() {
		elapsed := time.Since(startedAt)
		status.ElapsedSeconds = int64(elapsed.Seconds())
		if elapsed > 0 {
			status.Rate = uint64(float64(status.Attempts) / elapsed.Seconds())
		}
	}
	return status
}

// Candidates lists valid durable candidate onion addresses.
func (m *VanityManager) Candidates() []string {
	entries, err := os.ReadDir(m.root)
	if err != nil {
		return []string{}
	}
	addresses := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasSuffix(entry.Name(), ".onion") {
			continue
		}
		if _, err := readVanityCandidate(filepath.Join(m.root, entry.Name()), entry.Name()); err == nil {
			addresses = append(addresses, entry.Name())
		}
	}
	return addresses
}

// ImportCandidate copies a Tor v3 hidden-service key directory into durable
// candidate storage. The source is not modified.
func (m *VanityManager) ImportCandidate(sourceDir string) (string, error) {
	hostname, err := os.ReadFile(filepath.Join(sourceDir, "hostname"))
	if err != nil {
		return "", fmt.Errorf("read imported Tor hostname: %w", err)
	}
	address := strings.TrimSpace(string(hostname))
	if !validOnionAddress(address) {
		return "", errors.New("imported hostname is not a v3 onion address")
	}
	files, err := readVanityCandidate(sourceDir, address)
	if err != nil {
		return "", fmt.Errorf("validate imported Tor keys: %w", err)
	}
	if err := os.MkdirAll(m.root, 0700); err != nil {
		return "", fmt.Errorf("create Tor vanity candidate directory: %w", err)
	}
	if err := os.Chmod(m.root, 0700); err != nil {
		return "", fmt.Errorf("secure Tor vanity candidate directory: %w", err)
	}
	if err := writeVanityFiles(m.root, address, files.secret, files.public, []byte(address+"\n")); err != nil {
		return "", err
	}
	return address, nil
}

// ApplyCandidate swaps a verified candidate into the live hidden-service
// directory, then asks the caller to restart Tor and verify the published
// hostname. If startup fails or publishes another address, the previous keys
// are restored and the caller is asked to restart again with them.
func (m *VanityManager) ApplyCandidate(address, liveDir string, stop func() error, start func() (string, error)) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if !validOnionAddress(address) {
		return errors.New("invalid candidate onion address")
	}
	candidateDir := filepath.Join(m.root, address)
	_, err := readVanityCandidate(candidateDir, address)
	if err != nil {
		return fmt.Errorf("candidate keys are unavailable or invalid: %w", err)
	}
	if stop == nil || start == nil {
		return errors.New("tor stop and start callbacks are required")
	}
	if err := stop(); err != nil {
		return fmt.Errorf("stop Tor before applying vanity address: %w", err)
	}
	parent := filepath.Dir(liveDir)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("create Tor data directory: %w", err)
	}
	backupDir, err := os.MkdirTemp(parent, ".tor-site-backup-*")
	if err != nil {
		return fmt.Errorf("prepare previous Tor identity backup: %w", err)
	}
	if err := os.Chmod(backupDir, 0700); err != nil {
		_ = os.RemoveAll(backupDir)
		return fmt.Errorf("secure previous Tor identity backup: %w", err)
	}
	_ = os.Remove(backupDir)
	oldExists := false
	if _, err := os.Lstat(liveDir); err == nil {
		if err := os.Rename(liveDir, backupDir); err != nil {
			return fmt.Errorf("move previous Tor identity aside: %w", err)
		}
		oldExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect previous Tor identity: %w", err)
	}
	if err := os.Rename(candidateDir, liveDir); err != nil {
		if oldExists {
			_ = os.Rename(backupDir, liveDir)
		}
		return fmt.Errorf("install vanity Tor identity: %w", err)
	}
	rollback := func(cause error) error {
		if stopErr := stop(); stopErr != nil {
			cause = fmt.Errorf("%w; stop Tor after failed candidate startup: %v", cause, stopErr)
		}
		_ = os.RemoveAll(liveDir)
		if oldExists {
			if restoreErr := os.Rename(backupDir, liveDir); restoreErr != nil {
				return fmt.Errorf("%w; restore previous Tor identity: %v", cause, restoreErr)
			}
			if _, restoreStartErr := start(); restoreStartErr != nil {
				return fmt.Errorf("%w; restart previous Tor identity: %v", cause, restoreStartErr)
			}
		}
		return cause
	}
	published, err := start()
	if err != nil {
		return rollback(fmt.Errorf("start Tor with vanity identity: %w", err))
	}
	if !strings.EqualFold(strings.TrimSpace(published), address) {
		return rollback(fmt.Errorf("tor published %q after applying candidate %q", published, address))
	}
	if oldExists {
		if err := os.RemoveAll(backupDir); err != nil {
			return fmt.Errorf("remove previous Tor identity backup: %w", err)
		}
	}
	return nil
}

func onionV3Address(publicKey ed25519.PublicKey) string {
	version := byte(3)
	checksumInput := make([]byte, 0, len(".onion checksum")+len(publicKey)+1)
	checksumInput = append(checksumInput, ".onion checksum"...)
	checksumInput = append(checksumInput, publicKey...)
	checksumInput = append(checksumInput, version)
	checksum := sha3.Sum256(checksumInput)
	addressBytes := make([]byte, 0, len(publicKey)+3)
	addressBytes = append(addressBytes, publicKey...)
	addressBytes = append(addressBytes, checksum[0], checksum[1], version)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(addressBytes)) + ".onion"
}

func validOnionAddress(address string) bool {
	if len(address) != 62 || !strings.HasSuffix(address, ".onion") {
		return false
	}
	for _, char := range strings.TrimSuffix(address, ".onion") {
		if (char < 'a' || char > 'z') && (char < '2' || char > '7') {
			return false
		}
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSuffix(address, ".onion")))
	if err != nil || len(decoded) != ed25519.PublicKeySize+3 || decoded[len(decoded)-1] != 3 {
		return false
	}
	return onionV3Address(ed25519.PublicKey(decoded[:ed25519.PublicKeySize])) == address
}

func ValidOnionAddress(address string) bool { return validOnionAddress(address) }

type vanityFiles struct {
	secret []byte
	public []byte
}

func writeVanityCandidate(root, address string, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) error {
	if len(privateKey) != ed25519.PrivateKeySize || len(publicKey) != ed25519.PublicKeySize || onionV3Address(publicKey) != address {
		return errors.New("generated Tor vanity identity is invalid")
	}
	seed := privateKey[:ed25519.SeedSize]
	secret, err := expandedTorPrivateKey(seed)
	if err != nil {
		return err
	}
	return writeVanityFiles(root, address, secret, publicKey, []byte(address+"\n"))
}

func expandedTorPrivateKey(seed []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid Ed25519 seed length")
	}
	expanded := sha512.Sum512(seed)
	expanded[0] &= 248
	expanded[31] &= 63
	expanded[31] |= 64
	return expanded[:], nil
}

// ImportKeyFiles accepts a Tor secret-key file with optional matching public
// key and hostname files, deriving the missing public identity data safely.
func (m *VanityManager) ImportKeyFiles(secretFile, publicFile, hostnameFile []byte) (string, error) {
	if len(secretFile) != len(vanitySecretHeader)+64 || string(secretFile[:len(vanitySecretHeader)]) != vanitySecretHeader {
		return "", errors.New("invalid Tor v3 private-key file")
	}
	secret := append([]byte(nil), secretFile[len(vanitySecretHeader):]...)
	public, err := publicFromExpandedTorPrivateKey(secret)
	if err != nil {
		return "", err
	}
	if len(publicFile) > 0 {
		if len(publicFile) != len(vanityPublicHeader)+ed25519.PublicKeySize || string(publicFile[:len(vanityPublicHeader)]) != vanityPublicHeader {
			return "", errors.New("invalid Tor v3 public-key file")
		}
		if !bytes.Equal(public, publicFile[len(vanityPublicHeader):]) {
			return "", errors.New("tor v3 public and secret keys do not match")
		}
	}
	address := onionV3Address(public)
	if len(hostnameFile) > 0 && strings.TrimSpace(string(hostnameFile)) != address {
		return "", errors.New("tor hostname does not match the imported key")
	}
	if err := writeVanityFiles(m.root, address, secret, public, []byte(address+"\n")); err != nil {
		return "", err
	}
	return address, nil
}

func publicFromExpandedTorPrivateKey(secret []byte) (ed25519.PublicKey, error) {
	if len(secret) != 64 {
		return nil, errors.New("invalid expanded Tor private key")
	}
	if secret[0]&7 != 0 || secret[31]&0xc0 != 0x40 {
		return nil, errors.New("invalid expanded Tor private key")
	}
	scalar, err := edwards25519.NewScalar().SetBytesWithClamping(secret[:32])
	if err != nil {
		return nil, errors.New("invalid expanded Tor private key")
	}
	point := edwards25519.NewIdentityPoint().ScalarBaseMult(scalar)
	return ed25519.PublicKey(point.Bytes()), nil
}

func writeVanityFiles(root, address string, secret, public, hostname []byte) error {
	if !validOnionAddress(address) {
		return errors.New("invalid v3 onion candidate address")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return fmt.Errorf("create Tor vanity candidate directory: %w", err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		return fmt.Errorf("secure Tor vanity candidate directory: %w", err)
	}
	finalDir := filepath.Join(root, address)
	if _, err := os.Lstat(finalDir); err == nil {
		return fmt.Errorf("tor vanity candidate %s already exists", address)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect Tor vanity candidate destination: %w", err)
	}
	temporaryDir, err := os.MkdirTemp(root, ".vanity-candidate-*")
	if err != nil {
		return fmt.Errorf("create temporary Tor vanity candidate: %w", err)
	}
	defer os.RemoveAll(temporaryDir)
	if err := os.Chmod(temporaryDir, 0700); err != nil {
		return fmt.Errorf("secure temporary Tor vanity candidate: %w", err)
	}
	secretFile := append([]byte(vanitySecretHeader), secret...)
	publicFile := append([]byte(vanityPublicHeader), public...)
	files := []struct {
		name  string
		value []byte
	}{{"hs_ed25519_secret_key", secretFile}, {"hs_ed25519_public_key", publicFile}, {"hostname", hostname}}
	for _, file := range files {
		if err := writePrivateVanityFile(filepath.Join(temporaryDir, file.name), file.value); err != nil {
			return err
		}
	}
	if err := syncVanityDirectory(temporaryDir); err != nil {
		return err
	}
	if err := os.Rename(temporaryDir, finalDir); err != nil {
		return fmt.Errorf("publish Tor vanity candidate: %w", err)
	}
	return syncVanityDirectory(root)
}

func writePrivateVanityFile(path string, value []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create private Tor vanity file: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure private Tor vanity file: %w", err)
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		return fmt.Errorf("write private Tor vanity file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync private Tor vanity file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close private Tor vanity file: %w", err)
	}
	return nil
}

func syncVanityDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Tor vanity directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Tor vanity directory: %w", err)
	}
	return nil
}

func readVanityCandidate(dir, address string) (vanityFiles, error) {
	var files vanityFiles
	if !validOnionAddress(address) || filepath.Base(dir) != address {
		return files, errors.New("invalid Tor vanity candidate identity")
	}
	secretFile, err := os.ReadFile(filepath.Join(dir, "hs_ed25519_secret_key"))
	if err != nil {
		return files, err
	}
	publicFile, err := os.ReadFile(filepath.Join(dir, "hs_ed25519_public_key"))
	if err != nil {
		return files, err
	}
	hostname, err := os.ReadFile(filepath.Join(dir, "hostname"))
	if err != nil {
		return files, err
	}
	if len(secretFile) != len(vanitySecretHeader)+64 || string(secretFile[:len(vanitySecretHeader)]) != vanitySecretHeader {
		return files, errors.New("invalid Tor v3 private-key file")
	}
	if len(publicFile) != len(vanityPublicHeader)+ed25519.PublicKeySize || string(publicFile[:len(vanityPublicHeader)]) != vanityPublicHeader {
		return files, errors.New("invalid Tor v3 public-key file")
	}
	public := ed25519.PublicKey(publicFile[len(vanityPublicHeader):])
	derivedPublic, err := publicFromExpandedTorPrivateKey(secretFile[len(vanitySecretHeader):])
	if err != nil || !bytes.Equal(derivedPublic, public) || strings.TrimSpace(string(hostname)) != address || onionV3Address(public) != address {
		return files, errors.New("tor key files do not match their hostname")
	}
	return vanityFiles{
		secret: append([]byte(nil), secretFile[len(vanitySecretHeader):]...),
		public: append([]byte(nil), publicFile[len(vanityPublicHeader):]...),
	}, nil
}
