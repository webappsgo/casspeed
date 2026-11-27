package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	setupTokenHash []byte
	setupTokenPath string
	setupTokenUsed bool
	setupCompleted bool
	setupMutex     sync.RWMutex
	setupSessions  = make(map[string]time.Time)
)

// GenerateSetupToken generates a one-time setup token
// Format: 32 hexadecimal characters (128-bit random), no dashes
// Example: a1b2c3d4e5f67890abcdef1234567890
func GenerateSetupToken() (string, error) {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	// Generate 16 random bytes (128 bits)
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}

	// Convert to hex string (32 chars)
	token := hex.EncodeToString(bytes)
	hash := sha256.Sum256([]byte(token))
	setupTokenHash = append(setupTokenHash[:0], hash[:]...)
	setupTokenUsed = false

	return token, nil
}

// LoadOrCreateSetupToken stores only a SHA-256 hash and returns plaintext only on first creation.
func LoadOrCreateSetupToken(path string) (string, bool, error) {
	if strings.TrimSpace(path) == "" {
		return "", false, fmt.Errorf("setup token path is required")
	}
	setupMutex.Lock()
	defer setupMutex.Unlock()
	setupTokenPath = path
	if setupCompleted {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", false, fmt.Errorf("remove completed setup token: %w", err)
		}
		setupTokenHash = nil
		setupTokenUsed = false
		setupSessions = make(map[string]time.Time)
		return "", false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", false, fmt.Errorf("create setup token directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return "", false, fmt.Errorf("secure setup token directory: %w", err)
	}
	data, err := os.ReadFile(path)
	if err == nil {
		hash, decodeErr := hex.DecodeString(strings.TrimSpace(string(data)))
		if decodeErr != nil || len(hash) != sha256.Size {
			return "", false, fmt.Errorf("setup token hash file is invalid")
		}
		if err := os.Chmod(path, 0600); err != nil {
			return "", false, fmt.Errorf("secure setup token file: %w", err)
		}
		setupTokenHash = hash
		setupTokenUsed = false
		return "", false, nil
	}
	if !os.IsNotExist(err) {
		return "", false, fmt.Errorf("read setup token file: %w", err)
	}
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return "", false, fmt.Errorf("generate setup token: %w", err)
	}
	token := hex.EncodeToString(secret)
	hash := sha256.Sum256([]byte(token))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return "", false, fmt.Errorf("read concurrently created setup token: %w", readErr)
			}
			existingHash, decodeErr := hex.DecodeString(strings.TrimSpace(string(data)))
			if decodeErr != nil || len(existingHash) != sha256.Size {
				return "", false, fmt.Errorf("setup token hash file is invalid")
			}
			setupTokenHash = existingHash
			setupTokenUsed = false
			return "", false, nil
		}
		return "", false, fmt.Errorf("create setup token file: %w", err)
	}
	if _, err := file.WriteString(hex.EncodeToString(hash[:]) + "\n"); err != nil {
		file.Close()
		_ = os.Remove(path)
		return "", false, fmt.Errorf("write setup token hash: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(path)
		return "", false, fmt.Errorf("sync setup token hash: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", false, fmt.Errorf("close setup token file: %w", err)
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	setupTokenHash = append(setupTokenHash[:0], hash[:]...)
	setupTokenUsed = false
	return token, true, nil
}

// ValidateSetupToken checks if the provided token matches the setup token
func ValidateSetupToken(token string) bool {
	setupMutex.RLock()
	defer setupMutex.RUnlock()

	if setupCompleted {
		return false
	}

	if len(token) != 32 || len(setupTokenHash) != sha256.Size {
		return false
	}
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 16 {
		return false
	}
	hash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(hash[:], setupTokenHash) == 1
}

// IssueSetupSession exchanges the one-time setup token for a short-lived browser capability.
func IssueSetupSession(w http.ResponseWriter, r *http.Request) error {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generate setup session: %w", err)
	}
	value := hex.EncodeToString(secret)
	hash := sha256.Sum256(secret)
	expires := time.Now().Add(10 * time.Minute)
	setupMutex.Lock()
	if setupCompleted || setupTokenUsed {
		setupMutex.Unlock()
		return fmt.Errorf("setup token has already been used or setup is complete")
	}
	setupTokenUsed = true
	for existing, expiry := range setupSessions {
		if !expiry.After(time.Now()) {
			delete(setupSessions, existing)
		}
	}
	setupSessions[hex.EncodeToString(hash[:])] = expires
	setupMutex.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "casspeed_setup", Value: value, Path: "/", MaxAge: 600, Expires: expires, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	return nil
}

func validSetupSession(r *http.Request) bool {
	cookie, err := r.Cookie("casspeed_setup")
	if err != nil || len(cookie.Value) != 64 {
		return false
	}
	secret, err := hex.DecodeString(cookie.Value)
	if err != nil || len(secret) != 32 {
		return false
	}
	hash := sha256.Sum256(secret)
	key := hex.EncodeToString(hash[:])
	setupMutex.RLock()
	expires, exists := setupSessions[key]
	complete := setupCompleted
	setupMutex.RUnlock()
	return exists && !complete && expires.After(time.Now())
}

func consumeSetupSession(r *http.Request) {
	cookie, err := r.Cookie("casspeed_setup")
	if err == nil {
		secret, decodeErr := hex.DecodeString(cookie.Value)
		if decodeErr == nil {
			hash := sha256.Sum256(secret)
			setupMutex.Lock()
			delete(setupSessions, hex.EncodeToString(hash[:]))
			setupMutex.Unlock()
		}
	}
}

// MarkSetupComplete marks setup as completed and invalidates the token
func MarkSetupComplete() {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	setupCompleted = true
	setupTokenHash = nil
	setupTokenUsed = false
	setupSessions = make(map[string]time.Time)
	if setupTokenPath != "" {
		_ = os.Remove(setupTokenPath)
	}
}

// IsSetupComplete checks if initial setup has been completed
func IsSetupComplete() bool {
	setupMutex.RLock()
	defer setupMutex.RUnlock()

	return setupCompleted
}

// SetSetupComplete sets the setup complete status (for loading from DB)
func SetSetupComplete(completed bool) {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	setupCompleted = completed
	if completed {
		setupTokenHash = nil
		setupTokenUsed = false
		setupSessions = make(map[string]time.Time)
	} else {
		setupTokenHash = nil
		setupTokenUsed = false
		setupSessions = make(map[string]time.Time)
	}
}

// SetupWizardData holds the data collected during setup
type SetupWizardData struct {
	// Step 1: Admin Account
	AdminUsername string `json:"admin_username"`
	AdminPassword string `json:"admin_password"`

	// Step 2: API Token (auto-generated, shown to user)
	AdminAPIToken string `json:"admin_api_token"`

	// Step 3: Server Configuration
	AppName  string `json:"app_name"`
	Domain   string `json:"domain"`
	Mode     string `json:"mode"`
	Timezone string `json:"timezone"`

	// Step 4: Security Settings
	BackupEncryptionPassword string `json:"backup_encryption_password,omitempty"`
	Enable2FA                bool   `json:"enable_2fa"`

	// Step 5: Optional Services
	EnableSSL   bool `json:"enable_ssl"`
	EnableUsers bool `json:"enable_users"`

	// Internal
	SetupToken    string    `json:"setup_token"`
	CompletedAt   time.Time `json:"completed_at"`
	CompletedByIP string    `json:"completed_by_ip"`
}

// ValidateSetupData validates the setup wizard data
func ValidateSetupData(data *SetupWizardData) error {
	// Admin username required
	if data.AdminUsername == "" {
		return fmt.Errorf("admin username is required")
	}
	if len(data.AdminUsername) < 3 || len(data.AdminUsername) > 30 {
		return fmt.Errorf("admin username must be 3-30 characters")
	}

	// Admin password required
	if data.AdminPassword == "" {
		return fmt.Errorf("admin password is required")
	}
	if len(data.AdminPassword) < 8 {
		return fmt.Errorf("admin password must be at least 8 characters")
	}

	// App name optional, default to "casspeed"
	if data.AppName == "" {
		data.AppName = "casspeed"
	}

	// Mode optional, default to "production"
	if data.Mode == "" {
		data.Mode = "production"
	}
	if data.Mode != "production" && data.Mode != "development" {
		return fmt.Errorf("mode must be 'production' or 'development'")
	}

	// Timezone optional, default to "America/New_York"
	if data.Timezone == "" {
		data.Timezone = "America/New_York"
	}

	return nil
}
