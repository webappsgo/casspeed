package admin

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

var (
	setupToken     string
	setupCompleted bool
	setupMutex     sync.RWMutex
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
	setupToken = token

	return token, nil
}

// ValidateSetupToken checks if the provided token matches the setup token
func ValidateSetupToken(token string) bool {
	setupMutex.RLock()
	defer setupMutex.RUnlock()

	if setupCompleted {
		return false
	}

	return token == setupToken
}

// MarkSetupComplete marks setup as completed and invalidates the token
func MarkSetupComplete() {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	setupCompleted = true
	setupToken = "" // Invalidate token
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
