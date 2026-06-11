package auth

import (
"crypto/rand"
"crypto/subtle"
"encoding/hex"
"fmt"
"time"

"golang.org/x/crypto/argon2"
)

// HashPassword hashes a password using Argon2id
func HashPassword(password string) (string, error) {
salt := make([]byte, 16)
if _, err := rand.Read(salt); err != nil {
return "", err
}

// Argon2id parameters
hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

// Format: salt$hash (both hex encoded)
return hex.EncodeToString(salt) + "$" + hex.EncodeToString(hash), nil
}

// VerifyPassword verifies a password against a hash
func VerifyPassword(password, hashedPassword string) bool {
// Parse salt$hash
var saltHex, hashHex string
fmt.Sscanf(hashedPassword, "%32s$%64s", &saltHex, &hashHex)

salt, err := hex.DecodeString(saltHex)
if err != nil {
return false
}

expectedHash, err := hex.DecodeString(hashHex)
if err != nil {
return false
}

// Hash provided password with same salt
hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

// Constant-time comparison prevents timing attacks (PART 11 security requirement)
return subtle.ConstantTimeCompare(hash, expectedHash) == 1
}

// GenerateSessionID generates a random session ID
func GenerateSessionID() string {
b := make([]byte, 32)
rand.Read(b)
return hex.EncodeToString(b)
}

// Session represents an active user session
type Session struct {
ID        string
UserID    string
CreatedAt time.Time
ExpiresAt time.Time
IPAddress string
UserAgent string
}

// NewSession creates a new session
func NewSession(userID, ipAddress, userAgent string) *Session {
return &Session{
ID:        GenerateSessionID(),
UserID:    userID,
CreatedAt: time.Now(),
ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
IPAddress: ipAddress,
UserAgent: userAgent,
}
}

// IsExpired checks if session is expired
func (s *Session) IsExpired() bool {
return time.Now().After(s.ExpiresAt)
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
Token     string
UserID    string
ExpiresAt time.Time
}

// GeneratePasswordResetToken generates a password reset token
func GeneratePasswordResetToken(userID string) *PasswordResetToken {
b := make([]byte, 32)
rand.Read(b)

return &PasswordResetToken{
Token:     hex.EncodeToString(b),
UserID:    userID,
ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiry
}
}

// User validation
func ValidateUsername(username string) error {
if len(username) < 3 || len(username) > 30 {
return fmt.Errorf("username must be 3-30 characters")
}
// Add more validation as needed
return nil
}

func ValidateEmail(email string) error {
if len(email) < 3 || !contains(email,"@"){
return fmt.Errorf("invalid email address")
}
return nil
}

func ValidatePassword(password string) error {
if len(password) < 8 {
return fmt.Errorf("password must be at least 8 characters")
}
return nil
}

func contains(s, substr string) bool {
return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) && 
func() bool {
for i := 0; i <= len(s)-len(substr); i++ {
if s[i:i+len(substr)] == substr {
return true
}
}
return false
}()
}
