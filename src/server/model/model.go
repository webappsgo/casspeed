package model

import (
	"strconv"
	"time"
)

// UserIDString converts an integer user identifier to the opaque decimal form used by sessions and stores.
func UserIDString(id int64) string { return strconv.FormatInt(id, 10) }

type User struct {
	ID                        int64      `json:"id"`
	Username                  string     `json:"username"`
	Email                     string     `json:"email"`
	EmailVerified             bool       `json:"email_verified"`
	NotificationEmail         string     `json:"notification_email,omitempty"`
	NotificationEmailVerified bool       `json:"notification_email_verified"`
	DisplayName               string     `json:"display_name"`
	Bio                       string     `json:"bio"`
	Location                  string     `json:"location"`
	Website                   string     `json:"website"`
	AvatarURL                 string     `json:"avatar_url,omitempty"`
	Timezone                  string     `json:"timezone"`
	Language                  string     `json:"language"`
	Visibility                string     `json:"visibility"`
	OrgVisibility             bool       `json:"org_visibility"`
	PasswordHash              string     `json:"-"`
	ShareShowUsername         bool       `json:"share_show_username"`
	Role                      string     `json:"-"`
	Source                    string     `json:"-"`
	ExternalID                string     `json:"-"`
	Groups                    []string   `json:"-"`
	LastSync                  *time.Time `json:"-"`
	Approved                  bool       `json:"-"`
	Disabled                  bool       `json:"-"`
	TOTPSecret                string     `json:"-"`
	TOTPEnabled               bool       `json:"-"`
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"-"`
	LastLogin                 *time.Time `json:"-"`
}

// UserSettings stores privacy, notification, and appearance preferences.
type UserSettings struct {
	UserID          string `json:"user_id,omitempty"`
	ShowEmail       bool   `json:"show_email"`
	ShowActivity    bool   `json:"show_activity"`
	ShowOrgs        bool   `json:"show_orgs"`
	Searchable      bool   `json:"searchable"`
	EmailSecurity   bool   `json:"email_security"`
	EmailSession    bool   `json:"email_session"`
	EmailMentions   bool   `json:"email_mentions"`
	EmailUpdates    bool   `json:"email_updates"`
	EmailNewsletter bool   `json:"email_newsletter"`
	EmailDigest     string `json:"email_digest"`
	PushEnabled     bool   `json:"push_enabled"`
	PushMentions    bool   `json:"push_mentions"`
	Theme           string `json:"theme"`
	FontSize        string `json:"font_size"`
	ReduceMotion    bool   `json:"reduce_motion"`
	DateFormat      string `json:"date_format"`
	TimeFormat      string `json:"time_format"`
}

type Device struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Name      string    `json:"name"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
}

type SpeedTest struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id,omitempty"`
	DeviceID       string    `json:"device_id,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
	DownloadMbps   float64   `json:"download_mbps"`
	UploadMbps     float64   `json:"upload_mbps"`
	PingMs         float64   `json:"ping_ms"`
	JitterMs       float64   `json:"jitter_ms"`
	PacketLoss     float64   `json:"packet_loss"`
	ClientIPHash   string    `json:"-"`
	UserAgent      string    `json:"user_agent"`
	ServerID       string    `json:"server_id"`
	ShareCode      string    `json:"share_code,omitempty"`
	ShareViews     int       `json:"share_views"`
	OwnerTokenHash string    `json:"-"`
	CreatedAt      time.Time `json:"created_at"`
}

type APIToken struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	Token       string     `json:"-"`
	TokenPrefix string     `json:"token_prefix"`
	Name        string     `json:"name"`
	Scope       string     `json:"scope"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsed    time.Time  `json:"last_used,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Data      string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// UserActivationToken represents a one-use activation link without retaining its secret.
type UserActivationToken struct {
	UserID    string
	TokenHash string
	ExpiresAt time.Time
}

// UserInvite stores metadata and the hash of an administrator-issued registration code.
type UserInvite struct {
	ID        int64     `json:"id"`
	CodeHash  string    `json:"-"`
	Role      string    `json:"role"`
	MaxUses   int       `json:"max_uses"`
	UseCount  int       `json:"use_count"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedBy int64     `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// TOTPSecret stores an encrypted authenticator secret and hashed single-use recovery codes.
type TOTPSecret struct {
	UserID             string
	EncryptedSecret    string
	Enabled            bool
	RecoveryCodeHashes []string
}

// AdminTOTPSecret stores encrypted TOTP data for one server administrator.
type AdminTOTPSecret struct {
	AdminID            int
	EncryptedSecret    string
	Enabled            bool
	RecoveryCodeHashes []string
}

// PartialSession stores a short-lived post-password, pre-MFA authentication challenge.
type PartialSession struct {
	TokenHash string
	UserID    string
	UserType  string
	Remember  bool
	ExpiresAt time.Time
}

// Passkey stores a WebAuthn credential and its owner-scoped display name.
type Passkey struct {
	ID             string
	UserType       string
	UserID         string
	Name           string
	CredentialJSON string
	SignCount      uint32
	Transports     string
	AAGUID         string
	CreatedAt      time.Time
	LastUsed       *time.Time
	Active         bool
}

// PasskeyRecoveryCode stores one hashed, single-use recovery code for one account.
type PasskeyRecoveryCode struct {
	UserType string
	UserID   string
	CodeHash string
}

// WebAuthnChallenge stores short-lived ceremony state until it is consumed.
type WebAuthnChallenge struct {
	ID          string
	UserType    string
	UserID      string
	SessionJSON string
	ExpiresAt   time.Time
}

// Notification is a persistent message owned by one regular user.
type Notification struct {
	ID        string
	UserID    string
	Type      string
	Title     string
	Message   string
	Link      string
	ReadAt    *time.Time
	CreatedAt time.Time
}

type Admin struct {
	ID             int       `json:"id"`
	Username       string    `json:"username"`
	Password       string    `json:"-"`
	Email          string    `json:"email,omitempty"`
	Role           string    `json:"role"`
	Enabled        bool      `json:"enabled"`
	APITokenHash   string    `json:"-"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	LastLogin      time.Time `json:"last_login,omitempty"`
	FailedAttempts int       `json:"-"`
	LockedUntil    time.Time `json:"-"`
}

type AdminSession struct {
	ID         string    `json:"id"`
	AdminID    int       `json:"admin_id"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastActive time.Time `json:"last_active"`
}
