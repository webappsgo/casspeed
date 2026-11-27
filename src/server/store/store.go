package store

import (
	"context"
	"time"

	"github.com/casapps/casspeed/src/server/model"
)

type Store interface {
	CaptchaChallengeStore
	Close() error

	CreateUser(ctx context.Context, user *model.User) error
	GetUser(ctx context.Context, id string) (*model.User, error)
	GetUserByUsername(ctx context.Context, username string) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	UpdateUser(ctx context.Context, user *model.User) error
	UpdateUserLastLogin(ctx context.Context, userID string, at time.Time) error
	DeleteUser(ctx context.Context, id string) error

	CreateDevice(ctx context.Context, device *model.Device) error
	GetDevice(ctx context.Context, id string) (*model.Device, error)
	GetUserDevices(ctx context.Context, userID string) ([]*model.Device, error)
	UpdateDevice(ctx context.Context, device *model.Device) error
	DeleteDevice(ctx context.Context, id string) error

	CreateSpeedTest(ctx context.Context, test *model.SpeedTest) error
	GetSpeedTest(ctx context.Context, id string) (*model.SpeedTest, error)
	GetSpeedTestByShareCode(ctx context.Context, shareCode string) (*model.SpeedTest, error)
	GetUserSpeedTests(ctx context.Context, userID string, limit, offset int) ([]*model.SpeedTest, error)
	GetDeviceSpeedTests(ctx context.Context, deviceID string, limit, offset int) ([]*model.SpeedTest, error)
	UpdateSpeedTest(ctx context.Context, test *model.SpeedTest) error
	DeleteSpeedTest(ctx context.Context, id string) error
	DeleteAnonymousSpeedTestsBefore(ctx context.Context, cutoff time.Time) error
	IncrementShareViews(ctx context.Context, shareCode string) error
	CountSpeedTests(ctx context.Context) (int, error)
	CountUsers(ctx context.Context) (int, error)

	CreateAPIToken(ctx context.Context, token *model.APIToken) error
	GetAPIToken(ctx context.Context, id string) (*model.APIToken, error)
	GetAPITokenByToken(ctx context.Context, token string) (*model.APIToken, error)
	GetUserAPITokens(ctx context.Context, userID string) ([]*model.APIToken, error)
	UpdateAPIToken(ctx context.Context, token *model.APIToken) error
	DeleteAPIToken(ctx context.Context, id string) error
	DeleteExpiredAPITokens(ctx context.Context, now time.Time) error
	CreatePasswordResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	CompletePasswordReset(ctx context.Context, tokenHash string, now time.Time, passwordHash string) (bool, error)
	DeleteExpiredPasswordResetTokens(ctx context.Context, now time.Time) error

	CreateSession(ctx context.Context, session *model.Session) error
	GetSession(ctx context.Context, id string) (*model.Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context) error
	DeleteUserSessions(ctx context.Context, userID string) error

	// Admin methods
	GetAdminByUsername(ctx context.Context, username string) (*model.Admin, error)
	GetAdminByAPITokenHash(ctx context.Context, tokenHash string) (*model.Admin, error)
	CreateAdmin(ctx context.Context, admin *model.Admin) error
	UpdateAdminLastLogin(ctx context.Context, adminID int) error
	UpdateAdminAPITokenHash(ctx context.Context, adminID int, tokenHash string) error
	UpdateAdminFailedAttempts(ctx context.Context, adminID int, attempts int) error
	LockAdmin(ctx context.Context, adminID int, until time.Time) error
	CountAdmins(ctx context.Context) (int, error)

	// Admin session methods
	CreateAdminSession(ctx context.Context, session *model.AdminSession) error
	GetAdminSession(ctx context.Context, id string) (*model.AdminSession, error)
	UpdateAdminSessionActivity(ctx context.Context, id string) error
	DeleteAdminSession(ctx context.Context, id string) error
	DeleteExpiredAdminSessions(ctx context.Context) error

	// Setup status
	GetSetupComplete(ctx context.Context) (bool, error)
	SetSetupComplete(ctx context.Context, complete bool) error
}

// UserLifecycleStore provides administrative discovery and one-use account activation.
type UserLifecycleStore interface {
	ListUsers(context.Context, int, int, string) ([]*model.User, int, error)
	CreateUserActivationToken(context.Context, string, string, time.Time) error
	CompleteUserActivationToken(context.Context, string, time.Time, string) (bool, error)
}

// UserInviteStore manages reusable registration codes; raw codes are returned only at creation.
type UserInviteStore interface {
	CreateUserInvite(context.Context, *model.UserInvite) error
	GetUserInvite(context.Context, int64) (*model.UserInvite, error)
	GetUserInviteByCode(context.Context, string, time.Time) (*model.UserInvite, error)
	ListUserInvites(context.Context) ([]*model.UserInvite, error)
	RevokeUserInvite(context.Context, int64) error
	ConsumeUserInviteCode(context.Context, string, time.Time) (*model.UserInvite, error)
	CompleteUserInvite(context.Context, string, time.Time, *model.User) error
}

// AdminUsernameStore resolves a server administrator's own display username by ID.
type AdminUsernameStore interface {
	GetAdminUsername(context.Context, int) (string, error)
}

// CaptchaChallengeStore persists one-use answer hashes without storing answers.
type CaptchaChallengeStore interface {
	CreateCaptchaChallenge(context.Context, string, string, time.Time) error
	ConsumeCaptchaChallenge(context.Context, string) (string, time.Time, error)
	DeleteExpiredCaptchaChallenges(context.Context, time.Time) error
}

// UserNotificationStore persists notification history scoped to a regular user.
type UserNotificationStore interface {
	CreateUserNotification(context.Context, *model.Notification) error
	GetUserNotifications(context.Context, string, int) ([]*model.Notification, error)
	CountUnreadUserNotifications(context.Context, string) (int, error)
	MarkUserNotificationRead(context.Context, string, string, time.Time) error
	MarkAllUserNotificationsRead(context.Context, string, time.Time) error
	ClearUserNotifications(context.Context, string) error
}

// UserSettingsStore persists account preferences for a regular user.
type UserSettingsStore interface {
	GetOrCreateUserSettings(context.Context, string) (*model.UserSettings, error)
	UpdateUserSettings(context.Context, *model.UserSettings) error
}

// UserSessionStore exposes owner-scoped session listing for account settings.
type UserSessionStore interface {
	ListUserSessions(context.Context, string) ([]*model.Session, error)
	RevokeUserSession(context.Context, string, string) error
}

// RateCounterStore persists the in-process fallback windows used while an external cache is unavailable.
type RateCounterStore interface {
	LoadRateCounters(context.Context) (map[string][]time.Time, error)
	SaveRateCounters(context.Context, map[string][]time.Time) error
}

// EmailVerificationStore persists hashed single-use verification tokens.
type EmailVerificationStore interface {
	CreateEmailVerification(context.Context, string, string, time.Time) error
	CreatePendingEmailVerification(context.Context, string, string, string, string, time.Time) error
	VerifyEmailAddress(context.Context, string, time.Time) (bool, error)
}

// UserTOTPStore persists encrypted TOTP setup and one-time recovery code hashes.
type UserTOTPStore interface {
	GetUserTOTP(context.Context, string) (*model.TOTPSecret, error)
	SaveUserTOTP(context.Context, *model.TOTPSecret) error
	DeleteUserTOTP(context.Context, string) error
	ConsumeUserRecoveryCode(context.Context, string, string) (int, bool, error)
}

// AdminTOTPStore persists encrypted TOTP setup and hashed recovery codes for admins.
type AdminTOTPStore interface {
	GetAdminTOTP(context.Context, int) (*model.AdminTOTPSecret, error)
	SaveAdminTOTP(context.Context, *model.AdminTOTPSecret) error
	DeleteAdminTOTP(context.Context, int) error
	ConsumeAdminRecoveryCode(context.Context, int, string) (int, bool, error)
}

// PartialSessionStore persists one-time short-lived MFA challenges.
type PartialSessionStore interface {
	CreatePartialSession(context.Context, *model.PartialSession) error
	GetPartialSession(context.Context, string, time.Time) (*model.PartialSession, error)
	ConsumePartialSession(context.Context, string, time.Time) (*model.PartialSession, error)
}

// PasskeyStore persists owner-scoped WebAuthn credentials and expiring ceremony state.
type PasskeyStore interface {
	SavePasskey(context.Context, *model.Passkey) error
	GetPasskeys(context.Context, string, string) ([]*model.Passkey, error)
	GetPasskey(context.Context, string) (*model.Passkey, error)
	DeletePasskey(context.Context, string, string, string) error
	UpdatePasskey(context.Context, *model.Passkey) error
	CreateWebAuthnChallenge(context.Context, *model.WebAuthnChallenge) error
	GetWebAuthnChallenge(context.Context, string, time.Time) (*model.WebAuthnChallenge, error)
	ConsumeWebAuthnChallenge(context.Context, string, time.Time) (*model.WebAuthnChallenge, error)
	CreatePasskeyRecoveryCodes(context.Context, string, string, []string) error
	ConsumePasskeyRecoveryCode(context.Context, string, string, string) (int, bool, error)
	ActivatePasskey(context.Context, string, string, string) error
}
