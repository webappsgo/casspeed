package store

import (
	"context"
	"time"

	"github.com/casapps/casspeed/src/server/model"
)

type Store interface {
	Close() error

	CreateUser(ctx context.Context, user *model.User) error
	GetUser(ctx context.Context, id string) (*model.User, error)
	GetUserByUsername(ctx context.Context, username string) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	UpdateUser(ctx context.Context, user *model.User) error
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
	IncrementShareViews(ctx context.Context, shareCode string) error

	CreateAPIToken(ctx context.Context, token *model.APIToken) error
	GetAPIToken(ctx context.Context, id string) (*model.APIToken, error)
	GetAPITokenByToken(ctx context.Context, token string) (*model.APIToken, error)
	GetUserAPITokens(ctx context.Context, userID string) ([]*model.APIToken, error)
	UpdateAPIToken(ctx context.Context, token *model.APIToken) error
	DeleteAPIToken(ctx context.Context, id string) error

	CreateSession(ctx context.Context, session *model.Session) error
	GetSession(ctx context.Context, id string) (*model.Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context) error

	// Admin methods
	GetAdminByUsername(ctx context.Context, username string) (*model.Admin, error)
	CreateAdmin(ctx context.Context, admin *model.Admin) error
	UpdateAdminLastLogin(ctx context.Context, adminID int) error
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
