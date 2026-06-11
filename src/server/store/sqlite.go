package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/casapps/casspeed/src/server/model"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &SQLiteStore{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	return store, nil
}

func (s *SQLiteStore) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username TEXT UNIQUE NOT NULL,
	email TEXT UNIQUE NOT NULL,
	password_hash TEXT NOT NULL,
	share_show_username INTEGER DEFAULT 0,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	name TEXT NOT NULL,
	last_seen TIMESTAMP,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS speed_tests (
	id TEXT PRIMARY KEY,
	user_id TEXT,
	device_id TEXT,
	timestamp TIMESTAMP NOT NULL,
	download_mbps REAL NOT NULL,
	upload_mbps REAL NOT NULL,
	ping_ms REAL NOT NULL,
	jitter_ms REAL NOT NULL,
	packet_loss REAL NOT NULL,
	client_ip_hash TEXT NOT NULL,
	user_agent TEXT,
	server_id TEXT,
	share_code TEXT UNIQUE,
	share_views INTEGER DEFAULT 0,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
	FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	token TEXT UNIQUE NOT NULL,
	name TEXT,
	last_used TIMESTAMP,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	data TEXT NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_speed_tests_user ON speed_tests(user_id);
CREATE INDEX IF NOT EXISTS idx_speed_tests_device ON speed_tests(device_id);
CREATE INDEX IF NOT EXISTS idx_speed_tests_share ON speed_tests(share_code);
CREATE INDEX IF NOT EXISTS idx_speed_tests_timestamp ON speed_tests(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS admins (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	email TEXT,
	role TEXT NOT NULL DEFAULT 'admin',
	enabled INTEGER NOT NULL DEFAULT 1,
	api_token_hash TEXT,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
	updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
	last_login INTEGER,
	failed_attempts INTEGER NOT NULL DEFAULT 0,
	locked_until INTEGER,
	source TEXT NOT NULL DEFAULT 'local',
	external_id TEXT,
	groups TEXT,
	last_sync INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_admins_username ON admins(username);

CREATE TABLE IF NOT EXISTS admin_sessions (
	id TEXT PRIMARY KEY,
	admin_id INTEGER NOT NULL,
	ip_address TEXT NOT NULL,
	user_agent TEXT,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
	expires_at INTEGER NOT NULL,
	last_active INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin ON admin_sessions(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);

CREATE TABLE IF NOT EXISTS system_settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
`

	_, err := s.db.Exec(schema)
	return err
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) CreateUser(ctx context.Context, user *model.User) error {
	query := `INSERT INTO users (id, username, email, password_hash, share_show_username, created_at) 
		VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, user.ID, user.Username, user.Email, user.PasswordHash, user.ShareShowUsername, user.CreatedAt)
	return err
}

func (s *SQLiteStore) GetUser(ctx context.Context, id string) (*model.User, error) {
	user := &model.User{}
	query := `SELECT id, username, email, password_hash, share_show_username, created_at FROM users WHERE id = ?`
	err := s.db.QueryRowContext(ctx, query, id).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.ShareShowUsername, &user.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

func (s *SQLiteStore) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	user := &model.User{}
	query := `SELECT id, username, email, password_hash, share_show_username, created_at FROM users WHERE username = ?`
	err := s.db.QueryRowContext(ctx, query, username).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.ShareShowUsername, &user.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

func (s *SQLiteStore) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	user := &model.User{}
	query := `SELECT id, username, email, password_hash, share_show_username, created_at FROM users WHERE email = ?`
	err := s.db.QueryRowContext(ctx, query, email).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.ShareShowUsername, &user.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, user *model.User) error {
	query := `UPDATE users SET username = ?, email = ?, password_hash = ?, share_show_username = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, user.Username, user.Email, user.PasswordHash, user.ShareShowUsername, user.ID)
	return err
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) CreateDevice(ctx context.Context, device *model.Device) error {
	query := `INSERT INTO devices (id, user_id, name, last_seen, created_at) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, device.ID, device.UserID, device.Name, device.LastSeen, device.CreatedAt)
	return err
}

func (s *SQLiteStore) GetDevice(ctx context.Context, id string) (*model.Device, error) {
	device := &model.Device{}
	query := `SELECT id, user_id, name, last_seen, created_at FROM devices WHERE id = ?`
	err := s.db.QueryRowContext(ctx, query, id).Scan(&device.ID, &device.UserID, &device.Name, &device.LastSeen, &device.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return device, err
}

func (s *SQLiteStore) GetUserDevices(ctx context.Context, userID string) ([]*model.Device, error) {
	query := `SELECT id, user_id, name, last_seen, created_at FROM devices WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*model.Device
	for rows.Next() {
		device := &model.Device{}
		if err := rows.Scan(&device.ID, &device.UserID, &device.Name, &device.LastSeen, &device.CreatedAt); err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (s *SQLiteStore) UpdateDevice(ctx context.Context, device *model.Device) error {
	query := `UPDATE devices SET name = ?, last_seen = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, device.Name, device.LastSeen, device.ID)
	return err
}

func (s *SQLiteStore) DeleteDevice(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) CreateSpeedTest(ctx context.Context, test *model.SpeedTest) error {
	query := `INSERT INTO speed_tests (id, user_id, device_id, timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, share_code, share_views, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, test.ID, test.UserID, test.DeviceID, test.Timestamp, test.DownloadMbps, test.UploadMbps, test.PingMs, test.JitterMs, test.PacketLoss, test.ClientIPHash, test.UserAgent, test.ServerID, test.ShareCode, test.ShareViews, test.CreatedAt)
	return err
}

func (s *SQLiteStore) GetSpeedTest(ctx context.Context, id string) (*model.SpeedTest, error) {
	test := &model.SpeedTest{}
	query := `SELECT id, user_id, device_id, timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, share_code, share_views, created_at FROM speed_tests WHERE id = ?`
	err := s.db.QueryRowContext(ctx, query, id).Scan(&test.ID, &test.UserID, &test.DeviceID, &test.Timestamp, &test.DownloadMbps, &test.UploadMbps, &test.PingMs, &test.JitterMs, &test.PacketLoss, &test.ClientIPHash, &test.UserAgent, &test.ServerID, &test.ShareCode, &test.ShareViews, &test.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return test, err
}

func (s *SQLiteStore) GetSpeedTestByShareCode(ctx context.Context, shareCode string) (*model.SpeedTest, error) {
	test := &model.SpeedTest{}
	query := `SELECT id, user_id, device_id, timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, share_code, share_views, created_at FROM speed_tests WHERE share_code = ?`
	
	var userID, deviceID, userAgent, serverID sql.NullString
	err := s.db.QueryRowContext(ctx, query, shareCode).Scan(&test.ID, &userID, &deviceID, &test.Timestamp, &test.DownloadMbps, &test.UploadMbps, &test.PingMs, &test.JitterMs, &test.PacketLoss, &test.ClientIPHash, &userAgent, &serverID, &test.ShareCode, &test.ShareViews, &test.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	
	if userID.Valid {
		test.UserID = userID.String
	}
	if deviceID.Valid {
		test.DeviceID = deviceID.String
	}
	if userAgent.Valid {
		test.UserAgent = userAgent.String
	}
	if serverID.Valid {
		test.ServerID = serverID.String
	}
	
	return test, nil
}

func (s *SQLiteStore) GetUserSpeedTests(ctx context.Context, userID string, limit, offset int) ([]*model.SpeedTest, error) {
	var rows *sql.Rows
	var err error
	if userID == "" {
		// No user filter — return recent public results
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, user_id, device_id, timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, share_code, share_views, created_at FROM speed_tests ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
			limit, offset)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, user_id, device_id, timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, share_code, share_views, created_at FROM speed_tests WHERE user_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
			userID, limit, offset)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tests []*model.SpeedTest
	for rows.Next() {
		test := &model.SpeedTest{}
		if err := rows.Scan(&test.ID, &test.UserID, &test.DeviceID, &test.Timestamp, &test.DownloadMbps, &test.UploadMbps, &test.PingMs, &test.JitterMs, &test.PacketLoss, &test.ClientIPHash, &test.UserAgent, &test.ServerID, &test.ShareCode, &test.ShareViews, &test.CreatedAt); err != nil {
			return nil, err
		}
		tests = append(tests, test)
	}
	return tests, rows.Err()
}

func (s *SQLiteStore) GetDeviceSpeedTests(ctx context.Context, deviceID string, limit, offset int) ([]*model.SpeedTest, error) {
	query := `SELECT id, user_id, device_id, timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, share_code, share_views, created_at FROM speed_tests WHERE device_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, query, deviceID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tests []*model.SpeedTest
	for rows.Next() {
		test := &model.SpeedTest{}
		if err := rows.Scan(&test.ID, &test.UserID, &test.DeviceID, &test.Timestamp, &test.DownloadMbps, &test.UploadMbps, &test.PingMs, &test.JitterMs, &test.PacketLoss, &test.ClientIPHash, &test.UserAgent, &test.ServerID, &test.ShareCode, &test.ShareViews, &test.CreatedAt); err != nil {
			return nil, err
		}
		tests = append(tests, test)
	}
	return tests, rows.Err()
}

func (s *SQLiteStore) UpdateSpeedTest(ctx context.Context, test *model.SpeedTest) error {
	query := `UPDATE speed_tests SET share_code = ?, share_views = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, test.ShareCode, test.ShareViews, test.ID)
	return err
}

func (s *SQLiteStore) DeleteSpeedTest(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM speed_tests WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) IncrementShareViews(ctx context.Context, shareCode string) error {
	query := `UPDATE speed_tests SET share_views = share_views + 1 WHERE share_code = ?`
	_, err := s.db.ExecContext(ctx, query, shareCode)
	return err
}

func (s *SQLiteStore) CreateAPIToken(ctx context.Context, token *model.APIToken) error {
	query := `INSERT INTO api_tokens (id, user_id, token, name, last_used, created_at) VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, token.ID, token.UserID, token.Token, token.Name, token.LastUsed, token.CreatedAt)
	return err
}

func (s *SQLiteStore) GetAPIToken(ctx context.Context, id string) (*model.APIToken, error) {
	token := &model.APIToken{}
	query := `SELECT id, user_id, token, name, last_used, created_at FROM api_tokens WHERE id = ?`
	var lastUsed sql.NullTime
	err := s.db.QueryRowContext(ctx, query, id).Scan(&token.ID, &token.UserID, &token.Token, &token.Name, &lastUsed, &token.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if lastUsed.Valid {
		token.LastUsed = lastUsed.Time
	}
	return token, err
}

func (s *SQLiteStore) GetAPITokenByToken(ctx context.Context, tokenStr string) (*model.APIToken, error) {
	token := &model.APIToken{}
	query := `SELECT id, user_id, token, name, last_used, created_at FROM api_tokens WHERE token = ?`
	var lastUsed sql.NullTime
	err := s.db.QueryRowContext(ctx, query, tokenStr).Scan(&token.ID, &token.UserID, &token.Token, &token.Name, &lastUsed, &token.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if lastUsed.Valid {
		token.LastUsed = lastUsed.Time
	}
	return token, err
}

func (s *SQLiteStore) GetUserAPITokens(ctx context.Context, userID string) ([]*model.APIToken, error) {
	query := `SELECT id, user_id, token, name, last_used, created_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*model.APIToken
	for rows.Next() {
		token := &model.APIToken{}
		var lastUsed sql.NullTime
		if err := rows.Scan(&token.ID, &token.UserID, &token.Token, &token.Name, &lastUsed, &token.CreatedAt); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			token.LastUsed = lastUsed.Time
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (s *SQLiteStore) UpdateAPIToken(ctx context.Context, token *model.APIToken) error {
	query := `UPDATE api_tokens SET name = ?, last_used = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, token.Name, token.LastUsed, token.ID)
	return err
}

func (s *SQLiteStore) DeleteAPIToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) CreateSession(ctx context.Context, session *model.Session) error {
	query := `INSERT INTO sessions (id, user_id, data, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, session.ID, session.UserID, session.Data, session.ExpiresAt, session.CreatedAt)
	return err
}

func (s *SQLiteStore) GetSession(ctx context.Context, id string) (*model.Session, error) {
	session := &model.Session{}
	query := `SELECT id, user_id, data, expires_at, created_at FROM sessions WHERE id = ? AND expires_at > ?`
	err := s.db.QueryRowContext(ctx, query, id, time.Now()).Scan(&session.ID, &session.UserID, &session.Data, &session.ExpiresAt, &session.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return session, err
}

func (s *SQLiteStore) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now())
	return err
}


// Admin methods
func (s *SQLiteStore) GetAdminByUsername(ctx context.Context, username string) (*model.Admin, error) {
	admin := &model.Admin{}
	var createdAt, updatedAt, lastLogin, lockedUntil int64
	var email sql.NullString
	var apiTokenHash sql.NullString
	var lastLoginValid, lockedUntilValid bool
	var enabled int

	query := `SELECT id, username, password, email, role, enabled, created_at, updated_at, last_login, failed_attempts, locked_until, api_token_hash 
	          FROM admins WHERE username = ?`
	
	err := s.db.QueryRowContext(ctx, query, username).Scan(
		&admin.ID, &admin.Username, &admin.Password, &email, &admin.Role, &enabled,
		&createdAt, &updatedAt, &lastLogin, &admin.FailedAttempts, &lockedUntil, &apiTokenHash,
	)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	admin.Enabled = enabled == 1
	admin.CreatedAt = time.Unix(createdAt, 0)
	admin.UpdatedAt = time.Unix(updatedAt, 0)
	if email.Valid {
		admin.Email = email.String
	}
	if apiTokenHash.Valid {
		admin.APITokenHash = apiTokenHash.String
	}
	if lastLoginValid && lastLogin > 0 {
		admin.LastLogin = time.Unix(lastLogin, 0)
	}
	if lockedUntilValid && lockedUntil > 0 {
		admin.LockedUntil = time.Unix(lockedUntil, 0)
	}

	return admin, nil
}

func (s *SQLiteStore) CreateAdmin(ctx context.Context, admin *model.Admin) error {
	enabled := 0
	if admin.Enabled {
		enabled = 1
	}
	query := `INSERT INTO admins (username, password, email, role, enabled) VALUES (?, ?, ?, ?, ?)`
	result, err := s.db.ExecContext(ctx, query, admin.Username, admin.Password, admin.Email, admin.Role, enabled)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	admin.ID = int(id)
	return nil
}

func (s *SQLiteStore) UpdateAdminLastLogin(ctx context.Context, adminID int) error {
	query := `UPDATE admins SET last_login = strftime('%s', 'now'), failed_attempts = 0, locked_until = NULL WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, adminID)
	return err
}

func (s *SQLiteStore) UpdateAdminFailedAttempts(ctx context.Context, adminID int, attempts int) error {
	query := `UPDATE admins SET failed_attempts = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, attempts, adminID)
	return err
}

func (s *SQLiteStore) LockAdmin(ctx context.Context, adminID int, until time.Time) error {
	query := `UPDATE admins SET locked_until = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, until.Unix(), adminID)
	return err
}

func (s *SQLiteStore) CreateAdminSession(ctx context.Context, session *model.AdminSession) error {
	query := `INSERT INTO admin_sessions (id, admin_id, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, session.ID, session.AdminID, session.IPAddress, session.UserAgent, session.ExpiresAt.Unix())
	return err
}

func (s *SQLiteStore) GetAdminSession(ctx context.Context, id string) (*model.AdminSession, error) {
	session := &model.AdminSession{}
	var createdAt, expiresAt, lastActive int64
	var userAgent sql.NullString
	
	query := `SELECT id, admin_id, ip_address, user_agent, created_at, expires_at, last_active 
	          FROM admin_sessions WHERE id = ? AND expires_at > strftime('%s', 'now')`
	
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&session.ID, &session.AdminID, &session.IPAddress, &userAgent,
		&createdAt, &expiresAt, &lastActive,
	)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if userAgent.Valid {
		session.UserAgent = userAgent.String
	}
	session.CreatedAt = time.Unix(createdAt, 0)
	session.ExpiresAt = time.Unix(expiresAt, 0)
	session.LastActive = time.Unix(lastActive, 0)

	return session, nil
}

func (s *SQLiteStore) UpdateAdminSessionActivity(ctx context.Context, id string) error {
	query := `UPDATE admin_sessions SET last_active = strftime('%s', 'now') WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}

func (s *SQLiteStore) DeleteAdminSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) DeleteExpiredAdminSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE expires_at < strftime('%s', 'now')`)
	return err
}

func (s *SQLiteStore) CountAdmins(ctx context.Context) (int, error) {
var count int
query := `SELECT COUNT(*) FROM admins`
err := s.db.QueryRowContext(ctx, query).Scan(&count)
return count, err
}

func (s *SQLiteStore) GetSetupComplete(ctx context.Context) (bool, error) {
var value string
query := `SELECT value FROM system_settings WHERE key = 'setup_complete' LIMIT 1`
err := s.db.QueryRowContext(ctx, query).Scan(&value)

if err == sql.ErrNoRows {
return false, nil
}
if err != nil {
return false, err
}

return value == "true" || value == "1", nil
}

func (s *SQLiteStore) SetSetupComplete(ctx context.Context, complete bool) error {
value := "false"
if complete {
value = "true"
}

query := `INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('setup_complete', ?, strftime('%s', 'now'))`
_, err := s.db.ExecContext(ctx, query, value)
return err
}
