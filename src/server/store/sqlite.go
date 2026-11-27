package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/server/model"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *instrumentedDB
}

func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &SQLiteStore{db: &instrumentedDB{DB: db}}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	return store, nil
}

func (s *SQLiteStore) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT UNIQUE NOT NULL,
	email TEXT UNIQUE NOT NULL,
	display_name TEXT,
	bio TEXT,
	location TEXT,
	website TEXT,
	avatar_url TEXT,
	email_verified INTEGER NOT NULL DEFAULT 1,
	notification_email TEXT,
	notification_email_verified INTEGER NOT NULL DEFAULT 1,
	timezone TEXT,
	language TEXT NOT NULL DEFAULT 'en',
	visibility TEXT NOT NULL DEFAULT 'public',
	org_visibility INTEGER NOT NULL DEFAULT 1,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'user',
	source TEXT NOT NULL DEFAULT 'local',
	external_id TEXT,
	groups TEXT NOT NULL DEFAULT '[]',
	last_sync TIMESTAMP,
	approved INTEGER NOT NULL DEFAULT 1,
	disabled INTEGER NOT NULL DEFAULT 0,
	totp_secret TEXT NOT NULL DEFAULT '',
	totp_enabled INTEGER NOT NULL DEFAULT 0,
	share_show_username INTEGER DEFAULT 0,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_login TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_casefold ON users(username COLLATE NOCASE);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_casefold ON users(email COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS rate_limit_counters (
	key TEXT PRIMARY KEY,
	events_json TEXT NOT NULL,
	updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	last_seen TIMESTAMP,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS speed_tests (
	id TEXT PRIMARY KEY,
	user_id INTEGER,
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
	owner_token_hash TEXT,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
	FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
	id TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	token_hash TEXT UNIQUE NOT NULL,
	token_prefix TEXT NOT NULL,
	name TEXT,
	scope TEXT NOT NULL DEFAULT 'global',
	expires_at TIMESTAMP,
	last_used TIMESTAMP,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	data TEXT NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_totp_secrets (
	user_id INTEGER PRIMARY KEY,
	encrypted_secret TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 0,
	recovery_code_hashes TEXT NOT NULL DEFAULT '[]',
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS admin_totp_secrets (
	admin_id INTEGER PRIMARY KEY,
	encrypted_secret TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 0,
	recovery_code_hashes TEXT NOT NULL DEFAULT '[]',
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS partial_sessions (
	token_hash TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	user_type TEXT NOT NULL DEFAULT 'user',
	remember INTEGER NOT NULL DEFAULT 0,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS passkeys (
	id TEXT PRIMARY KEY,
	user_type TEXT NOT NULL CHECK(user_type IN ('admin', 'user')),
	user_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	public_key TEXT NOT NULL,
	sign_count INTEGER NOT NULL DEFAULT 0,
	transports TEXT NOT NULL DEFAULT '[]',
	aaguid TEXT,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_used TIMESTAMP,
	active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_type, user_id);

CREATE TABLE IF NOT EXISTS passkey_recovery_codes (
	owner_type TEXT NOT NULL CHECK(owner_type IN ('admin','user')),
	owner_id INTEGER NOT NULL,
	code_hash TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(owner_type, owner_id, code_hash)
);
CREATE INDEX IF NOT EXISTS idx_passkey_recovery_owner ON passkey_recovery_codes(owner_type, owner_id);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
	id TEXT PRIMARY KEY,
	user_type TEXT NOT NULL CHECK(user_type IN ('admin', 'user')),
	user_id INTEGER NOT NULL,
	session_data TEXT NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires ON webauthn_challenges(expires_at);

CREATE TABLE IF NOT EXISTS user_notifications (
	 id TEXT PRIMARY KEY,
	 user_id INTEGER NOT NULL,
	 type TEXT NOT NULL,
	 title TEXT NOT NULL,
	 message TEXT NOT NULL,
	 link TEXT NOT NULL,
	 read_at TIMESTAMP,
	 created_at TIMESTAMP NOT NULL,
	 FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_preferences (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL UNIQUE,
	show_email INTEGER NOT NULL DEFAULT 0,
	show_activity INTEGER NOT NULL DEFAULT 1,
	show_orgs INTEGER NOT NULL DEFAULT 1,
	searchable INTEGER NOT NULL DEFAULT 1,
	email_security INTEGER NOT NULL DEFAULT 1,
	email_session INTEGER NOT NULL DEFAULT 1,
	email_mentions INTEGER NOT NULL DEFAULT 1,
	email_updates INTEGER NOT NULL DEFAULT 1,
	email_newsletter INTEGER NOT NULL DEFAULT 0,
	email_digest TEXT NOT NULL DEFAULT 'weekly',
	push_enabled INTEGER NOT NULL DEFAULT 0,
	push_mentions INTEGER NOT NULL DEFAULT 1,
	theme TEXT NOT NULL DEFAULT 'dark',
	font_size TEXT NOT NULL DEFAULT 'medium',
	reduce_motion INTEGER NOT NULL DEFAULT 0,
	date_format TEXT NOT NULL DEFAULT 'YYYY-MM-DD',
	time_format TEXT NOT NULL DEFAULT '24h',
	created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
	updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_speed_tests_user ON speed_tests(user_id);
CREATE INDEX IF NOT EXISTS idx_speed_tests_device ON speed_tests(device_id);
CREATE INDEX IF NOT EXISTS idx_speed_tests_share ON speed_tests(share_code);
CREATE INDEX IF NOT EXISTS idx_speed_tests_timestamp ON speed_tests(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_notifications_user_created ON user_notifications(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_notifications_unread ON user_notifications(user_id, read_at);

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

CREATE TABLE IF NOT EXISTS app_secrets (
	name TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
	user_id INTEGER PRIMARY KEY,
	token_hash TEXT NOT NULL UNIQUE,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS email_verifications (
	token_hash TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	purpose TEXT NOT NULL DEFAULT 'registration',
	pending_email TEXT,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_activation_tokens (
	user_id INTEGER PRIMARY KEY,
	token_hash TEXT NOT NULL UNIQUE,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_invites (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	code_hash TEXT NOT NULL UNIQUE,
	role TEXT NOT NULL DEFAULT 'user',
	max_uses INTEGER NOT NULL DEFAULT 1 CHECK(max_uses>=0),
	use_count INTEGER NOT NULL DEFAULT 0 CHECK(use_count>=0),
	expires_at TIMESTAMP NOT NULL,
	created_by INTEGER NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_user_invites_expiry ON user_invites(expires_at);

CREATE INDEX IF NOT EXISTS idx_password_reset_expiry ON password_reset_tokens(expires_at);

CREATE TABLE IF NOT EXISTS security_reports (
	tracking_id TEXT PRIMARY KEY,
	id_window INTEGER NOT NULL,
	severity TEXT NOT NULL,
	component TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'received',
	body_enc BLOB NOT NULL,
	body_alg TEXT NOT NULL,
	contact_enc BLOB,
	credit_pref TEXT NOT NULL DEFAULT 'no',
	credit_name TEXT,
	researcher_comment TEXT NOT NULL DEFAULT '',
	disclosure_date DATE,
	cve_requested INTEGER NOT NULL DEFAULT 0,
	token_hash TEXT NOT NULL,
	token_last_used DATE,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	closed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_security_reports_status ON security_reports(status, created_at);

CREATE TABLE IF NOT EXISTS captcha_challenges (
	id VARCHAR(32) PRIMARY KEY,
	answer_hash VARCHAR(64) NOT NULL,
	expires_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_captcha_challenges_expires ON captcha_challenges(expires_at);

CREATE TABLE IF NOT EXISTS security_thanks (
	tracking_id TEXT PRIMARY KEY,
	credit TEXT NOT NULL,
	severity TEXT NOT NULL,
	disclosed_on DATE NOT NULL
);

CREATE TABLE IF NOT EXISTS security_keypair_metadata (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	fingerprint TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	last_rotated_at TIMESTAMP,
	keyservers_published TEXT NOT NULL DEFAULT '[]',
	revoked INTEGER NOT NULL DEFAULT 0
);
`

	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	if err := s.migrateUserSettings(); err != nil {
		return err
	}
	if err := s.migrateAPITokenStorage(); err != nil {
		return err
	}
	if err := s.migrateAPITokenPolicy(); err != nil {
		return err
	}
	if err := s.migrateSessionStorage(); err != nil {
		return err
	}
	if err := s.migratePasskeys(); err != nil {
		return err
	}
	columns, err := s.db.Query(`SELECT owner_token_hash FROM speed_tests LIMIT 0`)
	if err != nil {
		if _, migrateErr := s.db.Exec(`ALTER TABLE speed_tests ADD COLUMN owner_token_hash TEXT`); migrateErr != nil {
			return migrateErr
		}
	} else {
		columns.Close()
	}
	preferenceRows, err := s.db.Query(`PRAGMA table_info(user_preferences)`)
	if err != nil {
		return err
	}
	preferenceColumns := make(map[string]bool)
	for preferenceRows.Next() {
		var index, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := preferenceRows.Scan(&index, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			preferenceRows.Close()
			return err
		}
		preferenceColumns[name] = true
	}
	if err := preferenceRows.Close(); err != nil {
		return err
	}
	for _, column := range []struct{ name, definition string }{{"email_session", "INTEGER NOT NULL DEFAULT 1"}, {"email_newsletter", "INTEGER NOT NULL DEFAULT 0"}} {
		if !preferenceColumns[column.name] {
			if _, err := s.db.Exec(`ALTER TABLE user_preferences ADD COLUMN ` + column.name + ` ` + column.definition); err != nil {
				return err
			}
		}
	}
	if err := s.migrateUserPrimaryKey(); err != nil {
		return err
	}
	return nil
}

func (s *SQLiteStore) migratePasskeys() error {
	rows, err := s.db.Query(`PRAGMA table_info(passkeys)`)
	if err != nil {
		return err
	}
	hasActive := false
	for rows.Next() {
		var index, notNull, primary int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&index, &name, &dataType, &notNull, &defaultValue, &primary); err != nil {
			rows.Close()
			return err
		}
		if name == "active" {
			hasActive = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !hasActive {
		if _, err := s.db.Exec(`ALTER TABLE passkeys ADD COLUMN active INTEGER NOT NULL DEFAULT 1`); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) migrateUserPrimaryKey() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return err
	}
	var applied int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name='integer_user_ids'`).Scan(&applied); err != nil {
		return err
	}
	if applied != 0 {
		return nil
	}
	var idType string
	rows, err := s.db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var index, notNull, primary int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&index, &name, &dataType, &notNull, &defaultValue, &primary); err != nil {
			rows.Close()
			return err
		}
		if name == "id" {
			idType = strings.ToUpper(dataType)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if idType == "INTEGER" {
		_, err = s.db.Exec(`INSERT INTO schema_migrations(name) VALUES('integer_user_ids')`)
		return err
	}
	if _, err := s.db.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		return err
	}
	defer s.db.Exec(`PRAGMA foreign_keys = ON`)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE users_integer (
		id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
		display_name TEXT, bio TEXT, location TEXT, website TEXT, avatar_url TEXT,
		email_verified INTEGER NOT NULL DEFAULT 1, notification_email TEXT, notification_email_verified INTEGER NOT NULL DEFAULT 1,
		timezone TEXT, language TEXT NOT NULL DEFAULT 'en', visibility TEXT NOT NULL DEFAULT 'public',
		org_visibility INTEGER NOT NULL DEFAULT 1, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
		source TEXT NOT NULL DEFAULT 'local', external_id TEXT, groups TEXT NOT NULL DEFAULT '[]', last_sync TIMESTAMP,
		approved INTEGER NOT NULL DEFAULT 1, disabled INTEGER NOT NULL DEFAULT 0, totp_secret TEXT NOT NULL DEFAULT '',
		totp_enabled INTEGER NOT NULL DEFAULT 0, share_show_username INTEGER DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO users_integer(username,email,display_name,bio,location,website,avatar_url,email_verified,notification_email,notification_email_verified,timezone,language,visibility,org_visibility,password_hash,role,source,external_id,groups,last_sync,approved,disabled,totp_secret,totp_enabled,share_show_username,created_at,updated_at,last_login)
		SELECT username,email,display_name,bio,location,website,avatar_url,email_verified,notification_email,notification_email_verified,timezone,language,visibility,org_visibility,password_hash,role,source,external_id,groups,last_sync,approved,disabled,totp_secret,totp_enabled,share_show_username,created_at,updated_at,last_login FROM users ORDER BY rowid`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TEMP TABLE user_id_map(old_id TEXT PRIMARY KEY,new_id INTEGER NOT NULL)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO user_id_map(old_id,new_id) SELECT CAST(old.id AS TEXT), replacement.id FROM users old JOIN users_integer replacement ON replacement.username=old.username`); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE partial_sessions SET user_id=CAST((SELECT new_id FROM user_id_map WHERE old_id=CAST(partial_sessions.user_id AS TEXT)) AS TEXT) WHERE user_type='user' AND EXISTS(SELECT 1 FROM user_id_map WHERE old_id=CAST(partial_sessions.user_id AS TEXT))`); err != nil {
		return fmt.Errorf("migrate partial user sessions: %w", err)
	}
	for _, table := range []struct{ name, predicate string }{{"devices", "1=1"}, {"speed_tests", "user_id IS NOT NULL"}, {"api_tokens", "1=1"}, {"sessions", "1=1"}, {"user_totp_secrets", "1=1"}, {"user_notifications", "1=1"}, {"user_preferences", "1=1"}, {"password_reset_tokens", "1=1"}, {"email_verifications", "1=1"}, {"passkeys", "user_type='user'"}, {"webauthn_challenges", "user_type='user'"}} {
		query := `UPDATE ` + table.name + ` SET user_id=(SELECT new_id FROM user_id_map WHERE old_id=CAST(` + table.name + `.user_id AS TEXT)) WHERE ` + table.predicate + ` AND EXISTS(SELECT 1 FROM user_id_map WHERE old_id=CAST(` + table.name + `.user_id AS TEXT))`
		if _, err := tx.Exec(query); err != nil {
			return fmt.Errorf("migrate %s user references: %w", table.name, err)
		}
	}
	if _, err := tx.Exec(`UPDATE passkey_recovery_codes SET owner_id=(SELECT new_id FROM user_id_map WHERE old_id=CAST(passkey_recovery_codes.owner_id AS TEXT)) WHERE owner_type='user' AND EXISTS(SELECT 1 FROM user_id_map WHERE old_id=CAST(passkey_recovery_codes.owner_id AS TEXT))`); err != nil {
		return fmt.Errorf("migrate passkey recovery owner IDs: %w", err)
	}
	if err := rebuildUserReferenceTables(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE users`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE users_integer RENAME TO users`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_casefold ON users(username COLLATE NOCASE)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_casefold ON users(email COLLATE NOCASE)`); err != nil {
		return err
	}
	for _, index := range []string{
		`CREATE INDEX IF NOT EXISTS idx_speed_tests_user ON speed_tests(user_id)`, `CREATE INDEX IF NOT EXISTS idx_speed_tests_device ON speed_tests(device_id)`, `CREATE INDEX IF NOT EXISTS idx_speed_tests_share ON speed_tests(share_code)`, `CREATE INDEX IF NOT EXISTS idx_speed_tests_timestamp ON speed_tests(timestamp)`, `CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`, `CREATE INDEX IF NOT EXISTS idx_user_notifications_user_created ON user_notifications(user_id,created_at DESC)`, `CREATE INDEX IF NOT EXISTS idx_user_notifications_unread ON user_notifications(user_id,read_at)`, `CREATE INDEX IF NOT EXISTS idx_password_reset_expiry ON password_reset_tokens(expires_at)`, `CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_type,user_id)`, `CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires ON webauthn_challenges(expires_at)`, `CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)`,
	} {
		if _, err := tx.Exec(index); err != nil {
			return err
		}
	}
	fkRows, err := tx.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	if fkRows.Next() {
		var table string
		var rowID any
		var parent string
		var foreignKey int
		if err := fkRows.Scan(&table, &rowID, &parent, &foreignKey); err != nil {
			fkRows.Close()
			return err
		}
		fkRows.Close()
		return fmt.Errorf("user ID migration found an invalid reference in %s row %v to %s", table, rowID, parent)
	}
	if err := fkRows.Err(); err != nil {
		fkRows.Close()
		return err
	}
	if err := fkRows.Close(); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(name) VALUES('integer_user_ids')`); err != nil {
		return err
	}
	return tx.Commit()
}

func rebuildUserReferenceTables(tx *sql.Tx) error {
	tables := []struct{ name, create, columns string }{
		{"devices", `CREATE TABLE devices_integer(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,name TEXT NOT NULL,last_seen TIMESTAMP,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`, `id,user_id,name,last_seen,created_at`},
		{"speed_tests", `CREATE TABLE speed_tests_integer(id TEXT PRIMARY KEY,user_id INTEGER,device_id TEXT,timestamp TIMESTAMP NOT NULL,download_mbps REAL NOT NULL,upload_mbps REAL NOT NULL,ping_ms REAL NOT NULL,jitter_ms REAL NOT NULL,packet_loss REAL NOT NULL,client_ip_hash TEXT NOT NULL,user_agent TEXT,server_id TEXT,share_code TEXT UNIQUE,share_views INTEGER DEFAULT 0,owner_token_hash TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL)`, `id,user_id,device_id,timestamp,download_mbps,upload_mbps,ping_ms,jitter_ms,packet_loss,client_ip_hash,user_agent,server_id,share_code,share_views,owner_token_hash,created_at`},
		{"api_tokens", `CREATE TABLE api_tokens_integer(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,token_hash TEXT UNIQUE NOT NULL,token_prefix TEXT NOT NULL,name TEXT,scope TEXT NOT NULL DEFAULT 'global',expires_at TIMESTAMP,last_used TIMESTAMP,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`, `id,user_id,token_hash,token_prefix,name,scope,expires_at,last_used,created_at`},
		{"sessions", `CREATE TABLE sessions_integer(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,data TEXT NOT NULL,expires_at TIMESTAMP NOT NULL,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`, `id,user_id,data,expires_at,created_at`},
		{"user_totp_secrets", `CREATE TABLE user_totp_secrets_integer(user_id INTEGER PRIMARY KEY,encrypted_secret TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,recovery_code_hashes TEXT NOT NULL DEFAULT '[]',created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`, `user_id,encrypted_secret,enabled,recovery_code_hashes,created_at,updated_at`},
		{"user_notifications", `CREATE TABLE user_notifications_integer(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,type TEXT NOT NULL,title TEXT NOT NULL,message TEXT NOT NULL,link TEXT NOT NULL,read_at TIMESTAMP,created_at TIMESTAMP NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`, `id,user_id,type,title,message,link,read_at,created_at`},
		{"user_preferences", `CREATE TABLE user_preferences_integer(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL UNIQUE,show_email INTEGER NOT NULL DEFAULT 0,show_activity INTEGER NOT NULL DEFAULT 1,show_orgs INTEGER NOT NULL DEFAULT 1,searchable INTEGER NOT NULL DEFAULT 1,email_security INTEGER NOT NULL DEFAULT 1,email_session INTEGER NOT NULL DEFAULT 1,email_mentions INTEGER NOT NULL DEFAULT 1,email_updates INTEGER NOT NULL DEFAULT 1,email_newsletter INTEGER NOT NULL DEFAULT 0,email_digest TEXT NOT NULL DEFAULT 'weekly',push_enabled INTEGER NOT NULL DEFAULT 0,push_mentions INTEGER NOT NULL DEFAULT 1,theme TEXT NOT NULL DEFAULT 'dark',font_size TEXT NOT NULL DEFAULT 'medium',reduce_motion INTEGER NOT NULL DEFAULT 0,date_format TEXT NOT NULL DEFAULT 'YYYY-MM-DD',time_format TEXT NOT NULL DEFAULT '24h',created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`, `id,user_id,show_email,show_activity,show_orgs,searchable,email_security,email_session,email_mentions,email_updates,email_newsletter,email_digest,push_enabled,push_mentions,theme,font_size,reduce_motion,date_format,time_format,created_at,updated_at`},
		{"password_reset_tokens", `CREATE TABLE password_reset_tokens_integer(user_id INTEGER PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,expires_at TIMESTAMP NOT NULL,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`, `user_id,token_hash,expires_at,created_at`},
		{"email_verifications", `CREATE TABLE email_verifications_integer(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,purpose TEXT NOT NULL DEFAULT 'registration',pending_email TEXT,expires_at TIMESTAMP NOT NULL,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`, `token_hash,user_id,purpose,pending_email,expires_at,created_at`},
		{"passkeys", `CREATE TABLE passkeys_integer(id TEXT PRIMARY KEY,user_type TEXT NOT NULL CHECK(user_type IN ('admin','user')),user_id INTEGER NOT NULL,name TEXT NOT NULL,public_key TEXT NOT NULL,sign_count INTEGER NOT NULL DEFAULT 0,transports TEXT NOT NULL DEFAULT '[]',aaguid TEXT,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,last_used TIMESTAMP,active INTEGER NOT NULL DEFAULT 1)`, `id,user_type,user_id,name,public_key,sign_count,transports,aaguid,created_at,last_used,active`},
		{"webauthn_challenges", `CREATE TABLE webauthn_challenges_integer(id TEXT PRIMARY KEY,user_type TEXT NOT NULL CHECK(user_type IN ('admin','user')),user_id INTEGER NOT NULL,session_data TEXT NOT NULL,expires_at TIMESTAMP NOT NULL,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`, `id,user_type,user_id,session_data,expires_at,created_at`},
	}
	for _, table := range tables {
		if _, err := tx.Exec(table.create); err != nil {
			return fmt.Errorf("create integer %s table: %w", table.name, err)
		}
		if _, err := tx.Exec(`INSERT INTO ` + table.name + `_integer(` + table.columns + `) SELECT ` + table.columns + ` FROM ` + table.name); err != nil {
			return fmt.Errorf("copy integer %s table: %w", table.name, err)
		}
		if _, err := tx.Exec(`DROP TABLE ` + table.name); err != nil {
			return fmt.Errorf("drop legacy %s table: %w", table.name, err)
		}
		if _, err := tx.Exec(`ALTER TABLE ` + table.name + `_integer RENAME TO ` + table.name); err != nil {
			return fmt.Errorf("rename integer %s table: %w", table.name, err)
		}
	}
	return nil
}

func (s *SQLiteStore) migrateUserSettings() error {
	rows, err := s.db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var index int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&index, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, column := range []struct{ name, definition string }{
		{"display_name", "TEXT"}, {"bio", "TEXT"}, {"location", "TEXT"}, {"website", "TEXT"}, {"avatar_url", "TEXT"}, {"email_verified", "INTEGER NOT NULL DEFAULT 1"}, {"notification_email", "TEXT"}, {"notification_email_verified", "INTEGER NOT NULL DEFAULT 1"},
		{"timezone", "TEXT"}, {"language", "TEXT NOT NULL DEFAULT 'en'"},
		{"visibility", "TEXT NOT NULL DEFAULT 'public'"}, {"org_visibility", "INTEGER NOT NULL DEFAULT 1"},
		{"role", "TEXT NOT NULL DEFAULT 'user'"}, {"source", "TEXT NOT NULL DEFAULT 'local'"}, {"external_id", "TEXT"},
		{"groups", "TEXT NOT NULL DEFAULT '[]'"}, {"last_sync", "TIMESTAMP"}, {"approved", "INTEGER NOT NULL DEFAULT 1"},
		{"disabled", "INTEGER NOT NULL DEFAULT 0"}, {"totp_secret", "TEXT NOT NULL DEFAULT ''"}, {"totp_enabled", "INTEGER NOT NULL DEFAULT 0"},
		{"updated_at", "TIMESTAMP"}, {"last_login", "TIMESTAMP"},
	} {
		if columns[column.name] {
			continue
		}
		if _, err := s.db.Exec(`ALTER TABLE users ADD COLUMN ` + column.name + ` ` + column.definition); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL`); err != nil {
		return err
	}
	verificationRows, err := s.db.Query(`PRAGMA table_info(email_verifications)`)
	if err != nil {
		return err
	}
	verificationColumns := make(map[string]bool)
	for verificationRows.Next() {
		var index, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := verificationRows.Scan(&index, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			verificationRows.Close()
			return err
		}
		verificationColumns[name] = true
	}
	if err := verificationRows.Close(); err != nil {
		return err
	}
	for _, column := range []struct{ name, definition string }{{"purpose", "TEXT NOT NULL DEFAULT 'registration'"}, {"pending_email", "TEXT"}} {
		if !verificationColumns[column.name] {
			if _, err := s.db.Exec(`ALTER TABLE email_verifications ADD COLUMN ` + column.name + ` ` + column.definition); err != nil {
				return err
			}
		}
	}
	return nil
}

// CreateCaptchaChallenge persists only the hashed answer and its expiry.
func (s *SQLiteStore) CreateCaptchaChallenge(ctx context.Context, id, answerHash string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO captcha_challenges (id, answer_hash, expires_at) VALUES (?, ?, ?)`, id, answerHash, expiresAt.UTC())
	return err
}

// ConsumeCaptchaChallenge atomically deletes and returns a challenge, making every proof single-use.
func (s *SQLiteStore) ConsumeCaptchaChallenge(ctx context.Context, id string) (string, time.Time, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback()
	var answerHash string
	var expiresAt time.Time
	if err := tx.QueryRowContext(ctx, `SELECT answer_hash, expires_at FROM captcha_challenges WHERE id = ?`, id).Scan(&answerHash, &expiresAt); err != nil {
		return "", time.Time{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM captcha_challenges WHERE id = ?`, id); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, err
	}
	return answerHash, expiresAt, nil
}

// DeleteExpiredCaptchaChallenges removes expired one-use challenge records.
func (s *SQLiteStore) DeleteExpiredCaptchaChallenges(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM captcha_challenges WHERE expires_at <= ?`, now.UTC())
	return err
}

func (s *SQLiteStore) migrateSessionStorage() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return err
	}
	var applied int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = 'session_token_hashes'`).Scan(&applied); err != nil {
		return err
	}
	if applied > 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id FROM sessions`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		hash := sha256.Sum256([]byte(id))
		if _, err := tx.Exec(`UPDATE sessions SET id = ? WHERE id = ?`, hex.EncodeToString(hash[:]), id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations (name) VALUES ('session_token_hashes')`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) migrateAPITokenStorage() error {
	rows, err := s.db.Query(`SELECT id, user_id, token_hash FROM api_tokens LIMIT 0`)
	if err == nil {
		if err := rows.Close(); err != nil {
			return err
		}
		_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)`)
		return err
	}
	legacyRows, err := s.db.Query(`SELECT id, user_id, token, name, last_used, created_at FROM api_tokens`)
	if err != nil {
		return err
	}
	type legacyToken struct {
		id, userID, token, name string
		lastUsed, createdAt     sql.NullTime
	}
	var tokens []legacyToken
	for legacyRows.Next() {
		var token legacyToken
		if err := legacyRows.Scan(&token.id, &token.userID, &token.token, &token.name, &token.lastUsed, &token.createdAt); err != nil {
			legacyRows.Close()
			return err
		}
		tokens = append(tokens, token)
	}
	if err := legacyRows.Err(); err != nil {
		legacyRows.Close()
		return err
	}
	if err := legacyRows.Close(); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE api_tokens_migrated (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		token_hash TEXT UNIQUE NOT NULL,
		token_prefix TEXT NOT NULL,
		name TEXT,
		scope TEXT NOT NULL DEFAULT 'global',
		expires_at TIMESTAMP,
		last_used TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`); err != nil {
		return err
	}
	for _, token := range tokens {
		hash := sha256.Sum256([]byte(token.token))
		prefix := token.token
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		if _, err := tx.Exec(`INSERT INTO api_tokens_migrated (id, user_id, token_hash, token_prefix, name, last_used, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, token.id, token.userID, hex.EncodeToString(hash[:]), prefix, token.name, token.lastUsed, token.createdAt); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DROP TABLE api_tokens`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE api_tokens_migrated RENAME TO api_tokens`); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)`)
	if err != nil {
		return err
	}
	return s.migrateAPITokenPolicy()
}

func (s *SQLiteStore) migrateAPITokenPolicy() error {
	rows, err := s.db.Query(`PRAGMA table_info(api_tokens)`)
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !columns["scope"] {
		if _, err := s.db.Exec(`ALTER TABLE api_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT 'global'`); err != nil {
			return err
		}
	}
	if !columns["expires_at"] {
		if _, err := s.db.Exec(`ALTER TABLE api_tokens ADD COLUMN expires_at TIMESTAMP`); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) LoadRateCounters(ctx context.Context) (map[string][]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, events_json FROM rate_limit_counters`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counters := make(map[string][]time.Time)
	for rows.Next() {
		var key, encoded string
		if err := rows.Scan(&key, &encoded); err != nil {
			return nil, err
		}
		var events []time.Time
		if err := json.Unmarshal([]byte(encoded), &events); err != nil {
			return nil, fmt.Errorf("decode rate-limit counter: %w", err)
		}
		counters[key] = events
	}
	return counters, rows.Err()
}

func (s *SQLiteStore) SaveRateCounters(ctx context.Context, counters map[string][]time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM rate_limit_counters`); err != nil {
		tx.Rollback()
		return err
	}
	for key, events := range counters {
		encoded, err := json.Marshal(events)
		if err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO rate_limit_counters(key, events_json, updated_at) VALUES(?, ?, ?)`, key, string(encoded), time.Now().UTC()); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// DBStats returns the underlying sql.DB connection pool statistics.
func (s *SQLiteStore) DBStats() sql.DBStats {
	return s.db.Stats()
}

func (s *SQLiteStore) CreateUser(ctx context.Context, user *model.User) error {
	query := `INSERT INTO users (username, email, display_name, bio, location, website, avatar_url, email_verified, notification_email, notification_email_verified, timezone, language, visibility, org_visibility, password_hash, role, source, external_id, groups, last_sync, approved, disabled, totp_secret, totp_enabled, share_show_username, created_at, updated_at, last_login)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	language, visibility := user.Language, user.Visibility
	if language == "" {
		language = "en"
	}
	if visibility == "" {
		visibility = "public"
	}
	role, source := user.Role, user.Source
	if role == "" {
		role = "user"
	}
	if source == "" {
		source = "local"
	}
	approved := user.Approved || source == "local"
	groups, err := json.Marshal(user.Groups)
	if err != nil {
		return fmt.Errorf("encode user groups: %w", err)
	}
	if user.Groups == nil {
		groups = []byte("[]")
	}
	var externalID any
	if user.ExternalID != "" {
		externalID = user.ExternalID
	}
	updatedAt := user.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	result, err := s.db.ExecContext(ctx, query, user.Username, user.Email, user.DisplayName, user.Bio, user.Location, user.Website, user.AvatarURL, user.EmailVerified, user.NotificationEmail, user.NotificationEmailVerified, user.Timezone, language, visibility, user.OrgVisibility, user.PasswordHash, role, source, externalID, string(groups), user.LastSync, approved, user.Disabled, user.TOTPSecret, user.TOTPEnabled, user.ShareShowUsername, user.CreatedAt, updatedAt, user.LastLogin)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err == nil {
		user.ID = id
	}
	return err
}

type rowScanner interface{ Scan(...any) error }

const userSelectColumns = `id,username,email,display_name,bio,location,website,avatar_url,email_verified,notification_email,notification_email_verified,timezone,language,visibility,org_visibility,password_hash,role,source,external_id,groups,last_sync,approved,disabled,totp_secret,totp_enabled,share_show_username,created_at,updated_at,last_login`

func scanUser(row rowScanner) (*model.User, error) {
	user := &model.User{}
	var displayName, bio, location, website, avatarURL, notificationEmail, timezone sql.NullString
	var externalID, groups sql.NullString
	var lastSync, lastLogin sql.NullTime
	err := row.Scan(&user.ID, &user.Username, &user.Email, &displayName, &bio, &location, &website, &avatarURL,
		&user.EmailVerified, &notificationEmail, &user.NotificationEmailVerified, &timezone, &user.Language, &user.Visibility, &user.OrgVisibility,
		&user.PasswordHash, &user.Role, &user.Source, &externalID, &groups, &lastSync, &user.Approved, &user.Disabled, &user.TOTPSecret, &user.TOTPEnabled,
		&user.ShareShowUsername, &user.CreatedAt, &user.UpdatedAt, &lastLogin)
	if err != nil {
		return nil, err
	}
	user.DisplayName, user.Bio, user.Location = displayName.String, bio.String, location.String
	user.Website, user.AvatarURL, user.NotificationEmail, user.Timezone = website.String, avatarURL.String, notificationEmail.String, timezone.String
	if externalID.Valid {
		user.ExternalID = externalID.String
	}
	if groups.Valid && groups.String != "" {
		if err := json.Unmarshal([]byte(groups.String), &user.Groups); err != nil {
			return nil, fmt.Errorf("decode user groups: %w", err)
		}
	}
	if user.Groups == nil {
		user.Groups = []string{}
	}
	if lastSync.Valid {
		user.LastSync = &lastSync.Time
	}
	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}
	return user, nil
}

func (s *SQLiteStore) GetUser(ctx context.Context, id string) (*model.User, error) {
	user, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userSelectColumns+` FROM users WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

func (s *SQLiteStore) CreateUserNotification(ctx context.Context, notification *model.Notification) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO user_notifications (id, user_id, type, title, message, link, read_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		notification.ID, notification.UserID, notification.Type, notification.Title, notification.Message, notification.Link, notification.ReadAt, notification.CreatedAt)
	return err
}

func (s *SQLiteStore) GetUserNotifications(ctx context.Context, userID string, limit int) ([]*model.Notification, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, type, title, message, link, read_at, created_at FROM user_notifications WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	notifications := make([]*model.Notification, 0)
	for rows.Next() {
		item := &model.Notification{}
		var readAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.UserID, &item.Type, &item.Title, &item.Message, &item.Link, &readAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		if readAt.Valid {
			item.ReadAt = &readAt.Time
		}
		notifications = append(notifications, item)
	}
	return notifications, rows.Err()
}

func (s *SQLiteStore) CountUnreadUserNotifications(ctx context.Context, userID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_notifications WHERE user_id = ? AND read_at IS NULL`, userID).Scan(&count)
	return count, err
}

func (s *SQLiteStore) MarkUserNotificationRead(ctx context.Context, userID, notificationID string, readAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE user_notifications SET read_at = ? WHERE id = ? AND user_id = ? AND read_at IS NULL`, readAt, notificationID, userID)
	return err
}

func (s *SQLiteStore) MarkAllUserNotificationsRead(ctx context.Context, userID string, readAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE user_notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL`, readAt, userID)
	return err
}

func (s *SQLiteStore) ClearUserNotifications(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_notifications WHERE user_id = ?`, userID)
	return err
}

func (s *SQLiteStore) GetOrCreateUserSettings(ctx context.Context, userID string) (*model.UserSettings, error) {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO user_preferences (user_id) VALUES (?) ON CONFLICT(user_id) DO NOTHING`, userID); err != nil {
		return nil, err
	}
	settings := &model.UserSettings{UserID: userID}
	err := s.db.QueryRowContext(ctx, `SELECT show_email, show_activity, show_orgs, searchable, email_security, email_session, email_mentions, email_updates, email_newsletter, email_digest, push_enabled, push_mentions, theme, font_size, reduce_motion, date_format, time_format FROM user_preferences WHERE user_id = ?`, userID).Scan(
		&settings.ShowEmail, &settings.ShowActivity, &settings.ShowOrgs, &settings.Searchable,
		&settings.EmailSecurity, &settings.EmailSession, &settings.EmailMentions, &settings.EmailUpdates, &settings.EmailNewsletter, &settings.EmailDigest,
		&settings.PushEnabled, &settings.PushMentions, &settings.Theme, &settings.FontSize,
		&settings.ReduceMotion, &settings.DateFormat, &settings.TimeFormat,
	)
	if err != nil {
		return nil, err
	}
	return settings, nil
}

func (s *SQLiteStore) UpdateUserSettings(ctx context.Context, settings *model.UserSettings) error {
	_, err := s.db.ExecContext(ctx, `UPDATE user_preferences SET show_email=?, show_activity=?, show_orgs=?, searchable=?, email_security=1, email_session=?, email_mentions=?, email_updates=?, email_newsletter=?, email_digest=?, push_enabled=?, push_mentions=?, theme=?, font_size=?, reduce_motion=?, date_format=?, time_format=?, updated_at=strftime('%s','now') WHERE user_id=?`,
		settings.ShowEmail, settings.ShowActivity, settings.ShowOrgs, settings.Searchable,
		settings.EmailSession, settings.EmailMentions, settings.EmailUpdates, settings.EmailNewsletter, settings.EmailDigest, settings.PushEnabled,
		settings.PushMentions, settings.Theme, settings.FontSize, settings.ReduceMotion,
		settings.DateFormat, settings.TimeFormat, settings.UserID)
	return err
}

func (s *SQLiteStore) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	user, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userSelectColumns+` FROM users WHERE username = ? COLLATE NOCASE`, username))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

func (s *SQLiteStore) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	user, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userSelectColumns+` FROM users WHERE email = ? COLLATE NOCASE`, email))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, user *model.User) error {
	groups, err := json.Marshal(user.Groups)
	if err != nil {
		return fmt.Errorf("encode user groups: %w", err)
	}
	if user.Groups == nil {
		groups = []byte("[]")
	}
	query := `UPDATE users SET username=?, email=?, display_name=?, bio=?, location=?, website=?, avatar_url=?, email_verified=?, notification_email=?, notification_email_verified=?, timezone=?, language=?, visibility=?, org_visibility=?, password_hash=?, share_show_username=?, role=?, source=?, external_id=?, groups=?, last_sync=?, approved=?, disabled=?, totp_secret=?, totp_enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`
	_, err = s.db.ExecContext(ctx, query, user.Username, user.Email, user.DisplayName, user.Bio, user.Location, user.Website, user.AvatarURL, user.EmailVerified, user.NotificationEmail, user.NotificationEmailVerified, user.Timezone, user.Language, user.Visibility, user.OrgVisibility, user.PasswordHash, user.ShareShowUsername, user.Role, user.Source, nullableUserString(user.ExternalID), string(groups), user.LastSync, user.Approved, user.Disabled, user.TOTPSecret, user.TOTPEnabled, user.ID)
	return err
}

func nullableUserString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (s *SQLiteStore) ListUsers(ctx context.Context, limit, offset int, search string) ([]*model.User, int, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	search = strings.TrimSpace(search)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE ?='' OR instr(lower(username),lower(?))>0 OR instr(lower(email),lower(?))>0`, search, search, search).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+userSelectColumns+` FROM users WHERE ?='' OR instr(lower(username),lower(?))>0 OR instr(lower(email),lower(?))>0 ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, search, search, search, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	users := make([]*model.User, 0)
	for rows.Next() {
		user, scanErr := scanUser(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		users = append(users, user)
	}
	return users, total, rows.Err()
}

func (s *SQLiteStore) CreateUserActivationToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_activation_tokens WHERE expires_at<=?`, time.Now().UTC()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_activation_tokens WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_activation_tokens(user_id,token_hash,expires_at) VALUES(?,?,?)`, userID, tokenHash, expiresAt.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) CompleteUserActivationToken(ctx context.Context, tokenHash string, now time.Time, passwordHash string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var userID string
	rows, err := tx.QueryContext(ctx, `SELECT user_id,token_hash FROM user_activation_tokens WHERE expires_at>?`, now.UTC())
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var candidateID, candidateHash string
		if err := rows.Scan(&candidateID, &candidateHash); err != nil {
			rows.Close()
			return false, err
		}
		if len(candidateHash) == len(tokenHash) && subtle.ConstantTimeCompare([]byte(candidateHash), []byte(tokenHash)) == 1 {
			userID = candidateID
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	if userID == "" {
		return false, nil
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM user_activation_tokens WHERE token_hash=? AND expires_at>?`, tokenHash, now.UTC())
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if count != 1 {
		return false, nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET password_hash=?,email_verified=1,approved=1,disabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=?`, passwordHash, userID); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteStore) CreateUserInvite(ctx context.Context, invite *model.UserInvite) error {
	if invite == nil || invite.CodeHash == "" || invite.Role == "" || invite.MaxUses < 0 || invite.CreatedBy < 0 {
		return fmt.Errorf("invalid user invite")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO user_invites(code_hash,role,max_uses,use_count,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?,?)`, invite.CodeHash, invite.Role, invite.MaxUses, invite.UseCount, invite.ExpiresAt.UTC(), invite.CreatedBy, invite.CreatedAt.UTC())
	if err != nil {
		return err
	}
	invite.ID, err = result.LastInsertId()
	return err
}

func (s *SQLiteStore) GetUserInvite(ctx context.Context, id int64) (*model.UserInvite, error) {
	invite := &model.UserInvite{}
	err := s.db.QueryRowContext(ctx, `SELECT id,role,max_uses,use_count,expires_at,created_by,created_at FROM user_invites WHERE id=?`, id).Scan(&invite.ID, &invite.Role, &invite.MaxUses, &invite.UseCount, &invite.ExpiresAt, &invite.CreatedBy, &invite.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return invite, err
}

func (s *SQLiteStore) GetUserInviteByCode(ctx context.Context, rawCode string, now time.Time) (*model.UserInvite, error) {
	hash := tokenHash(rawCode)
	rows, err := s.db.QueryContext(ctx, `SELECT id,code_hash,role,max_uses,use_count,expires_at,created_by,created_at FROM user_invites WHERE expires_at>?`, now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var invite *model.UserInvite
	for rows.Next() {
		candidate := &model.UserInvite{}
		var candidateHash string
		if err := rows.Scan(&candidate.ID, &candidateHash, &candidate.Role, &candidate.MaxUses, &candidate.UseCount, &candidate.ExpiresAt, &candidate.CreatedBy, &candidate.CreatedAt); err != nil {
			return nil, err
		}
		if len(candidateHash) == len(hash) && subtle.ConstantTimeCompare([]byte(candidateHash), []byte(hash)) == 1 {
			invite = candidate
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if invite == nil || invite.MaxUses > 0 && invite.UseCount >= invite.MaxUses {
		return nil, nil
	}
	invite.CodeHash = ""
	return invite, nil
}

func (s *SQLiteStore) ListUserInvites(ctx context.Context) ([]*model.UserInvite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,role,max_uses,use_count,expires_at,created_by,created_at FROM user_invites ORDER BY created_at DESC,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	invites := make([]*model.UserInvite, 0)
	for rows.Next() {
		invite := &model.UserInvite{}
		if err := rows.Scan(&invite.ID, &invite.Role, &invite.MaxUses, &invite.UseCount, &invite.ExpiresAt, &invite.CreatedBy, &invite.CreatedAt); err != nil {
			return nil, err
		}
		invites = append(invites, invite)
	}
	return invites, rows.Err()
}

func (s *SQLiteStore) RevokeUserInvite(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_invites WHERE id=?`, id)
	return err
}

func (s *SQLiteStore) ConsumeUserInviteCode(ctx context.Context, rawCode string, now time.Time) (*model.UserInvite, error) {
	hash := tokenHash(rawCode)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,code_hash,role,max_uses,use_count,expires_at,created_by,created_at FROM user_invites WHERE expires_at>?`, now.UTC())
	if err != nil {
		return nil, err
	}
	var invite *model.UserInvite
	for rows.Next() {
		candidate := &model.UserInvite{}
		var candidateHash string
		if err := rows.Scan(&candidate.ID, &candidateHash, &candidate.Role, &candidate.MaxUses, &candidate.UseCount, &candidate.ExpiresAt, &candidate.CreatedBy, &candidate.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		if len(candidateHash) == len(hash) && subtle.ConstantTimeCompare([]byte(candidateHash), []byte(hash)) == 1 {
			invite = candidate
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if invite == nil || invite.MaxUses > 0 && invite.UseCount >= invite.MaxUses {
		return nil, nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE user_invites SET use_count=use_count+1 WHERE id=? AND expires_at>? AND (max_uses=0 OR use_count<max_uses)`, invite.ID, now.UTC())
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, nil
	}
	invite.UseCount++
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return invite, nil
}

func (s *SQLiteStore) CompleteUserInvite(ctx context.Context, rawCode string, now time.Time, user *model.User) error {
	if user == nil || user.Username == "" || user.Email == "" || user.PasswordHash == "" {
		return fmt.Errorf("invalid user invite registration")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	hash := tokenHash(rawCode)
	rows, err := tx.QueryContext(ctx, `SELECT id,code_hash,role,max_uses,use_count,expires_at,created_by,created_at FROM user_invites WHERE expires_at>?`, now.UTC())
	if err != nil {
		return err
	}
	var invite *model.UserInvite
	for rows.Next() {
		candidate := &model.UserInvite{}
		var candidateHash string
		if err := rows.Scan(&candidate.ID, &candidateHash, &candidate.Role, &candidate.MaxUses, &candidate.UseCount, &candidate.ExpiresAt, &candidate.CreatedBy, &candidate.CreatedAt); err != nil {
			rows.Close()
			return err
		}
		if len(candidateHash) == len(hash) && subtle.ConstantTimeCompare([]byte(candidateHash), []byte(hash)) == 1 {
			invite = candidate
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if invite == nil || invite.MaxUses > 0 && invite.UseCount >= invite.MaxUses {
		return fmt.Errorf("invalid or expired user invite")
	}
	result, err := tx.ExecContext(ctx, `UPDATE user_invites SET use_count=use_count+1 WHERE id=? AND expires_at>? AND (max_uses=0 OR use_count<max_uses)`, invite.ID, now.UTC())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("user invite use limit reached")
	}
	user.Role, user.Source, user.Approved, user.Disabled = invite.Role, "local", true, false
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now.UTC()
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now.UTC()
	}
	if err := insertUser(ctx, tx, user); err != nil {
		return err
	}
	return tx.Commit()
}

type userExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertUser(ctx context.Context, exec userExecer, user *model.User) error {
	query := `INSERT INTO users (username,email,display_name,bio,location,website,avatar_url,email_verified,notification_email,notification_email_verified,timezone,language,visibility,org_visibility,password_hash,role,source,external_id,groups,last_sync,approved,disabled,totp_secret,totp_enabled,share_show_username,created_at,updated_at,last_login) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	language, visibility, role, source := user.Language, user.Visibility, user.Role, user.Source
	if language == "" {
		language = "en"
	}
	if visibility == "" {
		visibility = "public"
	}
	if role == "" {
		role = "user"
	}
	if source == "" {
		source = "local"
	}
	groups, err := json.Marshal(user.Groups)
	if err != nil {
		return fmt.Errorf("encode user groups: %w", err)
	}
	if user.Groups == nil {
		groups = []byte("[]")
	}
	var externalID any
	if user.ExternalID != "" {
		externalID = user.ExternalID
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now().UTC()
	}
	result, err := exec.ExecContext(ctx, query, user.Username, user.Email, user.DisplayName, user.Bio, user.Location, user.Website, user.AvatarURL, user.EmailVerified, user.NotificationEmail, user.NotificationEmailVerified, user.Timezone, language, visibility, user.OrgVisibility, user.PasswordHash, role, source, externalID, string(groups), user.LastSync, user.Approved, user.Disabled, user.TOTPSecret, user.TOTPEnabled, user.ShareShowUsername, user.CreatedAt, user.UpdatedAt, user.LastLogin)
	if err != nil {
		return err
	}
	user.ID, err = result.LastInsertId()
	return err
}

func (s *SQLiteStore) UpdateUserLastLogin(ctx context.Context, userID string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET last_login = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, at.UTC(), userID)
	return err
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`DELETE FROM speed_tests WHERE user_id = ?`,
		`DELETE FROM devices WHERE user_id = ?`,
		`DELETE FROM api_tokens WHERE user_id = ?`,
		`DELETE FROM sessions WHERE user_id = ?`,
		`DELETE FROM partial_sessions WHERE user_type='user' AND user_id = ?`,
		`DELETE FROM user_totp_secrets WHERE user_id = ?`,
		`DELETE FROM user_notifications WHERE user_id = ?`,
		`DELETE FROM user_preferences WHERE user_id = ?`,
		`DELETE FROM password_reset_tokens WHERE user_id = ?`,
		`DELETE FROM email_verifications WHERE user_id = ?`,
		`DELETE FROM user_activation_tokens WHERE user_id = ?`,
		`DELETE FROM passkeys WHERE user_type='user' AND user_id = ?`,
		`DELETE FROM passkey_recovery_codes WHERE owner_type='user' AND owner_id = ?`,
		`DELETE FROM webauthn_challenges WHERE user_type='user' AND user_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, statement, id); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) CreateEmailVerification(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM email_verifications WHERE user_id = ?`, userID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO email_verifications(token_hash, user_id, purpose, expires_at) VALUES(?, ?, 'registration', ?)`, tokenHash, userID, expiresAt.UTC())
	return err
}

func (s *SQLiteStore) CreatePendingEmailVerification(ctx context.Context, userID, tokenHash, email, purpose string, expiresAt time.Time) error {
	if purpose != "account_change" && purpose != "notification_change" {
		return fmt.Errorf("invalid email verification purpose")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM email_verifications WHERE user_id = ? AND purpose = ?`, userID, purpose); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO email_verifications(token_hash, user_id, purpose, pending_email, expires_at) VALUES(?, ?, ?, ?, ?)`, tokenHash, userID, purpose, email, expiresAt.UTC())
	return err
}

func (s *SQLiteStore) GetUserTOTP(ctx context.Context, userID string) (*model.TOTPSecret, error) {
	secret := &model.TOTPSecret{UserID: userID}
	var hashes string
	err := s.db.QueryRowContext(ctx, `SELECT encrypted_secret, enabled, recovery_code_hashes FROM user_totp_secrets WHERE user_id = ?`, userID).Scan(&secret.EncryptedSecret, &secret.Enabled, &hashes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(hashes), &secret.RecoveryCodeHashes); err != nil {
		return nil, fmt.Errorf("decode recovery code hashes: %w", err)
	}
	return secret, nil
}

func (s *SQLiteStore) SaveUserTOTP(ctx context.Context, secret *model.TOTPSecret) error {
	hashes, err := json.Marshal(secret.RecoveryCodeHashes)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO user_totp_secrets(user_id, encrypted_secret, enabled, recovery_code_hashes) VALUES(?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET encrypted_secret=excluded.encrypted_secret, enabled=excluded.enabled, recovery_code_hashes=excluded.recovery_code_hashes, updated_at=CURRENT_TIMESTAMP`, secret.UserID, secret.EncryptedSecret, secret.Enabled, string(hashes))
	return err
}

func (s *SQLiteStore) DeleteUserTOTP(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_totp_secrets WHERE user_id = ?`, userID)
	return err
}

func (s *SQLiteStore) CreatePartialSession(ctx context.Context, session *model.PartialSession) error {
	if session.UserType != "user" && session.UserType != "admin" {
		return fmt.Errorf("unsupported partial-session account type")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM partial_sessions WHERE expires_at <= ?`, time.Now().UTC()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO partial_sessions(token_hash, user_id, user_type, remember, expires_at) VALUES(?, ?, ?, ?, ?)`, session.TokenHash, session.UserID, session.UserType, session.Remember, session.ExpiresAt.UTC())
	return err
}

func (s *SQLiteStore) GetPartialSession(ctx context.Context, tokenHash string, now time.Time) (*model.PartialSession, error) {
	session := &model.PartialSession{TokenHash: tokenHash}
	err := s.db.QueryRowContext(ctx, `SELECT user_id, user_type, remember, expires_at FROM partial_sessions WHERE token_hash = ? AND expires_at > ?`, tokenHash, now.UTC()).Scan(&session.UserID, &session.UserType, &session.Remember, &session.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return session, err
}

func (s *SQLiteStore) ConsumePartialSession(ctx context.Context, tokenHash string, now time.Time) (*model.PartialSession, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	session := &model.PartialSession{TokenHash: tokenHash}
	err = tx.QueryRowContext(ctx, `SELECT user_id, user_type, remember, expires_at FROM partial_sessions WHERE token_hash = ? AND expires_at > ?`, tokenHash, now.UTC()).Scan(&session.UserID, &session.UserType, &session.Remember, &session.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM partial_sessions WHERE token_hash = ?`, tokenHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *SQLiteStore) ConsumeUserRecoveryCode(ctx context.Context, userID, hash string) (int, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	var encoded []byte
	if err := tx.QueryRowContext(ctx, `SELECT recovery_code_hashes FROM user_totp_secrets WHERE user_id = ? AND enabled = 1`, userID).Scan(&encoded); err != nil {
		return 0, false, err
	}
	var hashes []string
	if err := json.Unmarshal(encoded, &hashes); err != nil {
		return 0, false, fmt.Errorf("decode recovery code hashes: %w", err)
	}
	matched := -1
	for i, candidate := range hashes {
		if len(candidate) == len(hash) && subtle.ConstantTimeCompare([]byte(candidate), []byte(hash)) == 1 {
			matched = i
		}
	}
	if matched < 0 {
		return len(hashes), false, nil
	}
	hashes = append(hashes[:matched], hashes[matched+1:]...)
	encoded, err = json.Marshal(hashes)
	if err != nil {
		return 0, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_totp_secrets SET recovery_code_hashes = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?`, string(encoded), userID); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return len(hashes), true, nil
}

func (s *SQLiteStore) GetAdminTOTP(ctx context.Context, adminID int) (*model.AdminTOTPSecret, error) {
	secret := &model.AdminTOTPSecret{AdminID: adminID}
	var hashes string
	err := s.db.QueryRowContext(ctx, `SELECT encrypted_secret, enabled, recovery_code_hashes FROM admin_totp_secrets WHERE admin_id = ?`, adminID).Scan(&secret.EncryptedSecret, &secret.Enabled, &hashes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(hashes), &secret.RecoveryCodeHashes); err != nil {
		return nil, fmt.Errorf("decode admin recovery code hashes: %w", err)
	}
	return secret, nil
}

func (s *SQLiteStore) SaveAdminTOTP(ctx context.Context, secret *model.AdminTOTPSecret) error {
	hashes, err := json.Marshal(secret.RecoveryCodeHashes)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO admin_totp_secrets(admin_id, encrypted_secret, enabled, recovery_code_hashes) VALUES(?, ?, ?, ?) ON CONFLICT(admin_id) DO UPDATE SET encrypted_secret=excluded.encrypted_secret, enabled=excluded.enabled, recovery_code_hashes=excluded.recovery_code_hashes, updated_at=CURRENT_TIMESTAMP`, secret.AdminID, secret.EncryptedSecret, secret.Enabled, string(hashes))
	return err
}

func (s *SQLiteStore) DeleteAdminTOTP(ctx context.Context, adminID int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_totp_secrets WHERE admin_id = ?`, adminID)
	return err
}

func (s *SQLiteStore) ConsumeAdminRecoveryCode(ctx context.Context, adminID int, hash string) (int, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	var encoded []byte
	if err := tx.QueryRowContext(ctx, `SELECT recovery_code_hashes FROM admin_totp_secrets WHERE admin_id = ? AND enabled = 1`, adminID).Scan(&encoded); err != nil {
		return 0, false, err
	}
	var hashes []string
	if err := json.Unmarshal(encoded, &hashes); err != nil {
		return 0, false, fmt.Errorf("decode admin recovery code hashes: %w", err)
	}
	matched := -1
	for i, candidate := range hashes {
		if len(candidate) == len(hash) && subtle.ConstantTimeCompare([]byte(candidate), []byte(hash)) == 1 {
			matched = i
		}
	}
	if matched < 0 {
		return len(hashes), false, nil
	}
	hashes = append(hashes[:matched], hashes[matched+1:]...)
	encoded, err = json.Marshal(hashes)
	if err != nil {
		return 0, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE admin_totp_secrets SET recovery_code_hashes = ?, updated_at=CURRENT_TIMESTAMP WHERE admin_id = ?`, string(encoded), adminID); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return len(hashes), true, nil
}

func (s *SQLiteStore) SavePasskey(ctx context.Context, passkey *model.Passkey) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO passkeys(id,user_type,user_id,name,public_key,sign_count,transports,aaguid,created_at,last_used,active) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, passkey.ID, passkey.UserType, passkey.UserID, passkey.Name, passkey.CredentialJSON, passkey.SignCount, passkey.Transports, passkey.AAGUID, passkey.CreatedAt.UTC(), passkey.LastUsed, passkey.Active)
	return err
}

func (s *SQLiteStore) GetPasskeys(ctx context.Context, userType, userID string) ([]*model.Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,user_type,user_id,name,public_key,sign_count,transports,aaguid,created_at,last_used,active FROM passkeys WHERE user_type=? AND user_id=? ORDER BY created_at DESC`, userType, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]*model.Passkey, 0)
	for rows.Next() {
		item := &model.Passkey{}
		var count int64
		var aaguid sql.NullString
		var lastUsed sql.NullTime
		if err := rows.Scan(&item.ID, &item.UserType, &item.UserID, &item.Name, &item.CredentialJSON, &count, &item.Transports, &aaguid, &item.CreatedAt, &lastUsed, &item.Active); err != nil {
			return nil, err
		}
		item.SignCount = uint32(count)
		if aaguid.Valid {
			item.AAGUID = aaguid.String
		}
		if lastUsed.Valid {
			item.LastUsed = &lastUsed.Time
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *SQLiteStore) GetPasskey(ctx context.Context, credentialID string) (*model.Passkey, error) {
	item := &model.Passkey{}
	var count int64
	var aaguid sql.NullString
	var lastUsed sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT id,user_type,user_id,name,public_key,sign_count,transports,aaguid,created_at,last_used,active FROM passkeys WHERE id=?`, credentialID).Scan(&item.ID, &item.UserType, &item.UserID, &item.Name, &item.CredentialJSON, &count, &item.Transports, &aaguid, &item.CreatedAt, &lastUsed, &item.Active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.SignCount = uint32(count)
	if aaguid.Valid {
		item.AAGUID = aaguid.String
	}
	if lastUsed.Valid {
		item.LastUsed = &lastUsed.Time
	}
	return item, nil
}

func (s *SQLiteStore) DeletePasskey(ctx context.Context, userType, userID, credentialID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM passkeys WHERE user_type=? AND user_id=? AND id=?`, userType, userID, credentialID)
	return err
}

func (s *SQLiteStore) UpdatePasskey(ctx context.Context, passkey *model.Passkey) error {
	_, err := s.db.ExecContext(ctx, `UPDATE passkeys SET public_key=?, sign_count=?, transports=?, aaguid=?, last_used=?, active=? WHERE id=? AND user_type=? AND user_id=?`, passkey.CredentialJSON, passkey.SignCount, passkey.Transports, passkey.AAGUID, passkey.LastUsed, passkey.Active, passkey.ID, passkey.UserType, passkey.UserID)
	return err
}

func (s *SQLiteStore) CreatePasskeyRecoveryCodes(ctx context.Context, userType, userID string, hashes []string) error {
	if (userType != "user" && userType != "admin") || len(hashes) != 10 {
		return fmt.Errorf("exactly ten owner-scoped recovery hashes are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM passkey_recovery_codes WHERE owner_type=? AND owner_id=?`, userType, userID); err != nil {
		return err
	}
	for _, hash := range hashes {
		if hash == "" {
			return fmt.Errorf("empty passkey recovery hash")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO passkey_recovery_codes(owner_type,owner_id,code_hash) VALUES(?,?,?)`, userType, userID, hash); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) ConsumePasskeyRecoveryCode(ctx context.Context, userType, userID, hash string) (int, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	var remaining int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkey_recovery_codes WHERE owner_type=? AND owner_id=?`, userType, userID).Scan(&remaining); err != nil {
		return 0, false, err
	}
	var stored string
	err = tx.QueryRowContext(ctx, `SELECT code_hash FROM passkey_recovery_codes WHERE owner_type=? AND owner_id=? AND code_hash=?`, userType, userID, hash).Scan(&stored)
	if err == sql.ErrNoRows {
		return remaining, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if len(stored) != len(hash) || subtle.ConstantTimeCompare([]byte(stored), []byte(hash)) != 1 {
		return 0, false, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM passkey_recovery_codes WHERE owner_type=? AND owner_id=? AND code_hash=?`, userType, userID, hash); err != nil {
		return 0, false, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkey_recovery_codes WHERE owner_type=? AND owner_id=?`, userType, userID).Scan(&count); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return count, true, nil
}

func (s *SQLiteStore) ActivatePasskey(ctx context.Context, userType, userID, credentialID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var recoveryCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkey_recovery_codes WHERE owner_type=? AND owner_id=?`, userType, userID).Scan(&recoveryCount); err != nil {
		return err
	}
	if recoveryCount != 10 {
		return fmt.Errorf("ten recovery codes must be stored before activation")
	}
	result, err := tx.ExecContext(ctx, `UPDATE passkeys SET active=1 WHERE id=? AND user_type=? AND user_id=? AND active=0`, credentialID, userType, userID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("pending passkey not found")
	}
	return tx.Commit()
}

func (s *SQLiteStore) CreateWebAuthnChallenge(ctx context.Context, challenge *model.WebAuthnChallenge) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_challenges WHERE expires_at <= ?`, time.Now().UTC()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO webauthn_challenges(id,user_type,user_id,session_data,expires_at) VALUES(?,?,?,?,?)`, challenge.ID, challenge.UserType, challenge.UserID, challenge.SessionJSON, challenge.ExpiresAt.UTC())
	return err
}

func (s *SQLiteStore) GetWebAuthnChallenge(ctx context.Context, id string, now time.Time) (*model.WebAuthnChallenge, error) {
	item := &model.WebAuthnChallenge{}
	err := s.db.QueryRowContext(ctx, `SELECT id,user_type,user_id,session_data,expires_at FROM webauthn_challenges WHERE id=? AND expires_at>?`, id, now.UTC()).Scan(&item.ID, &item.UserType, &item.UserID, &item.SessionJSON, &item.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (s *SQLiteStore) ConsumeWebAuthnChallenge(ctx context.Context, id string, now time.Time) (*model.WebAuthnChallenge, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	item := &model.WebAuthnChallenge{}
	err = tx.QueryRowContext(ctx, `SELECT id,user_type,user_id,session_data,expires_at FROM webauthn_challenges WHERE id=? AND expires_at>?`, id, now.UTC()).Scan(&item.ID, &item.UserType, &item.UserID, &item.SessionJSON, &item.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_challenges WHERE id=?`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *SQLiteStore) VerifyEmailAddress(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var userID, purpose string
	var pendingEmail sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT user_id, purpose, pending_email FROM email_verifications WHERE token_hash = ? AND expires_at > ?`, tokenHash, now.UTC()).Scan(&userID, &purpose, &pendingEmail)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch purpose {
	case "account_change":
		if !pendingEmail.Valid {
			return false, fmt.Errorf("account email verification has no pending address")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET email = ?, email_verified = 1 WHERE id = ?`, pendingEmail.String, userID); err != nil {
			return false, err
		}
	case "notification_change":
		if !pendingEmail.Valid {
			return false, fmt.Errorf("notification email verification has no pending address")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET notification_email = ?, notification_email_verified = 1 WHERE id = ?`, pendingEmail.String, userID); err != nil {
			return false, err
		}
	default:
		if _, err := tx.ExecContext(ctx, `UPDATE users SET email_verified = 1 WHERE id = ?`, userID); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM email_verifications WHERE user_id = ? AND purpose = ?`, userID, purpose); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
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
	var userID, deviceID any
	if test.UserID != "" {
		userID = test.UserID
	}
	if test.DeviceID != "" {
		deviceID = test.DeviceID
	}
	var shareCode any
	if test.ShareCode != "" {
		shareCode = test.ShareCode
	}
	query := `INSERT INTO speed_tests (id, user_id, device_id, timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, share_code, share_views, owner_token_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, test.ID, userID, deviceID, test.Timestamp, test.DownloadMbps, test.UploadMbps, test.PingMs, test.JitterMs, test.PacketLoss, test.ClientIPHash, test.UserAgent, test.ServerID, shareCode, test.ShareViews, test.OwnerTokenHash, test.CreatedAt)
	return err
}

func (s *SQLiteStore) GetSpeedTest(ctx context.Context, id string) (*model.SpeedTest, error) {
	test := &model.SpeedTest{}
	query := `SELECT id, COALESCE(user_id, ''), COALESCE(device_id, ''), timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, COALESCE(share_code, ''), share_views, COALESCE(owner_token_hash, ''), created_at FROM speed_tests WHERE id = ?`
	err := s.db.QueryRowContext(ctx, query, id).Scan(&test.ID, &test.UserID, &test.DeviceID, &test.Timestamp, &test.DownloadMbps, &test.UploadMbps, &test.PingMs, &test.JitterMs, &test.PacketLoss, &test.ClientIPHash, &test.UserAgent, &test.ServerID, &test.ShareCode, &test.ShareViews, &test.OwnerTokenHash, &test.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return test, err
}

func (s *SQLiteStore) GetSpeedTestByShareCode(ctx context.Context, shareCode string) (*model.SpeedTest, error) {
	test := &model.SpeedTest{}
	query := `SELECT id, COALESCE(user_id, ''), COALESCE(device_id, ''), timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, COALESCE(share_code, ''), share_views, COALESCE(owner_token_hash, ''), created_at FROM speed_tests WHERE share_code = ?`

	var userID, deviceID, userAgent, serverID sql.NullString
	err := s.db.QueryRowContext(ctx, query, shareCode).Scan(&test.ID, &userID, &deviceID, &test.Timestamp, &test.DownloadMbps, &test.UploadMbps, &test.PingMs, &test.JitterMs, &test.PacketLoss, &test.ClientIPHash, &userAgent, &serverID, &test.ShareCode, &test.ShareViews, &test.OwnerTokenHash, &test.CreatedAt)
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
			`SELECT id, COALESCE(user_id, ''), COALESCE(device_id, ''), timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, COALESCE(share_code, ''), share_views, created_at FROM speed_tests ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
			limit, offset)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, COALESCE(user_id, ''), COALESCE(device_id, ''), timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, COALESCE(share_code, ''), share_views, created_at FROM speed_tests WHERE user_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
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
	query := `SELECT id, COALESCE(user_id, ''), COALESCE(device_id, ''), timestamp, download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss, client_ip_hash, user_agent, server_id, COALESCE(share_code, ''), share_views, created_at FROM speed_tests WHERE device_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`
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
	var shareCode any
	if test.ShareCode != "" {
		shareCode = test.ShareCode
	}
	query := `UPDATE speed_tests SET download_mbps = ?, upload_mbps = ?, ping_ms = ?, jitter_ms = ?, packet_loss = ?, share_code = ?, share_views = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, test.DownloadMbps, test.UploadMbps, test.PingMs, test.JitterMs, test.PacketLoss, shareCode, test.ShareViews, test.ID)
	return err
}

func (s *SQLiteStore) DeleteSpeedTest(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM speed_tests WHERE id = ?`, id)
	return err
}

// DeleteAnonymousSpeedTestsBefore removes expired anonymous results in bounded batches.
func (s *SQLiteStore) DeleteAnonymousSpeedTestsBefore(ctx context.Context, cutoff time.Time) error {
	for {
		result, err := s.db.ExecContext(ctx, `DELETE FROM speed_tests WHERE id IN (
			SELECT id FROM speed_tests WHERE (user_id IS NULL OR user_id = '') AND timestamp < ? ORDER BY timestamp LIMIT 500
		)`, cutoff.UTC())
		if err != nil {
			return err
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if deleted < 500 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (s *SQLiteStore) IncrementShareViews(ctx context.Context, shareCode string) error {
	query := `UPDATE speed_tests SET share_views = share_views + 1 WHERE share_code = ?`
	_, err := s.db.ExecContext(ctx, query, shareCode)
	return err
}

func (s *SQLiteStore) CountSpeedTests(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM speed_tests`).Scan(&count)
	return count, err
}

func (s *SQLiteStore) CountUsers(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

func (s *SQLiteStore) CreateAPIToken(ctx context.Context, token *model.APIToken) error {
	if token.Scope == "" {
		token.Scope = "global"
	}
	var expiresAt any
	if token.ExpiresAt != nil {
		expiresAt = *token.ExpiresAt
	}
	query := `INSERT INTO api_tokens (id, user_id, token_hash, token_prefix, name, scope, expires_at, last_used, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, token.ID, token.UserID, token.Token, token.TokenPrefix, token.Name, token.Scope, expiresAt, token.LastUsed, token.CreatedAt)
	return err
}

func (s *SQLiteStore) GetAPIToken(ctx context.Context, id string) (*model.APIToken, error) {
	token := &model.APIToken{}
	query := `SELECT id, user_id, token_hash, token_prefix, name, scope, expires_at, last_used, created_at FROM api_tokens WHERE id = ?`
	var expiresAt, lastUsed sql.NullTime
	err := s.db.QueryRowContext(ctx, query, id).Scan(&token.ID, &token.UserID, &token.Token, &token.TokenPrefix, &token.Name, &token.Scope, &expiresAt, &lastUsed, &token.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if lastUsed.Valid {
		token.LastUsed = lastUsed.Time
	}
	if expiresAt.Valid {
		expires := expiresAt.Time
		token.ExpiresAt = &expires
	}
	return token, err
}

func (s *SQLiteStore) GetAPITokenByToken(ctx context.Context, tokenStr string) (*model.APIToken, error) {
	token := &model.APIToken{}
	query := `SELECT id, user_id, token_hash, token_prefix, name, scope, expires_at, last_used, created_at FROM api_tokens WHERE token_hash = ?`
	var expiresAt, lastUsed sql.NullTime
	err := s.db.QueryRowContext(ctx, query, tokenHash(tokenStr)).Scan(&token.ID, &token.UserID, &token.Token, &token.TokenPrefix, &token.Name, &token.Scope, &expiresAt, &lastUsed, &token.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if lastUsed.Valid {
		token.LastUsed = lastUsed.Time
	}
	if expiresAt.Valid {
		expires := expiresAt.Time
		token.ExpiresAt = &expires
	}
	return token, err
}

func (s *SQLiteStore) GetUserAPITokens(ctx context.Context, userID string) ([]*model.APIToken, error) {
	query := `SELECT id, user_id, token_hash, token_prefix, name, scope, expires_at, last_used, created_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*model.APIToken
	for rows.Next() {
		token := &model.APIToken{}
		var expiresAt, lastUsed sql.NullTime
		if err := rows.Scan(&token.ID, &token.UserID, &token.Token, &token.TokenPrefix, &token.Name, &token.Scope, &expiresAt, &lastUsed, &token.CreatedAt); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			token.LastUsed = lastUsed.Time
		}
		if expiresAt.Valid {
			expires := expiresAt.Time
			token.ExpiresAt = &expires
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (s *SQLiteStore) UpdateAPIToken(ctx context.Context, token *model.APIToken) error {
	query := `UPDATE api_tokens SET name = ?, scope = ?, expires_at = ?, last_used = ? WHERE id = ?`
	var expiresAt any
	if token.ExpiresAt != nil {
		expiresAt = *token.ExpiresAt
	}
	_, err := s.db.ExecContext(ctx, query, token.Name, token.Scope, expiresAt, token.LastUsed, token.ID)
	return err
}

func (s *SQLiteStore) DeleteAPIToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) DeleteExpiredAPITokens(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE expires_at IS NOT NULL AND expires_at <= ?`, now.UTC())
	return err
}

func (s *SQLiteStore) CreatePasswordResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE user_id = ?`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO password_reset_tokens(user_id, token_hash, expires_at) VALUES (?, ?, ?)`, userID, tokenHash, expiresAt.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) CompletePasswordReset(ctx context.Context, tokenHash string, now time.Time, passwordHash string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var userID string
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM password_reset_tokens WHERE token_hash = ? AND expires_at > ?`, tokenHash, now.UTC()).Scan(&userID)
	if err == sql.ErrNoRows {
		_, deleteErr := tx.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE token_hash = ?`, tokenHash)
		if deleteErr != nil {
			return false, deleteErr
		}
		return false, tx.Commit()
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, userID); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE token_hash = ? AND expires_at > ?`, tokenHash, now.UTC())
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if count != 1 {
		return false, tx.Commit()
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteStore) DeleteExpiredPasswordResetTokens(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE expires_at <= ?`, now.UTC())
	return err
}

func (s *SQLiteStore) CreateSession(ctx context.Context, session *model.Session) error {
	query := `INSERT INTO sessions (id, user_id, data, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, tokenHash(session.ID), session.UserID, session.Data, session.ExpiresAt, session.CreatedAt)
	return err
}

func (s *SQLiteStore) GetSession(ctx context.Context, id string) (*model.Session, error) {
	session := &model.Session{}
	query := `SELECT id, user_id, data, expires_at, created_at FROM sessions WHERE id = ? AND expires_at > ?`
	err := s.db.QueryRowContext(ctx, query, tokenHash(id), time.Now()).Scan(&session.ID, &session.UserID, &session.Data, &session.ExpiresAt, &session.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err == nil {
		session.ID = id
	}
	return session, err
}

func (s *SQLiteStore) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, tokenHash(id))
	return err
}

func (s *SQLiteStore) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now())
	return err
}

func (s *SQLiteStore) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

func (s *SQLiteStore) ListUserSessions(ctx context.Context, userID string) ([]*model.Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, data, expires_at, created_at FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC`, userID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := make([]*model.Session, 0)
	for rows.Next() {
		item := &model.Session{}
		if err := rows.Scan(&item.ID, &item.UserID, &item.Data, &item.ExpiresAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (s *SQLiteStore) RevokeUserSession(ctx context.Context, userID, sessionHash string) error {
	if len(sessionHash) != 64 {
		return sql.ErrNoRows
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ? AND user_id = ?`, sessionHash, userID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Admin methods
func (s *SQLiteStore) GetAdminByUsername(ctx context.Context, username string) (*model.Admin, error) {
	admin := &model.Admin{}
	var createdAt, updatedAt int64
	var email, apiTokenHash sql.NullString
	var lastLogin, lockedUntil sql.NullInt64
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
	if lastLogin.Valid && lastLogin.Int64 > 0 {
		admin.LastLogin = time.Unix(lastLogin.Int64, 0)
	}
	if lockedUntil.Valid && lockedUntil.Int64 > 0 {
		admin.LockedUntil = time.Unix(lockedUntil.Int64, 0)
	}

	return admin, nil
}

// GetAdminByAPITokenHash finds an enabled admin with the supplied one-way token hash.
func (s *SQLiteStore) GetAdminByAPITokenHash(ctx context.Context, tokenHash string) (*model.Admin, error) {
	admin := &model.Admin{}
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT id, username, role, enabled, api_token_hash FROM admins WHERE api_token_hash = ?`, tokenHash).Scan(
		&admin.ID, &admin.Username, &admin.Role, &enabled, &admin.APITokenHash,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	admin.Enabled = enabled == 1
	return admin, nil
}

// GetAdminUsername returns the display name for an authenticated admin session.
func (s *SQLiteStore) GetAdminUsername(ctx context.Context, adminID int) (string, error) {
	var username string
	err := s.db.QueryRowContext(ctx, `SELECT username FROM admins WHERE id = ? AND enabled = 1`, adminID).Scan(&username)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return username, err
}

// GetOrCreateInstallationSecret returns the cluster-wide installation secret encoded in app_secrets.
func (s *SQLiteStore) GetOrCreateInstallationSecret(ctx context.Context) ([]byte, error) {
	return s.GetOrCreateAppSecret(ctx, "installation_secret")
}

// GetOrCreateCSRFSecret returns the independently persisted CSRF HMAC secret.
func (s *SQLiteStore) GetOrCreateCSRFSecret(ctx context.Context) ([]byte, error) {
	return s.GetOrCreateAppSecret(ctx, "csrf_token_secret")
}

// GetOrCreateAppSecret creates or returns a named 32-byte base64 secret.
func (s *SQLiteStore) GetOrCreateAppSecret(ctx context.Context, name string) ([]byte, error) {
	if name != "installation_secret" && name != "csrf_token_secret" && name != "cookie_signing_key" {
		return nil, errors.New("unsupported application secret name")
	}
	var encoded string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name = ?`, name).Scan(&encoded)
	if err == nil {
		secret, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr != nil || len(secret) != 32 {
			return nil, errors.New("stored installation secret is invalid")
		}
		return secret, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	encoded = base64.StdEncoding.EncodeToString(secret)
	_, err = s.db.ExecContext(ctx, `INSERT INTO app_secrets(name,value) VALUES(?,?) ON CONFLICT(name) DO NOTHING`, name, encoded)
	if err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name = ?`, name).Scan(&encoded); err != nil {
		return nil, err
	}
	secret, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(secret) != 32 {
		return nil, errors.New("stored installation secret is invalid")
	}
	return secret, nil
}

func (s *SQLiteStore) CreateAdmin(ctx context.Context, admin *model.Admin) error {
	enabled := 0
	if admin.Enabled {
		enabled = 1
	}
	var tokenHash any
	if admin.APITokenHash != "" {
		tokenHash = admin.APITokenHash
	}
	query := `INSERT INTO admins (username, password, email, role, enabled, api_token_hash) VALUES (?, ?, ?, ?, ?, ?)`
	result, err := s.db.ExecContext(ctx, query, admin.Username, admin.Password, admin.Email, admin.Role, enabled, tokenHash)
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

func (s *SQLiteStore) UpdateAdminAPITokenHash(ctx context.Context, adminID int, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE admins SET api_token_hash = ? WHERE id = ?`, tokenHash, adminID)
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

// SecurityReportRecord contains encrypted report data and non-sensitive triage metadata.
type SecurityReportRecord struct {
	TrackingID        string
	IDWindow          int64
	Severity          string
	Component         string
	Status            string
	BodyEnc           []byte
	BodyAlg           string
	ContactEnc        []byte
	CreditPreference  string
	CreditName        *string
	ResearcherComment string
	DisclosureDate    *time.Time
	CVERequested      bool
	TokenHash         string
	TokenLastUsed     *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	ClosedAt          *time.Time
}

// SecurityKeypairMetadata records the active project OpenPGP public-key metadata.
type SecurityKeypairMetadata struct {
	Fingerprint         string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	LastRotatedAt       *time.Time
	KeyserversPublished string
	Revoked             bool
}

// SecurityThanksRecord is a public, non-sensitive disclosed-credit entry.
type SecurityThanksRecord struct {
	Credit      string    `json:"credit"`
	Severity    string    `json:"severity"`
	DisclosedOn time.Time `json:"disclosed_on"`
}

// ListSecurityThanks returns disclosed credits in newest-first order.
func (s *SQLiteStore) ListSecurityThanks(ctx context.Context) ([]SecurityThanksRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT credit,severity,disclosed_on FROM security_thanks ORDER BY disclosed_on DESC, credit COLLATE NOCASE ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []SecurityThanksRecord
	for rows.Next() {
		var entry SecurityThanksRecord
		var disclosed string
		if err := rows.Scan(&entry.Credit, &entry.Severity, &disclosed); err != nil {
			return nil, err
		}
		entry.DisclosedOn, err = time.Parse(time.RFC3339Nano, disclosed)
		if err != nil {
			entry.DisclosedOn, err = time.Parse("2006-01-02", disclosed)
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// GetSecurityKeypairMetadata returns active key metadata, if one exists.
func (s *SQLiteStore) GetSecurityKeypairMetadata(ctx context.Context) (*SecurityKeypairMetadata, error) {
	metadata := &SecurityKeypairMetadata{}
	var rotated sql.NullTime
	var revoked int
	err := s.db.QueryRowContext(ctx, `SELECT fingerprint,created_at,expires_at,last_rotated_at,keyservers_published,revoked FROM security_keypair_metadata WHERE id=1`).Scan(&metadata.Fingerprint, &metadata.CreatedAt, &metadata.ExpiresAt, &rotated, &metadata.KeyserversPublished, &revoked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if rotated.Valid {
		value := rotated.Time
		metadata.LastRotatedAt = &value
	}
	metadata.Revoked = revoked != 0
	return metadata, nil
}

// SaveSecurityKeypairMetadata commits the fingerprint that marks a staged key as active.
func (s *SQLiteStore) SaveSecurityKeypairMetadata(ctx context.Context, metadata SecurityKeypairMetadata) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO security_keypair_metadata(id,fingerprint,created_at,expires_at,last_rotated_at,keyservers_published,revoked) VALUES(1,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint,created_at=excluded.created_at,expires_at=excluded.expires_at,last_rotated_at=excluded.last_rotated_at,keyservers_published=excluded.keyservers_published,revoked=excluded.revoked`, metadata.Fingerprint, metadata.CreatedAt, metadata.ExpiresAt, metadata.LastRotatedAt, metadata.KeyserversPublished, metadata.Revoked)
	return err
}

// RotateSecurityKeypair re-encrypts all PGP report bodies and commits their new
// ciphertext together with the fingerprint that identifies the new active key.
func (s *SQLiteStore) RotateSecurityKeypair(ctx context.Context, metadata SecurityKeypairMetadata, reencrypt func([]byte) ([]byte, error)) error {
	if reencrypt == nil {
		return errors.New("report re-encryption callback is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT tracking_id,body_enc FROM security_reports WHERE body_alg='pgp'`)
	if err != nil {
		return err
	}
	type encryptedReport struct {
		id   string
		body []byte
	}
	var reports []encryptedReport
	for rows.Next() {
		var report encryptedReport
		if err := rows.Scan(&report.id, &report.body); err != nil {
			rows.Close()
			return err
		}
		reports = append(reports, report)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, report := range reports {
		body, err := reencrypt(report.body)
		if err != nil {
			return fmt.Errorf("reencrypt report %s: %w", report.id, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE security_reports SET body_enc=? WHERE tracking_id=? AND body_alg='pgp'`, body, report.id); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO security_keypair_metadata(id,fingerprint,created_at,expires_at,last_rotated_at,keyservers_published,revoked) VALUES(1,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint,created_at=excluded.created_at,expires_at=excluded.expires_at,last_rotated_at=excluded.last_rotated_at,keyservers_published=excluded.keyservers_published,revoked=excluded.revoked`, metadata.Fingerprint, metadata.CreatedAt, metadata.ExpiresAt, metadata.LastRotatedAt, metadata.KeyserversPublished, metadata.Revoked); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateSecurityReport stores only encrypted report and contact bodies.
func (s *SQLiteStore) CreateSecurityReport(ctx context.Context, report SecurityReportRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO security_reports
		(tracking_id,id_window,severity,component,status,body_enc,body_alg,contact_enc,credit_pref,credit_name,cve_requested,token_hash,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, report.TrackingID, report.IDWindow, report.Severity, report.Component, report.Status, report.BodyEnc, report.BodyAlg, report.ContactEnc, report.CreditPreference, report.CreditName, report.CVERequested, report.TokenHash, report.CreatedAt, report.UpdatedAt)
	return err
}

// GetSecurityReport returns a report row by tracking identifier.
func (s *SQLiteStore) GetSecurityReport(ctx context.Context, trackingID string) (*SecurityReportRecord, error) {
	return scanSecurityReport(s.db.QueryRowContext(ctx, securityReportSelect+` WHERE tracking_id = ?`, trackingID))
}

// ListSecurityReports returns report metadata and ciphertext for authenticated operator views.
func (s *SQLiteStore) ListSecurityReports(ctx context.Context, status string, limit, offset int) ([]SecurityReportRecord, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	query := securityReportSelect + ` WHERE (? = '' OR status = ?) ORDER BY created_at DESC LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, query, status, status, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []SecurityReportRecord
	for rows.Next() {
		report, err := scanSecurityReport(rows)
		if err != nil {
			return nil, err
		}
		reports = append(reports, *report)
	}
	return reports, rows.Err()
}

// UpdateSecurityReport updates triage metadata and creates a hall-of-fame entry on disclosure atomically.
func (s *SQLiteStore) UpdateSecurityReport(ctx context.Context, report SecurityReportRecord, oldStatus string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE security_reports SET severity=?,status=?,researcher_comment=?,disclosure_date=?,updated_at=?,closed_at=? WHERE tracking_id=?`, report.Severity, report.Status, report.ResearcherComment, report.DisclosureDate, report.UpdatedAt, report.ClosedAt, report.TrackingID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return sql.ErrNoRows
	}
	if report.Status == "disclosed" && oldStatus != "disclosed" && report.CreditPreference != "no" {
		credit := ""
		if report.CreditPreference == "anon" {
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_thanks WHERE credit GLOB 'Anonymous Researcher #[0-9]*'`).Scan(&count); err != nil {
				return err
			}
			credit = fmt.Sprintf("Anonymous Researcher #%d", count+1)
		} else if report.CreditName != nil {
			credit = *report.CreditName
		}
		if credit != "" {
			_, err = tx.ExecContext(ctx, `INSERT INTO security_thanks(tracking_id,credit,severity,disclosed_on) VALUES(?,?,?,?) ON CONFLICT(tracking_id) DO NOTHING`, report.TrackingID, credit, report.Severity, report.UpdatedAt.UTC().Format("2006-01-02"))
			if err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// ConsumeSecurityStatusToken verifies token hash and atomically enforces one read per UTC day.
func (s *SQLiteStore) ConsumeSecurityStatusToken(ctx context.Context, trackingID, tokenHash, utcDate string) (*SecurityReportRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	report, err := scanSecurityReport(tx.QueryRowContext(ctx, securityReportSelect+` WHERE tracking_id = ? AND token_hash = ?`, trackingID, tokenHash))
	if err != nil || report == nil {
		return nil, err
	}
	if report.TokenLastUsed != nil && *report.TokenLastUsed == utcDate {
		return nil, nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE security_reports SET token_last_used=? WHERE tracking_id=? AND token_hash=? AND (token_last_used IS NULL OR token_last_used <> ?)`, utcDate, trackingID, tokenHash, utcDate)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	report.TokenLastUsed = &utcDate
	return report, nil
}

// CleanupSecurityReports removes only reports closed before the supplied cutoff.
func (s *SQLiteStore) CleanupSecurityReports(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM security_reports WHERE closed_at IS NOT NULL AND closed_at < ?`, cutoff.UTC())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

const securityReportSelect = `SELECT tracking_id,id_window,severity,component,status,body_enc,body_alg,contact_enc,credit_pref,credit_name,researcher_comment,disclosure_date,cve_requested,token_hash,token_last_used,created_at,updated_at,closed_at FROM security_reports`

type securityReportScanner interface {
	Scan(...any) error
}

func scanSecurityReport(scanner securityReportScanner) (*SecurityReportRecord, error) {
	report := &SecurityReportRecord{}
	var creditName, disclosureDate, tokenLastUsed sql.NullString
	var closedAt sql.NullTime
	var createdAt, updatedAt time.Time
	var cveRequested int
	err := scanner.Scan(&report.TrackingID, &report.IDWindow, &report.Severity, &report.Component, &report.Status, &report.BodyEnc, &report.BodyAlg, &report.ContactEnc, &report.CreditPreference, &creditName, &report.ResearcherComment, &disclosureDate, &cveRequested, &report.TokenHash, &tokenLastUsed, &createdAt, &updatedAt, &closedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	report.CreatedAt = createdAt
	report.UpdatedAt = updatedAt
	report.CVERequested = cveRequested != 0
	if creditName.Valid {
		report.CreditName = &creditName.String
	}
	if disclosureDate.Valid {
		parsed, parseErr := time.Parse("2006-01-02", disclosureDate.String)
		if parseErr != nil {
			return nil, parseErr
		}
		report.DisclosureDate = &parsed
	}
	if tokenLastUsed.Valid {
		report.TokenLastUsed = &tokenLastUsed.String
	}
	if closedAt.Valid {
		closed := closedAt.Time
		report.ClosedAt = &closed
	}
	return report, nil
}
