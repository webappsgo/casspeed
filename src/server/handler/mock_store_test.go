package handler

import (
	"context"
	"errors"
	"time"

	"github.com/casapps/casspeed/src/server/model"
)

// mockStore is a zero-dependency in-memory implementation of store.Store.
// Only the methods exercised by the handler tests need real implementations;
// the rest return nil errors and nil values.
type mockStore struct {
	users    map[string]*model.User
	sessions map[string]*model.Session
	tests    map[string]*model.SpeedTest
	testsByCode map[string]*model.SpeedTest

	// Inject controllable errors.
	errGetUserByUsername error
	errGetUserByEmail    error
	errCreateSession     error
	errDeleteSession     error
	errGetSpeedTest      error
	errGetByShareCode    error
	errGetHistory        error
	errCreateUser        error
}

func newMockStore() *mockStore {
	return &mockStore{
		users:       make(map[string]*model.User),
		sessions:    make(map[string]*model.Session),
		tests:       make(map[string]*model.SpeedTest),
		testsByCode: make(map[string]*model.SpeedTest),
	}
}

func (m *mockStore) Close() error { return nil }

func (m *mockStore) CreateUser(_ context.Context, u *model.User) error {
	if m.errCreateUser != nil {
		return m.errCreateUser
	}
	m.users[u.ID] = u
	return nil
}

func (m *mockStore) GetUser(_ context.Context, id string) (*model.User, error) {
	u := m.users[id]
	return u, nil
}

func (m *mockStore) GetUserByUsername(_ context.Context, username string) (*model.User, error) {
	if m.errGetUserByUsername != nil {
		return nil, m.errGetUserByUsername
	}
	for _, u := range m.users {
		if u.Username == username {
			return u, nil
		}
	}
	return nil, nil
}

func (m *mockStore) GetUserByEmail(_ context.Context, email string) (*model.User, error) {
	if m.errGetUserByEmail != nil {
		return nil, m.errGetUserByEmail
	}
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

func (m *mockStore) UpdateUser(_ context.Context, u *model.User) error {
	m.users[u.ID] = u
	return nil
}

func (m *mockStore) DeleteUser(_ context.Context, id string) error {
	delete(m.users, id)
	return nil
}

func (m *mockStore) CreateDevice(_ context.Context, _ *model.Device) error  { return nil }
func (m *mockStore) GetDevice(_ context.Context, _ string) (*model.Device, error) {
	return nil, nil
}
func (m *mockStore) GetUserDevices(_ context.Context, _ string) ([]*model.Device, error) {
	return nil, nil
}
func (m *mockStore) UpdateDevice(_ context.Context, _ *model.Device) error  { return nil }
func (m *mockStore) DeleteDevice(_ context.Context, _ string) error         { return nil }

func (m *mockStore) CreateSpeedTest(_ context.Context, t *model.SpeedTest) error {
	m.tests[t.ID] = t
	if t.ShareCode != "" {
		m.testsByCode[t.ShareCode] = t
	}
	return nil
}

func (m *mockStore) GetSpeedTest(_ context.Context, id string) (*model.SpeedTest, error) {
	if m.errGetSpeedTest != nil {
		return nil, m.errGetSpeedTest
	}
	return m.tests[id], nil
}

func (m *mockStore) GetSpeedTestByShareCode(_ context.Context, code string) (*model.SpeedTest, error) {
	if m.errGetByShareCode != nil {
		return nil, m.errGetByShareCode
	}
	return m.testsByCode[code], nil
}

func (m *mockStore) GetUserSpeedTests(_ context.Context, _ string, _, _ int) ([]*model.SpeedTest, error) {
	if m.errGetHistory != nil {
		return nil, m.errGetHistory
	}
	out := make([]*model.SpeedTest, 0, len(m.tests))
	for _, t := range m.tests {
		out = append(out, t)
	}
	return out, nil
}

func (m *mockStore) GetDeviceSpeedTests(_ context.Context, _ string, _, _ int) ([]*model.SpeedTest, error) {
	return nil, nil
}

func (m *mockStore) UpdateSpeedTest(_ context.Context, t *model.SpeedTest) error {
	m.tests[t.ID] = t
	return nil
}

func (m *mockStore) DeleteSpeedTest(_ context.Context, id string) error {
	delete(m.tests, id)
	return nil
}

func (m *mockStore) IncrementShareViews(_ context.Context, code string) error {
	if t, ok := m.testsByCode[code]; ok {
		t.ShareViews++
	}
	return nil
}

func (m *mockStore) CreateAPIToken(_ context.Context, _ *model.APIToken) error { return nil }
func (m *mockStore) GetAPIToken(_ context.Context, _ string) (*model.APIToken, error) {
	return nil, nil
}
func (m *mockStore) GetAPITokenByToken(_ context.Context, _ string) (*model.APIToken, error) {
	return nil, nil
}
func (m *mockStore) GetUserAPITokens(_ context.Context, _ string) ([]*model.APIToken, error) {
	return nil, nil
}
func (m *mockStore) UpdateAPIToken(_ context.Context, _ *model.APIToken) error { return nil }
func (m *mockStore) DeleteAPIToken(_ context.Context, _ string) error          { return nil }

func (m *mockStore) CreateSession(_ context.Context, s *model.Session) error {
	if m.errCreateSession != nil {
		return m.errCreateSession
	}
	m.sessions[s.ID] = s
	return nil
}

func (m *mockStore) GetSession(_ context.Context, id string) (*model.Session, error) {
	return m.sessions[id], nil
}

func (m *mockStore) DeleteSession(_ context.Context, id string) error {
	if m.errDeleteSession != nil {
		return m.errDeleteSession
	}
	delete(m.sessions, id)
	return nil
}

func (m *mockStore) DeleteExpiredSessions(_ context.Context) error { return nil }

func (m *mockStore) GetAdminByUsername(_ context.Context, _ string) (*model.Admin, error) {
	return nil, nil
}
func (m *mockStore) CreateAdmin(_ context.Context, _ *model.Admin) error { return nil }
func (m *mockStore) UpdateAdminLastLogin(_ context.Context, _ int) error { return nil }
func (m *mockStore) UpdateAdminFailedAttempts(_ context.Context, _ int, _ int) error {
	return nil
}
func (m *mockStore) LockAdmin(_ context.Context, _ int, _ time.Time) error { return nil }
func (m *mockStore) CountAdmins(_ context.Context) (int, error)            { return 0, nil }

func (m *mockStore) CreateAdminSession(_ context.Context, _ *model.AdminSession) error {
	return nil
}
func (m *mockStore) GetAdminSession(_ context.Context, _ string) (*model.AdminSession, error) {
	return nil, nil
}
func (m *mockStore) UpdateAdminSessionActivity(_ context.Context, _ string) error { return nil }
func (m *mockStore) DeleteAdminSession(_ context.Context, _ string) error         { return nil }
func (m *mockStore) DeleteExpiredAdminSessions(_ context.Context) error           { return nil }
func (m *mockStore) GetSetupComplete(_ context.Context) (bool, error)             { return true, nil }
func (m *mockStore) SetSetupComplete(_ context.Context, _ bool) error             { return nil }

// sentinel error for tests
var errDB = errors.New("db error")
