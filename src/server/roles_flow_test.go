package server

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
)

func TestRoleLifecycleValidatesPersistsAndProtectsAssignedRoles(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	configPath := filepath.Join(t.TempDir(), "server.yml")
	cfg := config.Default()
	s := &Server{Config: cfg, ConfigPath: configPath, Store: st}
	if err := s.createRole("x", []string{"read"}); err == nil {
		t.Fatal("role names shorter than two characters were accepted")
	}
	if err := s.createRole("reviewer", []string{"write", "read", "read"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := s.createRole("reviewer", []string{"read"}); err == nil {
		t.Fatal("duplicate role was accepted")
	}
	if got := cfg.Server.Users.Roles.Permissions["reviewer"]; !reflect.DeepEqual(got, []string{"read", "write"}) {
		t.Fatalf("stored role permissions = %v", got)
	}
	if err := s.updateRole("admin", []string{"read"}); err == nil {
		t.Fatal("protected admin role was editable")
	}
	if err := s.updateRole("reviewer", []string{"moderate"}); err != nil {
		t.Fatalf("update role: %v", err)
	}
	if err := s.deleteRole(context.Background(), cfg.Server.Users.Roles.Default); err == nil {
		t.Fatal("default role was deleted")
	}
	if err := s.deleteRole(context.Background(), "user"); err == nil {
		t.Fatal("protected user role was deleted")
	}
	if err := s.deleteRole(context.Background(), "reviewer"); err != nil {
		t.Fatalf("delete unassigned role: %v", err)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("role changes were not persisted: %v", err)
	}
	if roles := s.rolesLocked(); len(roles) == 0 {
		t.Fatal("built-in roles disappeared")
	}
}

func TestRoleDeletionRejectsRolesAssignedToUsers(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.Default()
	cfg.Server.Users.Roles.Available = append(cfg.Server.Users.Roles.Available, "reviewer")
	cfg.Server.Users.Roles.Default = "user"
	cfg.Server.Users.Roles.Permissions["reviewer"] = []string{"read"}
	s := &Server{Config: cfg, Store: st}
	if err := s.createRole("reviewer", []string{"read"}); err == nil {
		t.Fatal("duplicate role was accepted")
	}
	if err := st.CreateUser(context.Background(), &model.User{Username: "assigned", Email: "assigned@example.test", Role: "reviewer", Approved: true, EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.deleteRole(context.Background(), "reviewer"); err == nil {
		t.Fatal("role assigned to an account was deleted")
	}
	if err := s.deleteRole(context.Background(), "missing"); err == nil {
		t.Fatal("unknown role was deleted")
	}
}
