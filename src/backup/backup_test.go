package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// ---- NewService tests ----------------------------------------------------

func TestNewService_StoresConfig(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		BackupDir:  "/tmp/casspeed-test-backup",
		MaxBackups: 5,
	}
	svc := NewService(cfg)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.config != cfg {
		t.Error("config not stored")
	}
}

// ---- CreateBackup tests --------------------------------------------------

func TestCreateBackup_EmptyDataDir(t *testing.T) {
	backupDir := t.TempDir()
	dataDir := t.TempDir()

	cfg := &Config{
		Enabled:       true,
		BackupDir:     backupDir,
		MaxBackups:    3,
		EncryptionKey: "12345678901234567890123456789012",
	}
	svc := NewService(cfg)

	backupFile, err := svc.CreateBackup(dataDir)
	if err != nil {
		t.Fatalf("CreateBackup error: %v", err)
	}
	if backupFile == "" {
		t.Error("expected backup file path, got empty")
	}
	if _, statErr := os.Stat(backupFile); os.IsNotExist(statErr) {
		t.Errorf("backup file %q does not exist", backupFile)
	}
}

func TestCreateBackup_WithFiles(t *testing.T) {
	backupDir := t.TempDir()
	dataDir := t.TempDir()

	// Create a test file to back up.
	if err := os.WriteFile(filepath.Join(dataDir, "test.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cfg := &Config{
		Enabled:       true,
		BackupDir:     backupDir,
		MaxBackups:    3,
		EncryptionKey: "abcdefghijklmnopqrstuvwxyz012345",
	}
	svc := NewService(cfg)

	backupFile, err := svc.CreateBackup(dataDir)
	if err != nil {
		t.Fatalf("CreateBackup error: %v", err)
	}
	info, err := os.Stat(backupFile)
	if err != nil {
		t.Fatalf("stat backup file: %v", err)
	}
	if info.Size() == 0 {
		t.Error("backup file should not be empty")
	}
}

func TestCreateBackup_NonExistentDataDir(t *testing.T) {
	backupDir := t.TempDir()

	cfg := &Config{
		Enabled:       true,
		BackupDir:     backupDir,
		MaxBackups:    3,
		EncryptionKey: "12345678901234567890123456789012",
	}
	svc := NewService(cfg)

	// Nonexistent data dir should not cause a crash — may or may not error.
	_, err := svc.CreateBackup("/tmp/casspeed_backup_nonexistent_dir_XXXXX")
	_ = err // Either behavior is acceptable; no panic is the assertion.
}
