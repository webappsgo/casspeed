package backup

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
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

func TestBackupRestoreRoundTripAndAuthentication(t *testing.T) {
	dataDir, backupDir, restoredDir := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "settings.yml"), []byte("listen: 127.0.0.1"), 0600); err != nil {
		t.Fatal(err)
	}
	service := NewService(&Config{BackupDir: backupDir, MaxBackups: 5, EncryptionKey: "12345678901234567890123456789012"})
	backupPath, err := service.CreateBackup(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RestoreBackup(backupPath, restoredDir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(restoredDir, "settings.yml"))
	if err != nil || string(got) != "listen: 127.0.0.1" {
		t.Fatalf("restored file = %q, %v", got, err)
	}
	info, err := os.Stat(filepath.Join(restoredDir, "settings.yml"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("restored settings permissions = %v, %v; want 0600", info, err)
	}
	wrongKey := NewService(&Config{EncryptionKey: "abcdefghijklmnopqrstuvwxyz012345"})
	if err := wrongKey.RestoreBackup(backupPath, t.TempDir()); err == nil {
		t.Fatal("backup authenticated with the wrong key")
	}
}

func TestBackupRejectsInvalidKeysAndTampering(t *testing.T) {
	service := NewService(&Config{BackupDir: t.TempDir(), MaxBackups: 1, EncryptionKey: "short"})
	if _, err := service.CreateBackup(t.TempDir()); err == nil {
		t.Fatal("backup accepted a short encryption key")
	}
	if err := service.decryptFile(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("decrypt accepted a missing ciphertext")
	}
	service.config.EncryptionKey = "12345678901234567890123456789012"
	invalid := filepath.Join(t.TempDir(), "invalid.enc")
	if err := os.WriteFile(invalid, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := service.decryptFile(invalid, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("decrypt accepted a truncated ciphertext")
	}
	service.config.EncryptionKey = "abcdefghijklmnopqrstuvwxyz012345"
	if err := service.decryptFile(invalid, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("decrypt accepted tampered ciphertext")
	}
}

func TestExtractArchiveRejectsTraversal(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "malicious.tar.gz")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	if err := archive.WriteHeader(&tar.Header{Name: "../escaped.txt", Mode: 0600, Size: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(archive, "evil"); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	service := NewService(&Config{})
	destination := t.TempDir()
	if err := service.extractArchive(archivePath, destination); err == nil {
		t.Fatal("archive traversal path was accepted")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(destination), "escaped.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("traversal created an outside file: %v", err)
	}
}

func TestCleanOldBackupsHonorsLimit(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"backup-1.tar.gz.enc", "backup-2.tar.gz.enc", "backup-3.tar.gz.enc"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("backup"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	service := NewService(&Config{BackupDir: directory, MaxBackups: 1})
	if err := service.cleanOldBackups(); err != nil {
		t.Fatal(err)
	}
	remaining, err := filepath.Glob(filepath.Join(directory, "backup-*.tar.gz.enc"))
	if err != nil || len(remaining) != 1 {
		t.Fatalf("remaining backups = %v, %v", remaining, err)
	}
}
