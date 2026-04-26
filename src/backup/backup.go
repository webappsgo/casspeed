package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Config holds backup configuration
type Config struct {
	Enabled       bool
	BackupDir     string
	MaxBackups    int
	Schedule      string
	EncryptionKey string
}

// Service manages backup operations
type Service struct {
	config *Config
}

// NewService creates a new backup service
func NewService(cfg *Config) *Service {
	return &Service{config: cfg}
}

// CreateBackup creates an encrypted backup
func (s *Service) CreateBackup(dataDir string) (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(s.config.BackupDir, fmt.Sprintf("backup-%s.tar.gz.enc", timestamp))

	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(s.config.BackupDir, 0700); err != nil {
		return "", fmt.Errorf("creating backup directory: %w", err)
	}

	// Create temporary unencrypted archive
	tmpFile := filename + ".tmp"
	if err := s.createArchive(dataDir, tmpFile); err != nil {
		return "", fmt.Errorf("creating archive: %w", err)
	}
	defer os.Remove(tmpFile)

	// Encrypt the archive
	if err := s.encryptFile(tmpFile, filename); err != nil {
		return "", fmt.Errorf("encrypting backup: %w", err)
	}

	// Clean old backups
	s.cleanOldBackups()

	return filename, nil
}

// RestoreBackup restores from an encrypted backup
func (s *Service) RestoreBackup(backupFile, dataDir string) error {
	// Decrypt to temporary file
	tmpFile := backupFile + ".decrypted"
	if err := s.decryptFile(backupFile, tmpFile); err != nil {
		return fmt.Errorf("decrypting backup: %w", err)
	}
	defer os.Remove(tmpFile)

	// Extract archive
	if err := s.extractArchive(tmpFile, dataDir); err != nil {
		return fmt.Errorf("extracting archive: %w", err)
	}

	return nil
}

// createArchive creates a tar.gz archive of the data directory
func (s *Service) createArchive(srcDir, destFile string) error {
	file, err := os.Create(destFile)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(tarWriter, f)
		return err
	})
}

// extractArchive extracts a tar.gz archive
func (s *Service) extractArchive(srcFile, destDir string) error {
	file, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		path := filepath.Join(destDir, header.Name)

		// Create directory if needed
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		// Extract file
		f, err := os.Create(path)
		if err != nil {
			return err
		}

		if _, err := io.Copy(f, tarReader); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	return nil
}

// encryptFile encrypts a file using AES-256-GCM
func (s *Service) encryptFile(srcFile, destFile string) error {
	plaintext, err := os.ReadFile(srcFile)
	if err != nil {
		return err
	}

	key := []byte(s.config.EncryptionKey)
	if len(key) != 32 {
		return fmt.Errorf("encryption key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return os.WriteFile(destFile, ciphertext, 0600)
}

// decryptFile decrypts an AES-256-GCM encrypted file
func (s *Service) decryptFile(srcFile, destFile string) error {
	ciphertext, err := os.ReadFile(srcFile)
	if err != nil {
		return err
	}

	key := []byte(s.config.EncryptionKey)
	if len(key) != 32 {
		return fmt.Errorf("encryption key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	return os.WriteFile(destFile, plaintext, 0600)
}

// cleanOldBackups removes backups beyond MaxBackups limit
func (s *Service) cleanOldBackups() error {
	files, err := filepath.Glob(filepath.Join(s.config.BackupDir, "backup-*.tar.gz.enc"))
	if err != nil {
		return err
	}

	if len(files) <= s.config.MaxBackups {
		return nil
	}

	// Sort by modification time and remove oldest
	// (simplified - should sort by timestamp)
	for i := 0; i < len(files)-s.config.MaxBackups; i++ {
		os.Remove(files[i])
	}

	return nil
}
