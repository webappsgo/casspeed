package update

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Config holds update configuration
type Config struct {
	Enabled     bool
	RepoOwner   string
	RepoName    string
	Branch      string
	CurrentVer  string
	BinaryPath  string
}

// Release represents a release version
type Release struct {
	Version     string
	CommitID    string
	BuildDate   string
	DownloadURL string
	Changelog   string
}

// Service manages update operations
type Service struct {
	config *Config
}

// NewService creates a new update service
func NewService(cfg *Config) *Service {
	return &Service{config: cfg}
}

// CheckForUpdates checks if a new version is available
func (s *Service) CheckForUpdates() (*Release, error) {
	if !s.config.Enabled {
		return nil, fmt.Errorf("updates not enabled")
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest",
		s.config.RepoOwner, s.config.RepoName)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github API returned status %d", resp.StatusCode)
	}

	var apiResp struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		Body        string `json:"body"`
		PublishedAt string `json:"published_at"`
		Assets      []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("parsing release info: %w", err)
	}

	// Find asset for current platform
	assetName := s.getAssetName()
	var downloadURL string

	for _, asset := range apiResp.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return nil, fmt.Errorf("no binary found for platform %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	return &Release{
		Version:     strings.TrimPrefix(apiResp.TagName, "v"),
		BuildDate:   apiResp.PublishedAt,
		DownloadURL: downloadURL,
		Changelog:   apiResp.Body,
	}, nil
}

// PerformUpdate downloads and installs an update
func (s *Service) PerformUpdate(release *Release) error {
	// Download new binary
	tmpFile, err := s.downloadBinary(release.DownloadURL)
	if err != nil {
		return fmt.Errorf("downloading update: %w", err)
	}
	defer os.Remove(tmpFile)

	// Verify binary
	if err := s.verifyBinary(tmpFile); err != nil {
		return fmt.Errorf("verifying binary: %w", err)
	}

	// Replace current binary
	if err := s.replaceBinary(tmpFile); err != nil {
		return fmt.Errorf("replacing binary: %w", err)
	}

	return nil
}

// downloadBinary downloads a binary to a temporary file
func (s *Service) downloadBinary(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Create temporary file
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("casspeed-update-%d", time.Now().Unix()))
	out, err := os.Create(tmpFile)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return "", err
	}

	// Make executable
	if err := os.Chmod(tmpFile, 0755); err != nil {
		return "", err
	}

	return tmpFile, nil
}

// verifyBinary checks if a binary is valid
func (s *Service) verifyBinary(path string) error {
	// Run --version to verify it works
	cmd := exec.Command(path, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("binary verification failed: %w", err)
	}

	// Check output contains version info
	if !strings.Contains(string(output), "casspeed") {
		return fmt.Errorf("binary verification failed: unexpected output")
	}

	return nil
}

// replaceBinary replaces the current binary with a new one
func (s *Service) replaceBinary(newPath string) error {
	currentPath := s.config.BinaryPath
	if currentPath == "" {
		// Use current executable path
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		currentPath = exe
	}

	// Backup current binary
	backupPath := currentPath + ".backup"
	if err := os.Rename(currentPath, backupPath); err != nil {
		return fmt.Errorf("backing up current binary: %w", err)
	}

	// Copy new binary
	if err := copyFile(newPath, currentPath); err != nil {
		// Restore backup on failure
		os.Rename(backupPath, currentPath)
		return fmt.Errorf("installing new binary: %w", err)
	}

	// Remove backup
	os.Remove(backupPath)

	return nil
}

// getAssetName returns the expected asset name for current platform
func (s *Service) getAssetName() string {
	os := runtime.GOOS
	arch := runtime.GOARCH

	name := fmt.Sprintf("casspeed-%s-%s", os, arch)
	if os == "windows" {
		name += ".exe"
	}

	return name
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	dest, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dest.Close()

	if _, err := io.Copy(dest, source); err != nil {
		return err
	}

	// Preserve permissions
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.Chmod(dst, srcInfo.Mode())
}

// GetCurrentVersion returns the current version
func (s *Service) GetCurrentVersion() string {
	return s.config.CurrentVer
}

// SetBranch sets the update branch
func (s *Service) SetBranch(branch string) {
	s.config.Branch = branch
}

// GetBranch returns the current update branch
func (s *Service) GetBranch() string {
	return s.config.Branch
}
