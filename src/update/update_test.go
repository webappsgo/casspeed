package update

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// ---- NewService tests ----------------------------------------------------

func TestNewService_StoresConfig(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		RepoOwner:  "casapps",
		RepoName:   "casspeed",
		Branch:     "main",
		CurrentVer: "1.2.3",
	}
	svc := NewService(cfg)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.config != cfg {
		t.Error("config not stored correctly")
	}
}

// ---- GetCurrentVersion tests ---------------------------------------------

func TestGetCurrentVersion(t *testing.T) {
	svc := NewService(&Config{CurrentVer: "2.0.0"})
	if got := svc.GetCurrentVersion(); got != "2.0.0" {
		t.Errorf("GetCurrentVersion() = %q, want '2.0.0'", got)
	}
}

func TestGetCurrentVersion_Empty(t *testing.T) {
	svc := NewService(&Config{})
	if got := svc.GetCurrentVersion(); got != "" {
		t.Errorf("GetCurrentVersion() = %q, want empty", got)
	}
}

// ---- GetBranch / SetBranch tests ----------------------------------------

func TestGetBranch_Default(t *testing.T) {
	svc := NewService(&Config{Branch: "main"})
	if got := svc.GetBranch(); got != "main" {
		t.Errorf("GetBranch() = %q, want 'main'", got)
	}
}

func TestSetBranch(t *testing.T) {
	svc := NewService(&Config{Branch: "main"})
	svc.SetBranch("develop")
	if got := svc.GetBranch(); got != "develop" {
		t.Errorf("GetBranch() after SetBranch = %q, want 'develop'", got)
	}
}

// ---- getAssetName tests --------------------------------------------------

func TestGetAssetName_ContainsPlatform(t *testing.T) {
	svc := NewService(&Config{})
	name := svc.getAssetName()

	if !strings.Contains(name, runtime.GOOS) {
		t.Errorf("asset name %q should contain OS %q", name, runtime.GOOS)
	}
	if !strings.Contains(name, runtime.GOARCH) {
		t.Errorf("asset name %q should contain arch %q", name, runtime.GOARCH)
	}
}

func TestGetAssetName_StartsWithBinaryName(t *testing.T) {
	svc := NewService(&Config{})
	name := svc.getAssetName()
	if !strings.HasPrefix(name, "casspeed-") {
		t.Errorf("asset name %q should start with 'casspeed-'", name)
	}
}

// ---- CheckForUpdates when disabled --------------------------------------

func TestCheckForUpdates_Disabled(t *testing.T) {
	svc := NewService(&Config{Enabled: false})
	_, err := svc.CheckForUpdates()
	if err == nil {
		t.Error("expected error when updates are disabled")
	}
}

// ---- copyFile tests -----------------------------------------------------

func TestCopyFile_CopiesContent(t *testing.T) {
	src := t.TempDir() + "/src.bin"
	dst := t.TempDir() + "/dst.bin"

	if err := os.WriteFile(src, []byte("hello casspeed"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile error: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello casspeed" {
		t.Errorf("copyFile content = %q, want 'hello casspeed'", string(got))
	}
}

func TestCopyFile_MissingSource(t *testing.T) {
	err := copyFile("/nonexistent/src.bin", t.TempDir()+"/dst.bin")
	if err == nil {
		t.Error("expected error for missing source file")
	}
}

func TestCopyFile_BadDestination(t *testing.T) {
	src := t.TempDir() + "/src.bin"
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := copyFile(src, "/nonexistent/path/dst.bin")
	if err == nil {
		t.Error("expected error for invalid destination path")
	}
}
