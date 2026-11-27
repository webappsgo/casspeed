package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/config"
)

func TestRunServesRequestAndShutsDownOnCancellation(t *testing.T) {
	root := t.TempDir()
	cfg := *config.Default()
	cfg.Server.I2P.Enabled = false
	cfg.Runtime = config.RuntimeInfo{
		ConfigDir: filepath.Join(root, "config"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
		LogDir:    filepath.Join(root, "logs"),
		BackupDir: filepath.Join(root, "backups"),
		PIDFile:   filepath.Join(root, "run", "server.pid"),
		Version:   "test-version",
		CommitID:  "test-commit",
	}
	if err := os.MkdirAll(cfg.Runtime.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	secrets := "server:\n  token: adm_" + strings.Repeat("a", 32) + "\nsecurity:\n  encryption_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n  encryption_key_version: 1\n"
	if err := os.WriteFile(filepath.Join(cfg.Runtime.ConfigDir, "secrets.yml"), []byte(secrets), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Runtime.ConfigDir, "setup_token.txt"), []byte(strings.Repeat("a", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, listener, ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("run exited before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not become ready")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get("http://" + listener.Addr().String() + "/server/healthz")
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("health response = %d body=%s read=%v close=%v", response.StatusCode, body, readErr, closeErr)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not stop after context cancellation")
	}
}

func TestConfiguredPortHandlesSupportedValues(t *testing.T) {
	for _, test := range []struct {
		value any
		want  int
	}{{8080, 8080}, {"9090", 9090}, {"invalid", 64580}, {nil, 64580}, {0, 64580}} {
		if got := configuredPort(test.value); got != test.want {
			t.Errorf("configuredPort(%v) = %d, want %d", test.value, got, test.want)
		}
	}
}
