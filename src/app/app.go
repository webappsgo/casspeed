package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/casapps/casspeed/src/admin"
	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/mode"
	"github.com/casapps/casspeed/src/paths"
	"github.com/casapps/casspeed/src/pid"
	"github.com/casapps/casspeed/src/server"
)

// Run starts the application and owns OS signal handling and graceful shutdown.
func Run(ctx context.Context, cfg config.Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	return run(ctx, cfg, nil, nil)
}

func run(ctx context.Context, cfg config.Config, listener net.Listener, ready chan<- struct{}) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate configuration: %w", err)
	}
	appPaths, err := paths.Detect(cfg.Runtime.ConfigDir, cfg.Runtime.DataDir, cfg.Runtime.CacheDir, cfg.Runtime.LogDir, cfg.Runtime.BackupDir)
	if err != nil {
		return fmt.Errorf("detect paths: %w", err)
	}
	if cfg.Runtime.PIDFile != "" {
		appPaths.PID = cfg.Runtime.PIDFile
	}
	if err := appPaths.Ensure(); err != nil {
		return fmt.Errorf("create directories: %w", err)
	}
	appMode, err := mode.Detect(cfg.Server.Mode, "")
	if err != nil {
		return fmt.Errorf("detect application mode: %w", err)
	}
	if err := pid.WritePIDFile(appPaths.PID); err != nil {
		return fmt.Errorf("write PID file: %w", err)
	}
	defer func() { _ = pid.RemovePIDFile(appPaths.PID) }()
	buildDate := "N/A"
	if epoch, parseErr := strconv.ParseInt(cfg.Runtime.BuildEpoch, 10, 64); parseErr == nil && epoch > 0 {
		buildDate = time.Unix(epoch, 0).UTC().Format("2006-01-02T15:04:05Z")
	}
	srv, err := server.New(&cfg, appMode, appPaths.Config, appPaths.Data, appPaths.Log, cfg.Runtime.Version, cfg.Runtime.CommitID, buildDate)
	if err != nil {
		return fmt.Errorf("initialize server: %w", err)
	}
	setupToken, generated, err := admin.LoadOrCreateSetupToken(filepath.Join(appPaths.Config, "setup_token.txt"))
	if err != nil {
		_ = srv.Shutdown()
		return fmt.Errorf("initialize setup token: %w", err)
	}
	if !admin.IsSetupComplete() && generated {
		address := cfg.Server.Address
		if address == "" {
			address = "[::]"
		}
		port := configuredPort(cfg.Server.Port)
		fmt.Fprintf(os.Stderr, "First-run setup: http://%s:%d/server/%s/setup\nSetup token: %s\n", address, port, cfg.Server.AdminPath, setupToken)
	}
	if listener == nil {
		address := cfg.Server.Address
		if address == "" {
			address = "[::]"
		}
		listener, err = net.Listen("tcp", net.JoinHostPort(address, strconv.Itoa(configuredPort(cfg.Server.Port))))
		if err != nil {
			_ = srv.Shutdown()
			return fmt.Errorf("listen: %w", err)
		}
	}
	return srv.Serve(ctx, listener, ready)
}

func configuredPort(value any) int {
	switch port := value.(type) {
	case int:
		if port > 0 {
			return port
		}
	case string:
		if parsed, err := strconv.Atoi(port); err == nil && parsed > 0 {
			return parsed
		}
	}
	return 64580
}
