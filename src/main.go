package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/casapps/casspeed/src/admin"
	"github.com/casapps/casspeed/src/backup"
	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/mode"
	"github.com/casapps/casspeed/src/paths"
	"github.com/casapps/casspeed/src/pid"
	"github.com/casapps/casspeed/src/server"
	"github.com/casapps/casspeed/src/update"
)

// Version information (set by linker flags during build)
var (
	Version   = "dev"
	CommitID  = "unknown"
	BuildDate = "unknown"
)

func main() {
	// Get binary name for help text
	binaryName := filepath.Base(os.Args[0])

	// Define flags
	var (
		showHelp    bool
		showVersion bool
		showStatus  bool
		daemonFlag  bool
		debugFlag   bool
		modeFlag    string
		colorFlag   string
		langFlag    string
		baseurlFlag string
		shellCmd    string
		configDir   string
		dataDir     string
		cacheDir    string
		logDir      string
		backupDir   string
		pidFile     string
		address     string
		portFlag    string
		serviceCmd  string
		maintCmd    string
		updateCmd   string
	)

	flag.BoolVar(&showHelp, "help", false, "Show help information")
	flag.BoolVar(&showHelp, "h", false, "Show help information (short)")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.BoolVar(&showVersion, "v", false, "Show version information (short)")
	flag.BoolVar(&showStatus, "status", false, "Show status and health (exit 0=healthy, 1=unhealthy)")
	flag.BoolVar(&daemonFlag, "daemon", false, "Run as daemon (detach from terminal)")
	flag.BoolVar(&debugFlag, "debug", false, "Enable debug mode (verbose logging, debug endpoints)")
	flag.StringVar(&modeFlag, "mode", "", "Application mode (production|development)")
	flag.StringVar(&colorFlag, "color", "auto", "Color output (auto|yes|no)")
	flag.StringVar(&langFlag, "lang", "", "Language for output (default: auto from LANG env)")
	flag.StringVar(&baseurlFlag, "baseurl", "/", "URL path prefix (default: /)")
	flag.StringVar(&shellCmd, "shell", "", "Shell integration (completions|init|help) [SHELL]")
	flag.StringVar(&configDir, "config", "", "Configuration directory")
	flag.StringVar(&dataDir, "data", "", "Data directory")
	flag.StringVar(&cacheDir, "cache", "", "Cache directory")
	flag.StringVar(&logDir, "log", "", "Log directory")
	flag.StringVar(&backupDir, "backup", "", "Backup directory")
	flag.StringVar(&pidFile, "pid", "", "PID file path")
	flag.StringVar(&address, "address", "", "Listen address (default: [::])")
	flag.StringVar(&portFlag, "port", "", "Listen port (default: random 64xxx)")
	flag.StringVar(&serviceCmd, "service", "", "Service management (start|stop|restart|reload|install|uninstall|help)")
	flag.StringVar(&maintCmd, "maintenance", "", "Maintenance operations (backup|restore|update|mode|setup)")
	flag.StringVar(&updateCmd, "update", "", "Update operations (check|yes|branch stable|beta|daily)")

	flag.Usage = func() {
		showHelpText(binaryName)
	}

	flag.Parse()

	// Resolve color mode — CLI flag > config > NO_COLOR env > auto-detect
	colorEnabled := resolveColorMode(colorFlag)

	// Handle --help
	if showHelp {
		showHelpText(binaryName)
		os.Exit(0)
	}

	// Handle --version
	if showVersion {
		showVersionInfo(binaryName, colorEnabled)
		os.Exit(0)
	}

	// Handle --status
	if showStatus {
		showStatusInfo(binaryName)
		os.Exit(0)
	}

	// Handle --shell completions|init|help [SHELL]
	if shellCmd != "" {
		handleShell(binaryName, shellCmd, flag.Args())
		os.Exit(0)
	}

	// Suppress unused variable warning for langFlag and baseurlFlag
	// (used in future i18n and reverse-proxy base path support)
	_ = langFlag
	_ = baseurlFlag

	// Handle --service
	if serviceCmd != "" {
		handleService(binaryName, serviceCmd)
		os.Exit(0)
	}

	// Handle --maintenance
	if maintCmd != "" {
		handleMaintenance(binaryName, maintCmd, flag.Args())
		os.Exit(0)
	}

	// Handle --update
	if updateCmd != "" {
		handleUpdate(binaryName, updateCmd, flag.Args())
		os.Exit(0)
	}

	// Handle --daemon
	if daemonFlag {
		fmt.Fprintln(os.Stderr, "Error: --daemon not supported")
		fmt.Fprintln(os.Stderr, "Use systemd (Type=simple), Docker, or run in foreground")
		os.Exit(1)
	}

	// Detect application mode (debug flag is bool per spec PART 8)
	debugStr := ""
	if debugFlag {
		debugStr = "true"
	}
	appMode, err := mode.Detect(modeFlag, debugStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Apply env var fallbacks for directory flags (PART 12 spec requirement)
	// Priority: CLI flag > environment variable > auto-detect
	if configDir == "" {
		configDir = os.Getenv("CONFIG_DIR")
	}
	if dataDir == "" {
		dataDir = os.Getenv("DATA_DIR")
	}
	if cacheDir == "" {
		cacheDir = os.Getenv("CACHE_DIR")
	}
	if logDir == "" {
		logDir = os.Getenv("LOG_DIR")
	}
	if backupDir == "" {
		backupDir = os.Getenv("BACKUP_DIR")
	}
	if pidFile == "" {
		pidFile = os.Getenv("PID_FILE")
	}
	if address == "" {
		address = os.Getenv("LISTEN")
	}
	if portFlag == "" {
		portFlag = os.Getenv("PORT")
	}
	if modeFlag == "" && os.Getenv("MODE") != "" {
		modeFlag = os.Getenv("MODE")
	}

	// Detect paths
	appPaths, err := paths.Detect(configDir, dataDir, cacheDir, logDir, backupDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error detecting paths: %v\n", err)
		os.Exit(1)
	}

	// Set PID file if specified
	if pidFile != "" {
		appPaths.PID = pidFile
	}

	// Override DB dir if DATABASE_DIR env is set (PART 12 - Docker: /data/db/sqlite)
	if dbDir := os.Getenv("DATABASE_DIR"); dbDir != "" {
		appPaths.DB = dbDir
	}

	// Ensure all directories exist
	if err := appPaths.Ensure(); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating directories: %v\n", err)
		os.Exit(1)
	}

	// Load configuration
	configPath := filepath.Join(appPaths.Config, "server.yml")
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Override config with CLI flags
	if address != "" {
		cfg.Server.Address = address
	}
	if portFlag != "" {
		cfg.Server.Port = portFlag
	}
	if modeFlag != "" {
		cfg.Server.Mode = modeFlag
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Save default configuration if it doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := config.Save(cfg, configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not save default config: %v\n", err)
		}
	}

	// Print startup banner
	printBanner(appMode, cfg)

	// Write PID file
	if err := pid.WritePIDFile(appPaths.PID); err != nil {
		fmt.Fprintf(os.Stderr, "PID file error: %v\n", err)
		os.Exit(1)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	// Remove PID file on exit
	defer func() {
		if err := pid.RemovePIDFile(appPaths.PID); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not remove PID file: %v\n", err)
		}
	}()

	// Determine listen address and port
	listenAddr := cfg.Server.Address
	if listenAddr == "" {
		listenAddr = "[::]"
	}

	listenPort := 64580
	if cfg.Server.Port != nil {
		switch p := cfg.Server.Port.(type) {
		case int:
			listenPort = p
		case string:
			if p != "" {
				fmt.Sscanf(p, "%d", &listenPort)
			}
		}
	}

	// Create and start server
	srv, err := server.New(cfg, appMode, appPaths.Data, appPaths.Log, Version, CommitID, BuildDate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Server initialization error: %v\n", err)
		os.Exit(1)
	}

	// Check if setup is complete, if not generate and display setup token
	if !admin.IsSetupComplete() {
		setupToken, err := admin.GenerateSetupToken()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating setup token: %v\n", err)
			os.Exit(1)
		}
		printSetupInstructions(listenAddr, listenPort, setupToken)
	}

	if err := srv.Start(listenAddr, listenPort); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func showHelpText(binaryName string) {
	fmt.Printf(`%s v%s - Self-hosted speed testing server

Usage:
  %s [flags]

Information:
  -h, --help                             Show help (--help for any command shows its help)
  -v, --version                          Show version
  --status                               Show server status and health

Shell Integration:
  --shell completions [SHELL]            Print shell completions
  --shell init [SHELL]                   Print shell init command
  --shell help                           Show shell help

Server Configuration:
  --mode {production|development}        Application mode (default: production)
  --config DIR                           Config directory
  --data DIR                             Data directory
  --cache DIR                            Cache directory
  --log DIR                              Log directory
  --backup DIR                           Backup directory
  --pid FILE                             PID file path
  --address ADDR                         Listen address (default: [::])
  --port PORT                            Listen port (default: random 64xxx)
  --baseurl PATH                         URL path prefix (default: /)
  --daemon                               Run as daemon (detach from terminal)
  --debug                                Enable debug mode
  --color {auto|yes|no}                  Color output (default: auto)
  --lang CODE                            Language for output (default: auto)

Service Management:
  --service CMD                          Service management (run --service help for details)
  --maintenance CMD                      Maintenance operations (run --maintenance help for details)
  --update [CMD]                         Check/perform updates (run --update help for details)

Run '%s <command> help' for detailed help on any command.
`, binaryName, Version, binaryName, binaryName)
}

// resolveColorMode determines if color/emoji output should be used.
// Priority: --color flag > NO_COLOR env > auto-detect TTY.
func resolveColorMode(flag string) bool {
	switch strings.ToLower(flag) {
	case "yes", "on", "1", "true":
		return true
	case "no", "off", "0", "false":
		return false
	}
	// auto: NO_COLOR env disables color
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	// auto: no TTY = no color (piped output)
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func showVersionInfo(binaryName string, colorEnabled bool) {
	fmt.Printf("%s v%s (%s) built %s\n", binaryName, Version, CommitID, BuildDate)
}

// handleShell implements --shell completions|init|help [SHELL]
func handleShell(binaryName, cmd string, args []string) {
	targetShell := ""
	if len(args) > 0 {
		targetShell = args[0]
	}
	if targetShell == "" {
		// Auto-detect from SHELL env
		shell := os.Getenv("SHELL")
		if shell != "" {
			parts := strings.Split(shell, "/")
			targetShell = parts[len(parts)-1]
		}
		if targetShell == "" {
			targetShell = "bash"
		}
	}

	switch cmd {
	case "completions":
		handleShellCompletions(binaryName, targetShell)
	case "init":
		handleShellInit(binaryName, targetShell)
	case "help", "--help":
		fmt.Printf(`Shell Integration for %s

Usage:
  %s --shell completions [SHELL]  Print shell completions
  %s --shell init [SHELL]         Print shell init command
  %s --shell help                 Show this help

Supported shells: bash, zsh, fish

Add to your shell config:
  bash:  eval "$(%s --shell init bash)"
  zsh:   eval "$(%s --shell init zsh)"
  fish:  %s --shell init fish | source
`, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName)
	default:
		fmt.Fprintf(os.Stderr, "Unknown shell command: %s\n", cmd)
		fmt.Fprintf(os.Stderr, "Run '%s --shell help' for available commands\n", binaryName)
		os.Exit(2)
	}
}

func handleShellCompletions(binaryName, shell string) {
	switch shell {
	case "bash":
		fmt.Printf(`_%s_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="--help --version --status --mode --config --data --cache --log --backup --pid --address --port --baseurl --daemon --debug --color --lang --service --maintenance --update --shell"
    COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
}
complete -F _%s_completions %s
`, binaryName, binaryName, binaryName)
	case "zsh":
		fmt.Printf(`#compdef %s
_%s() {
    local -a opts
    opts=(
        '--help:Show help'
        '--version:Show version'
        '--status:Show server status'
        '--mode:Application mode (production|development)'
        '--config:Configuration directory'
        '--data:Data directory'
        '--port:Listen port'
        '--address:Listen address'
        '--debug:Enable debug mode'
        '--color:Color output (auto|yes|no)'
    )
    _describe '%s options' opts
}
_%s "$@"
`, binaryName, binaryName, binaryName, binaryName)
	case "fish":
		fmt.Printf(`complete -c %s -l help -s h -d 'Show help'
complete -c %s -l version -s v -d 'Show version'
complete -c %s -l status -d 'Show server status'
complete -c %s -l mode -d 'Application mode' -r -a 'production development'
complete -c %s -l config -d 'Configuration directory' -r -F
complete -c %s -l data -d 'Data directory' -r -F
complete -c %s -l port -d 'Listen port' -r
complete -c %s -l address -d 'Listen address' -r
complete -c %s -l debug -d 'Enable debug mode'
complete -c %s -l color -d 'Color output' -r -a 'auto yes no'
`, binaryName, binaryName, binaryName, binaryName, binaryName,
			binaryName, binaryName, binaryName, binaryName, binaryName)
	default:
		fmt.Fprintf(os.Stderr, "Unsupported shell: %s (supported: bash, zsh, fish)\n", shell)
		os.Exit(2)
	}
}

func handleShellInit(binaryName, shell string) {
	switch shell {
	case "bash":
		fmt.Printf(`eval "$(%s --shell completions bash)"
`, binaryName)
	case "zsh":
		fmt.Printf(`eval "$(%s --shell completions zsh)"
`, binaryName)
	case "fish":
		fmt.Printf(`%s --shell completions fish | source
`, binaryName)
	default:
		fmt.Fprintf(os.Stderr, "Unsupported shell: %s (supported: bash, zsh, fish)\n", shell)
		os.Exit(2)
	}
}

func printBanner(appMode *mode.State, cfg *config.Config) {
	colorEnabled := resolveColorMode("auto")

	if colorEnabled {
		fmt.Println("╭─────────────────────────────────────────────────────────────╮")
		fmt.Printf("│  🚀 CASSPEED · 📦 v%s%s│\n", Version, pad(Version))
		fmt.Println("├─────────────────────────────────────────────────────────────┤")
		fmt.Printf("│  %s Running in mode: %s%s│\n", appMode.GetConsoleIcon(), appMode.String(), padMode(appMode.String()))
		fmt.Println("├─────────────────────────────────────────────────────────────┤")
		fmt.Println("│  Server initialization...                                   │")
		fmt.Println("╰─────────────────────────────────────────────────────────────╯")
	} else {
		fmt.Printf("casspeed v%s - mode: %s\n", Version, appMode.String())
		fmt.Println("Server initialization...")
	}
}

func pad(version string) string {
	// Pad to align with banner width (60 chars minus prefix)
	needed := 60 - len("🚀 CASSPEED · 📦 v") - len(version)
	if needed < 0 {
		needed = 0
	}
	return fmt.Sprintf("%*s", needed, "")
}

func padMode(modeStr string) string {
	// Pad mode line
	needed := 60 - len("Running in mode: ") - len(modeStr) - 2
	if needed < 0 {
		needed = 0
	}
	return fmt.Sprintf("%*s", needed, "")
}

func showStatusInfo(binaryName string) {
	fmt.Printf("%s Status\n", binaryName)
	fmt.Println("─────────────────────────────────────")
	
	// Check if server is running via health endpoint
	resp, err := http.Get("http://localhost:64580/healthz")
	if err != nil {
		fmt.Println("Status: Stopped (not responding)")
		fmt.Println("Health: Unavailable")
		fmt.Println()
		fmt.Printf("Start the server with: %s\n", binaryName)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		fmt.Println("Status: Running")
		fmt.Println("Health: OK")
		fmt.Printf("Endpoint: http://localhost:64580\n")
	} else {
		fmt.Printf("Status: Running (unhealthy, HTTP %d)\n", resp.StatusCode)
		fmt.Println("Health: Error")
	}
}

func handleService(binaryName string, cmd string) {
	fmt.Printf("%s: Service Management\n", binaryName)
	fmt.Println("─────────────────────────────────────")
	
	switch cmd {
	case "start":
		fmt.Println("Service management: Use systemd, Docker, or run directly")
		fmt.Printf("Direct: %s --daemon\n", binaryName)
		fmt.Println("Systemd: systemctl start casspeed")
		fmt.Println("Docker: docker-compose up -d")
	case "stop":
		fmt.Println("Service management: Use systemd, Docker, or kill process")
		fmt.Println("Systemd: systemctl stop casspeed")
		fmt.Println("Docker: docker-compose down")
	case "restart":
		fmt.Println("Service management: Use systemd, Docker, or kill + restart")
		fmt.Println("Systemd: systemctl restart casspeed")
		fmt.Println("Docker: docker-compose restart")
	case "reload":
		fmt.Println("Configuration reload: Send SIGHUP to process")
		fmt.Println("Kill: pkill -HUP casspeed")
		fmt.Println("Systemd: systemctl reload casspeed")
	case "install", "--install":
		fmt.Println("Service installation:")
		fmt.Println("1. Copy binary to /usr/local/bin/casspeed")
		fmt.Println("2. Create systemd unit: /etc/systemd/system/casspeed.service")
		fmt.Println("3. Enable: systemctl enable casspeed")
		fmt.Println("Or use Docker Compose for containerized deployment")
	case "uninstall", "--uninstall":
		fmt.Println("Service removal:")
		fmt.Println("1. Stop service: systemctl stop casspeed")
		fmt.Println("2. Disable: systemctl disable casspeed")
		fmt.Println("3. Remove unit: rm /etc/systemd/system/casspeed.service")
		fmt.Println("4. Remove binary: rm /usr/local/bin/casspeed")
	case "help", "--help":
		fmt.Printf(`Service Management Commands:

  %s --service start       Start the service
  %s --service stop        Stop the service
  %s --service restart     Restart the service
  %s --service reload      Reload configuration
  %s --service install     Install service (systemd/launchd/etc)
  %s --service uninstall   Uninstall service
  %s --service help        Show this help

Note: Use systemd/launchd/Docker for production deployments.
Manual service management is for advanced users only.
`, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName)
	default:
		fmt.Printf("Unknown service command: %s\n", cmd)
		fmt.Printf("Run '%s --service help' for available commands\n", binaryName)
		os.Exit(1)
	}
}

func handleMaintenance(binaryName string, cmd string, args []string) {
	fmt.Printf("%s: Maintenance Operations\n", binaryName)
	fmt.Println("─────────────────────────────────────")

	// Detect paths for backup operations
	appPaths, err := paths.Detect("", "", "", "", "")
	if err != nil {
		fmt.Printf("Error detecting paths: %v\n", err)
		os.Exit(1)
	}

	switch cmd {
	case "backup":
		fmt.Println("Creating encrypted backup...")

		// Get or generate encryption key
		encKey := os.Getenv("CASSPEED_BACKUP_KEY")
		if encKey == "" {
			// Generate a new key and show it to user
			keyBytes := make([]byte, 32)
			if _, err := rand.Read(keyBytes); err != nil {
				fmt.Printf("Error generating key: %v\n", err)
				os.Exit(1)
			}
			encKey = hex.EncodeToString(keyBytes)
			fmt.Printf("\n⚠️  Generated new encryption key (save this!):\n")
			fmt.Printf("   CASSPEED_BACKUP_KEY=%s\n\n", encKey)
		}

		// Decode hex key to bytes
		keyBytes, err := hex.DecodeString(encKey)
		if err != nil || len(keyBytes) != 32 {
			fmt.Println("Error: CASSPEED_BACKUP_KEY must be 64 hex characters (32 bytes)")
			os.Exit(1)
		}

		backupSvc := backup.NewService(&backup.Config{
			Enabled:       true,
			BackupDir:     appPaths.Backup,
			MaxBackups:    4,
			EncryptionKey: string(keyBytes),
		})

		backupFile, err := backupSvc.CreateBackup(appPaths.Data)
		if err != nil {
			fmt.Printf("Backup failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✅ Backup created: %s\n", backupFile)

	case "restore":
		if len(args) == 0 {
			fmt.Println("Usage: --maintenance restore <backup-file>")
			os.Exit(1)
		}

		backupFile := args[0]
		if _, err := os.Stat(backupFile); os.IsNotExist(err) {
			fmt.Printf("Backup file not found: %s\n", backupFile)
			os.Exit(1)
		}

		encKey := os.Getenv("CASSPEED_BACKUP_KEY")
		if encKey == "" {
			fmt.Println("Error: CASSPEED_BACKUP_KEY environment variable required for restore")
			os.Exit(1)
		}

		keyBytes, err := hex.DecodeString(encKey)
		if err != nil || len(keyBytes) != 32 {
			fmt.Println("Error: CASSPEED_BACKUP_KEY must be 64 hex characters (32 bytes)")
			os.Exit(1)
		}

		fmt.Printf("Restoring from: %s\n", backupFile)
		fmt.Println("⚠️  Warning: This will overwrite existing data!")

		backupSvc := backup.NewService(&backup.Config{
			Enabled:       true,
			BackupDir:     appPaths.Backup,
			MaxBackups:    4,
			EncryptionKey: string(keyBytes),
		})

		if err := backupSvc.RestoreBackup(backupFile, appPaths.Data); err != nil {
			fmt.Printf("Restore failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("✅ Restore completed successfully")

	case "update":
		fmt.Println("Server update:")
		fmt.Println("1. Download latest binary from GitHub releases")
		fmt.Println("2. Stop server")
		fmt.Println("3. Replace binary")
		fmt.Println("4. Start server")
		fmt.Println()
		fmt.Println("Docker: docker-compose pull && docker-compose up -d")
	case "mode":
		if len(args) > 0 {
			mode := args[0]
			if mode == "production" || mode == "development" {
				fmt.Printf("Set mode in config: server.mode: %s\n", mode)
				fmt.Printf("Or use environment: MODE=%s\n", mode)
				fmt.Printf("Or use CLI flag: %s --mode %s\n", binaryName, mode)
			} else {
				fmt.Println("Invalid mode. Use: production or development")
				os.Exit(1)
			}
		} else {
			fmt.Println("Usage: --maintenance mode <production|development>")
			os.Exit(1)
		}
	case "setup":
		fmt.Println("Setup guide:")
		fmt.Println("1. First run creates default config in /etc/casapps/casspeed/")
		fmt.Println("2. Edit server.yml for custom configuration")
		fmt.Println("3. Database auto-created on first run")
		fmt.Println("4. No additional setup required")
	default:
		fmt.Printf("Unknown maintenance command: %s\n", cmd)
		fmt.Printf("Available: backup, restore, update, mode, setup\n")
		os.Exit(1)
	}
}

func handleUpdate(binaryName string, cmd string, args []string) {
	fmt.Printf("%s: Update System\n", binaryName)
	fmt.Println("─────────────────────────────────────")

	updateSvc := update.NewService(&update.Config{
		Enabled:    true,
		RepoOwner:  "casapps",
		RepoName:   "casspeed",
		Branch:     "stable",
		CurrentVer: Version,
	})

	switch cmd {
	case "check":
		fmt.Println("Checking for updates...")
		fmt.Printf("Current version: %s\n", Version)
		fmt.Println()

		release, err := updateSvc.CheckForUpdates()
		if err != nil {
			fmt.Printf("Error checking updates: %v\n", err)
			fmt.Println()
			fmt.Println("Manual check:")
			fmt.Println("https://github.com/casapps/casspeed/releases/latest")
			os.Exit(1)
		}

		if release.Version == Version || "v"+release.Version == Version {
			fmt.Println("✅ You are running the latest version")
		} else {
			fmt.Printf("🆕 New version available: %s\n", release.Version)
			fmt.Printf("   Download: %s\n", release.DownloadURL)
			fmt.Println()
			fmt.Printf("Run '%s --update yes' to update\n", binaryName)
		}

	case "yes":
		fmt.Println("Checking for updates...")
		release, err := updateSvc.CheckForUpdates()
		if err != nil {
			fmt.Printf("Error checking updates: %v\n", err)
			os.Exit(1)
		}

		if release.Version == Version || "v"+release.Version == Version {
			fmt.Println("✅ Already running latest version")
			return
		}

		fmt.Printf("Updating to version %s...\n", release.Version)
		fmt.Println("⏳ Downloading...")

		if err := updateSvc.PerformUpdate(release); err != nil {
			fmt.Printf("Update failed: %v\n", err)
			fmt.Println()
			fmt.Println("Manual update instructions:")
			fmt.Println("1. Download latest binary from GitHub releases")
			fmt.Println("2. Stop casspeed: systemctl stop casspeed")
			fmt.Println("3. Replace binary: cp casspeed-new /usr/local/bin/casspeed")
			fmt.Println("4. Start casspeed: systemctl start casspeed")
			os.Exit(1)
		}

		fmt.Println("✅ Update completed!")
		fmt.Println("Restart the service to use the new version:")
		fmt.Println("  systemctl restart casspeed")

	case "branch":
		if len(args) > 0 {
			branch := args[0]
			if branch == "stable" || branch == "beta" || branch == "daily" {
				updateSvc.SetBranch(branch)
				fmt.Printf("Update branch set to: %s\n", branch)
				fmt.Println()
				fmt.Printf("Docker users: ghcr.io/casapps/casspeed:%s\n", branch)
			} else {
				fmt.Printf("Invalid branch: %s (use: stable, beta, daily)\n", branch)
				os.Exit(1)
			}
		} else {
			fmt.Printf("Current branch: %s\n", updateSvc.GetBranch())
			fmt.Println()
			fmt.Println("Usage: --update branch <stable|beta|daily>")
		}
	default:
		fmt.Printf("Unknown update command: %s\n", cmd)
		fmt.Printf("Available: check, yes, branch <stable|beta|daily>\n")
		os.Exit(1)
	}
}

func printSetupInstructions(listenAddr string, listenPort int, setupToken string) {
fmt.Println()
fmt.Println("╔══════════════════════════════════════════════════════════════════════╗")
fmt.Println("║                       FIRST-TIME SETUP REQUIRED                      ║")
fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
fmt.Println("║                                                                      ║")
fmt.Println("║  🌐 Web Interface:                                                   ║")
if listenAddr == "[::]" || listenAddr == "0.0.0.0" || listenAddr == "" {
fmt.Printf("║      http://localhost:%d                                    ║\n", listenPort)
} else {
fmt.Printf("║      http://%s:%d                                    ║\n", listenAddr, listenPort)
}
fmt.Println("║                                                                      ║")
fmt.Println("║  🔧 Admin Panel:                                                     ║")
if listenAddr == "[::]" || listenAddr == "0.0.0.0" || listenAddr == "" {
fmt.Printf("║      http://localhost:%d/admin                               ║\n", listenPort)
} else {
fmt.Printf("║      http://%s:%d/admin                               ║\n", listenAddr, listenPort)
}
fmt.Println("║                                                                      ║")
fmt.Println("║  🔑 Setup Token (use at /admin):                                     ║")
fmt.Printf("║      %-64s ║\n", setupToken)
fmt.Println("║                                                                      ║")
fmt.Println("║  ⚠️  Save the setup token! It will not be shown again.               ║")
fmt.Println("║                                                                      ║")
fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")
fmt.Println()
}
