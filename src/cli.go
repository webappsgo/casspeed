package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/app"
	"github.com/casapps/casspeed/src/backup"
	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/mode"
	"github.com/casapps/casspeed/src/paths"
	"github.com/casapps/casspeed/src/update"
)

func runCLI(args []string) int {
	// Get binary name for help text
	binaryName := filepath.Base(os.Args[0])
	flags := flag.NewFlagSet(binaryName, flag.ContinueOnError)

	// Define flags
	var (
		showHelp    bool
		showVersion bool
		showStatus  bool
		daemonFlag  bool
		debugFlag   bool
		i2pFlag     bool
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

	flags.BoolVar(&showHelp, "help", false, "Show help information")
	flags.BoolVar(&showHelp, "h", false, "Show help information (short)")
	flags.BoolVar(&showVersion, "version", false, "Show version information")
	flags.BoolVar(&showVersion, "v", false, "Show version information (short)")
	flags.BoolVar(&showStatus, "status", false, "Show status and health (exit 0=healthy, 1=unhealthy)")
	flags.BoolVar(&daemonFlag, "daemon", false, "Run as daemon (detach from terminal)")
	flags.BoolVar(&debugFlag, "debug", false, "Enable debug mode (verbose logging, debug endpoints)")
	flags.BoolVar(&i2pFlag, "i2p", config.DefaultI2PEnabled(), "Enable the I2P eepsite (default on in containers)")
	flags.StringVar(&modeFlag, "mode", "", "Application mode (production|development)")
	flags.StringVar(&colorFlag, "color", "auto", "Color output (auto|yes|no)")
	flags.StringVar(&langFlag, "lang", "", "Language for output (default: auto from LANG env)")
	flags.StringVar(&baseurlFlag, "baseurl", "/", "URL path prefix (default: /)")
	flags.StringVar(&shellCmd, "shell", "", "Shell integration (completions|init|help) [SHELL]")
	flags.StringVar(&configDir, "config", "", "Configuration directory")
	flags.StringVar(&dataDir, "data", "", "Data directory")
	flags.StringVar(&cacheDir, "cache", "", "Cache directory")
	flags.StringVar(&logDir, "log", "", "Log directory")
	flags.StringVar(&backupDir, "backup", "", "Backup directory")
	flags.StringVar(&pidFile, "pid", "", "PID file path")
	flags.StringVar(&address, "address", "", "Listen address (default: [::])")
	flags.StringVar(&portFlag, "port", "", "Listen port (default: random 64xxx)")
	flags.StringVar(&serviceCmd, "service", "", "Service management (start|stop|restart|reload|install|uninstall|help)")
	flags.StringVar(&maintCmd, "maintenance", "", "Maintenance operations (backup|restore|update|mode|setup)")
	flags.StringVar(&updateCmd, "update", "", "Update operations (check|yes|branch stable|beta|daily)")

	flags.Usage = func() {
		showHelpText(binaryName)
	}

	if err := flags.Parse(args); err != nil {
		return 2
	}
	i2pFlagSet := false
	flags.Visit(func(parsed *flag.Flag) {
		if parsed.Name == "i2p" {
			i2pFlagSet = true
		}
	})

	// Resolve color mode — CLI flag > config > NO_COLOR env > auto-detect
	colorEnabled := resolveColorMode(colorFlag)

	// Handle --help
	if showHelp {
		showHelpText(binaryName)
		return 0
	}

	// Handle --version
	if showVersion {
		showVersionInfo(binaryName, colorEnabled)
		return 0
	}

	// Handle --shell completions|init|help [SHELL]
	if shellCmd != "" {
		handleShell(binaryName, shellCmd, flags.Args())
		return 0
	}

	// baseurlFlag is reserved for reverse-proxy base path support.
	_ = baseurlFlag

	// Handle --service
	if serviceCmd != "" {
		handleService(binaryName, serviceCmd)
		return 0
	}

	// Handle --maintenance
	if maintCmd != "" {
		handleMaintenance(binaryName, maintCmd, flags.Args())
		return 0
	}

	// Handle --update
	if updateCmd != "" {
		handleUpdate(binaryName, updateCmd, flags.Args())
		return 0
	}

	// Handle --daemon
	if daemonFlag {
		fmt.Fprintln(os.Stderr, "Error: --daemon not supported")
		fmt.Fprintln(os.Stderr, "Use systemd (Type=simple), Docker, or run in foreground")
		return 1
	}

	// Detect application mode (debug flag is bool per spec PART 8)
	debugStr := ""
	if debugFlag {
		debugStr = "true"
	}
	appMode, err := mode.Detect(modeFlag, debugStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
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
		return 1
	}

	// Set PID file if specified
	if pidFile != "" {
		appPaths.PID = pidFile
	}

	// Override DB dir if DATABASE_DIR env is set (PART 12 - Docker: /data/db/sqlite)
	if dbDir := os.Getenv("DATABASE_DIR"); dbDir != "" {
		appPaths.DB = dbDir
	}

	// Load configuration
	configPath := filepath.Join(appPaths.Config, "server.yml")
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		return 1
	}
	if i2pFlagSet {
		cfg.Server.I2P.Enabled = i2pFlag
	}
	if langFlag == "" {
		langFlag = os.Getenv("LC_ALL")
	}
	if langFlag == "" {
		langFlag = os.Getenv("LANG")
	}
	if langFlag != "" {
		cfg.Language = i18n.Normalize(langFlag)
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
	if showStatus {
		return showStatusInfo(binaryName, cfg)
	}

	// Ensure all directories exist
	if err := appPaths.Ensure(); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating directories: %v\n", err)
		return 1
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		return 1
	}

	// Save default configuration if it doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := config.Save(cfg, configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not save default config: %v\n", err)
		}
	}

	cfg.Runtime = config.RuntimeInfo{
		ConfigDir: appPaths.Config, DataDir: appPaths.Data, CacheDir: appPaths.Cache,
		LogDir: appPaths.Log, BackupDir: appPaths.Backup, PIDFile: appPaths.PID,
		Version: Version, CommitID: CommitID, BuildEpoch: BuildEpoch, OfficialSite: OfficialSite,
	}
	printBanner(appMode, cfg)
	if err := app.Run(context.Background(), *cfg); err != nil {
		if strings.Contains(err.Error(), "write PID file:") {
			fmt.Fprintf(os.Stderr, "PID file error: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		}
		return 1
	}
	return 0
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
  --i2p                                  Enable the I2P eepsite (default on in a container, off elsewhere; supports --i2p=false)
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
    local opts="--help --version --status --mode --config --data --cache --log --backup --pid --address --port --baseurl --daemon --debug --i2p --color --lang --service --maintenance --update --shell"
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
        '--i2p:Enable the I2P eepsite'
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
complete -c %s -l i2p -d 'Enable the I2P eepsite'
complete -c %s -l color -d 'Color output' -r -a 'auto yes no'
`, binaryName, binaryName, binaryName, binaryName, binaryName,
			binaryName, binaryName, binaryName, binaryName, binaryName, binaryName)
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

func showStatusInfo(binaryName string, cfg *config.Config) int {
	client := &http.Client{Timeout: 5 * time.Second}
	port := 64580
	if cfg != nil && cfg.Server.Port != nil {
		switch configuredPort := cfg.Server.Port.(type) {
		case int:
			if configuredPort > 0 {
				port = configuredPort
			}
		case string:
			if parsed, err := strconv.Atoi(configuredPort); err == nil && parsed > 0 {
				port = parsed
			}
		}
	}
	host := "localhost"
	apiBasePath := "/api/v1"
	if cfg != nil {
		configuredHost := strings.Trim(cfg.Server.Address, "[]")
		if configuredHost != "" && configuredHost != "0.0.0.0" && configuredHost != "::" {
			host = configuredHost
		}
		apiBasePath = cfg.APIBasePath()
	}
	endpoint := "http://" + net.JoinHostPort(host, strconv.Itoa(port))
	resp, err := client.Get(endpoint + apiBasePath + "/server/healthz")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: server is not responding at %s\n", binaryName, endpoint)
		return 1
	}
	defer resp.Body.Close()
	var health struct {
		Status   string `json:"status"`
		Mode     string `json:"mode"`
		Features struct {
			Tor struct {
				Enabled  bool   `json:"enabled"`
				Running  bool   `json:"running"`
				Status   string `json:"status"`
				Hostname string `json:"hostname"`
			} `json:"tor"`
			I2P struct {
				Enabled  bool   `json:"enabled"`
				Running  bool   `json:"running"`
				Status   string `json:"status"`
				Hostname string `json:"hostname"`
				Provider string `json:"provider"`
			} `json:"i2p"`
		} `json:"features"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil || resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "%s: health check failed (HTTP %d)\n", binaryName, resp.StatusCode)
		return 1
	}
	if health.Status != "healthy" {
		fmt.Fprintf(os.Stderr, "%s: server health is %q\n", binaryName, health.Status)
		return 1
	}
	fmt.Printf("%s Status\n", binaryName)
	fmt.Println("─────────────────────────────────────")
	fmt.Println("Status: Running")
	fmt.Printf("Health: %s\n", health.Status)
	fmt.Printf("Endpoint: %s\n", endpoint)
	if health.Mode != "" {
		fmt.Printf("Mode: %s\n", health.Mode)
	}
	if health.Features.Tor.Enabled {
		status := health.Features.Tor.Status
		if health.Features.Tor.Running {
			status = "Connected"
		}
		fmt.Printf("Tor Hidden Service: %s\n", status)
		if health.Features.Tor.Hostname != "" {
			fmt.Printf("  Address: %s\n", health.Features.Tor.Hostname)
		}
	}
	if health.Features.I2P.Enabled || health.Features.I2P.Status == "disabled" {
		status := health.Features.I2P.Status
		if health.Features.I2P.Running {
			status = "Running (" + health.Features.I2P.Provider + ")"
		}
		if status == "unavailable" {
			status = "Error"
			if health.Features.I2P.Provider == "none" {
				status = "No Provider"
			}
		}
		if status == "starting" {
			status = "Starting"
		}
		if status == "disabled" {
			status = "Disabled"
		}
		fmt.Printf("I2P Eepsite: %s\n", status)
		if health.Features.I2P.Hostname != "" {
			fmt.Printf("  Address: %s\n", health.Features.I2P.Hostname)
		}
	}
	return 0
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
