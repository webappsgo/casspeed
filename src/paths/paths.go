package paths

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

// Paths represents all application paths
type Paths struct {
	Config   string // Configuration directory
	Data     string // Data directory
	Cache    string // Cache directory
	Log      string // Log directory
	Backup   string // Backup directory
	DB       string // Database directory
	PID      string // PID file path
	SSL      string // SSL certificates directory
	Security string // Security databases directory (GeoIP, etc.)
}

// Detect automatically determines appropriate paths for current OS and privilege level
func Detect(configOverride, dataOverride, cacheOverride, logOverride, backupOverride string) (*Paths, error) {
	isRoot := isRunningAsRoot()
	isContainer := isRunningInContainer()

	var paths *Paths
	var err error

	// Container paths take highest priority
	if isContainer {
		paths = containerPaths()
	} else {
		switch runtime.GOOS {
		case "linux":
			if isRoot {
				paths = linuxPrivilegedPaths()
			} else {
				paths = linuxUserPaths()
			}
		case "darwin":
			if isRoot {
				paths = darwinPrivilegedPaths()
			} else {
				paths = darwinUserPaths()
			}
		case "freebsd", "openbsd", "netbsd":
			if isRoot {
				paths = bsdPrivilegedPaths()
			} else {
				paths = bsdUserPaths()
			}
		case "windows":
			if isRoot {
				paths = windowsPrivilegedPaths()
			} else {
				paths = windowsUserPaths()
			}
		default:
			return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	}

	// Apply overrides
	if configOverride != "" {
		paths.Config = configOverride
		paths.SSL = filepath.Join(configOverride, "ssl")
		paths.Security = filepath.Join(configOverride, "security")
	}
	if dataOverride != "" {
		paths.Data = dataOverride
		paths.DB = filepath.Join(dataOverride, "db")
	}
	if cacheOverride != "" {
		paths.Cache = cacheOverride
	}
	if logOverride != "" {
		paths.Log = logOverride
	}
	if backupOverride != "" {
		paths.Backup = backupOverride
	}

	return paths, err
}

// Ensure creates all directories if they don't exist
func (p *Paths) Ensure() error {
	dirs := []string{
		p.Config,
		p.Data,
		p.Cache,
		p.Log,
		p.DB,
		p.Backup,
		filepath.Join(p.SSL, "letsencrypt"),
		filepath.Join(p.SSL, "local"),
		filepath.Join(p.Security, "geoip"),
		filepath.Join(p.Security, "blocklists"),
		filepath.Join(p.Security, "cve"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Ensure PID file directory exists
	pidDir := filepath.Dir(p.PID)
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		return fmt.Errorf("failed to create PID directory %s: %w", pidDir, err)
	}

	return nil
}

// isRunningAsRoot checks if process is running with elevated privileges
func isRunningAsRoot() bool {
	if runtime.GOOS == "windows" {
		// Windows admin check: defaults to false (user paths)
		// Could implement using Windows API but not critical
		return false
	}
	return os.Geteuid() == 0
}

// isRunningInContainer checks if running in a container
func isRunningInContainer() bool {
	// Check for /.dockerenv file
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// Check for container environment variables
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	if os.Getenv("container") != "" {
		return true
	}
	return false
}

// Linux privileged paths
func linuxPrivilegedPaths() *Paths {
	return &Paths{
		Config:   "/etc/casapps/casspeed",
		Data:     "/var/lib/casapps/casspeed",
		Cache:    "/var/cache/casapps/casspeed",
		Log:      "/var/log/casapps/casspeed",
		Backup:   "/var/backups/casapps/casspeed",
		DB:       "/var/lib/casapps/casspeed/db",
		PID:      "/var/run/casapps/casspeed.pid",
		SSL:      "/etc/casapps/casspeed/ssl",
		Security: "/etc/casapps/casspeed/security",
	}
}

// Linux user paths
func linuxUserPaths() *Paths {
	home, _ := os.UserHomeDir()
	return &Paths{
		Config:   filepath.Join(home, ".config/casapps/casspeed"),
		Data:     filepath.Join(home, ".local/share/casapps/casspeed"),
		Cache:    filepath.Join(home, ".cache/casapps/casspeed"),
		Log:      filepath.Join(home, ".local/share/casapps/casspeed/logs"),
		Backup:   filepath.Join(home, ".local/backups/casapps/casspeed"),
		DB:       filepath.Join(home, ".local/share/casapps/casspeed/db"),
		PID:      filepath.Join(home, ".local/share/casapps/casspeed/casspeed.pid"),
		SSL:      filepath.Join(home, ".config/casapps/casspeed/ssl"),
		Security: filepath.Join(home, ".config/casapps/casspeed/security"),
	}
}

// macOS privileged paths
func darwinPrivilegedPaths() *Paths {
	return &Paths{
		Config:   "/usr/local/etc/casapps/casspeed",
		Data:     "/usr/local/var/casapps/casspeed",
		Cache:    "/var/cache/casapps/casspeed",
		Log:      "/var/log/casapps/casspeed",
		Backup:   "/var/backups/casapps/casspeed",
		DB:       "/usr/local/var/casapps/casspeed/db",
		PID:      "/var/run/casapps/casspeed.pid",
		SSL:      "/usr/local/etc/casapps/casspeed/ssl",
		Security: "/usr/local/etc/casapps/casspeed/security",
	}
}

// macOS user paths
func darwinUserPaths() *Paths {
	home, _ := os.UserHomeDir()
	return &Paths{
		Config:   filepath.Join(home, ".config/casapps/casspeed"),
		Data:     filepath.Join(home, ".local/share/casapps/casspeed"),
		Cache:    filepath.Join(home, ".cache/casapps/casspeed"),
		Log:      filepath.Join(home, ".local/share/casapps/casspeed/logs"),
		Backup:   filepath.Join(home, ".local/backups/casapps/casspeed"),
		DB:       filepath.Join(home, ".local/share/casapps/casspeed/db"),
		PID:      filepath.Join(home, ".local/share/casapps/casspeed/casspeed.pid"),
		SSL:      filepath.Join(home, ".config/casapps/casspeed/ssl"),
		Security: filepath.Join(home, ".config/casapps/casspeed/security"),
	}
}

// BSD privileged paths
func bsdPrivilegedPaths() *Paths {
	return &Paths{
		Config:   "/usr/local/etc/casapps/casspeed",
		Data:     "/var/db/casapps/casspeed",
		Cache:    "/var/cache/casapps/casspeed",
		Log:      "/var/log/casapps/casspeed",
		Backup:   "/var/backups/casapps/casspeed",
		DB:       "/var/db/casapps/casspeed/db",
		PID:      "/var/run/casapps/casspeed.pid",
		SSL:      "/usr/local/etc/casapps/casspeed/ssl",
		Security: "/usr/local/etc/casapps/casspeed/security",
	}
}

// BSD user paths
func bsdUserPaths() *Paths {
	home, _ := os.UserHomeDir()
	return &Paths{
		Config:   filepath.Join(home, ".config/casapps/casspeed"),
		Data:     filepath.Join(home, ".local/share/casapps/casspeed"),
		Cache:    filepath.Join(home, ".cache/casapps/casspeed"),
		Log:      filepath.Join(home, ".local/share/casapps/casspeed/logs"),
		Backup:   filepath.Join(home, ".local/backups/casapps/casspeed"),
		DB:       filepath.Join(home, ".local/share/casapps/casspeed/db"),
		PID:      filepath.Join(home, ".local/share/casapps/casspeed/casspeed.pid"),
		SSL:      filepath.Join(home, ".config/casapps/casspeed/ssl"),
		Security: filepath.Join(home, ".config/casapps/casspeed/security"),
	}
}

// Windows privileged paths
func windowsPrivilegedPaths() *Paths {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = "C:\\ProgramData"
	}
	return &Paths{
		Config:   filepath.Join(programData, "casapps\\casspeed"),
		Data:     filepath.Join(programData, "casapps\\casspeed\\data"),
		Cache:    filepath.Join(programData, "casapps\\casspeed\\cache"),
		Log:      filepath.Join(programData, "casapps\\casspeed\\logs"),
		Backup:   filepath.Join(programData, "Backups\\casapps\\casspeed"),
		DB:       filepath.Join(programData, "casapps\\casspeed\\db"),
		PID:      filepath.Join(programData, "casapps\\casspeed\\casspeed.pid"),
		SSL:      filepath.Join(programData, "casapps\\casspeed\\ssl"),
		Security: filepath.Join(programData, "casapps\\casspeed\\security"),
	}
}

// Windows user paths
func windowsUserPaths() *Paths {
	appData := os.Getenv("AppData")
	localAppData := os.Getenv("LocalAppData")
	if appData == "" {
		u, _ := user.Current()
		appData = filepath.Join(u.HomeDir, "AppData\\Roaming")
	}
	if localAppData == "" {
		u, _ := user.Current()
		localAppData = filepath.Join(u.HomeDir, "AppData\\Local")
	}
	return &Paths{
		Config:   filepath.Join(appData, "casapps\\casspeed"),
		Data:     filepath.Join(localAppData, "casapps\\casspeed"),
		Cache:    filepath.Join(localAppData, "casapps\\casspeed\\cache"),
		Log:      filepath.Join(localAppData, "casapps\\casspeed\\logs"),
		Backup:   filepath.Join(localAppData, "Backups\\casapps\\casspeed"),
		DB:       filepath.Join(localAppData, "casapps\\casspeed\\db"),
		PID:      filepath.Join(localAppData, "casapps\\casspeed\\casspeed.pid"),
		SSL:      filepath.Join(appData, "casapps\\casspeed\\ssl"),
		Security: filepath.Join(appData, "casapps\\casspeed\\security"),
	}
}

// Container paths
func containerPaths() *Paths {
	return &Paths{
		Config:   "/config",
		Data:     "/data",
		Cache:    "/data/cache",
		Log:      "/data/logs",
		Backup:   "/data/backup",
		DB:       "/data/db",
		PID:      "/data/casspeed.pid",
		SSL:      "/config/ssl",
		Security: "/config/security",
	}
}
