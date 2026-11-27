package service

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Manager handles systemd service management
type Manager struct {
	ServiceName string
	BinaryPath  string
	User        string
}

// New creates a new service manager
func New(serviceName, binaryPath, user string) *Manager {
	return &Manager{
		ServiceName: serviceName,
		BinaryPath:  binaryPath,
		User:        user,
	}
}

// Install installs the service
func (m *Manager) Install() error {
	switch runtime.GOOS {
	case "linux":
		return m.installLinux()
	case "darwin":
		return m.installDarwin()
	case "windows":
		return m.installWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Uninstall uninstalls the service
func (m *Manager) Uninstall() error {
	switch runtime.GOOS {
	case "linux":
		return m.uninstallLinux()
	case "darwin":
		return m.uninstallDarwin()
	case "windows":
		return m.uninstallWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Start starts the service
func (m *Manager) Start() error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("systemctl", "start", m.ServiceName).Run()
	case "darwin":
		return exec.Command("launchctl", "load", m.getplistPath()).Run()
	case "windows":
		return exec.Command("sc", "start", m.ServiceName).Run()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Stop stops the service
func (m *Manager) Stop() error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("systemctl", "stop", m.ServiceName).Run()
	case "darwin":
		return exec.Command("launchctl", "unload", m.getplistPath()).Run()
	case "windows":
		return exec.Command("sc", "stop", m.ServiceName).Run()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Restart restarts the service
func (m *Manager) Restart() error {
	if err := m.Stop(); err != nil {
		return err
	}
	return m.Start()
}

// Status returns service status
func (m *Manager) Status() (string, error) {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("systemctl", "is-active", m.ServiceName).Output()
		if err != nil {
			return "inactive", nil
		}
		return strings.TrimSpace(string(out)), nil
	case "darwin":
		out, err := exec.Command("launchctl", "print", "system/"+m.ServiceName).CombinedOutput()
		if err != nil {
			if strings.Contains(strings.ToLower(string(out)), "could not find service") {
				return "inactive", nil
			}
			return "unknown", fmt.Errorf("checking launchd service status: %w", err)
		}
		if strings.Contains(string(out), "state = running") {
			return "active", nil
		}
		return "inactive", nil
	case "windows":
		out, err := exec.Command("sc", "query", m.ServiceName).CombinedOutput()
		if err != nil {
			return "unknown", fmt.Errorf("checking Windows service status: %w", err)
		}
		status := strings.ToUpper(string(out))
		if strings.Contains(status, "RUNNING") {
			return "active", nil
		}
		if strings.Contains(status, "STOPPED") {
			return "inactive", nil
		}
		return "unknown", nil
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// installLinux installs systemd service
func (m *Manager) installLinux() error {
	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", m.ServiceName)

	content := fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
User=%s
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, m.ServiceName, m.User, m.BinaryPath)

	if err := os.WriteFile(servicePath, []byte(content), 0644); err != nil {
		return err
	}

	return exec.Command("systemctl", "daemon-reload").Run()
}

// uninstallLinux uninstalls systemd service
func (m *Manager) uninstallLinux() error {
	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", m.ServiceName)

	// Stopping is best-effort during service removal.
	_ = m.Stop()

	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return exec.Command("systemctl", "daemon-reload").Run()
}

// installDarwin installs launchd service
func (m *Manager) installDarwin() error {
	plistPath := m.getplistPath()

	content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
`, m.ServiceName, m.BinaryPath)

	return os.WriteFile(plistPath, []byte(content), 0644)
}

// uninstallDarwin uninstalls launchd service
func (m *Manager) uninstallDarwin() error {
	plistPath := m.getplistPath()

	// Stopping is best-effort during service removal.
	_ = m.Stop()

	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// installWindows installs Windows service
func (m *Manager) installWindows() error {
	return exec.Command("sc", "create", m.ServiceName, "binPath=", m.BinaryPath, "start=", "auto").Run()
}

// uninstallWindows uninstalls Windows service
func (m *Manager) uninstallWindows() error {
	if err := m.Stop(); err != nil {
		// Ignore error if already stopped
	}

	return exec.Command("sc", "delete", m.ServiceName).Run()
}

// getplistPath returns the launchd plist path
func (m *Manager) getplistPath() string {
	return fmt.Sprintf("/Library/LaunchDaemons/%s.plist", m.ServiceName)
}
