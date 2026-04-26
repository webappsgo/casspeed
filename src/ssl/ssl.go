package ssl

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertInfo represents SSL certificate information
type CertInfo struct {
	CertPath   string
	KeyPath    string
	Source     string    // "system", "app-managed", "user-provided"
	ExpiresAt  time.Time
	IsExpired  bool
	DaysLeft   int
}

// Manager handles SSL/TLS certificate management
type Manager struct {
	ConfigDir string
	FQDN      string
}

// NewManager creates a new SSL manager
func NewManager(configDir, fqdn string) *Manager {
	return &Manager{
		ConfigDir: configDir,
		FQDN:      fqdn,
	}
}

// FindCertificate searches for certificates in priority order
func (m *Manager) FindCertificate() (*CertInfo, error) {
	// Priority 1: System certbot - /etc/letsencrypt/live/domain/
	if cert := m.checkSystemCert("domain"); cert != nil {
		return cert, nil
	}

	// Priority 2: System certbot - /etc/letsencrypt/live/{fqdn}/
	if cert := m.checkSystemCert(m.FQDN); cert != nil {
		return cert, nil
	}

	// Priority 3: App-managed Let's Encrypt
	if cert := m.checkAppLetsEncrypt(); cert != nil {
		return cert, nil
	}

	// Priority 4: User-provided local certificate
	if cert := m.checkLocalCert(); cert != nil {
		return cert, nil
	}

	return nil, fmt.Errorf("no valid certificate found for %s", m.FQDN)
}

// checkSystemCert checks /etc/letsencrypt/live/{domain}/
func (m *Manager) checkSystemCert(domain string) *CertInfo {
	certPath := filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem")
	keyPath := filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")

	if cert := m.validateCertPaths(certPath, keyPath, "system"); cert != nil {
		return cert
	}
	return nil
}

// checkAppLetsEncrypt checks {config_dir}/ssl/letsencrypt/{fqdn}/
func (m *Manager) checkAppLetsEncrypt() *CertInfo {
	certPath := filepath.Join(m.ConfigDir, "ssl/letsencrypt", m.FQDN, "fullchain.pem")
	keyPath := filepath.Join(m.ConfigDir, "ssl/letsencrypt", m.FQDN, "privkey.pem")

	if cert := m.validateCertPaths(certPath, keyPath, "app-managed"); cert != nil {
		return cert
	}
	return nil
}

// checkLocalCert checks {config_dir}/ssl/local/{fqdn}/
func (m *Manager) checkLocalCert() *CertInfo {
	certPath := filepath.Join(m.ConfigDir, "ssl/local", m.FQDN, "cert.pem")
	keyPath := filepath.Join(m.ConfigDir, "ssl/local", m.FQDN, "key.pem")

	if cert := m.validateCertPaths(certPath, keyPath, "user-provided"); cert != nil {
		return cert
	}
	return nil
}

// validateCertPaths validates certificate and key files exist and are valid
func (m *Manager) validateCertPaths(certPath, keyPath, source string) *CertInfo {
	// Check if files exist
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil
	}

	// Load certificate to check validity
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil
	}

	// Parse certificate to check expiration
	if len(cert.Certificate) == 0 {
		return nil
	}

	// Get expiration from first certificate in chain
	leaf := cert.Leaf
	if leaf == nil {
		// Parse if not already done
		parsed, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil || len(parsed.Certificate) == 0 {
			return nil
		}
		leaf = parsed.Leaf
	}

	if leaf == nil {
		return nil
	}

	now := time.Now()
	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)

	return &CertInfo{
		CertPath:  certPath,
		KeyPath:   keyPath,
		Source:    source,
		ExpiresAt: leaf.NotAfter,
		IsExpired: now.After(leaf.NotAfter),
		DaysLeft:  daysLeft,
	}
}

// NeedsRenewal checks if certificate should be renewed
func (c *CertInfo) NeedsRenewal() bool {
	// Renew 7 days before expiry for app-managed certs
	if c.Source == "app-managed" && c.DaysLeft < 7 {
		return true
	}
	return c.IsExpired
}

// GetFQDN resolves the fully qualified domain name
func GetFQDN(projectName string) string {
	// 1. DOMAIN env var (explicit user override)
	if domain := os.Getenv("DOMAIN"); domain != "" {
		// Return first domain if comma-separated list
		if idx := strings.Index(domain, ","); idx > 0 {
			return strings.TrimSpace(domain[:idx])
		}
		return strings.TrimSpace(domain)
	}

	// 2. os.Hostname()
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		if !isLoopback(hostname) {
			return hostname
		}
	}

	// 3. $HOSTNAME env var
	if hostname := os.Getenv("HOSTNAME"); hostname != "" {
		if !isLoopback(hostname) {
			return hostname
		}
	}

	// 4. Global IPv6
	if ipv6 := getGlobalIPv6(); ipv6 != "" {
		return ipv6
	}

	// 5. Global IPv4
	if ipv4 := getGlobalIPv4(); ipv4 != "" {
		return ipv4
	}

	return "localhost"
}

// GetAllDomains returns all domains from DOMAIN env var
func GetAllDomains() []string {
	domain := os.Getenv("DOMAIN")
	if domain == "" {
		return nil
	}
	parts := strings.Split(domain, ",")
	domains := make([]string, 0, len(parts))
	for _, p := range parts {
		if d := strings.TrimSpace(p); d != "" {
			domains = append(domains, d)
		}
	}
	return domains
}

// isLoopback checks if host is localhost or loopback IP
func isLoopback(host string) bool {
	lower := strings.ToLower(host)
	if lower == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// getGlobalIPv6 returns first public IPv6 address
func getGlobalIPv6() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP
			if ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return ip.String()
			}
		}
	}
	return ""
}

// getGlobalIPv4 returns first public IPv4 address
func getGlobalIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP
			if ip4 := ip.To4(); ip4 != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return ip4.String()
			}
		}
	}
	return ""
}

// FormatURL formats a URL with proper protocol and port handling
func FormatURL(host string, port int, isHTTPS bool) string {
	proto := "http"
	if isHTTPS || port == 443 {
		proto = "https"
	}

	// Always strip :80 and :443
	if port == 80 || port == 443 {
		return proto + "://" + host
	}

	// IPv6 needs brackets
	if strings.Contains(host, ":") {
		return fmt.Sprintf("%s://[%s]:%d", proto, host, port)
	}

	return fmt.Sprintf("%s://%s:%d", proto, host, port)
}

// GetDisplayURL returns best URL for display
func GetDisplayURL(projectName string, port int, isHTTPS bool) string {
	fqdn := GetFQDN(projectName)

	// If valid production FQDN, use it
	if !isDevTLD(fqdn, projectName) && fqdn != "localhost" {
		return FormatURL(fqdn, port, isHTTPS)
	}

	// Dev TLD or localhost - use global IP instead
	if ipv6 := getGlobalIPv6(); ipv6 != "" {
		return FormatURL(ipv6, port, isHTTPS)
	}
	if ipv4 := getGlobalIPv4(); ipv4 != "" {
		return FormatURL(ipv4, port, isHTTPS)
	}

	return FormatURL(fqdn, port, isHTTPS)
}

// isDevTLD checks if host is a development TLD
func isDevTLD(host, projectName string) bool {
	lower := strings.ToLower(host)

	// Check dynamic project-specific TLD
	if projectName != "" && strings.HasSuffix(lower, "."+strings.ToLower(projectName)) {
		return true
	}

	// Check static dev TLDs
	devTLDs := []string{
		".local", ".test", ".example", ".invalid",
		".localhost", ".lan", ".internal", ".home",
		".localdomain", ".home.arpa", ".intranet",
		".corp", ".private",
	}

	for _, tld := range devTLDs {
		if strings.HasSuffix(lower, tld) || lower == strings.TrimPrefix(tld, ".") {
			return true
		}
	}

	return false
}
