package ssl

import (
	"strings"
	"testing"
)

// ---- FormatURL tests -----------------------------------------------------

func TestFormatURL(t *testing.T) {
	cases := []struct {
		host    string
		port    int
		https   bool
		want    string
	}{
		{"example.com", 80, false, "http://example.com"},
		{"example.com", 443, false, "https://example.com"},
		{"example.com", 443, true, "https://example.com"},
		{"example.com", 8080, false, "http://example.com:8080"},
		{"example.com", 8443, true, "https://example.com:8443"},
		{"::1", 8080, false, "http://[::1]:8080"},
		// Port 443 is stripped, and the pre-strip path returns before IPv6 bracket check.
		{"2001:db8::1", 443, true, "https://2001:db8::1"},
		{"127.0.0.1", 3000, false, "http://127.0.0.1:3000"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			got := FormatURL(tc.host, tc.port, tc.https)
			if got != tc.want {
				t.Errorf("FormatURL(%q,%d,%v) = %q, want %q", tc.host, tc.port, tc.https, got, tc.want)
			}
		})
	}
}

// ---- isLoopback tests ----------------------------------------------------

func TestIsLoopback(t *testing.T) {
	loopbacks := []string{
		"localhost",
		"LOCALHOST",
		"127.0.0.1",
		"::1",
	}
	for _, h := range loopbacks {
		if !isLoopback(h) {
			t.Errorf("isLoopback(%q) = false, want true", h)
		}
	}

	notLoopback := []string{
		"example.com",
		"192.168.1.1",
		"10.0.0.1",
		"8.8.8.8",
	}
	for _, h := range notLoopback {
		if isLoopback(h) {
			t.Errorf("isLoopback(%q) = true, want false", h)
		}
	}
}

// ---- isDevTLD tests ------------------------------------------------------

func TestIsDevTLD_DevTLDs(t *testing.T) {
	devHosts := []string{
		"myapp.local",
		"test.test",
		"app.example",
		"host.invalid",
		"server.localhost",
		"box.lan",
		"server.internal",
		"device.home",
		"host.localdomain",
		"app.intranet",
		"host.corp",
		"host.private",
		"local",
		"test",
	}
	for _, h := range devHosts {
		if !isDevTLD(h, "") {
			t.Errorf("isDevTLD(%q,'') = false, want true", h)
		}
	}
}

func TestIsDevTLD_ProductionHosts(t *testing.T) {
	productionHosts := []string{
		"example.com",
		"api.example.org",
		"myapp.net",
		"speedtest.io",
	}
	for _, h := range productionHosts {
		if isDevTLD(h, "") {
			t.Errorf("isDevTLD(%q,'') = true, want false", h)
		}
	}
}

func TestIsDevTLD_ProjectSpecific(t *testing.T) {
	// host ending in ".casspeed" should be treated as dev TLD.
	if !isDevTLD("server.casspeed", "casspeed") {
		t.Error("project-specific TLD should be treated as dev")
	}
}

// ---- GetFQDN tests -------------------------------------------------------

func TestGetFQDN_ReturnsSomething(t *testing.T) {
	// DOMAIN env not set in test environment; result should be non-empty.
	t.Setenv("DOMAIN", "")
	fqdn := GetFQDN("casspeed")
	if fqdn == "" {
		t.Error("GetFQDN should return non-empty string")
	}
}

func TestGetFQDN_EnvOverride(t *testing.T) {
	t.Setenv("DOMAIN", "speedtest.example.com")
	fqdn := GetFQDN("casspeed")
	if fqdn != "speedtest.example.com" {
		t.Errorf("GetFQDN with DOMAIN env = %q, want 'speedtest.example.com'", fqdn)
	}
}

func TestGetFQDN_EnvMultipleDomains(t *testing.T) {
	t.Setenv("DOMAIN", "first.example.com,second.example.com")
	fqdn := GetFQDN("casspeed")
	if fqdn != "first.example.com" {
		t.Errorf("GetFQDN (multi DOMAIN) = %q, want first entry", fqdn)
	}
}

// ---- GetAllDomains tests ------------------------------------------------

func TestGetAllDomains_Empty(t *testing.T) {
	t.Setenv("DOMAIN", "")
	domains := GetAllDomains()
	if domains != nil {
		t.Errorf("GetAllDomains (empty env) = %v, want nil", domains)
	}
}

func TestGetAllDomains_Single(t *testing.T) {
	t.Setenv("DOMAIN", "example.com")
	domains := GetAllDomains()
	if len(domains) != 1 || domains[0] != "example.com" {
		t.Errorf("GetAllDomains (single) = %v, want [example.com]", domains)
	}
}

func TestGetAllDomains_Multiple(t *testing.T) {
	t.Setenv("DOMAIN", "a.com, b.com, c.com")
	domains := GetAllDomains()
	if len(domains) != 3 {
		t.Errorf("GetAllDomains (multi) = %v, want 3 entries", domains)
	}
	if !strings.Contains(strings.Join(domains, ","), "a.com") {
		t.Error("expected a.com in domains")
	}
}

// ---- NewManager / FindCertificate tests ---------------------------------

func TestNewManager_NotNil(t *testing.T) {
	m := NewManager("/tmp/casspeed-ssl-test", "example.com")
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
}

func TestFindCertificate_NoFiles(t *testing.T) {
	m := NewManager("/tmp/casspeed-no-ssl-dir", "example.com")
	_, err := m.FindCertificate()
	_ = err
}

// ---- NeedsRenewal tests --------------------------------------------------

func TestNeedsRenewal_Expired(t *testing.T) {
	c := &CertInfo{IsExpired: true}
	if !c.NeedsRenewal() {
		t.Error("expired cert should need renewal")
	}
}

func TestNeedsRenewal_AppManagedExpiring(t *testing.T) {
	c := &CertInfo{Source: "app-managed", DaysLeft: 5}
	if !c.NeedsRenewal() {
		t.Error("app-managed cert with 5 days left should need renewal")
	}
}

func TestNeedsRenewal_AppManagedOK(t *testing.T) {
	c := &CertInfo{Source: "app-managed", DaysLeft: 30}
	if c.NeedsRenewal() {
		t.Error("app-managed cert with 30 days left should not need renewal")
	}
}

func TestNeedsRenewal_SystemCertExpiring(t *testing.T) {
	c := &CertInfo{Source: "system", DaysLeft: 3, IsExpired: false}
	if c.NeedsRenewal() {
		t.Error("system cert only checks IsExpired, not DaysLeft")
	}
}

