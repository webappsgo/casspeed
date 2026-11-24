package geoip

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceInitializeAndLookup(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "geoip.json")
	want := &Location{IP: "8.8.8.8", CountryCode: "US", CountryName: "United States"}
	data, err := json.Marshal([]*Location{want})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	svc := &Service{db: make(map[string]*Location)}
	if err := svc.Initialize(&Config{Enabled: true, DBPath: dbPath}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if !svc.IsEnabled() {
		t.Fatal("initialized service should be enabled")
	}
	got, err := svc.Lookup("8.8.8.8")
	if err != nil {
		t.Fatalf("Lookup known IP: %v", err)
	}
	if got.CountryCode != want.CountryCode || got.CountryName != want.CountryName {
		t.Errorf("Lookup known IP = %#v, want %#v", got, want)
	}

	unknown, err := svc.Lookup("1.1.1.1")
	if err != nil {
		t.Fatalf("Lookup unknown public IP: %v", err)
	}
	if unknown.CountryCode != "XX" || unknown.CountryName != "Unknown" {
		t.Errorf("unknown lookup = %#v, want unknown location", unknown)
	}
}

func TestServiceLookupRejectsDisabledAndInvalidAddresses(t *testing.T) {
	svc := &Service{db: make(map[string]*Location)}
	if _, err := svc.Lookup("8.8.8.8"); err == nil {
		t.Fatal("Lookup on a disabled service should fail")
	}
	if err := svc.Initialize(&Config{Enabled: true, DBPath: filepath.Join(t.TempDir(), "missing.json")}); err != nil {
		t.Fatalf("Initialize with missing database: %v", err)
	}
	if _, err := svc.Lookup("not-an-ip"); err == nil {
		t.Fatal("Lookup should reject malformed IP addresses")
	}
}

func TestServiceInitializeRejectsMalformedDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "geoip.json")
	if err := os.WriteFile(dbPath, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{}).Initialize(&Config{Enabled: true, DBPath: dbPath}); err == nil {
		t.Fatal("Initialize should report malformed database data")
	}
}

func TestServiceUpdateDatabase(t *testing.T) {
	location := &Location{IP: "9.9.9.9", CountryCode: "GB", CountryName: "United Kingdom"}
	body, err := json.Marshal([]*Location{location})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("request method = %s, want GET", r.Method)
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	dbPath := filepath.Join(t.TempDir(), "geoip.json")
	svc := &Service{db: make(map[string]*Location)}
	if err := svc.Initialize(&Config{Enabled: true, DBPath: dbPath, UpdateURL: server.URL}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if err := svc.UpdateDatabase(); err != nil {
		t.Fatalf("UpdateDatabase: %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("updated database was not installed: %v", err)
	}
	got, err := svc.Lookup(location.IP)
	if err != nil {
		t.Fatalf("Lookup updated address: %v", err)
	}
	if got.CountryCode != location.CountryCode {
		t.Errorf("updated country code = %q, want %q", got.CountryCode, location.CountryCode)
	}
}

func TestServiceUpdateDatabaseRejectsHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	svc := &Service{db: make(map[string]*Location)}
	if err := svc.Initialize(&Config{Enabled: true, DBPath: filepath.Join(t.TempDir(), "geoip.json"), UpdateURL: server.URL}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if err := svc.UpdateDatabase(); err == nil {
		t.Fatal("UpdateDatabase should report a non-200 response")
	}
}

// ---- GetCountryName tests ------------------------------------------------

func TestGetCountryName_KnownCodes(t *testing.T) {
	cases := []struct {
		code string
		want string
	}{
		{"US", "United States"},
		{"GB", "United Kingdom"},
		{"CA", "Canada"},
		{"AU", "Australia"},
		{"DE", "Germany"},
		{"FR", "France"},
		{"JP", "Japan"},
		{"CN", "China"},
		{"IN", "India"},
		{"BR", "Brazil"},
		{"XX", "Unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			got := GetCountryName(tc.code)
			if got != tc.want {
				t.Errorf("GetCountryName(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}

func TestGetCountryName_LowercaseNormalized(t *testing.T) {
	// Function should uppercase the code before lookup.
	got := GetCountryName("us")
	if got != "United States" {
		t.Errorf("GetCountryName(us) = %q, want 'United States'", got)
	}
}

func TestGetCountryName_UnknownCodePassthrough(t *testing.T) {
	// Unknown codes are returned as-is.
	got := GetCountryName("ZZ")
	if got != "ZZ" {
		t.Errorf("GetCountryName(ZZ) = %q, want 'ZZ' (passthrough)", got)
	}
}

func TestGetCountryName_Empty(t *testing.T) {
	got := GetCountryName("")
	if got != "" {
		t.Errorf("GetCountryName('') = %q, want empty", got)
	}
}

// ---- IsPrivateIP tests ---------------------------------------------------

func TestIsPrivateIP_PrivateRanges(t *testing.T) {
	privateIPs := []string{
		"10.0.0.1",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.0.1",
		"192.168.255.255",
		"127.0.0.1",
		"127.0.0.254",
		"169.254.0.1",
		"::1",
	}
	for _, ip := range privateIPs {
		t.Run(ip, func(t *testing.T) {
			if !IsPrivateIP(ip) {
				t.Errorf("IsPrivateIP(%q) = false, want true", ip)
			}
		})
	}
}

func TestIsPrivateIP_PublicRanges(t *testing.T) {
	publicIPs := []string{
		"8.8.8.8",
		"1.1.1.1",
		"203.0.113.1",
		"93.184.216.34",
		"2001:db8::1",
	}
	for _, ip := range publicIPs {
		t.Run(ip, func(t *testing.T) {
			if IsPrivateIP(ip) {
				t.Errorf("IsPrivateIP(%q) = true, want false", ip)
			}
		})
	}
}

func TestIsPrivateIP_InvalidIP(t *testing.T) {
	if IsPrivateIP("not-an-ip") {
		t.Error("invalid IP should return false")
	}
	if IsPrivateIP("") {
		t.Error("empty string should return false")
	}
	if IsPrivateIP("256.0.0.1") {
		t.Error("out-of-range IP should return false")
	}
}
