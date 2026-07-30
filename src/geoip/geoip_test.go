package geoip

import (
	"testing"
)

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
