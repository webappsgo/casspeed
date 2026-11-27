package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

const researcherKeyLimit = 64 * 1024

var researcherKeyBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("64:ff9b::/96"),
}

// EncryptResearcherAcknowledgment encrypts an acknowledgment to the supplied key without exposing report content.
func EncryptResearcherAcknowledgment(ctx context.Context, supplied string, plaintext []byte) ([]byte, error) {
	key := []byte(strings.TrimSpace(supplied))
	if strings.HasPrefix(strings.ToLower(string(key)), "https://") {
		var err error
		key, err = fetchResearcherPublicKey(ctx, string(key))
		if err != nil {
			return nil, err
		}
	}
	ciphertext, err := EncryptToPublicKey(key, plaintext)
	if err != nil {
		return nil, errors.New("researcher OpenPGP key cannot encrypt messages")
	}
	var armored bytes.Buffer
	writer, err := armor.Encode(&armored, "PGP MESSAGE", nil)
	if err != nil {
		return nil, errors.New("unable to armor encrypted acknowledgment")
	}
	if _, err := writer.Write(ciphertext); err != nil {
		_ = writer.Close()
		return nil, errors.New("unable to armor encrypted acknowledgment")
	}
	if err := writer.Close(); err != nil {
		return nil, errors.New("unable to finish encrypted acknowledgment")
	}
	return armored.Bytes(), nil
}

func fetchResearcherPublicKey(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("researcher key URL must be HTTPS")
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	if port != "443" {
		return nil, errors.New("researcher key URL uses an unsupported port")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("researcher key host could not be resolved")
	}
	publicIPs := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		ip, ok := netip.AddrFromSlice(address.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if publicResearcherKeyIP(ip) {
			publicIPs = append(publicIPs, ip)
		}
	}
	if len(publicIPs) == 0 {
		return nil, errors.New("researcher key host did not resolve to a public address")
	}
	transport := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host},
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			var lastErr error
			for _, ip := range publicIPs {
				connection, dialErr := dialer.DialContext(dialCtx, network, net.JoinHostPort(ip.String(), strconv.Itoa(443)))
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, errors.New("unable to request researcher key")
	}
	request.Header.Set("Accept", "application/pgp-keys, text/plain;q=0.9")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("unable to retrieve researcher key")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("researcher key server returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, researcherKeyLimit+1))
	if err != nil || len(body) > researcherKeyLimit {
		return nil, errors.New("researcher key response is invalid or too large")
	}
	if !bytes.Contains(body, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		return nil, errors.New("researcher key response is not an armored public key")
	}
	if _, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(body)); err != nil {
		return nil, errors.New("researcher key response is invalid")
	}
	return body, nil
}

func publicResearcherKeyIP(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, blocked := range researcherKeyBlockedPrefixes {
		if blocked.Contains(ip) {
			return false
		}
	}
	return true
}
