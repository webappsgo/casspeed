package server

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/casapps/casspeed/src/config"
	"golang.org/x/net/publicsuffix"
)

type trustedProxyContextKey struct{}
type originalPeerContextKey struct{}

type trustedProxyDNSResult struct {
	addresses []net.IP
	expiresAt time.Time
}

var trustedProxyDNSCache = struct {
	sync.RWMutex
	entries map[string]trustedProxyDNSResult
}{entries: make(map[string]trustedProxyDNSResult)}

func trustedProxyMiddleware(config config.TrustedProxyConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), trustedProxyContextKey{}, config)
			ctx = context.WithValue(ctx, originalPeerContextKey{}, r.RemoteAddr)
			r = r.WithContext(ctx)
			if !isOverlayRequest(r) && isTrustedProxy(r) {
				clientIP := resolveClientIP(r, config)
				if clientIP == "" {
					clientIP = peerIP(r.RemoteAddr)
				}
				if clientIP != "" {
					r.RemoteAddr = clientIP
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) learnProxyOrigins(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isTrustedProxy(r) && strings.TrimSpace(r.Header.Get("X-Forwarded-Host")) != "" {
			if host, port, ok := parseRequestHost(firstHeaderValue(r.Header.Get("X-Forwarded-Host"))); ok {
				domains := requestDomains()
				if len(domains) > 1 {
					next.ServeHTTP(w, r)
					return
				}
				if len(domains) == 1 {
					base := strings.TrimPrefix(domains[0], "*.")
					if host == base || !strings.HasSuffix(host, "."+base) {
						next.ServeHTTP(w, r)
						return
					}
				}
				resolved, err := url.Parse(BuildURL(r, "/"))
				if err == nil {
					if port != "" && !(port == "80" && resolved.Scheme == "http") && !(port == "443" && resolved.Scheme == "https") {
						host = net.JoinHostPort(host, port)
					} else if port == "" && strings.Contains(host, ":") && net.ParseIP(host) != nil {
						host = "[" + host + "]"
					}
					origin := resolved.Scheme + "://" + host
					s.originMutex.Lock()
					if s.learnedOrigins == nil {
						s.learnedOrigins = make(map[string]struct{})
					}
					s.learnedOrigins[origin] = struct{}{}
					s.originMutex.Unlock()
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) learnedOriginList() []string {
	s.originMutex.RLock()
	defer s.originMutex.RUnlock()
	origins := make([]string, 0, len(s.learnedOrigins))
	for origin := range s.learnedOrigins {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	return origins
}

// BuildURL resolves an absolute request URL using only validated host data and trusted proxy headers.
func BuildURL(r *http.Request, path string) string {
	overlay := isOverlayRequest(r)
	trusted := !overlay && isTrustedProxy(r)
	domains := requestDomains()
	hostValue := ""
	port := ""
	if overlay {
		if candidate, candidatePort, ok := parseRequestHost(r.Host); ok {
			hostValue, port = candidate, candidatePort
		}
	} else if trusted {
		for _, header := range []string{"X-Forwarded-Host", "X-Real-Host", "X-Original-Host"} {
			if candidate, candidatePort, ok := parseRequestHost(firstHeaderValue(r.Header.Get(header))); ok {
				hostValue, port = candidate, candidatePort
				break
			}
		}
	}
	if hostValue == "" {
		if candidate, candidatePort, ok := parseRequestHost(r.Host); ok && (len(domains) == 0 || domainAllowed(candidate, domains)) {
			hostValue, port = candidate, candidatePort
		}
	}
	if hostValue == "" {
		for _, domain := range domains {
			if candidate, _, ok := parseRequestHost(domain); ok {
				hostValue = candidate
				break
			}
		}
	}
	if hostValue == "" {
		for _, candidate := range []string{hostOnly(mustHostname()), hostOnly(os.Getenv("HOSTNAME"))} {
			if host, _, ok := parseRequestHost(candidate); ok {
				hostValue = host
				break
			}
		}
	}
	if hostValue == "" {
		hostValue = firstPublicIP()
	}
	if hostValue == "" {
		hostValue = "localhost"
	}

	scheme := "http"
	proxySchemeSet := overlay
	if trusted {
		for _, candidate := range []string{firstHeaderValue(r.Header.Get("X-Forwarded-Proto")), firstHeaderValue(r.Header.Get("X-Url-Scheme"))} {
			if strings.EqualFold(candidate, "http") || strings.EqualFold(candidate, "https") {
				scheme = strings.ToLower(candidate)
				proxySchemeSet = true
				break
			}
		}
		if !proxySchemeSet && strings.EqualFold(r.Header.Get("X-Forwarded-Ssl"), "on") {
			scheme = "https"
			proxySchemeSet = true
		}
	}
	if !proxySchemeSet {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if trusted {
		if forwardedPort := firstHeaderValue(r.Header.Get("X-Forwarded-Port")); validPort(forwardedPort) {
			port = forwardedPort
		}
	}
	if port == "80" && scheme == "http" || port == "443" && scheme == "https" {
		port = ""
	}
	if port != "" {
		hostValue = net.JoinHostPort(hostValue, port)
	} else if strings.Contains(hostValue, ":") && net.ParseIP(hostValue) != nil {
		hostValue = "[" + hostValue + "]"
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if trusted {
		prefix := firstHeaderValue(r.Header.Get("X-Forwarded-Prefix"))
		if prefix == "" {
			prefix = firstHeaderValue(r.Header.Get("X-Forwarded-Path"))
		}
		if prefix == "" {
			prefix = firstHeaderValue(r.Header.Get("X-Script-Name"))
		}
		if validBasePath(prefix) && prefix != "/" {
			path = strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(path, "/")
		}
	}
	return (&url.URL{Scheme: scheme, Host: hostValue, Path: path}).String()
}

func firstPublicIP() string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, family := range []int{6, 4} {
		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip != nil && (family == 6 && ip.To4() == nil || family == 4 && ip.To4() != nil) && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip.String()
			}
		}
	}
	return ""
}

func buildRequestURL(r *http.Request, path string) string {
	return BuildURL(r, path)
}

func isTrustedProxy(r *http.Request) bool {
	if isOverlayRequest(r) {
		return false
	}
	remoteAddr, ok := r.Context().Value(originalPeerContextKey{}).(string)
	if !ok || remoteAddr == "" {
		remoteAddr = r.RemoteAddr
	}
	return isTrustedPeerAddress(remoteAddr, trustedProxyConfig(r))
}

func trustedProxyConfig(r *http.Request) config.TrustedProxyConfig {
	proxyConfig, _ := r.Context().Value(trustedProxyContextKey{}).(config.TrustedProxyConfig)
	return proxyConfig
}

func isTrustedPeerAddress(remoteAddr string, proxyConfig config.TrustedProxyConfig) bool {
	remoteHost, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteHost = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(remoteHost, "[]"))
	if ip == nil {
		return false
	}
	return isTrustedIP(ip, proxyConfig)
}

func isTrustedIP(ip net.IP, proxyConfig config.TrustedProxyConfig) bool {
	if listenerIP := net.ParseIP(strings.Trim(proxyConfig.ListenAddress, "[]")); listenerIP != nil && listenerIP.To4() != nil {
		_, listenerSubnet, _ := net.ParseCIDR(listenerIP.String() + "/24")
		if listenerSubnet != nil && listenerSubnet.Contains(ip) {
			return true
		}
	}
	for _, cidr := range trustedPrivateNetworks {
		if cidr.Contains(ip) {
			return true
		}
	}
	for _, entry := range proxyConfig.Additional {
		entry = strings.TrimSpace(entry)
		if parsed := net.ParseIP(entry); parsed != nil && parsed.Equal(ip) {
			return true
		}
		if _, network, parseErr := net.ParseCIDR(entry); parseErr == nil && network.Contains(ip) {
			return true
		}
		if validHostname(strings.ToLower(strings.TrimSuffix(entry, "."))) && trustedProxyDNSContains(entry, ip) {
			return true
		}
	}
	return false
}

func trustedProxyDNSContains(hostname string, ip net.IP) bool {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	now := time.Now()
	trustedProxyDNSCache.RLock()
	cached, found := trustedProxyDNSCache.entries[hostname]
	trustedProxyDNSCache.RUnlock()
	if !found || !now.Before(cached.expiresAt) {
		cached = resolveTrustedProxyDNS(hostname, now)
	}
	for _, address := range cached.addresses {
		if address.Equal(ip) {
			return true
		}
	}
	return false
}

func refreshTrustedProxyDNS(proxyConfig config.TrustedProxyConfig) {
	for _, entry := range proxyConfig.Additional {
		entry = strings.TrimSpace(entry)
		if net.ParseIP(entry) == nil {
			if _, _, err := net.ParseCIDR(entry); err != nil && validHostname(strings.ToLower(strings.TrimSuffix(entry, "."))) {
				resolveTrustedProxyDNS(entry, time.Now())
			}
		}
	}
}

func resolveTrustedProxyDNS(hostname string, now time.Time) trustedProxyDNSResult {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	cancel()
	if err != nil {
		addresses = nil
	}
	result := trustedProxyDNSResult{addresses: addresses, expiresAt: now.Add(5 * time.Minute)}
	trustedProxyDNSCache.Lock()
	trustedProxyDNSCache.entries[hostname] = result
	trustedProxyDNSCache.Unlock()
	return result
}

func resolveClientIP(r *http.Request, proxyConfig config.TrustedProxyConfig) string {
	header := strings.TrimSpace(proxyConfig.ClientIPHeader)
	if header == "" || strings.EqualFold(header, "auto") {
		for _, name := range []string{"X-Forwarded-For", "Forwarded", "CF-Connecting-IP", "True-Client-IP", "X-Real-IP", "X-Client-IP"} {
			if ip := clientIPFromHeader(r.Header.Get(name), name, proxyConfig); ip != "" {
				return ip
			}
		}
		return peerIP(r.RemoteAddr)
	}
	return clientIPFromHeader(r.Header.Get(header), header, proxyConfig)
}

func clientIPFromHeader(value, header string, proxyConfig config.TrustedProxyConfig) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	if strings.EqualFold(header, "Forwarded") {
		parts = nil
		for _, item := range strings.Split(value, ",") {
			for _, pair := range strings.Split(item, ";") {
				key, raw, found := strings.Cut(strings.TrimSpace(pair), "=")
				if found && strings.EqualFold(key, "for") {
					parts = append(parts, strings.Trim(raw, "\""))
				}
			}
		}
	}
	for index := len(parts) - 1; index >= 0; index-- {
		ip := parseForwardedIP(parts[index])
		if ip == nil {
			continue
		}
		if !isTrustedIP(ip, proxyConfig) {
			return ip.String()
		}
	}
	if len(parts) > 0 {
		if ip := parseForwardedIP(parts[0]); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func parseForwardedIP(value string) net.IP {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return net.ParseIP(strings.Trim(host, "[]"))
	}
	return nil
}

func peerIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String()
	}
	return ""
}

var trustedPrivateNetworks = func() []*net.IPNet {
	entries := []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"}
	networks := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		_, network, _ := net.ParseCIDR(entry)
		networks = append(networks, network)
	}
	return networks
}()

func requestDomains() []string {
	var domains []string
	for _, entry := range strings.Split(os.Getenv("DOMAIN"), ",") {
		entry = strings.TrimSpace(entry)
		if strings.HasPrefix(entry, "*.") && validHostname(strings.TrimPrefix(entry, "*.")) {
			domains = append(domains, strings.ToLower(entry))
			continue
		}
		if host, _, ok := parseRequestHost(entry); ok {
			domains = append(domains, host)
		}
	}
	if len(domains) >= 2 {
		base := ""
		sameBase := true
		for _, domain := range domains {
			if strings.HasPrefix(domain, "*.") || net.ParseIP(domain) != nil {
				sameBase = false
				break
			}
			root, err := publicsuffix.EffectiveTLDPlusOne(domain)
			if err != nil {
				sameBase = false
				break
			}
			if base == "" {
				base = root
			} else if !strings.EqualFold(base, root) {
				sameBase = false
				break
			}
		}
		wildcard := "*." + base
		if sameBase && base != "" && !containsString(domains, wildcard) {
			domains = append(domains, wildcard)
		}
	}
	return domains
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func domainAllowed(host string, domains []string) bool {
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			if strings.HasSuffix(host, strings.TrimPrefix(domain, "*")) {
				return true
			}
		} else if strings.EqualFold(host, domain) {
			return true
		}
	}
	return false
}

func parseRequestHost(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n/\\@ \t") {
		return "", "", false
	}
	parsed, err := url.Parse("//" + value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if !validHostname(host) {
		return "", "", false
	}
	port := parsed.Port()
	if port != "" && !validPort(port) {
		return "", "", false
	}
	return host, port, true
}

func validHostname(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port > 0 && port <= 65535
}

func validBasePath(value string) bool {
	if value == "" {
		return true
	}
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#\\\r\n") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." || segment == "." {
			return false
		}
	}
	return true
}

func firstHeaderValue(value string) string {
	value, _, _ = strings.Cut(value, ",")
	return strings.TrimSpace(value)
}

func hostOnly(value string) string {
	if host, _, ok := parseRequestHost(value); ok {
		return host
	}
	return ""
}

func mustHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}
