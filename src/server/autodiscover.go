package server

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func (s *Server) handleAPIAutodiscover(w http.ResponseWriter, r *http.Request) {
	version := "v1"
	if s.Config != nil && strings.TrimSpace(s.Config.Server.APIVersion) != "" {
		version = strings.TrimSpace(s.Config.Server.APIVersion)
	}
	cliMinVersion, agentMinVersion := "", ""
	cliDirectory := filepath.Join(s.DataDir, "cli")
	if s.Config != nil {
		cliMinVersion = s.Config.Server.Update.CLIMinVersion
		agentMinVersion = s.Config.Server.Update.AgentMinVersion
		if strings.TrimSpace(s.Config.CLI.BinaryDownload.Dir) != "" {
			cliDirectory = s.Config.CLI.BinaryDownload.Dir
		}
	}
	data := map[string]any{
		"name":              "CasSpeed",
		"version":           s.version,
		"api":               map[string]string{"current_version": version},
		"urls":              s.autodiscoverURLs(r),
		"cli_versions":      s.readBinaryVersionCatalog(cliDirectory, "casspeed-cli-"),
		"cli_min_version":   cliMinVersion,
		"agent_versions":    s.readBinaryVersionCatalog(filepath.Join(s.DataDir, "agent"), "casspeed-agent-"),
		"agent_min_version": agentMinVersion,
	}
	if address := s.exposedI2PAddress(); address != "" {
		data["i2p"] = address
	}
	if s.Config != nil && s.Config.Server.Tor.Expose {
		if state := s.currentTorState(); state.Running && state.Hostname != "" {
			data["tor"] = state.Hostname
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": data})
}

func (s *Server) readBinaryVersionCatalog(directory, prefix string) map[string]map[string]string {
	catalog := make(map[string]map[string]string)
	if strings.TrimSpace(directory) == "" {
		return catalog
	}
	versionBytes, err := os.ReadFile(filepath.Join(directory, "version.txt"))
	if err != nil {
		return catalog
	}
	version := strings.TrimSpace(string(versionBytes))
	if version == "" {
		return catalog
	}
	checksumFile, err := os.Open(filepath.Join(directory, "sha256.txt"))
	if err != nil {
		return catalog
	}
	defer checksumFile.Close()
	checksums := make(map[string]string)
	scanner := bufio.NewScanner(checksumFile)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		filename := filepath.Base(fields[len(fields)-1])
		if decoded, err := hex.DecodeString(fields[0]); err == nil && len(decoded) == sha256.Size {
			checksums[filename] = strings.ToLower(fields[0])
		}
	}
	if scanner.Err() != nil {
		return catalog
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return catalog
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		filename := entry.Name()
		platform := strings.TrimPrefix(strings.TrimSuffix(filename, ".exe"), prefix)
		if strings.Count(platform, "-") != 1 || platform == "" {
			continue
		}
		expected := checksums[filename]
		if expected == "" {
			s.warnInvalidBinaryCatalogFile(filename, "missing SHA-256 entry")
			continue
		}
		file, err := os.Open(filepath.Join(directory, filename))
		if err != nil {
			s.warnInvalidBinaryCatalogFile(filename, "cannot read binary")
			continue
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != expected {
			s.warnInvalidBinaryCatalogFile(filename, "SHA-256 mismatch")
			continue
		}
		catalog[platform] = map[string]string{"version": version, "sha256": expected}
	}
	return catalog
}

func (s *Server) warnInvalidBinaryCatalogFile(filename, reason string) {
	if s.Logger != nil && s.Logger.Error != nil {
		s.Logger.Error.Printf("WARN: autodiscover skipped %s: %s\n", filename, reason)
	}
}

func (s *Server) autodiscoverURLs(r *http.Request) []string {
	urls := make([]string, 0)
	seen := make(map[string]struct{})
	add := func(value string) {
		origin, ok := publicOrigin(value)
		if !ok {
			return
		}
		if _, exists := seen[origin]; exists {
			return
		}
		seen[origin] = struct{}{}
		urls = append(urls, origin)
	}
	add(BuildURL(r, "/"))
	if overlayRequestKind(r) == "tor" {
		return urls
	}
	for _, entry := range strings.Split(os.Getenv("DOMAIN"), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "*.") {
			continue
		}
		if !strings.Contains(entry, "://") {
			entry = "https://" + entry
		}
		add(entry)
	}
	for _, origin := range s.learnedOriginList() {
		add(origin)
	}
	return urls
}

func publicOrigin(value string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	if parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
		return "", false
	}
	port := parsed.Port()
	if port != "" && (parsed.Scheme == "https" && port == "443" || parsed.Scheme == "http" && port == "80") {
		parsed.Host = host
	} else if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]"
	} else {
		parsed.Host = host
	}
	return parsed.Scheme + "://" + parsed.Host, true
}
