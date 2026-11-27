package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
)

var cliBinaryFilenamePattern = regexp.MustCompile(`^casspeed-cli-(linux|darwin|windows|freebsd)-(amd64|arm64)(\.exe)?$`)

func (s *Server) cliBinaryDirectory() string {
	if s.Config != nil && strings.TrimSpace(s.Config.CLI.BinaryDownload.Dir) != "" {
		return s.Config.CLI.BinaryDownload.Dir
	}
	return filepath.Join(s.DataDir, "cli")
}

func (s *Server) handleCLIBinaryDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filename := chi.URLParam(r, "filename")
	match := cliBinaryFilenamePattern.FindStringSubmatch(filename)
	if match == nil {
		http.NotFound(w, r)
		return
	}
	if s.Config.CLI.BinaryDownload.RequireAuth {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			s.cliDownloadAuthFailure(r, "")
			s.writeBearerError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		value := strings.TrimPrefix(header, "Bearer ")
		if _, _, valid := s.validateBearerToken(r.Context(), value); !valid {
			s.cliDownloadAuthFailure(r, value)
			s.writeBearerError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
	}
	directory := s.cliBinaryDirectory()
	catalog := s.readBinaryVersionCatalog(directory, "casspeed-cli-")
	platform := match[1] + "-" + match[2]
	if _, ok := catalog[platform]; !ok {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(directory, filename)
	file, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if s.Logger != nil && s.Logger.Audit != nil {
		entry, _ := json.Marshal(map[string]string{
			"event": "cli.update_started", "platform": platform, "version": catalog[platform]["version"],
			"client_ip": resolveClientIP(r, trustedProxyConfig(r)),
		})
		s.Logger.Audit.Printf("%s\n", entry)
	}
	http.ServeContent(w, r, filename, info.ModTime(), file)
}

func (s *Server) cliDownloadAuthFailure(r *http.Request, token string) {
	if !strings.Contains(strings.ToLower(r.UserAgent()), "casspeed-cli/") || s.Logger == nil || s.Logger.Audit == nil {
		return
	}
	prefix := "unknown"
	if len(token) >= 4 {
		prefix = token[:4]
	}
	entry, _ := json.Marshal(map[string]string{"event": "cli.token_revoked_detected", "token_prefix": prefix})
	s.Logger.Audit.Printf("%s\n", entry)
}
