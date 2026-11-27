package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const maxTorKeyFileSize = 4096

func (s *Server) handleTorVanityAPI(w http.ResponseWriter, r *http.Request) {
	s.overlayMu.RLock()
	vanity := s.torVanity
	s.overlayMu.RUnlock()
	if vanity == nil {
		writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Tor vanity manager is unavailable"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": vanity.Status()})
	case http.MethodPost:
		var input struct {
			Prefix  string `json:"prefix"`
			Workers int    `json:"workers"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid request"})
			return
		}
		if err := vanity.Start(context.Background(), input.Prefix, input.Workers); err != nil {
			status := http.StatusUnprocessableEntity
			if strings.Contains(err.Error(), "already running") || strings.Contains(err.Error(), "still stopping") {
				status = http.StatusConflict
			}
			writeUserJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeUserJSON(w, http.StatusAccepted, map[string]any{"ok": true, "data": vanity.Status()})
	case http.MethodDelete:
		if !vanity.Cancel() {
			writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "No Tor vanity search is running"})
			return
		}
		writeUserJSON(w, http.StatusAccepted, map[string]any{"ok": true, "state": "stopping"})
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "Method not allowed"})
	}
}

func (s *Server) handleTorVanityApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "Method not allowed"})
		return
	}
	var input struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid request"})
		return
	}
	s.overlayMu.RLock()
	vanity, manager := s.torVanity, s.torManager
	s.overlayMu.RUnlock()
	if vanity == nil || manager == nil {
		writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Tor manager is unavailable"})
		return
	}
	go func() {
		if err := manager.ApplyVanityCandidate(vanity, input.Address); err != nil && s.Logger != nil && s.Logger.Error != nil {
			s.Logger.Error.Printf("Tor vanity candidate apply failed: %v", err)
		}
	}()
	writeUserJSON(w, http.StatusAccepted, map[string]any{"ok": true, "state": "applying", "hostname": input.Address})
}

func (s *Server) handleTorVanityImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "Method not allowed"})
		return
	}
	browserRequest := strings.HasPrefix(r.URL.Path, "/server/")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if browserRequest && (!sameOriginPageRequest(r) || !validPreferenceCSRF(r)) {
		http.Error(w, "Tor key import failed security validation", http.StatusForbidden)
		return
	}
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid key upload"})
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	s.overlayMu.RLock()
	vanity := s.torVanity
	s.overlayMu.RUnlock()
	if vanity == nil {
		writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Tor vanity manager is unavailable"})
		return
	}
	root := filepath.Join(s.DataDir, "tor", "vanity")
	if err := os.MkdirAll(root, 0700); err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to prepare private import storage"})
		return
	}
	if err := os.Chmod(root, 0700); err != nil {
		writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Unable to secure private import storage"})
		return
	}
	files, err := readTorKeyUpload(r)
	if err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid Tor key files"})
		return
	}
	imported, err := vanity.ImportKeyFiles(files["hs_ed25519_secret_key"], files["hs_ed25519_public_key"], files["hostname"])
	if err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Tor key files do not form a valid hidden-service identity"})
		return
	}
	if browserRequest {
		s.configMu.RLock()
		adminPath := s.Config.Server.AdminPath
		s.configMu.RUnlock()
		if strings.Trim(adminPath, "/") == "" {
			adminPath = "administration"
		}
		http.Redirect(w, r, "/server/"+adminPath+"/network/tor", http.StatusSeeOther)
		return
	}
	writeUserJSON(w, http.StatusCreated, map[string]any{"ok": true, "hostname": imported})
}

func readTorKeyUpload(r *http.Request) (map[string][]byte, error) {
	files := make(map[string][]byte, 3)
	if archives := r.MultipartForm.File["archive"]; len(archives) > 0 {
		if len(archives) != 1 {
			return nil, errors.New("one archive is allowed")
		}
		archive, err := archives[0].Open()
		if err != nil {
			return nil, err
		}
		defer archive.Close()
		contents, err := io.ReadAll(io.LimitReader(archive, (1<<20)+1))
		if err != nil || len(contents) > 1<<20 {
			return nil, errors.New("archive too large")
		}
		reader, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
		if err != nil {
			return nil, err
		}
		for _, entry := range reader.File {
			name := filepath.Base(filepath.ToSlash(entry.Name))
			if name != "hostname" && name != "hs_ed25519_secret_key" && name != "hs_ed25519_public_key" {
				continue
			}
			if entry.FileInfo().IsDir() || entry.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("invalid archive member")
			}
			if _, exists := files[name]; exists {
				return nil, errors.New("duplicate key file")
			}
			opened, err := entry.Open()
			if err != nil {
				return nil, err
			}
			value, readErr := io.ReadAll(io.LimitReader(opened, maxTorKeyFileSize+1))
			closeErr := opened.Close()
			if readErr != nil || closeErr != nil || len(value) > maxTorKeyFileSize {
				return nil, errors.New("invalid archive member size")
			}
			files[name] = value
		}
	} else {
		for _, name := range []string{"hostname", "hs_ed25519_secret_key", "hs_ed25519_public_key"} {
			headers := r.MultipartForm.File[name]
			if len(headers) != 1 {
				continue
			}
			file, err := headers[0].Open()
			if err != nil {
				return nil, err
			}
			value, readErr := io.ReadAll(io.LimitReader(file, maxTorKeyFileSize+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || len(value) > maxTorKeyFileSize {
				return nil, errors.New("invalid uploaded key size")
			}
			files[name] = value
		}
	}
	if len(files["hs_ed25519_secret_key"]) == 0 {
		return nil, errors.New("missing hs_ed25519_secret_key")
	}
	return files, nil
}
