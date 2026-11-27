package server

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/i2p"
)

func (s *Server) handleI2PAdminAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.configMu.RLock()
		configured := s.Config.Server.I2P
		s.configMu.RUnlock()
		state := s.currentI2PState()
		var uptime int64
		if !state.StartedAt.IsZero() && state.Status == "running" {
			uptime = int64(time.Since(state.StartedAt).Seconds())
		}
		data := map[string]any{
			"status": map[string]any{
				"state": state.Status, "provider": state.Provider,
				"binary_path": state.BinaryPath, "sam_address": state.SAMAddress,
				"eepsite_address": state.EepsiteAddress, "uptime_seconds": uptime,
			},
			"config": configured,
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": data})
	case http.MethodPatch:
		var candidate config.I2PConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&candidate); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusBadRequest)})
			return
		}
		if err := s.validateI2PAdminConfig(candidate); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusBadRequest)})
			return
		}
		if err := s.updateI2PAdminConfig(candidate); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusInternalServerError)})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": candidate})
	default:
		w.Header().Set("Allow", "GET, PATCH")
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusMethodNotAllowed)})
	}
}

func (s *Server) handleI2PAdminValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusMethodNotAllowed)})
		return
	}
	var candidate config.I2PConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&candidate); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusBadRequest)})
		return
	}
	if err := s.validateI2PAdminConfig(candidate); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusBadRequest)})
		return
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "valid": true})
}

func (s *Server) handleI2PAdminAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusMethodNotAllowed)})
		return
	}
	s.overlayMu.RLock()
	manager := s.i2pManager
	s.overlayMu.RUnlock()
	if manager == nil {
		writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusServiceUnavailable)})
		return
	}
	switch r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:] {
	case "restart":
		s.configMu.RLock()
		configured := s.Config.Server.I2P
		s.configMu.RUnlock()
		if err := manager.UpdateConfig(s.i2pRuntimeConfig(filepath.Dir(s.ConfigPath), s.DataDir, s.LogDir, configured)); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusBadRequest)})
			return
		}
		writeUserJSON(w, http.StatusAccepted, map[string]any{"ok": true, "state": "starting"})
	case "regenerate":
		ctx, cancel := context.WithTimeout(r.Context(), 11*time.Minute)
		defer cancel()
		address, err := manager.RegenerateAddress(ctx)
		if err != nil {
			writeUserJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusBadGateway)})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "eepsite_address": address})
	default:
		writeUserJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": overlayAdminHTTPError(r, http.StatusNotFound)})
	}
}

func (s *Server) validateI2PAdminConfig(candidate config.I2PConfig) error {
	managerConfig := s.i2pRuntimeConfig(filepath.Dir(s.ConfigPath), s.DataDir, s.LogDir, candidate)
	return i2p.ValidateConfig(managerConfig)
}

func (s *Server) updateI2PAdminConfig(candidate config.I2PConfig) error {
	s.configMu.Lock()
	previous := s.Config.Server.I2P
	s.Config.Server.I2P = candidate
	if err := config.Save(s.Config, s.ConfigPath); err != nil {
		s.Config.Server.I2P = previous
		s.configMu.Unlock()
		return err
	}
	s.configMu.Unlock()

	s.overlayMu.RLock()
	manager := s.i2pManager
	s.overlayMu.RUnlock()
	if manager == nil {
		return nil
	}
	if err := manager.UpdateConfig(s.i2pRuntimeConfig(filepath.Dir(s.ConfigPath), s.DataDir, s.LogDir, candidate)); err != nil {
		s.configMu.Lock()
		s.Config.Server.I2P = previous
		_ = config.Save(s.Config, s.ConfigPath)
		s.configMu.Unlock()
		return err
	}
	return nil
}
