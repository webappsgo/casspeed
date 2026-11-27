package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/tor"
)

type torCircuitContextKey struct{}

func (s *Server) startTorManager(configDir, dataDir, logDir string, configured config.TorConfig) error {
	adminPath := configuredAdminPath(s.Config)
	s.Router.Post("/server/"+adminPath+"/network/tor/vanity", s.AdminHandler.RequireAuth(s.handleTorVanityPageAction))
	s.Router.Post("/server/"+adminPath+"/network/tor/import", s.AdminHandler.RequireAuth(s.handleTorVanityImport))
	basePath := "/api/v1/server/" + adminPath + "/network/tor"
	s.Router.Get(basePath, s.requireOperatorAPI(s.handleTorAdminAPI))
	s.Router.Patch(basePath, s.requireOperatorAPI(s.handleTorAdminAPI))
	s.Router.Post(basePath+"/validate", s.requireOperatorAPI(s.handleTorAdminValidate))
	s.Router.Post(basePath+"/regenerate", s.requireOperatorAPI(s.handleTorAdminAction))
	s.Router.Post(basePath+"/restart", s.requireOperatorAPI(s.handleTorAdminAction))
	vanityPath := basePath + "/vanity"
	s.Router.Get(vanityPath, s.requireOperatorAPI(s.handleTorVanityAPI))
	s.Router.Post(vanityPath, s.requireOperatorAPI(s.handleTorVanityAPI))
	s.Router.Delete(vanityPath, s.requireOperatorAPI(s.handleTorVanityAPI))
	s.Router.Post(vanityPath+"/apply", s.requireOperatorAPI(s.handleTorVanityApply))
	s.Router.Post(basePath+"/import", s.requireOperatorAPI(s.handleTorVanityImport))
	runtimeConfig := s.torRuntimeConfig(configDir, dataDir, logDir, configured)
	manager := tor.NewManager(context.Background(), runtimeConfig, func(state tor.State) {
		s.overlayMu.Lock()
		s.torState = state
		startBackend := state.Running && s.torHTTP == nil
		manager := s.torManager
		s.overlayMu.Unlock()
		if startBackend && manager != nil {
			listener := manager.Listener()
			if listener != nil {
				_ = s.serveTorBackend(listener)
			}
		}
	})
	s.overlayMu.Lock()
	s.torManager = manager
	s.torVanity = tor.NewVanityManager(dataDir)
	s.torState = manager.State()
	s.overlayMu.Unlock()
	if s.ContactHandler != nil {
		s.ContactHandler.SetCaptchaHTTPClient(manager.GetHTTPClient(configured.UseNetwork))
	}
	return manager.Start()
}

func (s *Server) serveTorBackend(listener net.Listener) error {
	if listener == nil {
		return errors.New("tor backend listener is nil")
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.overlayMu.RLock()
			manager := s.torManager
			s.overlayMu.RUnlock()
			if manager == nil || !sameOverlayHost(r.Host, manager.OnionAddress()) {
				http.Error(w, "Misdirected request", http.StatusMisdirectedRequest)
				return
			}
			ctx := context.WithValue(r.Context(), overlayRequestKey{}, "tor")
			circuitID := torCircuitIDFromRequest(r)
			if circuitID == "" {
				r.RemoteAddr = "tor"
			} else {
				r.RemoteAddr = "tor:" + circuitID
			}
			s.Router.ServeHTTP(w, r.WithContext(ctx))
		}),
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if circuit := tor.CircuitIDFromConn(conn); circuit != "" {
				return context.WithValue(ctx, torCircuitContextKey{}, circuit)
			}
			return ctx
		},
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	s.overlayMu.Lock()
	s.torHTTP = server
	s.overlayMu.Unlock()
	go func() {
		err := server.Serve(listener)
		s.overlayMu.Lock()
		if s.torHTTP == server {
			s.torHTTP = nil
		}
		s.overlayMu.Unlock()
		if err != nil && !errors.Is(err, http.ErrServerClosed) && s.Logger != nil && s.Logger.Error != nil {
			s.Logger.Error.Printf("Tor backend listener stopped: %v", err)
		}
	}()
	return nil
}

func (s *Server) currentTorState() tor.State {
	s.overlayMu.RLock()
	manager, state := s.torManager, s.torState
	s.overlayMu.RUnlock()
	if manager != nil {
		state = manager.State()
	}
	return state
}

func (s *Server) torHealth() healthTor {
	state := s.currentTorState()
	s.configMu.RLock()
	expose := s.Config != nil && s.Config.Server.Tor.Expose
	s.configMu.RUnlock()
	hostname := ""
	if expose {
		hostname = state.Hostname
	}
	return healthTor{Enabled: state.Enabled, Running: state.Running, Status: state.Status, Hostname: hostname}
}

func (s *Server) handleTorAdminAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		state := s.currentTorState()
		uptime := int64(0)
		if !state.StartedAt.IsZero() && state.Running {
			uptime = int64(time.Since(state.StartedAt).Seconds())
		}
		s.configMu.RLock()
		configured := s.Config.Server.Tor
		s.configMu.RUnlock()
		w.Header().Set("Cache-Control", "no-store")
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"status": map[string]any{"state": state.Status, "running": state.Running, "binary_path": state.Binary, "version": state.Version, "circuits_active": state.CircuitsActive, "hostname": state.Hostname, "uptime_seconds": uptime}, "config": configured}})
	case http.MethodPatch:
		var candidate config.TorConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&candidate); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": overlayAdminText(r, "tor.error_config", nil)})
			return
		}
		if err := s.validateTorAdminConfig(candidate); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": overlayAdminText(r, "tor.error_config", nil)})
			return
		}
		if err := s.updateTorAdminConfig(candidate); err != nil {
			writeUserJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": overlayAdminText(r, "tor.error_apply", nil)})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": candidate})
	default:
		w.Header().Set("Allow", "GET, PATCH")
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": overlayAdminText(r, "common.method_not_allowed", nil)})
	}
}

func (s *Server) torRuntimeConfig(configDir, dataDir, logDir string, configured config.TorConfig) tor.Config {
	return tor.Config{Enabled: true, TorBinary: configured.Binary, ConfigDir: configDir, DataDir: dataDir, LogDir: logDir,
		StartupTimeout: time.Duration(configured.StartupTimeout) * time.Second, BootstrapTimeout: time.Duration(configured.BootstrapTimeout) * time.Second,
		VirtualPort: configured.VirtualPort, MaxCircuits: configured.MaxCircuits, CircuitTimeout: configured.CircuitTimeout,
		SafeLogging: configured.SafeLogging, MaxStreamsPerCircuit: configured.MaxStreamsPerCircuit,
		CloseCircuitOnStreamLimit: configured.CloseCircuitOnStreamLimit, BandwidthRate: configured.BandwidthRate,
		BandwidthBurst: configured.BandwidthBurst, MaxMonthlyBandwidth: configured.MaxMonthlyBandwidth,
		NumIntroPoints: configured.NumIntroPoints, ContactEmail: configured.ContactEmail,
		UseNetwork: configured.UseNetwork, AllowUserPreference: configured.AllowUserPreference}
}

func (s *Server) handleTorAdminValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": overlayAdminText(r, "common.method_not_allowed", nil)})
		return
	}
	var candidate config.TorConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&candidate); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": overlayAdminText(r, "tor.error_config", nil)})
		return
	}
	if err := s.validateTorAdminConfig(candidate); err != nil {
		writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": overlayAdminText(r, "tor.error_config", nil)})
		return
	}
	writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "valid": true})
}

func (s *Server) handleTorAdminAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": overlayAdminText(r, "common.method_not_allowed", nil)})
		return
	}
	s.overlayMu.RLock()
	manager := s.torManager
	s.overlayMu.RUnlock()
	if manager == nil {
		writeUserJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": overlayAdminText(r, "tor.error_unavailable", nil)})
		return
	}
	switch r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:] {
	case "restart":
		if err := manager.Restart(); err != nil {
			writeUserJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": overlayAdminText(r, "tor.error_restart", nil)})
			return
		}
		writeUserJSON(w, http.StatusAccepted, map[string]any{"ok": true, "state": "starting"})
	case "regenerate":
		go func() {
			if _, err := manager.RegenerateAddress(); err != nil && s.Logger != nil && s.Logger.Error != nil {
				s.Logger.Error.Printf("Tor address regeneration failed: %v", err)
			}
		}()
		writeUserJSON(w, http.StatusAccepted, map[string]any{"ok": true, "state": "starting"})
	default:
		writeUserJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": overlayAdminText(r, "tor.error_action", nil)})
	}
}

func (s *Server) validateTorAdminConfig(candidate config.TorConfig) error {
	return tor.ValidateConfig(s.torRuntimeConfig(filepath.Dir(s.ConfigPath), s.DataDir, s.LogDir, candidate))
}

func (s *Server) updateTorAdminConfig(candidate config.TorConfig) error {
	s.configMu.Lock()
	previous := s.Config.Server.Tor
	s.Config.Server.Tor = candidate
	if err := config.Save(s.Config, s.ConfigPath); err != nil {
		s.Config.Server.Tor = previous
		s.configMu.Unlock()
		return err
	}
	s.configMu.Unlock()
	s.overlayMu.RLock()
	manager := s.torManager
	s.overlayMu.RUnlock()
	if manager != nil {
		if err := manager.UpdateConfig(s.torRuntimeConfig(filepath.Dir(s.ConfigPath), s.DataDir, s.LogDir, candidate)); err != nil {
			s.configMu.Lock()
			s.Config.Server.Tor = previous
			_ = config.Save(s.Config, s.ConfigPath)
			s.configMu.Unlock()
			return err
		}
	}
	return nil
}

func torCircuitIDFromRequest(r *http.Request) string {
	value, _ := r.Context().Value(torCircuitContextKey{}).(string)
	return strings.TrimSpace(value)
}

func requestRateIdentity(r *http.Request) string {
	switch overlayRequestKind(r) {
	case "tor":
		if circuit := torCircuitIDFromRequest(r); circuit != "" {
			return "tor:" + circuit
		}
		return "tor"
	case "i2p":
		return "i2p"
	default:
		return "ip:" + peerIP(r.RemoteAddr)
	}
}
