package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/i2p"
)

type overlayRequestKey struct{}

func overlayRequestHandler(kind string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), overlayRequestKey{}, kind)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func overlayRequestKind(r *http.Request) string {
	kind, _ := r.Context().Value(overlayRequestKey{}).(string)
	return kind
}

func isOverlayRequest(r *http.Request) bool {
	return overlayRequestKind(r) != ""
}

func (s *Server) serveI2PBackend(listener net.Listener) error {
	if listener == nil {
		return errors.New("I2P backend listener is nil")
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.overlayMu.RLock()
			manager := s.i2pManager
			s.overlayMu.RUnlock()
			if manager == nil || !sameOverlayHost(r.Host, manager.EepsiteAddress()) {
				http.Error(w, "Misdirected request", http.StatusMisdirectedRequest)
				return
			}
			ctx := context.WithValue(r.Context(), overlayRequestKey{}, "i2p")
			r.RemoteAddr = "i2p"
			s.Router.ServeHTTP(w, r.WithContext(ctx))
		}),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	s.overlayMu.Lock()
	s.i2pHTTP = server
	s.overlayMu.Unlock()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && s.Logger != nil && s.Logger.Error != nil {
			s.Logger.Error.Printf("I2P backend listener stopped: %v", err)
		}
	}()
	return nil
}

func (s *Server) startI2PManager(configDir, dataDir, logDir string, configured config.I2PConfig) error {
	adminPath := configuredAdminPath(s.Config)
	basePath := "/api/v1/server/" + adminPath + "/network/i2p"
	s.Router.Post("/server/"+adminPath+"/network/i2p", s.AdminHandler.RequireAuth(s.handleI2PAdminPage))
	s.Router.Get(basePath, s.requireOperatorAPI(s.handleI2PAdminAPI))
	s.Router.Patch(basePath, s.requireOperatorAPI(s.handleI2PAdminAPI))
	s.Router.Post(basePath+"/validate", s.requireOperatorAPI(s.handleI2PAdminValidate))
	s.Router.Post(basePath+"/regenerate", s.requireOperatorAPI(s.handleI2PAdminAction))
	s.Router.Post(basePath+"/restart", s.requireOperatorAPI(s.handleI2PAdminAction))
	managerConfig := s.i2pRuntimeConfig(configDir, dataDir, logDir, configured)
	managerConfig.BackendReady = s.serveI2PBackend
	managerConfig.OnState = func(state i2p.State) {
		s.overlayMu.Lock()
		s.i2pState = state
		s.overlayMu.Unlock()
	}
	manager := i2p.NewManager(context.Background(), managerConfig)
	s.overlayMu.Lock()
	s.i2pManager = manager
	s.i2pState = manager.State()
	s.overlayMu.Unlock()
	if err := manager.Start(); err != nil {
		_ = manager.Close()
		return err
	}
	return nil
}

func configuredAdminPath(cfg *config.Config) string {
	if cfg == nil || strings.Trim(cfg.Server.AdminPath, "/") == "" {
		return "administration"
	}
	return strings.Trim(cfg.Server.AdminPath, "/")
}

func (s *Server) i2pRuntimeConfig(configDir, dataDir, logDir string, configured config.I2PConfig) i2p.Config {
	managerConfig := i2p.DefaultConfig()
	managerConfig.Enabled = configured.Enabled
	managerConfig.Expose = configured.Expose
	managerConfig.Binary = configured.Binary
	managerConfig.SAMAddress = configured.SAMAddress
	managerConfig.VirtualPort = configured.VirtualPort
	managerConfig.InboundLength = configured.InboundLength
	managerConfig.OutboundLength = configured.OutboundLength
	managerConfig.InboundQuantity = configured.InboundQuantity
	managerConfig.OutboundQuantity = configured.OutboundQuantity
	managerConfig.SignatureType = configured.SignatureType
	managerConfig.BootstrapTimeout = time.Duration(configured.BootstrapTimeout) * time.Second
	managerConfig.ConfigDir = configDir
	managerConfig.DataDir = dataDir
	managerConfig.LogDir = logDir
	managerConfig.BackendReady = s.serveI2PBackend
	if s.Logger != nil {
		managerConfig.Logger = s.Logger.Error
	}
	return managerConfig
}

func (s *Server) currentI2PState() i2p.State {
	s.overlayMu.RLock()
	manager := s.i2pManager
	state := s.i2pState
	s.overlayMu.RUnlock()
	if manager != nil {
		state = manager.State()
	}
	return state
}

func (s *Server) i2PHealth() healthI2P {
	state := s.currentI2PState()
	s.configMu.RLock()
	configuredEnabled := s.Config != nil && s.Config.Server.I2P.Enabled
	expose := s.Config != nil && s.Config.Server.I2P.Expose
	s.configMu.RUnlock()
	info := healthI2P{State: state.Status, Provider: string(state.Provider), Status: "disabled"}
	if info.State == "" {
		info.State = "disabled"
	}
	if info.Provider == "" {
		info.Provider = string(i2p.ProviderNone)
	}
	switch state.Status {
	case "starting", "building":
		info.Enabled = true
		info.Status = "starting"
	case "running":
		info.Enabled = true
		info.Running = true
		info.Status = "healthy"
		if expose {
			info.Hostname = state.EepsiteAddress
		}
	case "error":
		info.Enabled = configuredEnabled
		info.Status = "unavailable"
	case "no_provider", "disabled":
		info.State = state.Status
		if state.Status == "no_provider" && configuredEnabled {
			info.Enabled = true
			info.Status = "unavailable"
		} else {
			info.Provider = string(i2p.ProviderNone)
		}
	}
	if !configuredEnabled {
		info.Enabled = false
		info.Running = false
		info.Hostname = ""
		info.Status = "disabled"
		info.Provider = string(i2p.ProviderNone)
	}
	return info
}

func (s *Server) exposedI2PAddress() string {
	if s.Config == nil || !s.Config.Server.I2P.Expose {
		return ""
	}
	info := s.i2PHealth()
	if info.Status != "healthy" {
		return ""
	}
	return info.Hostname
}

func sameOverlayHost(requestHost, expectedHost string) bool {
	requestHost, _, requestOK := parseRequestHost(requestHost)
	expectedHost, _, expectedOK := parseRequestHost(expectedHost)
	return requestOK && expectedOK && strings.EqualFold(requestHost, expectedHost)
}
