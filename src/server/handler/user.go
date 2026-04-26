package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/casapps/casspeed/src/auth"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

type UserHandler struct {
	store store.Store
}

func NewUserHandler(st store.Store) *UserHandler {
	return &UserHandler{
		store: st,
	}
}


func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate input
	if err := auth.ValidateUsername(req.Username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := auth.ValidateEmail(req.Email); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Generate user ID
	userID := make([]byte, 16)
	rand.Read(userID)
	
	// Hash password using auth package
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	
	user := &model.User{
		ID:           hex.EncodeToString(userID),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
	}

	if err := h.store.CreateUser(r.Context(), user); err != nil {
		http.Error(w, "Registration failed", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
	}

	w.Header().Set("Content-Type", "application/json")
	data, _ := json.MarshalIndent(response, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}

func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	user, err := h.store.GetUser(r.Context(), userID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	data, _ := json.MarshalIndent(user, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}

func (h *UserHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	devices, err := h.store.GetUserDevices(r.Context(), userID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	data, _ := json.MarshalIndent(devices, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}

func (h *UserHandler) CreateDevice(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	device := &model.Device{
		ID:     "device-" + req.Name, // Placeholder
		UserID: userID,
		Name:   req.Name,
	}

	if err := h.store.CreateDevice(r.Context(), device); err != nil {
		http.Error(w, "Failed to create device", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	data, _ := json.MarshalIndent(device, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}

func (h *UserHandler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")

	if err := h.store.DeleteDevice(r.Context(), deviceID); err != nil {
		http.Error(w, "Failed to delete device", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"status": "deleted"}
	data, _ := json.MarshalIndent(response, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}

func (h *UserHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	tokens, err := h.store.GetUserAPITokens(r.Context(), userID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	data, _ := json.MarshalIndent(tokens, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}

func (h *UserHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Generate token: 16 bytes (128 bits) = 32 hex chars
	tokenBytes := make([]byte, 16)
	rand.Read(tokenBytes)
	tokenID := hex.EncodeToString(tokenBytes)
	
	// Generate actual token with key_ prefix per PART 17
	actualTokenBytes := make([]byte, 32)
	rand.Read(actualTokenBytes)
	actualToken := "key_" + hex.EncodeToString(actualTokenBytes)

	token := &model.APIToken{
		ID:     tokenID,
		UserID: userID,
		Token:  actualToken, // key_ prefix per spec
		Name:   req.Name,
	}

	if err := h.store.CreateAPIToken(r.Context(), token); err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	data, _ := json.MarshalIndent(token, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}

func (h *UserHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "tokenId")

	if err := h.store.DeleteAPIToken(r.Context(), tokenID); err != nil {
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"status": "revoked"}
	data, _ := json.MarshalIndent(response, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}
