package handler

import (
"encoding/json"
"net/http"

"github.com/casapps/casspeed/src/auth"
"github.com/casapps/casspeed/src/server/model"
"github.com/casapps/casspeed/src/server/store"
)

type AuthHandler struct {
store store.Store
}

func NewAuthHandler(st store.Store) *AuthHandler {
return &AuthHandler{store: st}
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
var req struct {
Username string `json:"username"`
Password string `json:"password"`
}

if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
http.Error(w, "Invalid request", http.StatusBadRequest)
return
}

// Get user by username
user, err := h.store.GetUserByUsername(r.Context(), req.Username)
if err != nil || user == nil {
http.Error(w, "Invalid credentials", http.StatusUnauthorized)
return
}

// Verify password
if !auth.VerifyPassword(req.Password,user.PasswordHash){
http.Error(w, "Invalid credentials", http.StatusUnauthorized)
return
}

// Create session
session := auth.NewSession(user.ID, r.RemoteAddr, r.UserAgent())

// Store session in database
dbSession := &model.Session{
ID:        session.ID,
UserID:    session.UserID,
ExpiresAt: session.ExpiresAt,
CreatedAt: session.CreatedAt,
}

if err := h.store.CreateSession(r.Context(), dbSession); err != nil {
http.Error(w, "Failed to create session", http.StatusInternalServerError)
return
}

// Set session cookie — SameSite=Strict per PART 11 CSRF requirement
http.SetCookie(w, &http.Cookie{
Name:     "session",
Value:    session.ID,
Path:     "/",
Expires:  session.ExpiresAt,
HttpOnly: true,
Secure:   false, // Set to true when SSL enabled
SameSite: http.SameSiteStrictMode,
})

// Return canonical {"ok": true, "data": {...}} format (PART 9)
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]interface{}{
"ok": true,
"data": map[string]string{
"id":       user.ID,
"username": user.Username,
"email":    user.Email,
},
})
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
// Get session cookie
cookie, err := r.Cookie("session")
if err == nil && cookie.Value != "" {
// Delete session from database
h.store.DeleteSession(r.Context(), cookie.Value)
}

// Clear session cookie
http.SetCookie(w, &http.Cookie{
Name:     "session",
Value:    "",
Path:     "/",
MaxAge:   -1,
HttpOnly: true,
Secure:   false,
SameSite: http.SameSiteStrictMode,
})

w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "data": nil})
}

// PasswordResetRequest handles password reset request
func (h *AuthHandler) PasswordResetRequest(w http.ResponseWriter, r *http.Request) {
var req struct {
Email string `json:"email"`
}

if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
http.Error(w, "Invalid request", http.StatusBadRequest)
return
}

// Enumerate-safe: always return the same response regardless of whether
// the email exists (PART 11 enumeration mitigation requirement)
user, err := h.store.GetUserByEmail(r.Context(), req.Email)
if err == nil && user != nil {
// Generate token (email sending not yet implemented)
_ = auth.GeneratePasswordResetToken(user.ID)
}

// Identical response for all paths — prevents email enumeration
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]interface{}{
"ok": true,
"data": map[string]string{
"message": "If an account with that email exists, a reset link has been sent",
},
})
}
