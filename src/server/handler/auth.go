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

// Set session cookie
http.SetCookie(w, &http.Cookie{
Name:     "session",
Value:    session.ID,
Path:     "/",
Expires:  session.ExpiresAt,
HttpOnly: true,
Secure:   false, // Set to true when SSL enabled
SameSite: http.SameSiteLaxMode,
})

// Return success
response := map[string]interface{}{
"success": true,
"user": map[string]string{
"id":       user.ID,
"username": user.Username,
"email":    user.Email,
},
}

w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(response)
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
SameSite: http.SameSiteLaxMode,
})

// Return success
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]bool{"success": true})
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

// Get user by email
user, err := h.store.GetUserByEmail(r.Context(), req.Email)
if err != nil || user == nil {
// Don't reveal if email exists - return success anyway
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]string{
"message": "If the email exists, a reset link will be sent",
})
return
}

// Generate password reset token
_ =  auth.GeneratePasswordResetToken(user.ID)

// Store token in database (would need to add this method to store)
// h.store.CreatePasswordResetToken(r.Context(), token)

// Send email with reset link (would need email implementation)
// emailService.SendPasswordReset(user.Email, token.Token)

w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]string{
"message": "If the email exists, a reset link will be sent",
})
}
