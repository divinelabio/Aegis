package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// HandleGetProfile returns the current logged-in user's profile
// GET /api/profile
func (h *Handler) HandleGetProfile(w http.ResponseWriter, r *http.Request) {
	// 1. Get User ID from Session
	userIDStr := h.Sessions.GetString(r.Context(), "user_uuid")
	if userIDStr == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	uid, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, "Invalid session state", http.StatusUnauthorized)
		return
	}

	// 2. Fetch User
	u, err := h.UserRepo.GetUserByID(r.Context(), uid)
	if err != nil {
		h.Logger.Error("Failed to fetch profile", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if u == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 3. Return Safe Data
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          u.ID,
		"username":    u.Username,
		"email":       u.Email,
		"role_id":     u.RoleID,
		"mfa_enabled": u.MFAEnabled,
		"created_at":  u.CreatedAt,
		// Do not return password hash or MFA secret
	})
}

// HandleUpdateProfile updates the current user's credentials
// PUT /api/profile
func (h *Handler) HandleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	// 1. Get User ID from Session
	userIDStr := h.Sessions.GetString(r.Context(), "user_uuid")
	if userIDStr == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	uid, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, "Invalid session state", http.StatusUnauthorized)
		return
	}

	// 2. Parse Input
	var input struct {
		Password string `json:"password"`
		// Add Email later if needed
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if input.Password == "" {
		http.Error(w, "Password cannot be empty", http.StatusBadRequest)
		return
	}
	if len(input.Password) < 8 {
		http.Error(w, "Password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	// 3. Fetch Existing User
	u, err := h.UserRepo.GetUserByID(r.Context(), uid)
	if err != nil {
		h.Logger.Error("Failed to fetch user for update", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if u == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 4. Update Password using Argon2
	hash, err := user.HashPassword(input.Password)
	if err != nil {
		h.Logger.Error("Failed to hash password", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	u.PasswordHash = hash

	// 5. Persist
	if err := h.UserRepo.UpdateUser(r.Context(), u); err != nil {
		h.Logger.Error("Failed to update profile", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	h.invalidateUserSessions(u.ID)

	h.Audit.Log(r, "profile:update", u.ID.String(), "User changed their own password")
	h.Logger.Info("Profile password updated", zap.String("username", u.Username))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "updated", "reauth_required": true})
}
