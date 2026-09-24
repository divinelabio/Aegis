package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/divinelab-io/aegis/internal/infra/config"
	"go.uber.org/zap"
)

// generateToken creates a random 32-byte hex string
func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// hashToken SHA256 hashes the token for storage
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func passwordResetURL(token string) (string, error) {
	cfg := config.GetGlobalConfig()
	if cfg == nil {
		return "", fmt.Errorf("Aegis configuration is not loaded")
	}
	baseURL := strings.TrimSpace(cfg.Infrastructure.PublicBaseURL)
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("infrastructure.public_base_url must be an absolute HTTPS URL")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/admin/reset-confirm"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	query := parsed.Query()
	query.Set("token", token)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// HandleRequestPasswordReset initiates the flow
// POST /api/request-reset
func (h *Handler) HandleRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	host := h.authClientKey(r)
	if !h.allowPasswordReset(host) {
		h.Logger.Warn("Rate limit exceeded for password reset", zap.String("ip", host))
		http.Error(w, "Too many attempts. Please wait.", http.StatusTooManyRequests)
		return
	}

	var input struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Always return success to prevent enumeration
	defer func() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": "If the email exists, a reset link has been sent.",
		})
	}()

	u, err := h.UserRepo.GetUserByEmail(r.Context(), input.Email)
	if err != nil {
		h.Logger.Error("Failed to lookup user for reset", zap.Error(err))
		return
	}
	if u == nil {
		// User not found, do nothing (generic response sent by defer)
		return
	}
	if _, err := passwordResetURL(""); err != nil {
		// Keep the response generic, but do not issue a token whose link could
		// be controlled by an inbound Host header or sent over plain HTTP.
		h.Logger.Error("Password reset is unavailable: configure infrastructure.public_base_url as HTTPS", zap.Error(err))
		return
	}

	// Generate Token
	token, err := generateToken()
	if err != nil {
		h.Logger.Error("Failed to generate reset token", zap.Error(err))
		return
	}
	tokenHash := hashToken(token)

	// Expiry: 15 minutes
	expiresAt := time.Now().Add(15 * time.Minute)

	if err := h.UserRepo.CreatePasswordResetToken(r.Context(), u.ID, tokenHash, expiresAt, host); err != nil {
		h.Logger.Error("Failed to store reset token", zap.Error(err))
		return
	}

	// Construct the link solely from the configured canonical public HTTPS URL.
	resetLink, err := passwordResetURL(token)
	if err != nil {
		h.Logger.Error("Failed to construct password reset URL", zap.Error(err))
		return
	}

	// Send Email
	if err := h.Mailer.SendResetEmail(u.Email, resetLink); err != nil {
		h.Logger.Error("Failed to send reset email", zap.Error(err))
		return
	}

	h.Audit.Log(r, "auth:reset_request", u.ID.String(), "Password reset requested")
}

// HandleResetPassword completes the flow
// POST /api/reset-password
func (h *Handler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(input.Token) == "" || len(input.Password) < 8 {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	host := h.authClientKey(r)
	if !h.allowPasswordReset(host) {
		http.Error(w, "Too many attempts", http.StatusTooManyRequests)
		return
	}

	// Claim the token before changing credentials. PostgreSQL performs this
	// transition atomically, preventing a second request from reusing the link.
	tokenHash := hashToken(input.Token)
	resetToken, err := h.UserRepo.ConsumePasswordResetToken(r.Context(), tokenHash, time.Now().UTC())
	if err != nil {
		h.Logger.Error("Failed to retrieve token", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if resetToken == nil {
		// Invalid or expired
		h.Logger.Warn("Invalid password reset attempt", zap.String("ip", host))
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	// Update Password
	u, err := h.UserRepo.GetUserByID(r.Context(), resetToken.UserID)
	if err != nil {
		h.Logger.Error("Failed to fetch user for reset", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if u == nil {
		h.Logger.Warn("Password reset token references a missing user", zap.String("token_id", resetToken.ID.String()))
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	if !h.acquireAuthWork() {
		http.Error(w, "Authentication is temporarily busy. Please try again shortly.", http.StatusTooManyRequests)
		return
	}
	defer h.releaseAuthWork()

	newHash, err := user.HashPassword(input.Password)
	if err != nil {
		h.Logger.Error("Failed to hash password", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	u.PasswordHash = newHash
	if err := h.UserRepo.UpdateUser(r.Context(), u); err != nil {
		h.Logger.Error("Failed to update user password", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.invalidateUserSessions(u.ID)

	h.Audit.Log(r, "auth:reset_success", u.ID.String(), "Password successfully reset")
	h.Logger.Info("Password reset successful", zap.String("username", u.Username))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "Password updated successfully",
	})
}
