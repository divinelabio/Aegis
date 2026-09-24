package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

// HandleSetupMFA generates a new TOTP secret and returns the QR code
// POST /api/mfa/setup
func (h *Handler) HandleSetupMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 1. Get User from Session (Must be authenticated)
	username := h.Sessions.GetString(r.Context(), "user_id") // Using username as ID in this legacy session key
	if username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Session stores "user_uuid", so we use that.

	// Actually, wait, session stores "user_id" as username. But we need UUID for repo.
	// Best to refactor session to store UUID or look up by username.
	// Looking at HandleLogin, we store:
	// h.Sessions.Put(r.Context(), "user_id", u.Username)
	// h.Sessions.Put(r.Context(), "user_uuid", u.ID.String())

	userUUIDStr := h.Sessions.GetString(r.Context(), "user_uuid")
	if userUUIDStr == "" {
		h.Logger.Error("User UUID missing from session")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	uID, err := uuid.Parse(userUUIDStr)
	if err != nil {
		h.Logger.Error("Invalid UUID in session", zap.Error(err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	existing, err := h.UserRepo.GetUserByID(r.Context(), uID)
	if err != nil || existing == nil {
		h.Logger.Error("Failed to load user before MFA setup", zap.Error(err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if existing.MFAEnabled {
		http.Error(w, "Disable the existing MFA factor with its current code before enrolling a replacement", http.StatusConflict)
		return
	}

	// 2. Generate Key
	// Issuer: Aegis, AccountName: username
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Aegis",
		AccountName: username,
	})
	if err != nil {
		h.Logger.Error("Failed to generate TOTP key", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 3. Return Secret and QR Code
	// We return JSON with secret (text) and QR code (data URL or just URL)
	// For simplicity, let's return JSON with secret and base64 encoded image

	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		h.Logger.Error("Failed to generate QR image", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := png.Encode(&buf, img); err != nil {
		h.Logger.Error("Failed to encode QR image", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store secret temporarily? No, standard is client stores it until they verify.
	// OR we store it in session "pending_mfa_secret".
	h.Sessions.Put(r.Context(), "pending_mfa_secret", key.Secret())
	h.Sessions.Put(r.Context(), "pending_mfa_expires_at", time.Now().UTC().Add(10*time.Minute).Format(time.RFC3339Nano))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"secret":   key.Secret(),
		"qr_image": fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(buf.Bytes())),
	})
}

// HandleEnableMFA verifies the code and enables MFA
// POST /api/mfa/enable
func (h *Handler) HandleEnableMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	pendingSecret := h.Sessions.GetString(r.Context(), "pending_mfa_secret")
	pendingExpiry, expiryErr := time.Parse(time.RFC3339Nano, h.Sessions.GetString(r.Context(), "pending_mfa_expires_at"))
	if pendingSecret == "" || expiryErr != nil || !time.Now().UTC().Before(pendingExpiry) {
		h.Sessions.Remove(r.Context(), "pending_mfa_secret")
		h.Sessions.Remove(r.Context(), "pending_mfa_expires_at")
		http.Error(w, "No MFA setup pending", http.StatusBadRequest)
		return
	}

	if !totp.Validate(input.Code, pendingSecret) {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	userUUIDStr := h.Sessions.GetString(r.Context(), "user_uuid")
	uID, err := uuid.Parse(userUUIDStr)
	if err != nil {
		h.Logger.Error("Invalid UUID in session", zap.Error(err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Update DB
	if err := h.UserRepo.UpdateMFASecret(r.Context(), uID, pendingSecret, true); err != nil {
		h.Logger.Error("Failed to enable MFA", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.Sessions.Remove(r.Context(), "pending_mfa_secret")
	h.Sessions.Remove(r.Context(), "pending_mfa_expires_at")
	h.invalidateUserSessions(uID)

	h.recordAudit(r, "auth:mfa_enable", userUUIDStr, "MFA Enabled")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "enabled", "reauth_required": true})
}

// HandleDisableMFA disables MFA for the current admin account.
// POST /api/mfa/disable
func (h *Handler) HandleDisableMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userUUIDStr := h.Sessions.GetString(r.Context(), "user_uuid")
	uID, err := uuid.Parse(userUUIDStr)
	if err != nil {
		h.Logger.Error("Invalid UUID in session", zap.Error(err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var input struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	u, err := h.UserRepo.GetUserByID(r.Context(), uID)
	if err != nil || u == nil || !u.MFAEnabled || u.MFASecret == "" {
		http.Error(w, "MFA is not enabled", http.StatusBadRequest)
		return
	}
	if !totp.Validate(strings.TrimSpace(input.Code), u.MFASecret) {
		h.Logger.Warn("Invalid MFA code while disabling MFA", zap.String("user_id", userUUIDStr))
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	if err := h.UserRepo.UpdateMFASecret(r.Context(), uID, "", false); err != nil {
		h.Logger.Error("Failed to disable MFA", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.Sessions.Remove(r.Context(), "pending_mfa_secret")
	h.Sessions.Remove(r.Context(), "pending_mfa_expires_at")
	h.invalidateUserSessions(uID)
	h.recordAudit(r, "auth:mfa_disable", userUUIDStr, "MFA Disabled")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "disabled", "reauth_required": true})
}

// HandleVerifyMFA verifies code during login (2nd step)
// POST /api/login/mfa
func (h *Handler) HandleVerifyMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Session must contain "pre_auth_user_id"
	preAuthID := h.Sessions.GetString(r.Context(), "pre_auth_user_id")
	preAuthExpiry, err := time.Parse(time.RFC3339Nano, h.Sessions.GetString(r.Context(), "pre_auth_expires_at"))
	if preAuthID == "" || err != nil || !time.Now().UTC().Before(preAuthExpiry) {
		_ = h.Sessions.Destroy(r.Context())
		http.Error(w, "Session expired or invalid login flow", http.StatusUnauthorized)
		return
	}
	if !h.allowMFAAttempt("mfa:" + preAuthID + ":" + h.authClientKey(r)) {
		h.recordAudit(r, "auth:mfa_failure", preAuthID, "MFA verification rate limited")
		_ = h.Sessions.Destroy(r.Context())
		h.Logger.Warn("MFA verification rate limit exceeded", zap.String("user_id", preAuthID))
		http.Error(w, "Too many MFA attempts. Sign in again to continue.", http.StatusTooManyRequests)
		return
	}

	var input struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	uID, err := uuid.Parse(preAuthID)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}
	u, err := h.UserRepo.GetUserByID(r.Context(), uID)
	if err != nil || u == nil || !u.IsActive || !u.MFAEnabled || u.MFASecret == "" || u.LockedUntil.After(time.Now()) {
		h.recordAudit(r, "auth:mfa_failure", preAuthID, "MFA verification rejected")
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	if !totp.Validate(input.Code, u.MFASecret) {
		h.Logger.Warn("Invalid MFA code during login", zap.String("user_id", preAuthID))
		h.recordAudit(r, "auth:mfa_failure", preAuthID, "Invalid MFA code")
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	// Upgrade the short-lived pre-auth session into a newly rotated,
	// fully-authenticated session with a fresh CSRF token and permissions.
	if _, err := h.establishAuthenticatedSession(r, u, true); err != nil {
		h.Logger.Error("Failed to establish MFA session", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.recordAudit(r, "auth:login_success", u.ID.String(), "Logged in with MFA")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
