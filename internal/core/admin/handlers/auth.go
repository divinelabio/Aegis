package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit against the verified client identity when a trusted proxy is
	// configured. Do not collapse all reverse-proxy users into one bucket.
	host := h.authClientKey(r)

	if !h.LoginLimiter.Allow(host) {
		h.Logger.Warn("Rate limit exceeded for login", zap.String("ip", host))
		h.JSONError(w, "Too many login attempts. Please wait a minute.", http.StatusTooManyRequests)
		return
	}

	var creds struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		RememberMe bool   `json:"remember_me"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		h.JSONError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate against DB
	u, err := h.UserRepo.GetUserByUsername(r.Context(), creds.Username)
	if err != nil {
		h.Logger.Error("Failed to fetch user", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if u == nil {
		h.Logger.Warn("Failed login attempt (user not found)", zap.String("username", creds.Username))
		h.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check Lockout
	if u.LockedUntil.After(time.Now()) {
		h.Logger.Warn("Login attempt on locked account", zap.String("username", creds.Username))
		h.recordAudit(r, "auth:login_failure", "credentials", "Login attempt on locked account")
		h.JSONError(w, "Account temporarily locked. Please try again later.", http.StatusUnauthorized)
		return
	}

	if !u.IsActive {
		h.Logger.Warn("Failed login attempt (user inactive)", zap.String("username", creds.Username))
		h.recordAudit(r, "auth:login_failure", "credentials", "Login attempt on inactive account")
		h.JSONError(w, "Account disabled", http.StatusUnauthorized)
		return
	}

	// Check Password
	if !h.acquireAuthWork() {
		h.JSONError(w, "Authentication is temporarily busy. Please try again shortly.", http.StatusTooManyRequests)
		return
	}
	defer h.releaseAuthWork()

	match, err := user.CheckPassword(creds.Password, u.PasswordHash)
	if err != nil {
		h.Logger.Error("Password check failed", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !match {
		h.Logger.Warn("Invalid password attempt", zap.String("user", creds.Username))
		// Increment failed attempts
		if err := h.UserRepo.IncrementFailedLogin(r.Context(), u.Username); err != nil {
			h.Logger.Error("Failed to increment failed login", zap.Error(err))
		}
		h.recordAudit(r, "auth:login_failure", "credentials", "Invalid password")
		h.JSONError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Reset failed attempts on success
	if err := h.UserRepo.ResetFailedLogin(r.Context(), u.Username); err != nil {
		h.Logger.Error("Failed to reset failed login", zap.Error(err))
	}
	// ResetFailedLogin updates the identity revision. Reload it before storing
	// the revision in the authenticated session.
	u, err = h.UserRepo.GetUserByID(r.Context(), u.ID)
	if err != nil || u == nil {
		h.Logger.Error("Failed to reload user after successful login", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	// ResetFailedLogin advances the identity revision. Evict any cached state
	// before issuing the new session so it is validated against that revision.
	h.invalidateUserSessions(u.ID)

	// MFA Check
	if u.MFAEnabled {
		// Rotate before beginning a limited pre-authentication session to prevent
		// fixation and discard any authenticated state from an older session.
		if err := h.Sessions.RenewToken(r.Context()); err != nil {
			h.Logger.Error("Failed to renew MFA pre-auth session", zap.Error(err))
			h.JSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		for _, key := range []string{"user_id", "user_uuid", "role_id", "permissions", "csrf_token", "auth_revision", "mfa_authenticated", "pending_mfa_secret", "pending_mfa_expires_at"} {
			h.Sessions.Remove(r.Context(), key)
		}
		h.Sessions.Put(r.Context(), "pre_auth_user_id", u.ID.String())
		h.Sessions.Put(r.Context(), "pre_auth_expires_at", time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339Nano))

		h.Logger.Info("MFA required for login", zap.String("username", u.Username))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "mfa_required",
			"message": "Multi-factor authentication required",
		})
		return
	}

	csrfToken, err := h.establishAuthenticatedSession(r, u, false)
	if err != nil {
		h.Logger.Error("Failed to establish authenticated session", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.Logger.Info("Admin login successful", zap.String("username", creds.Username))
	h.recordAudit(r, "auth:login_success", u.ID.String(), "Logged in")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "ok",
		"csrf_token": csrfToken,
		"username":   u.Username, // Return username
	})
}

func (h *Handler) establishAuthenticatedSession(r *http.Request, u *user.User, mfaAuthenticated bool) (string, error) {
	if err := h.Sessions.RenewToken(r.Context()); err != nil {
		return "", err
	}

	permissions, err := h.UserRepo.GetPermissionsForRole(r.Context(), u.RoleID)
	if err != nil {
		return "", err
	}
	permSlugs := make([]string, len(permissions))
	for i, permission := range permissions {
		permSlugs[i] = permission.Slug
	}

	for _, key := range []string{"pre_auth_user_id", "pre_auth_expires_at", "user_id", "user_uuid", "role_id", "permissions", "csrf_token", "auth_revision", "mfa_authenticated", "pending_mfa_secret", "pending_mfa_expires_at"} {
		h.Sessions.Remove(r.Context(), key)
	}
	csrfToken := uuid.NewString()
	h.Sessions.Put(r.Context(), "user_id", u.Username)
	h.Sessions.Put(r.Context(), "user_uuid", u.ID.String())
	h.Sessions.Put(r.Context(), "role_id", u.RoleID.String())
	h.Sessions.Put(r.Context(), "permissions", permSlugs)
	h.Sessions.Put(r.Context(), "auth_revision", u.UpdatedAt.UTC().Format(time.RFC3339Nano))
	h.Sessions.Put(r.Context(), "csrf_token", csrfToken)
	h.Sessions.Put(r.Context(), "mfa_authenticated", mfaAuthenticated)
	return csrfToken, nil
}

func (h *Handler) HandleVerifySession(w http.ResponseWriter, r *http.Request) {
	// With LoadAndSave middleware, session is already loaded
	if !h.Sessions.Exists(r.Context(), "user_id") {
		h.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	csrfToken := h.Sessions.GetString(r.Context(), "csrf_token")
	if csrfToken == "" {
		csrfToken = uuid.NewString()
		h.Sessions.Put(r.Context(), "csrf_token", csrfToken)
	}

	// Retrieve permissions safely
	var permissions []string
	if val := h.Sessions.Get(r.Context(), "permissions"); val != nil {
		if p, ok := val.([]string); ok {
			permissions = p
		}
	}

	// The session must describe capabilities actually active in the runtime,
	// rather than inferring them from the compiled build or a licence label.
	snapshot := h.currentLicenseSnapshot()
	tier := snapshot.EffectiveTier
	features := snapshot.Features
	featureStrings := make([]string, len(features))
	for i, f := range features {
		featureStrings[i] = string(f)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "active",
		"csrf_token":      csrfToken,
		"username":        h.Sessions.GetString(r.Context(), "user_id"),
		"id":              h.Sessions.GetString(r.Context(), "user_uuid"),
		"role_id":         h.Sessions.GetString(r.Context(), "role_id"),
		"permissions":     permissions,
		"edition":         string(tier),
		"active_features": featureStrings,
	})
}

func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	h.recordAudit(r, "auth:logout", h.Sessions.GetString(r.Context(), "user_uuid"), "Logged out")
	// Destroy session
	if err := h.Sessions.Destroy(r.Context()); err != nil {
		h.Logger.Error("Failed to destroy session", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
}
