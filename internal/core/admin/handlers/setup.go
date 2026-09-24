package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/storage"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type setupStatusResponse struct {
	Status        string                `json:"status"`
	Completed     bool                  `json:"completed"`
	SetupRequired bool                  `json:"setup_required"`
	UserCount     int64                 `json:"user_count"`
	Storage       storageStatusResponse `json:"storage"`
}

type setupCompleteResponse struct {
	Status    string `json:"status"`
	Completed bool   `json:"completed"`
}

type setupBootstrapResponse struct {
	Status  string                 `json:"status"`
	Config  map[string]interface{} `json:"config"`
	Users   []user.User            `json:"users"`
	Roles   []user.Role            `json:"roles"`
	Modules map[string]string      `json:"modules"`
}

type setupFirstAdminResponse struct {
	Status      string   `json:"status"`
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	RoleID      string   `json:"role_id"`
	CSRFToken   string   `json:"csrf_token"`
	Permissions []string `json:"permissions"`
}

func (h *Handler) HandleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writePostgreSQLPreflightError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}

	cfg := config.GetGlobalConfig()
	if cfg == nil {
		writePostgreSQLPreflightError(w, http.StatusServiceUnavailable, "SETUP_STATUS_UNAVAILABLE")
		return
	}

	userCount, err := h.UserRepo.CountUsers(r.Context())
	if err != nil {
		h.Logger.Error("Failed to count users for setup status")
		writePostgreSQLPreflightError(w, http.StatusServiceUnavailable, "SETUP_STATUS_UNAVAILABLE")
		return
	}

	response := setupStatusResponse{
		Status:        "ok",
		Completed:     cfg.Server.Admin.SetupCompleted,
		SetupRequired: !cfg.Server.Admin.SetupCompleted,
		UserCount:     userCount,
		Storage:       setupStorageStatusSnapshot(r.Context(), cfg),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (h *Handler) HandleSetupBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writePostgreSQLPreflightError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	cfg, userCount, ok := h.setupState(w, r)
	if !ok {
		return
	}
	if cfg.Server.Admin.SetupCompleted {
		writePostgreSQLPreflightError(w, http.StatusConflict, "SETUP_NOT_REQUIRED")
		return
	}
	if userCount > 0 && !h.hasSetupSession(r) {
		writePostgreSQLPreflightError(w, http.StatusUnauthorized, "SETUP_AUTH_REQUIRED")
		return
	}

	roles, err := h.UserRepo.ListRoles(r.Context())
	if err != nil {
		h.Logger.Error("Failed to list setup roles", zap.Error(err))
		writePostgreSQLPreflightError(w, http.StatusServiceUnavailable, "SETUP_BOOTSTRAP_UNAVAILABLE")
		return
	}
	users := []user.User{}
	if userCount > 0 {
		users, err = h.UserRepo.ListUsers(r.Context(), 100, 0)
		if err != nil {
			h.Logger.Error("Failed to list setup users", zap.Error(err))
			writePostgreSQLPreflightError(w, http.StatusServiceUnavailable, "SETUP_BOOTSTRAP_UNAVAILABLE")
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(setupBootstrapResponse{
		Status: "ok",
		Config: sanitizedConfigSnapshot(),
		Users:  users,
		Roles:  roles,
		Modules: map[string]string{
			"license_tier": getLicenseTier(),
		},
	})
}

func (h *Handler) HandleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writePostgreSQLPreflightError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if err := config.UpdateConfig("server.admin.setup_completed", true); err != nil {
		h.Logger.Error("Failed to mark setup complete")
		writePostgreSQLPreflightError(w, http.StatusInternalServerError, "SETUP_COMPLETE_FAILED")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(setupCompleteResponse{Status: "ok", Completed: true})
}

func (h *Handler) HandleSetupFirstAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		writePostgreSQLPreflightError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if h.Sessions == nil {
		writePostgreSQLPreflightError(w, http.StatusServiceUnavailable, "SETUP_SESSION_UNAVAILABLE")
		return
	}
	if _, _, ok := h.requireFirstRunWithoutUsers(w, r); !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decoder.Decode(&input); err != nil {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_FIRST_ADMIN_REQUEST")
		return
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_FIRST_ADMIN_REQUEST")
		return
	}

	role, err := h.UserRepo.GetRoleByName(r.Context(), superAdminRoleName)
	if err != nil {
		h.Logger.Error("Failed to fetch setup super administrator role", zap.Error(err))
		writePostgreSQLPreflightError(w, http.StatusServiceUnavailable, "SETUP_ROLE_UNAVAILABLE")
		return
	}
	if role == nil {
		writePostgreSQLPreflightError(w, http.StatusServiceUnavailable, "SETUP_ROLE_UNAVAILABLE")
		return
	}
	if err := validateManagedUserInput(input.Username, input.Email, input.Password, role.ID, true); err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	input.Username, input.Email, _ = normalizeManagedUserIdentity(input.Username, input.Email)

	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()
	userCount, err := h.UserRepo.CountUsers(r.Context())
	if err != nil {
		h.Logger.Error("Failed to count users for first admin creation", zap.Error(err))
		writePostgreSQLPreflightError(w, http.StatusServiceUnavailable, "SETUP_STATUS_UNAVAILABLE")
		return
	}
	if userCount > 0 {
		writePostgreSQLPreflightError(w, http.StatusConflict, "SETUP_FIRST_ADMIN_ALREADY_EXISTS")
		return
	}
	if !h.ensureManagedIdentityAvailable(w, r, input.Username, input.Email, uuid.Nil) {
		return
	}

	hash, err := user.HashPassword(input.Password)
	if err != nil {
		h.Logger.Error("Failed to hash setup administrator password", zap.Error(err))
		writePostgreSQLPreflightError(w, http.StatusInternalServerError, "SETUP_FIRST_ADMIN_FAILED")
		return
	}
	newUser := &user.User{
		Username:     input.Username,
		Email:        input.Email,
		PasswordHash: hash,
		RoleID:       role.ID,
		IsActive:     true,
	}
	if err := h.UserRepo.CreateUser(r.Context(), newUser); err != nil {
		h.Logger.Error("Failed to create setup administrator", zap.Error(err))
		writePostgreSQLPreflightError(w, http.StatusInternalServerError, "SETUP_FIRST_ADMIN_FAILED")
		return
	}

	csrfToken, err := h.establishAuthenticatedSession(r, newUser, false)
	if err != nil {
		h.Logger.Error("Failed to establish setup administrator session", zap.Error(err))
		writePostgreSQLPreflightError(w, http.StatusInternalServerError, "SETUP_FIRST_ADMIN_SESSION_FAILED")
		return
	}
	permissions, err := h.UserRepo.GetPermissionsForRole(r.Context(), role.ID)
	if err != nil {
		h.Logger.Error("Failed to load setup administrator permissions", zap.Error(err))
		writePostgreSQLPreflightError(w, http.StatusInternalServerError, "SETUP_FIRST_ADMIN_SESSION_FAILED")
		return
	}
	permissionSlugs := make([]string, len(permissions))
	for i, permission := range permissions {
		permissionSlugs[i] = permission.Slug
	}

	h.auditUserMutation(r, "user:create", newUser.ID, map[string]interface{}{
		"target": userAuditSnapshot(newUser, role),
		"setup":  true,
	})

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(setupFirstAdminResponse{
		Status:      "created",
		ID:          newUser.ID.String(),
		Username:    newUser.Username,
		RoleID:      role.ID.String(),
		CSRFToken:   csrfToken,
		Permissions: permissionSlugs,
	})
}

func (h *Handler) HandleSetupStorageControlPostgreSQLPreflight(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := h.requireFirstRunWithoutUsers(w, r); !ok {
		return
	}
	h.HandleStorageControlPostgreSQLPreflight(w, r)
}

func (h *Handler) HandleSetupStorageControlPostgreSQLPending(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := h.requireFirstRunWithoutUsers(w, r); !ok {
		return
	}
	h.HandleStorageControlPostgreSQLPending(w, r)
}

func (h *Handler) HandleSetupStorageAnalyticsClickHousePreflight(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := h.requireFirstRunWithoutUsers(w, r); !ok {
		return
	}
	h.HandleStorageAnalyticsClickHousePreflight(w, r)
}

func (h *Handler) HandleSetupStorageAnalyticsClickHousePending(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := h.requireFirstRunWithoutUsers(w, r); !ok {
		return
	}
	h.HandleStorageAnalyticsClickHousePending(w, r)
}

func (h *Handler) setupState(w http.ResponseWriter, r *http.Request) (*config.Config, int64, bool) {
	cfg := config.GetGlobalConfig()
	if cfg == nil {
		writePostgreSQLPreflightError(w, http.StatusServiceUnavailable, "SETUP_STATUS_UNAVAILABLE")
		return nil, 0, false
	}
	userCount, err := h.UserRepo.CountUsers(r.Context())
	if err != nil {
		h.Logger.Error("Failed to count users for setup")
		writePostgreSQLPreflightError(w, http.StatusServiceUnavailable, "SETUP_STATUS_UNAVAILABLE")
		return nil, 0, false
	}
	return cfg, userCount, true
}

func (h *Handler) requireFirstRunWithoutUsers(w http.ResponseWriter, r *http.Request) (*config.Config, int64, bool) {
	cfg, userCount, ok := h.setupState(w, r)
	if !ok {
		return nil, 0, false
	}
	if cfg.Server.Admin.SetupCompleted {
		writePostgreSQLPreflightError(w, http.StatusConflict, "SETUP_NOT_REQUIRED")
		return nil, 0, false
	}
	if userCount > 0 {
		writePostgreSQLPreflightError(w, http.StatusConflict, "SETUP_FIRST_ADMIN_ALREADY_EXISTS")
		return nil, 0, false
	}
	return cfg, userCount, true
}

func (h *Handler) hasSetupSession(r *http.Request) bool {
	return h.Sessions != nil && h.Sessions.Exists(r.Context(), "user_id")
}

func setupStorageStatusSnapshot(ctx context.Context, cfg *config.Config) storageStatusResponse {
	response := storageStatusResponse{}
	response.Control = storageRuntimeStatus{
		Driver:            string(storage.ControlDriverPostgreSQL),
		Configured:        cfg.Storage.Control.Enabled,
		EnvironmentLocked: config.ControlDatabaseConfigurationEnvironmentLocked(),
		Active:            storage.ControlDB != nil,
	}
	if storage.ControlDB != nil {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		response.Control.Available = storage.ControlDB.Ping(pingCtx) == nil
		cancel()
	}

	analyticsMode := cfg.Storage.Analytics.EffectiveMode()
	response.Analytics = storageRuntimeStatus{
		Driver:                string(storage.DriverClickHouse),
		Configured:            analyticsMode != storage.AnalyticsModeDisabled,
		EnvironmentLocked:     config.AnalyticsDatabaseConfigurationEnvironmentLocked(),
		Active:                storage.DB != nil,
		Mode:                  string(analyticsMode),
		AnalyticsCapabilities: "telemetry, dashboards, aggregates, and retention",
	}
	if storage.DB != nil {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		response.Analytics.Available = storage.DB.PingContext(pingCtx) == nil
		cancel()
	}
	response.Control.RestartRequired = !storage.ControlConfigIsActive(cfg.Storage.Control)
	response.Analytics.RestartRequired = !storage.AnalyticsConfigIsActive(cfg.Storage.Analytics)
	return response
}
