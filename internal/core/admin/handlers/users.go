package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"unicode"

	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const superAdminRoleName = "super_admin"

// HandleListUsers returns a paginated list of users
// GET /api/users?page=1&limit=10
func (h *Handler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 10
	}
	offset := (page - 1) * limit

	users, err := h.UserRepo.ListUsers(r.Context(), limit, offset)
	if err != nil {
		h.Logger.Error("Failed to list users", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	total, err := h.UserRepo.CountUsers(r.Context())
	if err != nil {
		h.Logger.Error("Failed to count users", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": users,
		"meta": map[string]interface{}{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": (total + int64(limit) - 1) / int64(limit),
		},
	})
}

// HandleListRoles returns all built-in and configured roles.
// GET /api/roles
func (h *Handler) HandleListRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	roles, err := h.UserRepo.ListRoles(r.Context())
	if err != nil {
		h.Logger.Error("Failed to list roles", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	permissionsByRole, err := h.UserRepo.ListPermissionsForRoles(r.Context())
	if err != nil {
		h.Logger.Error("Failed to list role permissions", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	type roleResponse struct {
		user.Role
		Permissions []user.Permission `json:"permissions"`
		IsBuiltin   bool              `json:"is_builtin"`
	}

	payload := make([]roleResponse, 0, len(roles))
	for _, role := range roles {
		perms := permissionsByRole[role.ID]
		if perms == nil {
			perms = []user.Permission{}
		}
		payload = append(payload, roleResponse{Role: role, Permissions: perms, IsBuiltin: isBuiltInAdminRole(role.Name)})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"data": payload})
}

func validateManagedUserInput(username, email, password string, roleID uuid.UUID, passwordRequired bool) error {
	if _, _, err := normalizeManagedUserIdentity(username, email); err != nil {
		return err
	}
	if roleID == uuid.Nil {
		return fmt.Errorf("role is required")
	}
	if passwordRequired && len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if !passwordRequired && password != "" && len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	return nil
}

func normalizeManagedUserIdentity(username, email string) (string, string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", "", fmt.Errorf("username is required")
	}
	if len(username) > 64 {
		return "", "", fmt.Errorf("username must be at most 64 characters")
	}
	for _, character := range username {
		if unicode.IsControl(character) {
			return "", "", fmt.Errorf("username contains invalid characters")
		}
	}

	email = strings.TrimSpace(email)
	if email == "" {
		return "", "", fmt.Errorf("email is required")
	}
	if len(email) > 254 {
		return "", "", fmt.Errorf("email must be at most 254 characters")
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return "", "", fmt.Errorf("email must be a valid address")
	}
	return username, email, nil
}

func (h *Handler) roleByID(w http.ResponseWriter, r *http.Request, roleID uuid.UUID) (*user.Role, bool) {
	role, err := h.UserRepo.GetRoleByID(r.Context(), roleID)
	if err != nil {
		h.Logger.Error("Failed to fetch role", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return nil, false
	}
	if role == nil {
		h.JSONError(w, "Selected role does not exist", http.StatusBadRequest)
		return nil, false
	}
	return role, true
}

func (h *Handler) ensureManagedIdentityAvailable(w http.ResponseWriter, r *http.Request, username, email string, currentID uuid.UUID) bool {
	byUsername, err := h.UserRepo.GetUserByUsername(r.Context(), username)
	if err != nil {
		h.Logger.Error("Failed to validate username availability", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return false
	}
	if byUsername != nil && byUsername.ID != currentID {
		h.JSONError(w, "Username is already in use", http.StatusConflict)
		return false
	}
	byEmail, err := h.UserRepo.GetUserByEmail(r.Context(), email)
	if err != nil {
		h.Logger.Error("Failed to validate email availability", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return false
	}
	if byEmail != nil && byEmail.ID != currentID {
		h.JSONError(w, "Email is already in use", http.StatusConflict)
		return false
	}
	return true
}

func (h *Handler) currentOperatorID(r *http.Request) (uuid.UUID, bool) {
	if h.Sessions == nil {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(h.Sessions.GetString(r.Context(), "user_uuid"))
	return id, err == nil
}

func (h *Handler) protectLastSuperAdmin(w http.ResponseWriter, r *http.Request, existing *user.User, existingRole *user.Role, nextRoleID uuid.UUID, nextActive bool) bool {
	if !existing.IsActive || existingRole == nil || existingRole.Name != superAdminRoleName {
		return true
	}
	superAdminRole, err := h.UserRepo.GetRoleByName(r.Context(), superAdminRoleName)
	if err != nil {
		h.Logger.Error("Failed to fetch super administrator role", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return false
	}
	if superAdminRole == nil {
		h.Logger.Error("Required super administrator role is missing")
		h.JSONError(w, "Super administrator role is unavailable", http.StatusServiceUnavailable)
		return false
	}
	if existing.RoleID != superAdminRole.ID || (nextActive && nextRoleID == superAdminRole.ID) {
		return true
	}
	activeAdmins, err := h.UserRepo.CountActiveUsersByRole(r.Context(), superAdminRole.ID)
	if err != nil {
		h.Logger.Error("Failed to count active super administrators", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return false
	}
	if activeAdmins <= 1 {
		h.JSONError(w, "At least one active super administrator is required", http.StatusConflict)
		return false
	}
	return true
}

func (h *Handler) auditUserMutation(r *http.Request, action string, targetID uuid.UUID, metadata map[string]interface{}) {
	if h.Audit == nil {
		return
	}
	if h.Sessions != nil {
		metadata["actor_id"] = h.Sessions.GetString(r.Context(), "user_uuid")
		metadata["actor_username"] = h.Sessions.GetString(r.Context(), "user_id")
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		raw = []byte(`{"event":"user mutation"}`)
	}
	h.Audit.Log(r, action, targetID.String(), string(raw))
}

func userAuditSnapshot(account *user.User, role *user.Role) map[string]interface{} {
	roleName := ""
	if role != nil {
		roleName = role.Name
	}
	return map[string]interface{}{
		"id":        account.ID.String(),
		"username":  account.Username,
		"email":     account.Email,
		"role_id":   account.RoleID.String(),
		"role_name": roleName,
		"is_active": account.IsActive,
	}
}

// HandleCreateUser creates a new user
// POST /api/users
func (h *Handler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string    `json:"username"`
		Email    string    `json:"email"`
		Password string    `json:"password"`
		RoleID   uuid.UUID `json:"role_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	if err := validateManagedUserInput(input.Username, input.Email, input.Password, input.RoleID, true); err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	input.Username, input.Email, _ = normalizeManagedUserIdentity(input.Username, input.Email)
	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()
	if !h.ensureManagedIdentityAvailable(w, r, input.Username, input.Email, uuid.Nil) {
		return
	}
	role, ok := h.roleByID(w, r, input.RoleID)
	if !ok {
		return
	}

	// Hash Password
	hash, err := user.HashPassword(input.Password)
	if err != nil {
		h.Logger.Error("Failed to hash password", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newUser := &user.User{
		Username:     input.Username,
		Email:        input.Email,
		PasswordHash: hash,
		RoleID:       input.RoleID,
		IsActive:     true,
	}

	if err := h.UserRepo.CreateUser(r.Context(), newUser); err != nil {
		h.Logger.Error("Failed to create user", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.Logger.Info("User created", zap.String("username", newUser.Username))
	h.auditUserMutation(r, "user:create", newUser.ID, map[string]interface{}{
		"target": userAuditSnapshot(newUser, role),
	})

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "created", "id": newUser.ID.String()})
}

// HandleUpdateUser updates an existing user
// PUT /api/users
func (h *Handler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID       uuid.UUID `json:"id"`
		Username string    `json:"username"`
		Email    string    `json:"email"`
		RoleID   uuid.UUID `json:"role_id"`
		IsActive bool      `json:"is_active"`
		Password string    `json:"password"` // Optional, if empty don't update
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	if input.ID == uuid.Nil {
		h.JSONError(w, "user id is required", http.StatusBadRequest)
		return
	}
	if err := validateManagedUserInput(input.Username, input.Email, input.Password, input.RoleID, false); err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	input.Username, input.Email, _ = normalizeManagedUserIdentity(input.Username, input.Email)
	targetRole, ok := h.roleByID(w, r, input.RoleID)
	if !ok {
		return
	}

	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()

	// Fetch existing to get other fields
	existing, err := h.UserRepo.GetUserByID(r.Context(), input.ID)
	if err != nil {
		h.Logger.Error("Failed to fetch user for update", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existing == nil {
		h.JSONError(w, "User not found", http.StatusNotFound)
		return
	}
	if !h.ensureManagedIdentityAvailable(w, r, input.Username, input.Email, existing.ID) {
		return
	}
	previousRole, ok := h.roleByID(w, r, existing.RoleID)
	if !ok {
		return
	}
	if operatorID, ok := h.currentOperatorID(r); ok && operatorID == existing.ID && (!input.IsActive || input.RoleID != existing.RoleID) {
		h.JSONError(w, "You cannot deactivate yourself or change your own role. Ask another super administrator.", http.StatusConflict)
		return
	}
	if !h.protectLastSuperAdmin(w, r, existing, previousRole, input.RoleID, input.IsActive) {
		return
	}
	before := userAuditSnapshot(existing, previousRole)

	// Update fields
	existing.Username = input.Username
	existing.Email = input.Email
	existing.RoleID = input.RoleID
	existing.IsActive = input.IsActive

	if input.Password != "" {
		hash, err := user.HashPassword(input.Password)
		if err != nil {
			h.Logger.Error("Failed to hash password", zap.Error(err))
			h.JSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		existing.PasswordHash = hash
	}

	if err := h.UserRepo.UpdateUser(r.Context(), existing); err != nil {
		h.Logger.Error("Failed to update user", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	h.invalidateUserSessions(existing.ID)

	h.Logger.Info("User updated", zap.String("username", existing.Username))
	h.auditUserMutation(r, "user:update", existing.ID, map[string]interface{}{
		"before":           before,
		"after":            userAuditSnapshot(existing, targetRole),
		"password_changed": input.Password != "",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// HandleDeleteUser deletes a user
// DELETE /api/users?id=...
func (h *Handler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		h.JSONError(w, "Missing id", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		h.JSONError(w, "Invalid id", http.StatusBadRequest)
		return
	}

	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()

	existing, err := h.UserRepo.GetUserByID(r.Context(), id)
	if err != nil {
		h.Logger.Error("Failed to fetch user for deletion", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existing == nil {
		h.JSONError(w, "User not found", http.StatusNotFound)
		return
	}
	role, ok := h.roleByID(w, r, existing.RoleID)
	if !ok {
		return
	}
	if operatorID, ok := h.currentOperatorID(r); ok && operatorID == existing.ID {
		h.JSONError(w, "You cannot delete your own account. Ask another super administrator.", http.StatusConflict)
		return
	}
	if !h.protectLastSuperAdmin(w, r, existing, role, uuid.Nil, false) {
		return
	}

	if err := h.UserRepo.DeleteUser(r.Context(), id); err != nil {
		h.Logger.Error("Failed to delete user", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	h.invalidateUserSessions(id)

	h.Logger.Info("User deactivated", zap.String("id", id.String()))
	h.auditUserMutation(r, "user:deactivate", id, map[string]interface{}{
		"target": userAuditSnapshot(existing, role),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deactivated"})
}
