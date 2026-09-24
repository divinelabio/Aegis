package operatorcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/storage"
	"github.com/google/uuid"
)

// IdentityService provides the intentionally small local-recovery surface.
// Its commands operate on the transactional PostgreSQL identity source, not
// ClickHouse analytics, and leave the runtime security configuration alone.
type IdentityService struct {
	repo user.Repository
}

type UserSummary struct {
	ID        uuid.UUID `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	RoleID    uuid.UUID `json:"role_id"`
	IsActive  bool      `json:"is_active"`
	LastLogin time.Time `json:"last_login_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// OpenIdentity opens the PostgreSQL control plane without requiring the admin
// password currently configured for server bootstrap.
func OpenIdentity(ctx context.Context, configPath string) (*IdentityService, func(), error) {
	cfg, err := config.LoadControlPlaneConfig(configPath)
	if err != nil {
		return nil, nil, err
	}
	pool, err := storage.InitControlDB(ctx, cfg.Storage.Control)
	if err != nil {
		return nil, nil, err
	}
	repo, err := user.NewPostgreSQLRepository(ctx, pool)
	if err != nil {
		storage.CloseControlDB()
		return nil, nil, err
	}
	return &IdentityService{repo: repo}, storage.CloseControlDB, nil
}

func (s *IdentityService) List(ctx context.Context, limit int) ([]UserSummary, error) {
	if limit < 1 || limit > 500 {
		return nil, errors.New("limit must be between 1 and 500")
	}
	users, err := s.repo.ListUsers(ctx, limit, 0)
	if err != nil {
		return nil, err
	}
	results := make([]UserSummary, 0, len(users))
	for _, current := range users {
		results = append(results, UserSummary{
			ID: current.ID, Username: current.Username, Email: current.Email, RoleID: current.RoleID,
			IsActive: current.IsActive, LastLogin: current.LastLoginAt, CreatedAt: current.CreatedAt,
		})
	}
	return results, nil
}

// ResetPassword replaces a local identity password, clears a lockout, and
// advances the identity revision so authenticated Admin API sessions are
// rejected on their next request.
func (s *IdentityService) ResetPassword(ctx context.Context, username, password string) error {
	if len(password) < 12 {
		return errors.New("new password must be at least 12 characters")
	}
	target, err := s.lookup(ctx, username)
	if err != nil {
		return err
	}
	hash, err := user.HashPassword(password)
	if err != nil {
		return err
	}
	target.PasswordHash = hash
	target.FailedLoginAttempts = 0
	target.LockedUntil = time.Time{}
	target.UpdatedAt = time.Now().UTC()
	if err := s.repo.UpdateUser(ctx, target); err != nil {
		return err
	}
	return s.audit(ctx, target, "cli:user_reset_password", map[string]any{"sessions_invalidated": true})
}

// ResetMFA removes a lost TOTP factor and advances the identity revision. The
// operator must re-enrol the factor through the authenticated Admin UI.
func (s *IdentityService) ResetMFA(ctx context.Context, username string) error {
	target, err := s.lookup(ctx, username)
	if err != nil {
		return err
	}
	if err := s.repo.UpdateMFASecret(ctx, target.ID, "", false); err != nil {
		return err
	}
	return s.audit(ctx, target, "cli:mfa_reset", map[string]any{"sessions_invalidated": true, "mfa_reenrollment_required": true})
}

func (s *IdentityService) SetActive(ctx context.Context, username string, active bool) error {
	target, err := s.lookup(ctx, username)
	if err != nil {
		return err
	}
	if !active && target.IsActive {
		role, err := s.repo.GetRoleByID(ctx, target.RoleID)
		if err != nil {
			return err
		}
		if role != nil && role.Name == "super_admin" {
			count, err := s.repo.CountActiveUsersByRole(ctx, target.RoleID)
			if err != nil {
				return err
			}
			if count <= 1 {
				return errors.New("refusing to disable the last active super administrator")
			}
		}
	}
	target.IsActive = active
	target.UpdatedAt = time.Now().UTC()
	if err := s.repo.UpdateUser(ctx, target); err != nil {
		return err
	}
	action := "cli:user_enable"
	if !active {
		action = "cli:user_disable"
	}
	return s.audit(ctx, target, action, map[string]any{"sessions_invalidated": true})
}

// RevokeSessions advances the identity revision. The Admin authentication
// middleware validates that revision for every protected request, making all
// existing sessions for this user invalid without deleting unrelated data.
func (s *IdentityService) RevokeSessions(ctx context.Context, username string) error {
	target, err := s.lookup(ctx, username)
	if err != nil {
		return err
	}
	target.UpdatedAt = time.Now().UTC()
	if err := s.repo.UpdateUser(ctx, target); err != nil {
		return err
	}
	return s.audit(ctx, target, "cli:user_revoke_sessions", map[string]any{"sessions_invalidated": true})
}

func (s *IdentityService) lookup(ctx context.Context, username string) (*user.User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is required")
	}
	target, err := s.repo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, fmt.Errorf("user %q was not found", username)
	}
	return target, nil
}

func (s *IdentityService) audit(ctx context.Context, target *user.User, action string, metadata map[string]any) error {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	userID := target.ID
	return s.repo.CreateAuditLog(ctx, &user.AuditLog{
		UserID:          &userID,
		ActorUsername:   "aegisctl",
		ActorRoleID:     "local_operator",
		Action:          action,
		Resource:        "user/" + target.Username,
		Metadata:        string(encoded),
		IPAddress:       "local",
		PeerIPAddress:   "local",
		IPAddressSource: "local_cli",
		CreatedAt:       time.Now().UTC(),
	})
}
