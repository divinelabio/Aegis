package user

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Repository defines the contract for user data persistence
type Repository interface {
	// User Management
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	ListUsers(ctx context.Context, limit, offset int) ([]User, error)
	UpdateMFASecret(ctx context.Context, id uuid.UUID, secret string, enabled bool) error
	IncrementFailedLogin(ctx context.Context, username string) error
	ResetFailedLogin(ctx context.Context, username string) error
	CountUsers(ctx context.Context) (int64, error)

	// Role Management
	CreateRole(ctx context.Context, role *Role) error
	GetRoleByID(ctx context.Context, id uuid.UUID) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	ListRoles(ctx context.Context) ([]Role, error)
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, id uuid.UUID) error
	CountActiveUsersByRole(ctx context.Context, roleID uuid.UUID) (int64, error)
	CountUsersByRole(ctx context.Context, roleID uuid.UUID) (int64, error)

	// Permissions
	GetPermissionsForRole(ctx context.Context, roleID uuid.UUID) ([]Permission, error)
	ListPermissionsForRoles(ctx context.Context) (map[uuid.UUID][]Permission, error)
	ListPermissions(ctx context.Context) ([]Permission, error)
	SetPermissionsForRole(ctx context.Context, roleID uuid.UUID, permissions []Permission) error

	// Audit
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error)
	QueryAuditLogs(ctx context.Context, query AuditLogQuery) ([]AuditLog, error)
	PruneAuditLogs(ctx context.Context, before time.Time) (int64, error)

	// Password Reset
	CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time, ip string) error
	GetPasswordResetToken(ctx context.Context, tokenHash string) (*PasswordResetToken, error)
	// ConsumePasswordResetToken atomically claims a valid, unused reset token.
	// A consumed token must never be accepted again, including under concurrent requests.
	ConsumePasswordResetToken(ctx context.Context, tokenHash string, now time.Time) (*PasswordResetToken, error)
	MarkPasswordResetTokenUsed(ctx context.Context, id uuid.UUID) error
	DeletePasswordResetToken(ctx context.Context, id uuid.UUID) error
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func boolToUInt8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}
