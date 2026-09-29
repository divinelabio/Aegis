package user

import (
	"time"

	"github.com/google/uuid"
)

// Role represents a user role (e.g., super_admin, admin, auditor, viewer)
type Role struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// User represents a system user
type User struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	RoleID       uuid.UUID `json:"role_id" db:"role_id"`
	Role         *Role     `json:"role,omitempty" db:"-"` // Associated Role

	MFASecret  string `json:"-" db:"mfa_secret"`
	MFAEnabled bool   `json:"mfa_enabled" db:"mfa_enabled"`

	IsActive            bool      `json:"is_active" db:"is_active"`
	LastLoginAt         time.Time `json:"last_login_at" db:"last_login_at"`
	FailedLoginAttempts int       `json:"failed_login_attempts" db:"failed_login_attempts"`
	LockedUntil         time.Time `json:"locked_until" db:"locked_until"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time `json:"updated_at" db:"updated_at"`
	Version             int       `json:"-" db:"version"`
}

// Permission represents a specific capability
type Permission struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Slug        string    `json:"slug" db:"slug"` // e.g., 'rules:write'
	Description string    `json:"description" db:"description"`
}

// Session represents a user session (for introspection/admin view)
type Session struct {
	TokenHash string    `json:"-" db:"token_hash"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	IPAddress string    `json:"ip_address" db:"ip_address"`
	UserAgent string    `json:"user_agent" db:"user_agent"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// AuditLog represents a record of an administrative action
type AuditLog struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	UserID          *uuid.UUID `json:"user_id" db:"user_id"`
	ActorUsername   string     `json:"actor_username" db:"actor_username"`
	ActorRoleID     string     `json:"actor_role_id" db:"actor_role_id"`
	Action          string     `json:"action" db:"action"`
	Resource        string     `json:"resource" db:"resource"`
	Metadata        string     `json:"metadata" db:"metadata"` // JSON stored as string
	IPAddress       string     `json:"ip_address" db:"ip_address"`
	PeerIPAddress   string     `json:"peer_ip_address" db:"peer_ip_address"`
	IPAddressSource string     `json:"ip_address_source" db:"ip_address_source"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
}

// AuditLogCursor identifies a stable position in reverse chronological audit
// history. The (created_at, id) pair prevents duplicate or skipped records
// when multiple events share the same timestamp.
type AuditLogCursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

// AuditLogQuery is a bounded, index-friendly audit history query. Filters are
// exact-match by design so operator searches remain predictable on a local
// PostgreSQL control plane.
type AuditLogQuery struct {
	Limit         int
	Cursor        *AuditLogCursor
	Action        string
	ActorUsername string
	From          *time.Time
	To            *time.Time
}

// PasswordResetToken represents a token for resetting a password
type PasswordResetToken struct {
	ID        uuid.UUID `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	TokenHash string    `json:"-" db:"token_hash"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Used      bool      `json:"used" db:"used"`
	IPAddress string    `json:"ip_address" db:"ip_address"` // Added
	CreatedAt time.Time `json:"created_at" db:"created_at"` // Added
}
