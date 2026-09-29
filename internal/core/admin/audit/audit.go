package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/divinelab-io/aegis/internal/infra/transport"
	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const auditWriteTimeout = 3 * time.Second

// AuditLogger handles creation of audit logs
type AuditLogger struct {
	repo     user.Repository
	sessions *scs.SessionManager
	logger   *zap.Logger
	realIP   *transport.RealIPResolver

	writeSuccesses       atomic.Uint64
	writeFailures        atomic.Uint64
	lastWriteSuccessUnix atomic.Int64
	lastWriteFailureUnix atomic.Int64
	writeSequence        atomic.Uint64
	lastWriteSuccessSeq  atomic.Uint64
	lastWriteFailureSeq  atomic.Uint64

	retentionDays            atomic.Int64
	retentionRuns            atomic.Uint64
	retentionFailures        atomic.Uint64
	lastRetentionRunUnix     atomic.Int64
	lastRetentionFailureUnix atomic.Int64
	lastRetentionDeleted     atomic.Int64
	retentionStarted         atomic.Bool
}

// WriteStatus is process-local audit persistence health. It deliberately
// exposes counters and time only; database errors can contain deployment
// details and must remain in the server log.
type WriteStatus struct {
	SuccessfulWrites uint64
	FailedWrites     uint64
	LastSuccessAt    time.Time
	LastFailureAt    time.Time
	LastOutcome      string
}

// RetentionStatus is process-local operational evidence for the primary audit
// log cleanup worker. Retention remains disabled until the self-hosted operator
// sets server.admin.audit_retention_days to a positive value.
type RetentionStatus struct {
	Enabled       bool
	RetentionDays int
	Runs          uint64
	Failures      uint64
	LastRunAt     time.Time
	LastFailureAt time.Time
	LastDeleted   int64
}

func NewAuditLogger(repo user.Repository, sessions *scs.SessionManager, logger *zap.Logger) *AuditLogger {
	return &AuditLogger{
		repo:     repo,
		sessions: sessions,
		logger:   logger,
	}
}

// SetRealIPResolver configures trusted client-IP resolution for audit events.
// It is set during server construction before requests are served.
func (a *AuditLogger) SetRealIPResolver(resolver *transport.RealIPResolver) {
	if a != nil {
		a.realIP = resolver
	}
}

// Log records an action in the audit log. Callers that cannot safely fail the
// already-completed operation still receive the error so they can surface it
// through their own durable control-plane policy.
func (a *AuditLogger) Log(r *http.Request, action string, resource string, metadata string) error {
	// Audit persistence runs only on the administrative control plane, but it
	// must still have a hard deadline. A control-database outage must not leave
	// an admin request waiting indefinitely after its primary action completes.
	ctx, cancel := context.WithTimeout(r.Context(), auditWriteTimeout)
	defer cancel()

	username := a.sessions.GetString(ctx, "user_id")
	userUUID := a.sessions.GetString(ctx, "user_uuid")
	// A verified password plus an MFA challenge is not a fully authenticated
	// session, but it is still useful to attribute a failed MFA attempt to the
	// account that entered the challenge. The pre-auth id is server-issued and
	// short-lived; never derive an actor from request input.
	if userUUID == "" {
		userUUID = a.sessions.GetString(ctx, "pre_auth_user_id")
	}

	var userID *uuid.UUID
	var actor *user.User

	if parsed, err := uuid.Parse(userUUID); err == nil {
		userID = &parsed
	} else if username != "" {
		u, err := a.repo.GetUserByUsername(ctx, username)
		if err == nil && u != nil {
			userID = &u.ID
			actor = u
		}
	}
	if userID != nil && username == "" {
		u, err := a.repo.GetUserByID(ctx, *userID)
		if err == nil && u != nil {
			username = u.Username
			actor = u
		}
	}
	actorRoleID := a.sessions.GetString(ctx, "role_id")
	if actorRoleID == "" && actor != nil {
		actorRoleID = actor.RoleID.String()
	}

	peerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if peerIP == "" {
		peerIP = r.RemoteAddr
	}
	clientIP := peerIP
	ipSource := "remote_addr"
	if a.realIP != nil {
		info := a.realIP.Resolve(r)
		if info.IP != "" {
			clientIP = info.IP
		}
		if info.ImmediatePeer != "" {
			peerIP = info.ImmediatePeer
		}
		if info.Source != "" {
			ipSource = info.Source
		}
	}

	log := &user.AuditLog{
		ID:              uuid.New(),
		UserID:          userID,
		ActorUsername:   username,
		ActorRoleID:     actorRoleID,
		Action:          action,
		Resource:        resource,
		Metadata:        metadata,
		IPAddress:       clientIP,
		PeerIPAddress:   peerIP,
		IPAddressSource: ipSource,
		CreatedAt:       time.Now().UTC(),
	}

	if err := a.repo.CreateAuditLog(ctx, log); err != nil {
		sequence := a.writeSequence.Add(1)
		a.writeFailures.Add(1)
		a.lastWriteFailureUnix.Store(time.Now().UTC().UnixNano())
		a.lastWriteFailureSeq.Store(sequence)
		if a.logger != nil {
			a.logger.Error("Failed to write audit log", zap.Error(err))
		}
		return err
	}
	sequence := a.writeSequence.Add(1)
	a.writeSuccesses.Add(1)
	a.lastWriteSuccessUnix.Store(time.Now().UTC().UnixNano())
	a.lastWriteSuccessSeq.Store(sequence)
	return nil
}

// WriteStatus reports only non-sensitive, in-process audit writer health.
// The counters reset on restart, while durable audit events remain in
// PostgreSQL.
func (a *AuditLogger) WriteStatus() WriteStatus {
	if a == nil {
		return WriteStatus{}
	}
	status := WriteStatus{
		SuccessfulWrites: a.writeSuccesses.Load(),
		FailedWrites:     a.writeFailures.Load(),
	}
	if succeededAt := a.lastWriteSuccessUnix.Load(); succeededAt > 0 {
		status.LastSuccessAt = time.Unix(0, succeededAt).UTC()
	}
	if failedAt := a.lastWriteFailureUnix.Load(); failedAt > 0 {
		status.LastFailureAt = time.Unix(0, failedAt).UTC()
	}
	if successSeq, failureSeq := a.lastWriteSuccessSeq.Load(), a.lastWriteFailureSeq.Load(); successSeq > failureSeq {
		status.LastOutcome = "success"
	} else if failureSeq > 0 {
		status.LastOutcome = "failure"
	}
	return status
}

// ConfigureRetention records the operator-selected audit history window.
// A zero value is intentionally disabled: audit history is evidence and must
// not disappear merely because an installation upgraded.
func (a *AuditLogger) ConfigureRetention(days int) {
	if a == nil {
		return
	}
	if days < 0 {
		days = 0
	}
	a.retentionDays.Store(int64(days))
}

// StartRetention starts a low-frequency cleanup loop when retention is
// explicitly enabled. It runs once at startup and then every 24 hours. The
// caller provides the process lifecycle context so no orphan worker survives
// server shutdown.
func (a *AuditLogger) StartRetention(ctx context.Context) {
	if a == nil || a.retentionDays.Load() <= 0 || !a.retentionStarted.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer a.retentionStarted.Store(false)
		_, _ = a.RunRetention(ctx)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = a.RunRetention(ctx)
			}
		}
	}()
}

// RunRetention performs one configured cleanup. It is exported for controlled
// maintenance and focused verification; it is a no-op while retention is off.
func (a *AuditLogger) RunRetention(ctx context.Context) (int64, error) {
	if a == nil || a.retentionDays.Load() <= 0 {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -int(a.retentionDays.Load()))
	operationCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	a.retentionRuns.Add(1)
	a.lastRetentionRunUnix.Store(time.Now().UTC().UnixNano())
	deleted, err := a.repo.PruneAuditLogs(operationCtx, cutoff)
	if err != nil {
		a.retentionFailures.Add(1)
		a.lastRetentionFailureUnix.Store(time.Now().UTC().UnixNano())
		if a.logger != nil {
			a.logger.Warn("Failed to prune audit logs", zap.Error(err))
		}
		return 0, err
	}
	a.lastRetentionDeleted.Store(deleted)
	if a.logger != nil {
		a.logger.Info("Pruned expired audit logs", zap.Int64("deleted", deleted), zap.Time("before", cutoff))
	}
	return deleted, nil
}

// RetentionStatus reports configuration and only non-sensitive worker health.
func (a *AuditLogger) RetentionStatus() RetentionStatus {
	if a == nil {
		return RetentionStatus{}
	}
	status := RetentionStatus{
		RetentionDays: int(a.retentionDays.Load()),
		Runs:          a.retentionRuns.Load(),
		Failures:      a.retentionFailures.Load(),
		LastDeleted:   a.lastRetentionDeleted.Load(),
	}
	status.Enabled = status.RetentionDays > 0
	if value := a.lastRetentionRunUnix.Load(); value > 0 {
		status.LastRunAt = time.Unix(0, value).UTC()
	}
	if value := a.lastRetentionFailureUnix.Load(); value > 0 {
		status.LastFailureAt = time.Unix(0, value).UTC()
	}
	return status
}

// LogConfigMutation wraps a mutating admin/config endpoint and records its
// outcome after the handler has completed. Rejected changes are kept only for
// an authenticated operator so unauthenticated probes cannot fill the durable
// control-plane log.
func (a *AuditLogger) LogConfigMutation(resource string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := captureAuditBody(r)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		if !isMutatingMethod(r.Method) || shouldSkipConfigAudit(r.URL.Path) {
			return
		}
		rejected := rec.status >= http.StatusBadRequest
		if rejected && !a.hasAuthenticatedSession(r) {
			return
		}

		metadata := map[string]interface{}{
			"method":   r.Method,
			"path":     r.URL.Path,
			"status":   rec.status,
			"username": a.sessions.GetString(r.Context(), "user_id"),
			"outcome":  "applied",
		}
		if rejected {
			metadata["outcome"] = "rejected"
		}
		if fields := auditQueryFields(r.URL.Query()); len(fields) > 0 {
			// Do not persist query values. They often contain short-lived tokens
			// and credentials, while the field names remain useful audit context.
			metadata["query_fields"] = fields
		}
		if fields := auditJSONFields(body); len(fields) > 0 {
			metadata["fields"] = fields
		}
		if revision := rec.Header().Get("X-Aegis-Config-Revision"); revision != "" {
			metadata["revision"] = revision
		}
		raw, err := json.Marshal(metadata)
		if err != nil {
			raw = []byte("{}")
		}

		action := configAuditAction(r.Method)
		if rejected {
			action = "config:rejected"
		}
		_ = a.Log(r, action, resource, string(raw))
	})
}

func (a *AuditLogger) hasAuthenticatedSession(r *http.Request) bool {
	if a == nil || a.sessions == nil || r == nil {
		return false
	}
	_, err := uuid.Parse(a.sessions.GetString(r.Context(), "user_uuid"))
	return err == nil
}

func captureAuditBody(r *http.Request) []byte {
	if r.Body == nil || !isMutatingMethod(r.Method) {
		return nil
	}
	// Multipart bodies may contain private keys and can be much larger than the
	// audit limit. Do not consume, truncate, or record them; method/path/status
	// still provide a safe mutation audit entry.
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/") {
		return nil
	}
	original := r.Body
	body, err := io.ReadAll(io.LimitReader(original, 64*1024))
	r.Body = &auditReplayBody{
		Reader: io.MultiReader(bytes.NewReader(body), original),
		Closer: original,
	}
	if err != nil {
		return nil
	}
	return body
}

type auditReplayBody struct {
	io.Reader
	io.Closer
}

func auditJSONFields(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil || len(payload) == 0 {
		return nil
	}
	fields := make([]string, 0, len(payload))
	for key := range payload {
		key = strings.TrimSpace(key)
		if key != "" {
			fields = append(fields, key)
		}
	}
	sort.Strings(fields)
	return fields
}

func auditQueryFields(values map[string][]string) []string {
	if len(values) == 0 {
		return nil
	}
	fields := make([]string, 0, len(values))
	for key := range values {
		key = strings.TrimSpace(key)
		if key != "" {
			fields = append(fields, key)
		}
	}
	sort.Strings(fields)
	return fields
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(body)
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func shouldSkipConfigAudit(path string) bool {
	path = strings.TrimSuffix(path, "/")
	return strings.HasSuffix(path, "/config/test") ||
		strings.HasSuffix(path, "/test") ||
		strings.HasSuffix(path, "/test-payload") ||
		strings.HasSuffix(path, "/test_payload")
}

func configAuditAction(method string) string {
	switch method {
	case http.MethodPost:
		return "config:create"
	case http.MethodDelete:
		return "config:delete"
	default:
		return "config:update"
	}
}
