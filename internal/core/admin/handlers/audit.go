package handlers

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	defaultAuditPageSize   = 100
	maximumAuditPageSize   = 250
	defaultAuditExportSize = 1000
	maximumAuditExportSize = 5000
)

type auditLogView struct {
	ID              string `json:"id"`
	UserID          string `json:"user_id,omitempty"`
	Username        string `json:"username"`
	ActorRoleID     string `json:"actor_role_id,omitempty"`
	Action          string `json:"action"`
	Resource        string `json:"resource"`
	Details         string `json:"details"`
	IPAddress       string `json:"ip_address"`
	PeerIPAddress   string `json:"peer_ip_address,omitempty"`
	IPAddressSource string `json:"ip_address_source,omitempty"`
	CreatedAt       string `json:"created_at"`
}

// HandleListAuditLogs returns one bounded, reverse-chronological page of audit
// history. Filters are exact-match and the cursor is opaque and stable across
// events with the same timestamp.
// GET /api/audit-logs?limit=100&cursor=&action=&actor=&from=&to=
func (h *Handler) HandleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query, err := auditLogQueryFromRequest(r, defaultAuditPageSize, maximumAuditPageSize)
	if err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	logs, hasNext, err := h.queryAuditLogs(r, query)
	if err != nil {
		h.Logger.Error("Failed to query audit logs", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	views := h.auditLogViews(r, logs, true)
	meta := h.auditLogMeta(query.Limit, len(views))
	if hasNext && len(logs) > 0 {
		meta["next_cursor"] = encodeAuditCursor(user.AuditLogCursor{CreatedAt: logs[len(logs)-1].CreatedAt, ID: logs[len(logs)-1].ID})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"data": views,
		"meta": meta,
	})
}

// HandleExportAuditLogs generates a bounded CSV of the same audit query used
// by the page. It deliberately omits raw metadata to preserve the redaction
// boundary enforced for the UI and avoids unbounded control-plane reads.
// GET /api/audit-logs/export?limit=1000&action=&actor=&from=&to=
func (h *Handler) HandleExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query, err := auditLogQueryFromRequest(r, defaultAuditExportSize, maximumAuditExportSize)
	if err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	logs, hasNext, err := h.queryAuditLogs(r, query)
	if err != nil {
		h.Logger.Error("Failed to export audit logs", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	views := h.auditLogViews(r, logs, false)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"aegis-audit-logs-%s.csv\"", time.Now().UTC().Format("20060102-150405")))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if hasNext {
		w.Header().Set("X-Aegis-Export-Truncated", "true")
	}

	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"Timestamp", "Actor", "Actor role ID", "Action", "Resource", "Details", "Client IP", "Proxy peer IP", "IP source"})
	for _, entry := range views {
		_ = writer.Write([]string{
			safeAuditCSVCell(entry.CreatedAt),
			safeAuditCSVCell(entry.Username),
			safeAuditCSVCell(entry.ActorRoleID),
			safeAuditCSVCell(entry.Action),
			safeAuditCSVCell(entry.Resource),
			safeAuditCSVCell(entry.Details),
			safeAuditCSVCell(entry.IPAddress),
			safeAuditCSVCell(entry.PeerIPAddress),
			safeAuditCSVCell(entry.IPAddressSource),
		})
	}
	writer.Flush()
	if err := writer.Error(); err != nil && h.Logger != nil {
		h.Logger.Warn("Failed to write audit CSV response", zap.Error(err))
	}
}

func (h *Handler) queryAuditLogs(r *http.Request, query user.AuditLogQuery) ([]user.AuditLog, bool, error) {
	query.Limit++ // fetch one extra record to make pagination/export truncation explicit
	logs, err := h.UserRepo.QueryAuditLogs(r.Context(), query)
	if err != nil {
		return nil, false, err
	}
	hasNext := len(logs) > query.Limit-1
	if hasNext {
		logs = logs[:query.Limit-1]
	}
	return logs, hasNext, nil
}

func (h *Handler) auditLogViews(r *http.Request, logs []user.AuditLog, resolveLegacyActors bool) []auditLogView {
	views := make([]auditLogView, 0, len(logs))
	usernameCache := make(map[string]string)
	for _, log := range logs {
		userID := ""
		if log.UserID != nil {
			userID = log.UserID.String()
		}
		username := log.ActorUsername
		if username == "" {
			username = "System"
			if resolveLegacyActors && log.UserID != nil {
				if cached, ok := usernameCache[userID]; ok {
					username = cached
				} else if u, err := h.UserRepo.GetUserByID(r.Context(), *log.UserID); err == nil && u != nil {
					username = u.Username
					usernameCache[userID] = username
				} else {
					username = "Unknown user"
					usernameCache[userID] = username
				}
			}
		}
		views = append(views, auditLogView{
			ID:              log.ID.String(),
			UserID:          userID,
			Username:        username,
			ActorRoleID:     log.ActorRoleID,
			Action:          log.Action,
			Resource:        log.Resource,
			Details:         auditDetails(log.Action, log.Resource, log.Metadata),
			IPAddress:       log.IPAddress,
			PeerIPAddress:   log.PeerIPAddress,
			IPAddressSource: log.IPAddressSource,
			CreatedAt:       log.CreatedAt.Format("2006-01-02T15:04:05.000Z07:00"),
		})
	}
	return views
}

func (h *Handler) auditLogMeta(limit, count int) map[string]interface{} {
	meta := map[string]interface{}{
		"limit": limit,
		"count": count,
	}
	if h.Audit != nil {
		status := h.Audit.WriteStatus()
		meta["write_successes_total"] = status.SuccessfulWrites
		meta["write_failures_total"] = status.FailedWrites
		if !status.LastSuccessAt.IsZero() {
			meta["last_write_success_at"] = status.LastSuccessAt.Format(time.RFC3339Nano)
		}
		if !status.LastFailureAt.IsZero() {
			meta["last_write_failure_at"] = status.LastFailureAt.Format(time.RFC3339Nano)
		}
		if status.LastOutcome != "" {
			meta["last_write_outcome"] = status.LastOutcome
		}
		retention := h.Audit.RetentionStatus()
		retentionMeta := map[string]interface{}{
			"enabled":        retention.Enabled,
			"retention_days": retention.RetentionDays,
			"runs_total":     retention.Runs,
			"failures_total": retention.Failures,
			"last_deleted":   retention.LastDeleted,
		}
		if !retention.LastRunAt.IsZero() {
			retentionMeta["last_run_at"] = retention.LastRunAt.Format(time.RFC3339Nano)
		}
		if !retention.LastFailureAt.IsZero() {
			retentionMeta["last_failure_at"] = retention.LastFailureAt.Format(time.RFC3339Nano)
		}
		meta["retention"] = retentionMeta
	}
	return meta
}

type auditCursorPayload struct {
	CreatedAt string `json:"created_at"`
	ID        string `json:"id"`
}

func auditLogQueryFromRequest(r *http.Request, defaultLimit, maximumLimit int) (user.AuditLogQuery, error) {
	values := r.URL.Query()
	limit := defaultLimit
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maximumLimit {
			return user.AuditLogQuery{}, fmt.Errorf("limit must be between 1 and %d", maximumLimit)
		}
		limit = parsed
	}
	action, err := auditLogFilterValue("action", values.Get("action"))
	if err != nil {
		return user.AuditLogQuery{}, err
	}
	actor, err := auditLogFilterValue("actor", values.Get("actor"))
	if err != nil {
		return user.AuditLogQuery{}, err
	}
	from, err := auditLogFilterTime("from", values.Get("from"))
	if err != nil {
		return user.AuditLogQuery{}, err
	}
	to, err := auditLogFilterTime("to", values.Get("to"))
	if err != nil {
		return user.AuditLogQuery{}, err
	}
	if from != nil && to != nil && from.After(*to) {
		return user.AuditLogQuery{}, fmt.Errorf("from must be before to")
	}
	cursor, err := decodeAuditCursor(values.Get("cursor"))
	if err != nil {
		return user.AuditLogQuery{}, err
	}
	return user.AuditLogQuery{
		Limit:         limit,
		Cursor:        cursor,
		Action:        action,
		ActorUsername: actor,
		From:          from,
		To:            to,
	}, nil
}

func auditLogFilterValue(name, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("invalid %s filter", name)
	}
	return value, nil
}

func auditLogFilterTime(name, raw string) (*time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("%s must be an RFC3339 timestamp", name)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func encodeAuditCursor(cursor user.AuditLogCursor) string {
	payload, _ := json.Marshal(auditCursorPayload{CreatedAt: cursor.CreatedAt.UTC().Format(time.RFC3339Nano), ID: cursor.ID.String()})
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeAuditCursor(raw string) (*user.AuditLogCursor, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, nil
	}
	if len(value) > 512 {
		return nil, fmt.Errorf("invalid audit cursor")
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid audit cursor")
	}
	var decoded auditCursorPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, fmt.Errorf("invalid audit cursor")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, decoded.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("invalid audit cursor")
	}
	id, err := uuid.Parse(decoded.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid audit cursor")
	}
	return &user.AuditLogCursor{CreatedAt: createdAt.UTC(), ID: id}, nil
}

// safeAuditCSVCell prevents spreadsheet applications from treating audit data
// as a formula when an operator opens an export locally.
func safeAuditCSVCell(value string) string {
	if value == "" {
		return ""
	}
	if strings.ContainsAny(value[:1], "=+-@") {
		return "'" + value
	}
	return value
}

func auditDetails(action, resource, metadata string) string {
	if !strings.HasPrefix(action, "config:") {
		if strings.TrimSpace(metadata) != "" && !strings.HasPrefix(strings.TrimSpace(metadata), "{") {
			return metadata
		}
		return strings.TrimPrefix(action, "auth:")
	}

	var meta map[string]interface{}
	_ = json.Unmarshal([]byte(metadata), &meta)
	path, _ := meta["path"].(string)
	target := auditTargetLabel(resource, path)

	switch action {
	case "config:create":
		return fmt.Sprintf("Created %s", target)
	case "config:delete":
		return fmt.Sprintf("Deleted %s", target)
	case "config:rejected":
		return fmt.Sprintf("Rejected change to %s", target)
	default:
		return fmt.Sprintf("Updated %s", target)
	}
}

func auditTargetLabel(resource, path string) string {
	if strings.HasPrefix(path, "/api/sections/") {
		section := strings.TrimPrefix(path, "/api/sections/")
		section = strings.Trim(section, "/")
		if slash := strings.Index(section, "/"); slash >= 0 {
			section = section[:slash]
		}
		return auditTitle(strings.ReplaceAll(section, "_", " ")) + " configuration"
	}

	labels := map[string]string{
		"system.config":               "system configuration",
		"modules.captcha":             "CAPTCHA configuration",
		"modules.challenge":           "challenge configuration",
		"modules.reputation":          "reputation configuration",
		"infrastructure.upstreams":    "origin pools",
		"infrastructure.routes":       "routing rules",
		"infrastructure.certificates": "certificate configuration",
		"security.bot.rules":          "Bot Protection rule",
	}
	if label, ok := labels[resource]; ok {
		return label
	}
	if resource != "" {
		return strings.ReplaceAll(resource, ".", " ")
	}
	return "configuration"
}

func auditTitle(value string) string {
	parts := strings.Fields(value)
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}
