package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/divinelab-io/aegis/internal/sections"
	"go.uber.org/zap"
)

// alertItem is the compact in-app notification contract. It intentionally
// represents only current operational conditions; it has no external delivery
// channels or background dispatch work.
type alertItem struct {
	ID          string                 `json:"id"`
	Level       string                 `json:"level"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	CreatedAt   string                 `json:"created_at"`
	Read        bool                   `json:"read"`
	Source      string                 `json:"source,omitempty"`
	Route       string                 `json:"route,omitempty"`
	ActionLabel string                 `json:"action_label,omitempty"`
	Unresolved  bool                   `json:"unresolved"`
	Meta        map[string]interface{} `json:"meta,omitempty"`
}

type alertStateFile struct {
	FirstSeen  map[string]time.Time            `json:"first_seen"`
	ReadByUser map[string]map[string]time.Time `json:"read_by_user"`
}

// alertStateStore keeps the small amount of durable state an in-app inbox
// needs: when an active condition first appeared and which operator read it.
// Conditions themselves are rebuilt from the current section health/status
// snapshot, so resolved conditions naturally disappear.
type alertStateStore struct {
	path         string
	refreshEvery time.Duration
	refreshedAt  time.Time
	alerts       map[string]alertItem
	firstSeen    map[string]time.Time
	readByUser   map[string]map[string]time.Time
	stateMu      sync.Mutex
}

func newAlertStateStore(path string, refreshEvery time.Duration) *alertStateStore {
	state := &alertStateStore{
		path:         path,
		refreshEvery: refreshEvery,
		alerts:       make(map[string]alertItem),
		firstSeen:    make(map[string]time.Time),
		readByUser:   make(map[string]map[string]time.Time),
	}
	if path == "" {
		return state
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return state
	}
	var persisted alertStateFile
	if err := json.Unmarshal(contents, &persisted); err != nil {
		return state
	}
	if persisted.FirstSeen != nil {
		state.firstSeen = persisted.FirstSeen
	}
	if persisted.ReadByUser != nil {
		state.readByUser = persisted.ReadByUser
	}
	return state
}

func (s *alertStateStore) refreshDue(now time.Time) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.refreshedAt.IsZero() || now.Sub(s.refreshedAt) >= s.refreshEvery
}

func (s *alertStateStore) sync(now time.Time, current []alertItem) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	next := make(map[string]alertItem, len(current))
	changed := false
	for _, item := range current {
		item.ID = strings.TrimSpace(item.ID)
		if item.ID == "" {
			continue
		}
		firstSeen, exists := s.firstSeen[item.ID]
		if !exists {
			firstSeen = now.UTC()
			s.firstSeen[item.ID] = firstSeen
			changed = true
		}
		item.CreatedAt = firstSeen.Format(time.RFC3339Nano)
		item.Read = false
		item.Unresolved = true
		next[item.ID] = item
	}

	for id := range s.firstSeen {
		if _, active := next[id]; active {
			continue
		}
		delete(s.firstSeen, id)
		changed = true
	}
	for userID, readIDs := range s.readByUser {
		for id := range readIDs {
			if _, active := next[id]; active {
				continue
			}
			delete(readIDs, id)
			changed = true
		}
		if len(readIDs) == 0 {
			delete(s.readByUser, userID)
		}
	}

	s.alerts = next
	s.refreshedAt = now
	if !changed {
		return nil
	}
	return s.persistLocked()
}

func (s *alertStateStore) list(userID string) []alertItem {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	readIDs := s.readByUser[userID]
	items := make([]alertItem, 0, len(s.alerts))
	for _, item := range s.alerts {
		item.Read = !readIDs[item.ID].IsZero()
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		leftRank, rightRank := alertSeverityRank(items[i].Level), alertSeverityRank(items[j].Level)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		return items[i].CreatedAt > items[j].CreatedAt
	})
	return items
}

func (s *alertStateStore) markRead(userID string, ids []string, all bool, now time.Time) (int, error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	if userID == "" {
		return 0, errors.New("authenticated operator is required")
	}
	selected := make(map[string]struct{})
	if all {
		for id := range s.alerts {
			selected[id] = struct{}{}
		}
	} else {
		for _, id := range ids {
			if _, exists := s.alerts[id]; exists {
				selected[id] = struct{}{}
			}
		}
	}
	if len(selected) == 0 {
		return 0, nil
	}

	previous := cloneAlertReadIDs(s.readByUser[userID])
	if s.readByUser[userID] == nil {
		s.readByUser[userID] = make(map[string]time.Time)
	}
	marked := 0
	for id := range selected {
		if s.readByUser[userID][id].IsZero() {
			s.readByUser[userID][id] = now.UTC()
			marked++
		}
	}
	if marked == 0 {
		return 0, nil
	}
	if err := s.persistLocked(); err != nil {
		s.readByUser[userID] = previous
		if len(previous) == 0 {
			delete(s.readByUser, userID)
		}
		return 0, err
	}
	return marked, nil
}

func cloneAlertReadIDs(input map[string]time.Time) map[string]time.Time {
	if len(input) == 0 {
		return nil
	}
	copy := make(map[string]time.Time, len(input))
	for id, readAt := range input {
		copy[id] = readAt
	}
	return copy
}

func (s *alertStateStore) persistLocked() error {
	if s.path == "" {
		return nil
	}
	contents, err := json.Marshal(alertStateFile{FirstSeen: s.firstSeen, ReadByUser: s.readByUser})
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".alerts-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, s.path); err == nil {
		return nil
	}
	// Windows cannot always replace an existing file with Rename. The state is
	// small and protected by stateMu, so retrying after removal is safe here.
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(temporaryPath, s.path)
}

func (h *Handler) alertStore() *alertStateStore {
	h.alertStateMu.Lock()
	defer h.alertStateMu.Unlock()
	if h.alertState == nil {
		h.alertState = newAlertStateStore(filepath.Join("data", "alerts-state.json"), 30*time.Second)
	}
	return h.alertState
}

func (h *Handler) alertUserID(r *http.Request) string {
	if h.Sessions == nil {
		return ""
	}
	if userID := strings.TrimSpace(h.Sessions.GetString(r.Context(), "user_uuid")); userID != "" {
		return userID
	}
	return strings.TrimSpace(h.Sessions.GetString(r.Context(), "user_id"))
}

func (h *Handler) operationalAlerts() []alertItem {
	if h.Sections == nil {
		return nil
	}
	return operationalAlertsForSnapshot(h.Sections.GetHealth(), h.Sections.GetStats())
}

// operationalAlertsForSnapshot returns actionable service conditions only.
// A disabled section is an intentional operator choice, not an incident. It
// must therefore neither create its own notification nor elevate its health
// state into one. An enabled section that is degraded or unhealthy remains an
// actionable alert.
func operationalAlertsForSnapshot(healthBySection map[string]sections.HealthStatus, statsBySection map[string]sections.SectionStats) []alertItem {
	alerts := make([]alertItem, 0)
	for sectionID, status := range healthBySection {
		if stats, exists := statsBySection[sectionID]; exists && !stats.Enabled {
			continue
		}
		if status.Status == sections.HealthStateHealthy || status.Status == "" {
			continue
		}
		level := "warning"
		if status.Status == sections.HealthStateUnhealthy {
			level = "critical"
		}
		message := strings.TrimSpace(status.Message)
		if message == "" {
			message = "This protection section is not reporting a healthy state."
		}
		alerts = append(alerts, alertItem{
			ID:          "section-health-" + sectionID + "-" + string(status.Status),
			Level:       level,
			Title:       sectionName(sectionID) + " needs attention",
			Message:     message,
			Source:      sectionName(sectionID),
			Route:       sectionRoute(sectionID),
			ActionLabel: "Open section",
			Meta:        map[string]interface{}{"status": status.Status},
		})
	}
	return alerts
}

func (h *Handler) refreshAlerts(now time.Time) {
	store := h.alertStore()
	if !store.refreshDue(now) {
		return
	}
	if err := store.sync(now, h.operationalAlerts()); err != nil && h.Logger != nil {
		h.Logger.Warn("Failed to persist in-app alert state", zap.Error(err))
	}
}

func (h *Handler) HandleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID := h.alertUserID(r)
	if userID == "" {
		h.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	h.refreshAlerts(time.Now())
	alerts := h.alertStore().list(userID)
	unread := 0
	for _, alert := range alerts {
		if !alert.Read {
			unread++
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"alerts": alerts, "unread_count": unread})
}

func (h *Handler) HandleAlertsRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID := h.alertUserID(r)
	if userID == "" {
		h.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var input struct {
		All bool     `json:"all"`
		IDs []string `json:"ids"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		h.JSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if !input.All && len(input.IDs) == 0 {
		h.JSONError(w, "An alert id or all=true is required", http.StatusBadRequest)
		return
	}
	if len(input.IDs) > 100 {
		h.JSONError(w, "At most 100 alert ids can be acknowledged", http.StatusBadRequest)
		return
	}
	ids := make([]string, 0, len(input.IDs))
	seen := make(map[string]struct{}, len(input.IDs))
	for _, id := range input.IDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	h.refreshAlerts(time.Now())
	marked, err := h.alertStore().markRead(userID, ids, input.All, time.Now())
	if err != nil {
		if h.Logger != nil {
			h.Logger.Error("Failed to save alert acknowledgement", zap.Error(err))
		}
		h.JSONError(w, "Failed to save alert acknowledgement", http.StatusInternalServerError)
		return
	}
	h.recordAudit(r, "alerts:read", "alerts", "")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "marked": marked})
}

func alertSeverityRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 3
	case "warning":
		return 2
	default:
		return 1
	}
}

func sectionName(sectionID string) string {
	switch sectionID {
	case "waf_core":
		return "WAF"
	case "bot_protection":
		return "Bot Protection"
	case "traffic_control":
		return "Traffic Control"
	case "access_control":
		return "Edge Access"
	case "api_security":
		return "API Security"
	case "http_security":
		return "App Security"
	default:
		return strings.ReplaceAll(sectionID, "_", " ")
	}
}

func sectionRoute(sectionID string) string {
	switch sectionID {
	case "waf_core":
		return "waf_config"
	case "bot_protection":
		return "antibots_config"
	case "traffic_control":
		return "traffic_config"
	case "access_control":
		return "access_config"
	case "api_security":
		return "apisecurity_config"
	case "http_security":
		return "httpsecurity_config"
	default:
		return "security_analytics"
	}
}
