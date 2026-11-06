package telemetry

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type requestLogMetadataKey struct{}

// RequestLogMetadata contains proxy and security-decision attributes that are
// added to the canonical request event emitted by Middleware after the response
// is complete.
type RequestLogMetadata struct {
	Host          string
	Section       string
	RuleID        string
	RuleName      string
	RuleType      string
	Action        string
	Blocked       bool
	Logged        bool
	Score         int
	Upstream      string
	RouteName     string
	ExtraMetadata map[string]string
}

type requestLogMetadataState struct {
	mu        sync.RWMutex
	startTime time.Time
	requestID string
	value     RequestLogMetadata
}

// WithRequestLogMetadata initializes mutable request-scoped log metadata.
// The state is shared by request clones created by net/http's reverse proxy.
func WithRequestLogMetadata(r *http.Request) *http.Request {
	if r == nil {
		return r
	}
	if existing := requestLogMetadataStateFromContext(r.Context()); existing != nil {
		return r
	}
	reqID, _ := r.Context().Value(RequestIDKey).(string)
	if reqID == "" {
		reqID = strings.TrimSpace(r.Header.Get("X-Request-Id"))
	}
	state := &requestLogMetadataState{
		startTime: time.Now(),
		requestID: reqID,
	}
	return r.WithContext(context.WithValue(r.Context(), requestLogMetadataKey{}, state))
}

// UpdateRequestLogMetadata adds non-empty proxy or security metadata to the
// current request. It deliberately never emits an event itself.
func UpdateRequestLogMetadata(r *http.Request, update RequestLogMetadata) {
	if r == nil {
		return
	}
	state := requestLogMetadataStateFromContext(r.Context())
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if update.Host != "" {
		state.value.Host = update.Host
	}
	if update.Section != "" {
		state.value.Section = update.Section
	}
	if update.RuleID != "" {
		state.value.RuleID = update.RuleID
	}
	if update.RuleName != "" {
		state.value.RuleName = update.RuleName
	}
	if update.RuleType != "" {
		state.value.RuleType = update.RuleType
	}
	if update.Action != "" {
		state.value.Action = update.Action
	}
	if update.Blocked {
		state.value.Blocked = true
	}
	if update.Logged {
		state.value.Logged = true
	}
	if update.Score > 0 || state.value.Score == 0 {
		state.value.Score = update.Score
	}
	if update.Upstream != "" {
		state.value.Upstream = update.Upstream
	}
	if update.RouteName != "" {
		state.value.RouteName = update.RouteName
	}
	if len(update.ExtraMetadata) > 0 {
		if state.value.ExtraMetadata == nil {
			state.value.ExtraMetadata = make(map[string]string)
		}
		for k, v := range update.ExtraMetadata {
			state.value.ExtraMetadata[k] = v
		}
	}
}

// RequestLogMetadataFromRequest returns a stable snapshot for final event
// emission after the downstream handler has completed.
func RequestLogMetadataFromRequest(r *http.Request) RequestLogMetadata {
	if r == nil {
		return RequestLogMetadata{}
	}
	state := requestLogMetadataStateFromContext(r.Context())
	if state == nil {
		return RequestLogMetadata{}
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.value
}

// RequestIDFromRequest returns the correlated request ID for r, generating and
// attaching one to r.Header if none is present yet.
func RequestIDFromRequest(r *http.Request) string {
	if r == nil {
		return uuid.NewString()
	}
	if reqID, ok := r.Context().Value(RequestIDKey).(string); ok && strings.TrimSpace(reqID) != "" {
		return strings.TrimSpace(reqID)
	}
	if state := requestLogMetadataStateFromContext(r.Context()); state != nil {
		state.mu.RLock()
		reqID := state.requestID
		state.mu.RUnlock()
		if strings.TrimSpace(reqID) != "" {
			return strings.TrimSpace(reqID)
		}
	}
	if reqID := strings.TrimSpace(r.Header.Get("X-Request-Id")); reqID != "" {
		return reqID
	}
	if reqID := strings.TrimSpace(r.Header.Get("X-Request-ID")); reqID != "" {
		return reqID
	}
	reqID := uuid.NewString()
	if r.Header != nil {
		r.Header.Set("X-Request-Id", reqID)
		r.Header.Set("X-Request-ID", reqID)
	}
	return reqID
}

// RequestLatencyMs computes the elapsed request latency in milliseconds from
// the start of telemetry.Middleware (or X-Aegis-Start-UnixNano header).
func RequestLatencyMs(r *http.Request) int64 {
	if r == nil {
		return 0
	}
	if state := requestLogMetadataStateFromContext(r.Context()); state != nil && !state.startTime.IsZero() {
		ms := time.Since(state.startTime).Milliseconds()
		if ms < 0 {
			return 0
		}
		return ms
	}
	if raw := strings.TrimSpace(r.Header.Get("X-Aegis-Start-UnixNano")); raw != "" {
		if ns, err := strconv.ParseInt(raw, 10, 64); err == nil && ns > 0 {
			ms := (time.Now().UnixNano() - ns) / int64(time.Millisecond)
			if ms > 0 {
				return ms
			}
		}
	}
	return 0
}

func requestLogMetadataStateFromContext(ctx context.Context) *requestLogMetadataState {
	state, _ := ctx.Value(requestLogMetadataKey{}).(*requestLogMetadataState)
	return state
}
