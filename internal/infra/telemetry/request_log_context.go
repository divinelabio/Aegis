package telemetry

import (
	"context"
	"net/http"
	"sync"
)

type requestLogMetadataKey struct{}

// RequestLogMetadata contains proxy-only attributes that are added to the
// single request event emitted by Middleware after the response is complete.
// Keeping this state in the request context lets the reverse proxy enrich the
// event without emitting a second traffic record.
type RequestLogMetadata struct {
	Host      string
	RuleID    string
	RuleName  string
	RuleType  string
	Upstream  string
	RouteName string
}

type requestLogMetadataState struct {
	mu    sync.RWMutex
	value RequestLogMetadata
}

// WithRequestLogMetadata initializes mutable request-scoped log metadata.
// The state is shared by request clones created by net/http's reverse proxy.
func WithRequestLogMetadata(r *http.Request) *http.Request {
	if r == nil || requestLogMetadataStateFromContext(r.Context()) != nil {
		return r
	}
	state := &requestLogMetadataState{}
	return r.WithContext(context.WithValue(r.Context(), requestLogMetadataKey{}, state))
}

// UpdateRequestLogMetadata adds non-empty proxy metadata to the current
// request. It deliberately never emits an event itself.
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
	if update.RuleID != "" {
		state.value.RuleID = update.RuleID
	}
	if update.RuleName != "" {
		state.value.RuleName = update.RuleName
	}
	if update.RuleType != "" {
		state.value.RuleType = update.RuleType
	}
	if update.Upstream != "" {
		state.value.Upstream = update.Upstream
	}
	if update.RouteName != "" {
		state.value.RouteName = update.RouteName
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

func requestLogMetadataStateFromContext(ctx context.Context) *requestLogMetadataState {
	state, _ := ctx.Value(requestLogMetadataKey{}).(*requestLogMetadataState)
	return state
}
