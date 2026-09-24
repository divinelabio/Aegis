package handlers

import (
	"net/http"
	"strings"

	"github.com/divinelab-io/aegis/internal/analytics"
)

func (h *Handler) HandleAnalytics(w http.ResponseWriter, r *http.Request) {
	if h.AnalyticsStore == nil {
		h.JSONError(w, "Analytics store not available", http.StatusServiceUnavailable)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/analytics"), "/")
	query := analytics.Query{
		Limit:     parseInt(r.URL.Query().Get("limit"), 100),
		Action:    r.URL.Query().Get("action"),
		RuleID:    r.URL.Query().Get("rule_id"),
		RuleName:  r.URL.Query().Get("rule_name"),
		RuleType:  r.URL.Query().Get("rule_type"),
		Section:   r.URL.Query().Get("section"),
		Country:   r.URL.Query().Get("country"),
		IP:        r.URL.Query().Get("ip"),
		Path:      r.URL.Query().Get("path"),
		Method:    r.URL.Query().Get("method"),
		UserAgent: r.URL.Query().Get("user_agent"),
		JA3:       r.URL.Query().Get("ja3"),
	}
	if scoreMin := r.URL.Query().Get("score_min"); scoreMin != "" {
		parsed := parseInt(scoreMin, 0)
		query.ScoreMin = &parsed
	}
	if scoreMax := r.URL.Query().Get("score_max"); scoreMax != "" {
		parsed := parseInt(scoreMax, 0)
		query.ScoreMax = &parsed
	}
	if since := parseTime(r.URL.Query().Get("since")); !since.IsZero() {
		query.Since = since
	}
	if until := parseTime(r.URL.Query().Get("until")); !until.IsZero() {
		query.Until = until
	}

	parts := strings.Split(path, "/")
	if len(parts) >= 3 && parts[0] == "sections" {
		if parts[1] == "" {
			path = "sections"
		} else {
			query.Section = parts[1]
			path = parts[2]
		}
	}

	switch path {
	case "sections":
		writeJSON(w, map[string]any{"sections": []map[string]string{
			{"id": "waf_core", "name": "WAF Core"},
			{"id": "bot_protection", "name": "Bot Protection"},
			{"id": "traffic_control", "name": "Traffic Control"},
			{"id": "access_control", "name": "Edge Access"},
			{"id": "api_security", "name": "API Security"},
			{"id": "http_security", "name": "App Security"},
		}})
	case "", "events":
		events, err := h.AnalyticsStore.List(r.Context(), query)
		if err != nil {
			h.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"events": events})
	case "summary":
		summary, err := h.AnalyticsStore.Summary(r.Context(), query)
		if err != nil {
			h.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"summary": summary})
	case "timeline":
		items, err := h.AnalyticsStore.Timeline(r.Context(), query)
		writeAggregate(w, h, items, err)
	case "top-paths":
		items, err := h.AnalyticsStore.Top(r.Context(), "paths", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-ips":
		items, err := h.AnalyticsStore.Top(r.Context(), "ips", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-countries":
		items, err := h.AnalyticsStore.Top(r.Context(), "geo", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-rules":
		items, err := h.AnalyticsStore.Top(r.Context(), "rules", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top":
		field := r.URL.Query().Get("field")
		if field == "" {
			field = "paths"
		}
		items, err := h.AnalyticsStore.Top(r.Context(), normalizeAnalyticsTopField(field), query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-actions":
		items, err := h.AnalyticsStore.Top(r.Context(), "actions", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-statuses":
		items, err := h.AnalyticsStore.Top(r.Context(), "statuses", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-user-agents":
		items, err := h.AnalyticsStore.Top(r.Context(), "user_agents", query, query.Limit)
		writeAggregate(w, h, items, err)
	default:
		h.JSONError(w, "Analytics endpoint not found", http.StatusNotFound)
	}
}

func normalizeAnalyticsTopField(field string) string {
	switch strings.TrimSpace(strings.ToLower(field)) {
	case "path", "paths":
		return "paths"
	case "ip", "ips":
		return "ips"
	case "country", "countries", "geo":
		return "geo"
	case "rule", "rules":
		return "rules"
	case "action", "actions":
		return "actions"
	case "status", "statuses", "status_code":
		return "statuses"
	case "user_agent", "user_agents", "user-agents":
		return "user_agents"
	default:
		return "paths"
	}
}
