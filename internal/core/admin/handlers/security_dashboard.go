package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/divinelab-io/aegis/internal/edition"
	"github.com/divinelab-io/aegis/internal/infra/storage"
	"go.uber.org/zap"
)

// HandleSecurityDashboard serves the cross-section Security Dashboard. It is
// intentionally separate from command-center status data and from raw Traffic
// Events: this endpoint contains only protection decisions and detections.
func (h *Handler) HandleSecurityDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/security/dashboard"), "/")
	if strings.HasPrefix(path, "events/") {
		id := strings.TrimPrefix(path, "events/")
		event, err := storage.GetSecurityAnalyticsEvent(id)
		if err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if event == nil {
			h.JSONError(w, "Security event not found", http.StatusNotFound)
			return
		}
		if !h.isSectionEntitled(event.Section) {
			h.JSONError(w, "Security event not found", http.StatusNotFound)
			return
		}
		writeSecurityDashboardJSON(w, map[string]any{"success": true, "event": event})
		return
	}
	if path != "" {
		h.JSONError(w, "Security dashboard endpoint not found", http.StatusNotFound)
		return
	}
	query, err := securityDashboardQuery(r)
	if err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if query.Section != "" && !h.isSectionEntitled(query.Section) {
		query.Section = ""
	}
	dashboard, err := storage.GetSecurityAnalyticsDashboard(query)
	if err != nil {
		if h.Logger != nil {
			h.Logger.Error("Unable to load security analytics", zap.Error(err))
		}
		h.JSONError(w, "Unable to load security analytics: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	h.filterDashboardByEntitlements(&dashboard)
	writeSecurityDashboardJSON(w, map[string]any{"success": true, "dashboard": dashboard})
}

func (h *Handler) isSectionEntitled(section string) bool {
	switch section {
	case "waf_core", "traffic_control", "http_security":
		return true
	case "bot_protection":
		return h != nil && h.License != nil && h.License.Has(edition.FeatureBotProtection)
	case "api_security":
		return h != nil && h.License != nil && h.License.Has(edition.FeatureAPISecurity)
	case "access_control":
		return h != nil && h.License != nil && h.License.Has(edition.FeatureAccessControl)
	default:
		return true
	}
}

func (h *Handler) filterDashboardByEntitlements(dashboard *storage.WAFAnalyticsDashboard) {
	if dashboard == nil {
		return
	}
	if len(dashboard.SectionAnalytics) > 0 {
		filtered := make([]storage.SecuritySectionAnalytics, 0, len(dashboard.SectionAnalytics))
		for _, sa := range dashboard.SectionAnalytics {
			if h.isSectionEntitled(sa.Section) {
				filtered = append(filtered, sa)
			}
		}
		dashboard.SectionAnalytics = filtered
	}
	if sectionItems, ok := dashboard.Breakdowns["sections"]; ok {
		filtered := make([]storage.WAFBreakdownItem, 0, len(sectionItems))
		for _, item := range sectionItems {
			if h.isSectionEntitled(item.Key) {
				filtered = append(filtered, item)
			}
		}
		dashboard.Breakdowns["sections"] = filtered
	}
	if len(dashboard.Events.Events) > 0 {
		filtered := make([]storage.WAFAnalyticsEvent, 0, len(dashboard.Events.Events))
		for _, ev := range dashboard.Events.Events {
			if h.isSectionEntitled(ev.Section) {
				filtered = append(filtered, ev)
			}
		}
		dashboard.Events.Events = filtered
		dashboard.Events.Count = len(filtered)
	}
}

func securityDashboardQuery(r *http.Request) (storage.WAFAnalyticsQuery, error) {
	values := r.URL.Query()
	query := storage.WAFAnalyticsQuery{
		Window:       values.Get("window"),
		Interval:     values.Get("interval"),
		Section:      values.Get("section"),
		Action:       values.Get("action"),
		Category:     values.Get("category"),
		RuleID:       values.Get("rule_id"),
		IP:           values.Get("ip"),
		Path:         values.Get("path"),
		Method:       values.Get("method"),
		Host:         values.Get("host"),
		Country:      values.Get("country"),
		Status:       values.Get("status"),
		Severity:     values.Get("severity"),
		MatchedField: values.Get("matched_field"),
		UserAgent:       values.Get("user_agent"),
		UserAgentFamily: values.Get("user_agent_family"),
		RequestID:       values.Get("request_id"),
		StatusClass:     values.Get("status_class"),
		RuleName:        values.Get("rule_name"),
		JA3:             values.Get("ja3"),
		JA4:             values.Get("ja4"),
		ASN:             values.Get("asn"),
		Policy:          values.Get("policy"),
		Since:           values.Get("since"),
		Until:           values.Get("until"),
		Cursor:          values.Get("cursor"),
		Sort:            values.Get("sort"),
		Limit:           securityDashboardQueryInt(values.Get("limit"), 50),
	}
	query.Limit = storage.NormalizeWAFLimit(query.Limit, 50, 500)
	if query.Window == "" {
		query.Window = "24h"
	}
	if err := storage.ValidateWindow(query.Window); err != nil {
		return query, err
	}
	if values.Get("min_score") != "" {
		value := securityDashboardQueryInt(values.Get("min_score"), 0)
		query.MinScore = &value
	}
	if values.Get("max_score") != "" {
		value := securityDashboardQueryInt(values.Get("max_score"), 0)
		query.MaxScore = &value
	}
	return query, nil
}

func securityDashboardQueryInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func writeSecurityDashboardJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
