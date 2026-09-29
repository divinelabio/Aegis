package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/divinelab-io/aegis/internal/infra/storage"
)

func (h *Handler) HandleTrafficEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/traffic-events"), "/")
	query, err := trafficEventsQueryFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch path {
	case "", "dashboard":
		dashboard, err := storage.GetCachedTrafficEventsDashboard(query)
		if err != nil {
			if isTrafficEventsRequestError(err) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			h.Logger.Error("Failed to get traffic events dashboard")
			http.Error(w, "Failed to get traffic events dashboard", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "dashboard": dashboard})
	case "events":
		page, err := storage.GetTrafficEvents(query)
		if err != nil {
			if isTrafficEventsRequestError(err) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			h.Logger.Error("Failed to get traffic events")
			http.Error(w, "Failed to get traffic events", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "events": page.Events, "count": page.Count, "next_cursor": page.NextCursor})
	default:
		http.Error(w, "Traffic events endpoint not found", http.StatusNotFound)
	}
}

func trafficEventsQueryFromRequest(r *http.Request) (storage.TrafficEventsQuery, error) {
	values := r.URL.Query()
	query := storage.TrafficEventsQuery{
		Window:      values.Get("window"),
		Interval:    values.Get("interval"),
		Since:       values.Get("since"),
		Until:       values.Get("until"),
		Status:      firstQueryValue(values.Get("status"), values.Get("status_code")),
		StatusClass: values.Get("status_class"),
		IP:          values.Get("ip"),
		Country:     values.Get("country"),
		Method:      values.Get("method"),
		Host:        values.Get("host"),
		Path:        values.Get("path"),
		UserAgent:   values.Get("user_agent"),
		JA3:         values.Get("ja3"),
		JA4:         values.Get("ja4"),
		ASN:         values.Get("asn"),
		Route:       values.Get("route"),
		Upstream:    values.Get("upstream"),
		HTTPVersion: values.Get("http_version"),
		TLSVersion:  values.Get("tls_version"),
		IPVersion:   values.Get("ip_version"),
		ContentType: values.Get("content_type"),
		RequestID:   values.Get("request_id"),
		Cursor:      values.Get("cursor"),
		Sort:        values.Get("sort"),
		Limit:       storage.NormalizeWAFLimit(parseInt(values.Get("limit"), 50), 50, 500),
	}
	if query.Window == "" {
		query.Window = "24h"
	}
	if err := storage.ValidateWindow(query.Window); err != nil {
		return query, err
	}
	return query, nil
}

func firstQueryValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func isTrafficEventsRequestError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "invalid") || strings.Contains(message, "unsupported")
}
