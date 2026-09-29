package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/divinelab-io/aegis/internal/app"
)

func (h *Handler) HandleCommandCenter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.Sections == nil {
		h.JSONError(w, "Section manager unavailable", http.StatusServiceUnavailable)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	dashboard := h.Sections.GetCommandCenterDashboard(app.CommandCenterQuery{
		Window: r.URL.Query().Get("window"),
		Limit:  limit,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":   true,
		"dashboard": dashboard,
	})
}
