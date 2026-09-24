package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/analytics"
	"github.com/divinelab-io/aegis/internal/rules"
)

const maxV2BotRulesBody = 256 << 10
const maxV2BotRuleExpression = 8192
const maxV2BotBlockResponseBody = 64 << 10

func decodeV2BotRuleJSON(w http.ResponseWriter, r *http.Request, destination interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxV2BotRulesBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return fmt.Errorf("request body exceeds %d bytes", maxV2BotRulesBody)
		}
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func (h *Handler) decodeV2BotRuleJSON(w http.ResponseWriter, r *http.Request, destination interface{}, message string) bool {
	if err := decodeV2BotRuleJSON(w, r, destination); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "request body exceeds") {
			status = http.StatusRequestEntityTooLarge
		}
		h.JSONError(w, message+": "+err.Error(), status)
		return false
	}
	return true
}

func validateV2BotRuleShape(rule rules.SecurityRule) error {
	if strings.TrimSpace(rule.Name) == "" || len(rule.Name) > 256 {
		return errors.New("rule name is required and must not exceed 256 characters")
	}
	if err := validateV2BotExpression(rule.Expression); err != nil {
		return err
	}
	if err := validateV2BotRuleAction(rule.Action, rule.ActionParams); err != nil {
		return err
	}
	if len(rule.Tags) > 64 {
		return errors.New("rule tags exceed 64 entries")
	}
	if len(rule.ActionParams) > 64 {
		return errors.New("rule action_params exceed 64 entries")
	}
	return nil
}

func validateV2BotRuleAction(action rules.Action, params map[string]string) error {
	switch action {
	case "", rules.ActionAllow, rules.ActionBlock, rules.ActionChallenge, rules.ActionLog, rules.ActionRateLimit, rules.ActionRedirect:
	default:
		return fmt.Errorf("unsupported Bot rule action %q", action)
	}
	switch action {
	case rules.ActionBlock:
		if body := params["response_body"]; len(body) > maxV2BotBlockResponseBody {
			return fmt.Errorf("block response body exceeds %d bytes", maxV2BotBlockResponseBody)
		}
		if responseType := strings.TrimSpace(params["response_type"]); responseType != "" && responseType != "default" && responseType != "text/plain" && responseType != "text/html" && responseType != "application/json" && responseType != "application/xml" {
			return fmt.Errorf("unsupported block response type %q", responseType)
		}
		if rawStatus := strings.TrimSpace(params["response_code"]); rawStatus != "" {
			status, err := strconv.Atoi(rawStatus)
			if err != nil || status < http.StatusBadRequest || status >= http.StatusInternalServerError {
				return errors.New("block response code must be from 400 to 499")
			}
		}
	case rules.ActionRateLimit:
		if _, err := rules.ParseRateLimitActionParams(params); err != nil {
			return fmt.Errorf("invalid rate-limit action: %w", err)
		}
	case rules.ActionRedirect:
		if err := rules.ValidateRedirectTarget(params["location"]); err != nil {
			return err
		}
	}
	return nil
}

func validateV2BotExpression(expression string) error {
	if strings.TrimSpace(expression) == "" {
		return errors.New("rule expression is required")
	}
	if len(expression) > maxV2BotRuleExpression {
		return fmt.Errorf("rule expression exceeds %d characters", maxV2BotRuleExpression)
	}
	validation := rules.ValidateExpression(expression)
	if !validation.Valid {
		if len(validation.Errors) > 0 {
			return fmt.Errorf("invalid rule expression: %s", validation.Errors[0].Message)
		}
		if len(validation.Warnings) > 0 {
			return fmt.Errorf("invalid rule expression: %s", validation.Warnings[0])
		}
		return errors.New("invalid rule expression")
	}
	for _, field := range validation.FieldsUsed {
		if !rules.IsBotRuleField(field) {
			return fmt.Errorf("Bot Protection does not provide rule field %q", field)
		}
	}
	return nil
}

type reorderRequest struct {
	IDs []string `json:"ids"`
}

type testRuleRequest struct {
	Rule    rules.SecurityRule   `json:"rule"`
	Request rules.RequestContext `json:"request"`
}

type validateRuleRequest struct {
	Expression string             `json:"expression"`
	Rule       rules.SecurityRule `json:"rule"`
}

func (h *Handler) HandleV2BotRules(w http.ResponseWriter, r *http.Request) {
	h.handleV2SecurityRules(w, r, "/api/v2/security/bot/rules")
}

func (h *Handler) handleV2SecurityRules(w http.ResponseWriter, r *http.Request, prefix string) {
	if h.RuleStore == nil {
		h.JSONError(w, "Rules store not available", http.StatusServiceUnavailable)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	path = strings.Trim(path, "/")

	if path == "templates" {
		writeJSON(w, map[string]any{"templates": rules.Templates()})
		return
	}
	if path == "fields" {
		writeJSON(w, map[string]any{"fields": rules.BotRuleFields()})
		return
	}
	if path == "validate" {
		if r.Method != http.MethodPost {
			h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload validateRuleRequest
		if !h.decodeV2BotRuleJSON(w, r, &payload, "Invalid validation payload") {
			return
		}
		expression := payload.Expression
		if expression == "" {
			expression = payload.Rule.Expression
		}
		if err := validateV2BotExpression(expression); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, rules.ValidateExpression(expression))
		return
	}
	if path == "preview-sync" {
		if r.Method != http.MethodPost {
			h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload rules.SecurityRule
		if !h.decodeV2BotRuleJSON(w, r, &payload, "Invalid rule payload") {
			return
		}
		if err := validateV2BotRuleShape(payload); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		validation := rules.ValidateExpression(payload.Expression)
		writeJSON(w, map[string]any{
			"section_target": validation.SectionTarget,
			"sync_status":    h.previewSectionSync(payload),
			"fields_used":    validation.FieldsUsed,
			"warnings":       validation.Warnings,
		})
		return
	}
	if path == "reorder" {
		if r.Method != http.MethodPut {
			h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload reorderRequest
		if !h.decodeV2BotRuleJSON(w, r, &payload, "Invalid reorder payload") {
			return
		}
		if len(payload.IDs) == 0 || len(payload.IDs) > 500 {
			h.JSONError(w, "Reorder payload must contain between 1 and 500 rule IDs", http.StatusBadRequest)
			return
		}
		seenIDs := make(map[string]struct{}, len(payload.IDs))
		for _, id := range payload.IDs {
			id = strings.TrimSpace(id)
			if id == "" || len(id) > 128 {
				h.JSONError(w, "Reorder payload contains an invalid rule ID", http.StatusBadRequest)
				return
			}
			if _, duplicate := seenIDs[id]; duplicate {
				h.JSONError(w, "Reorder payload contains duplicate rule IDs", http.StatusBadRequest)
				return
			}
			seenIDs[id] = struct{}{}
		}
		if err := h.RuleStore.Reorder(r.Context(), payload.IDs); err != nil {
			h.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
		return
	}
	if path == "test" {
		if r.Method != http.MethodPost {
			h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload testRuleRequest
		if !h.decodeV2BotRuleJSON(w, r, &payload, "Invalid test payload") {
			return
		}
		if err := validateV2BotRuleShape(payload.Rule); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		matched, err := rules.EvaluateExpression(payload.Rule.Expression, payload.Request)
		if err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		validation := rules.ValidateExpression(payload.Rule.Expression)
		writeJSON(w, map[string]any{
			"matched":          matched,
			"action":           payload.Rule.Action,
			"action_params":    payload.Rule.ActionParams,
			"matched_fields":   validation.FieldsUsed,
			"evaluation_trace": []string{"parsed expression", "evaluated sample request"},
			"section_preview":  h.previewSectionSync(payload.Rule),
		})
		return
	}

	if path == "" {
		switch r.Method {
		case http.MethodGet:
			items, err := h.RuleStore.List(r.Context())
			if err != nil {
				h.JSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}
			items = append(items, h.sectionSecurityRules()...)
			items = dedupeSecurityRules(items)
			items = filterSecurityRules(items, r)
			writeJSON(w, map[string]any{"rules": items})
		case http.MethodPost:
			var rule rules.SecurityRule
			if !h.decodeV2BotRuleJSON(w, r, &rule, "Invalid rule payload") {
				return
			}
			if err := validateV2BotRuleShape(rule); err != nil {
				h.JSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			if synced, ok, err := h.applySectionSecurityRule(rule); ok || err != nil {
				if err != nil {
					h.JSONError(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusCreated)
				writeJSON(w, synced)
				return
			}
			created, err := h.RuleStore.Create(r.Context(), rule)
			if err != nil {
				h.JSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, created)
		default:
			h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	id := strings.Split(path, "/")[0]
	switch r.Method {
	case http.MethodGet:
		if rule, ok := h.getSectionSecurityRule(id); ok {
			writeJSON(w, rule)
			return
		}
		rule, err := h.RuleStore.Get(r.Context(), id)
		if err != nil {
			h.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if rule == nil {
			h.JSONError(w, "Rule not found", http.StatusNotFound)
			return
		}
		writeJSON(w, rule)
	case http.MethodPut:
		var rule rules.SecurityRule
		if !h.decodeV2BotRuleJSON(w, r, &rule, "Invalid rule payload") {
			return
		}
		if err := validateV2BotRuleShape(rule); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if synced, ok, err := h.applySectionSecurityRule(rule); ok || err != nil {
			if err != nil {
				h.JSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, synced)
			return
		}
		updated, err := h.RuleStore.Update(r.Context(), id, rule)
		if err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if updated == nil {
			h.JSONError(w, "Rule not found", http.StatusNotFound)
			return
		}
		writeJSON(w, updated)
	case http.MethodDelete:
		if h.deleteSectionSecurityRule(id) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := h.RuleStore.Delete(r.Context(), id); err != nil {
			h.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

type sectionRuleSync interface {
	SecurityRules() []rules.SecurityRule
	ApplySecurityRule(rules.SecurityRule) (rules.SecurityRule, bool, error)
	DeleteSecurityRule(id string) bool
}

func (h *Handler) sectionSecurityRules() []rules.SecurityRule {
	if h.Sections == nil {
		return nil
	}
	var out []rules.SecurityRule
	for _, id := range []string{"traffic_control", "bot_protection", "waf_core"} {
		section, ok := h.Sections.GetSection(id)
		if !ok {
			continue
		}
		syncer, ok := section.(interface{ SecurityRules() []rules.SecurityRule })
		if !ok {
			continue
		}
		out = append(out, syncer.SecurityRules()...)
	}
	return out
}

func dedupeSecurityRules(items []rules.SecurityRule) []rules.SecurityRule {
	if len(items) < 2 {
		return items
	}
	seen := map[string]struct{}{}
	out := make([]rules.SecurityRule, 0, len(items))
	for _, item := range items {
		key := item.ID
		if key == "" {
			key = item.Name + "|" + item.Expression + "|" + string(item.Type) + "|" + item.Section
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func (h *Handler) getSectionSecurityRule(id string) (rules.SecurityRule, bool) {
	for _, rule := range h.sectionSecurityRules() {
		if rule.ID == id {
			return rule, true
		}
	}
	return rules.SecurityRule{}, false
}

func (h *Handler) applySectionSecurityRule(rule rules.SecurityRule) (rules.SecurityRule, bool, error) {
	if h.Sections == nil {
		return rule, false, nil
	}
	for _, id := range []string{"traffic_control", "bot_protection", "waf_core"} {
		section, ok := h.Sections.GetSection(id)
		if !ok {
			continue
		}
		syncer, ok := section.(interface {
			ApplySecurityRule(rules.SecurityRule) (rules.SecurityRule, bool, error)
		})
		if !ok {
			continue
		}
		if synced, handled, err := syncer.ApplySecurityRule(rule); handled || err != nil {
			return synced, handled, err
		}
	}
	return rule, false, nil
}

func (h *Handler) deleteSectionSecurityRule(id string) bool {
	if h.Sections == nil {
		return false
	}
	for _, sectionID := range []string{"traffic_control", "bot_protection", "waf_core"} {
		section, ok := h.Sections.GetSection(sectionID)
		if !ok {
			continue
		}
		syncer, ok := section.(interface{ DeleteSecurityRule(id string) bool })
		if ok && syncer.DeleteSecurityRule(id) {
			return true
		}
	}
	return false
}

func (h *Handler) previewSectionSync(rule rules.SecurityRule) string {
	if h.Sections == nil {
		return "unified"
	}
	switch rule.Type {
	case rules.RuleTypeGeo, rules.RuleTypeIPAccess, rules.RuleTypeRateLimit:
		if _, ok := h.Sections.GetSection("traffic_control"); ok {
			return "traffic_control"
		}
	case rules.RuleTypeBot:
		if _, ok := h.Sections.GetSection("bot_protection"); ok {
			return "bot_protection"
		}
	case rules.RuleTypeWAF:
		if _, ok := h.Sections.GetSection("waf_core"); ok {
			return "waf_core"
		}
	case rules.RuleTypeAPI:
		if _, ok := h.Sections.GetSection("api_security"); ok {
			return "api_security"
		}
	case rules.RuleTypeHTTPSec:
		if _, ok := h.Sections.GetSection("http_security"); ok {
			return "http_security"
		}
	case rules.RuleTypeAccess:
		if _, ok := h.Sections.GetSection("access_control"); ok {
			return "access_control"
		}
	}
	return "unified"
}

func filterSecurityRules(items []rules.SecurityRule, r *http.Request) []rules.SecurityRule {
	section := strings.TrimSpace(r.URL.Query().Get("section"))
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	enabled := strings.TrimSpace(r.URL.Query().Get("enabled"))
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("query")))
	if section == "" && source == "" && enabled == "" && query == "" {
		return items
	}
	var out []rules.SecurityRule
	for _, rule := range items {
		if section != "" && !strings.EqualFold(rule.Section, section) && !strings.EqualFold(string(rule.Type), section) {
			continue
		}
		if source != "" && !strings.EqualFold(rule.Source, source) {
			continue
		}
		if enabled != "" {
			want := enabled == "true" || enabled == "1"
			if rule.Enabled != want {
				continue
			}
		}
		if query != "" {
			haystack := strings.ToLower(rule.Name + " " + rule.Description + " " + rule.Expression + " " + string(rule.Type))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		out = append(out, rule)
	}
	return out
}

func (h *Handler) HandleV2Analytics(w http.ResponseWriter, r *http.Request) {
	if h.AnalyticsStore == nil {
		h.JSONError(w, "Analytics store not available", http.StatusServiceUnavailable)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/analytics"), "/")
	query := analytics.Query{
		Limit:            parseInt(r.URL.Query().Get("limit"), 100),
		Action:           r.URL.Query().Get("action"),
		RuleID:           r.URL.Query().Get("rule_id"),
		RuleName:         r.URL.Query().Get("rule_name"),
		RuleType:         r.URL.Query().Get("rule_type"),
		Section:          r.URL.Query().Get("section"),
		Country:          r.URL.Query().Get("country"),
		IP:               r.URL.Query().Get("ip"),
		Path:             r.URL.Query().Get("path"),
		Method:           r.URL.Query().Get("method"),
		UserAgent:        r.URL.Query().Get("user_agent"),
		JA3:              r.URL.Query().Get("ja3"),
		JA4:              r.URL.Query().Get("ja4"),
		ASN:              r.URL.Query().Get("asn"),
		ASNOrg:           r.URL.Query().Get("asn_org"),
		TLSVersion:       r.URL.Query().Get("tls_version"),
		Host:             r.URL.Query().Get("host"),
		QueryString:      r.URL.Query().Get("query_string"),
		DecisionSource:   r.URL.Query().Get("decision_source"),
		ChallengeType:    r.URL.Query().Get("challenge_type"),
		ChallengeOutcome: r.URL.Query().Get("challenge_outcome"),
		RuleOverride:     r.URL.Query().Get("rule_override"),
	}
	if scoreMin := r.URL.Query().Get("score_min"); scoreMin != "" {
		parsed := parseInt(scoreMin, 0)
		query.ScoreMin = &parsed
	}
	if scoreMax := r.URL.Query().Get("score_max"); scoreMax != "" {
		parsed := parseInt(scoreMax, 0)
		query.ScoreMax = &parsed
	}
	if statusCode := r.URL.Query().Get("status_code"); statusCode != "" {
		parsed := parseInt(statusCode, 0)
		query.StatusCode = &parsed
	}
	if since := parseTime(r.URL.Query().Get("since")); !since.IsZero() {
		query.Since = since
	}
	if until := parseTime(r.URL.Query().Get("until")); !until.IsZero() {
		query.Until = until
	}

	switch path {
	case "events", "":
		events, err := h.AnalyticsStore.List(r.Context(), query)
		if err != nil {
			h.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"events": events})
	case "timeline":
		items, err := h.AnalyticsStore.Timeline(r.Context(), query)
		writeAggregate(w, h, items, err)
	case "top-ips":
		items, err := h.AnalyticsStore.Top(r.Context(), "ips", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-paths":
		items, err := h.AnalyticsStore.Top(r.Context(), "paths", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "geo":
		items, err := h.AnalyticsStore.Top(r.Context(), "geo", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "rules":
		items, err := h.AnalyticsStore.Top(r.Context(), "rules", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-user-agents":
		items, err := h.AnalyticsStore.Top(r.Context(), "user-agents", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-bot-categories":
		items, err := h.AnalyticsStore.Top(r.Context(), "bot-categories", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-decision-sources":
		items, err := h.AnalyticsStore.Top(r.Context(), "decision-source", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-decision-states":
		items, err := h.AnalyticsStore.Top(r.Context(), "decision-state", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-challenge-types":
		items, err := h.AnalyticsStore.Top(r.Context(), "challenge-type", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-challenge-outcomes":
		items, err := h.AnalyticsStore.Top(r.Context(), "challenge-outcome", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-rule-overrides":
		items, err := h.AnalyticsStore.Top(r.Context(), "rule-override", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-actions":
		items, err := h.AnalyticsStore.Top(r.Context(), "actions", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "top-statuses":
		items, err := h.AnalyticsStore.Top(r.Context(), "statuses", query, query.Limit)
		writeAggregate(w, h, items, err)
	case "summary":
		summary, err := h.AnalyticsStore.Summary(r.Context(), query)
		if err != nil {
			h.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"summary": summary})
	default:
		h.JSONError(w, "Analytics endpoint not found", http.StatusNotFound)
	}
}

func (h *Handler) HandleV2SecurityConfig(w http.ResponseWriter, r *http.Request) {
	section := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/security/"), "/")
	writeJSON(w, map[string]any{
		"section": section,
		"status":  "legacy_section_api",
		"message": "Use /api/sections/* for detailed configuration during phased migration.",
	})
}

func writeAggregate(w http.ResponseWriter, h *Handler, items []map[string]any, err error) {
	if err != nil {
		h.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"items": items})
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func parseInt(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func parseTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed
	}
	if duration, err := time.ParseDuration("-" + value); err == nil {
		return time.Now().UTC().Add(duration)
	}
	return time.Time{}
}
