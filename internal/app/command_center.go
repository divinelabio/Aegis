package app

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/storage"
	"github.com/divinelab-io/aegis/internal/sections"
)

type CommandCenterQuery struct {
	Window string
	Limit  int
}

type CommandCenterDashboard struct {
	PostureSummary  CommandCenterPostureSummary   `json:"posture_summary"`
	SectionPosture  []CommandCenterSectionPosture `json:"section_posture"`
	IncidentQueue   []CommandCenterIncident       `json:"incident_queue"`
	CoverageGaps    []CommandCenterAction         `json:"coverage_gaps"`
	Recommendations []CommandCenterAction         `json:"recommendations"`
	SignalMix       []CommandCenterBreakdown      `json:"signal_mix"`
	SectionActivity []CommandCenterBreakdown      `json:"section_activity"`
	SystemHealth    CommandCenterSystemHealth     `json:"system_health"`
	Launchers       []CommandCenterLauncher       `json:"launchers"`
	Warnings        []string                      `json:"warnings"`
}

type CommandCenterPostureSummary struct {
	InspectedTraffic int64   `json:"inspected_traffic"`
	EnforcedActions  int64   `json:"enforced_actions"`
	DetectedSignals  int64   `json:"detected_signals"`
	ActiveSections   int     `json:"active_sections"`
	TotalSections    int     `json:"total_sections"`
	PlatformHealth   string  `json:"platform_health"`
	P95OverheadMs    float64 `json:"p95_overhead_ms"`
	AvgOverheadMs    float64 `json:"avg_overhead_ms"`
	Window           string  `json:"window"`
}

type CommandCenterSectionPosture struct {
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	ShortName          string  `json:"short_name"`
	Enabled            bool    `json:"enabled"`
	Status             string  `json:"status"`
	Inspected          int64   `json:"inspected"`
	Enforced           int64   `json:"enforced"`
	Detected           int64   `json:"detected"`
	EventCount         int     `json:"event_count"`
	ConfigState        string  `json:"config_state"`
	TelemetryFreshness string  `json:"telemetry_freshness"`
	P95LatencyMs       float64 `json:"p95_latency_ms"`
	TopSignal          string  `json:"top_signal"`
	Message            string  `json:"message"`
}

type CommandCenterIncident struct {
	Priority  int    `json:"priority"`
	SectionID string `json:"section_id"`
	Section   string `json:"section"`
	Signal    string `json:"signal"`
	Action    string `json:"action"`
	Source    string `json:"source"`
	Target    string `json:"target"`
	Age       string `json:"age"`
	Timestamp int64  `json:"timestamp"`
}

type CommandCenterAction struct {
	Severity         string `json:"severity"`
	SectionID        string `json:"section_id,omitempty"`
	Title            string `json:"title"`
	Detail           string `json:"detail"`
	Route            string `json:"route,omitempty"`
	DashboardSection string `json:"dashboard_section,omitempty"`
	CTA              string `json:"cta,omitempty"`
}

type CommandCenterBreakdown struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Count  int64  `json:"count"`
	Tone   string `json:"tone"`
	Detail string `json:"detail"`
}

type CommandCenterSystemHealth struct {
	Status         string   `json:"status"`
	Message        string   `json:"message"`
	FailedChecks   int      `json:"failed_checks"`
	DegradedChecks int      `json:"degraded_checks"`
	DroppedEvents  int64    `json:"dropped_events"`
	Warnings       []string `json:"warnings"`
}

type CommandCenterLauncher struct {
	SectionID        string `json:"section_id"`
	Name             string `json:"name"`
	PrimaryLabel     string `json:"primary_label"`
	DashboardSection string `json:"dashboard_section,omitempty"`
	SecondaryLabel   string `json:"secondary_label"`
	Route            string `json:"route"`
	Detail           string `json:"detail"`
}

type commandCenterSectionDefinition struct {
	ID        string
	Name      string
	ShortName string
	Route     string
}

var commandCenterSections = []commandCenterSectionDefinition{
	{ID: "waf_core", Name: "WAF Core", ShortName: "WAF", Route: "waf_config"},
	{ID: "bot_protection", Name: "Bot Protection", ShortName: "Bots", Route: "antibots_config"},
	{ID: "traffic_control", Name: "Traffic Control", ShortName: "Traffic", Route: "traffic_config"},
	{ID: "access_control", Name: "Edge Access", ShortName: "Edge", Route: "access_config"},
	{ID: "api_security", Name: "API Security", ShortName: "API", Route: "apisecurity_config"},
	{ID: "http_security", Name: "App Security", ShortName: "App", Route: "httpsecurity_config"},
}

func (m *SectionManager) GetCommandCenterDashboard(q CommandCenterQuery) CommandCenterDashboard {
	if q.Window == "" {
		q.Window = "24h"
	}
	if q.Limit <= 0 {
		q.Limit = 20
	}
	stats := m.GetStats()
	health := m.GetHealth()
	dashboards := map[string]map[string]any{}
	warnings := []string{}

	for _, def := range commandCenterSections {
		dashboard, err := loadCommandCenterSectionDashboard(def.ID, q)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s analytics unavailable", def.Name))
			dashboards[def.ID] = map[string]any{}
			continue
		}
		dashboards[def.ID] = dashboard
	}

	out := CommandCenterDashboard{Warnings: warnings}
	out.SectionPosture = buildCommandCenterSectionPosture(m, stats, health, dashboards)
	out.PostureSummary = buildCommandCenterPostureSummary(out.SectionPosture, dashboards, q.Window)
	out.IncidentQueue = buildCommandCenterIncidentQueue(dashboards, q.Limit)
	out.CoverageGaps = buildCommandCenterCoverageGaps(out.SectionPosture)
	out.SignalMix = buildCommandCenterSignalMix(out.IncidentQueue)
	out.SectionActivity = buildCommandCenterSectionActivity(out.SectionPosture)
	out.SystemHealth = buildCommandCenterSystemHealth(health, dashboards, warnings)
	out.Recommendations = buildCommandCenterRecommendations(out)
	out.Launchers = buildCommandCenterLaunchers(out.SectionPosture)
	return out
}

func loadCommandCenterSectionDashboard(sectionID string, q CommandCenterQuery) (map[string]any, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 20
	}
	switch sectionID {
	case "waf_core":
		d, err := storage.GetWAFAnalyticsDashboard(storage.WAFAnalyticsQuery{Window: q.Window, Interval: "auto", Limit: limit})
		return commandCenterMap(d), err
	case "bot_protection":
		d, err := storage.GetBotAnalyticsDashboard(storage.BotAnalyticsQuery{Window: q.Window, Interval: "auto", Limit: limit})
		return commandCenterMap(d), err
	case "traffic_control":
		d, err := storage.GetTrafficAnalyticsDashboard(storage.TrafficAnalyticsQuery{Window: q.Window, Interval: "auto", Limit: limit})
		return commandCenterMap(d), err
	case "api_security":
		d, err := storage.GetAPISecurityAnalyticsDashboard(storage.APISecurityAnalyticsQuery{Window: q.Window, Interval: "auto", Limit: limit})
		return commandCenterMap(d), err
	case "http_security":
		d, err := storage.GetHTTPSecurityAnalyticsDashboard(storage.HTTPSecurityAnalyticsQuery{Window: q.Window, Interval: "auto", Limit: limit})
		return commandCenterMap(d), err
	default:
		return map[string]any{}, nil
	}
}

func commandCenterMap(value any) map[string]any {
	raw, err := json.Marshal(value)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func buildCommandCenterSectionPosture(m *SectionManager, stats map[string]sections.SectionStats, health map[string]sections.HealthStatus, dashboards map[string]map[string]any) []CommandCenterSectionPosture {
	out := make([]CommandCenterSectionPosture, 0, len(commandCenterSections))
	for _, def := range commandCenterSections {
		dashboard := dashboards[def.ID]
		summary := mapValue(dashboard, "summary")
		_, sectionRegistered := m.GetSection(def.ID)
		enabled := sectionRegistered
		if stat, ok := stats[def.ID]; ok {
			enabled = stat.Enabled
		}
		configState := "unavailable"
		if sectionRegistered {
			configState = "loaded"
		}
		status := "unavailable"
		message := "Telemetry unavailable"
		if h, ok := health[def.ID]; ok {
			status = string(h.Status)
			message = h.Message
		}
		if !enabled {
			status = "disabled"
		}
		healthMap := mapValue(dashboard, "health")
		freshness := stringValue(healthMap["freshness_status"], status)
		posture := CommandCenterSectionPosture{
			ID:                 def.ID,
			Name:               def.Name,
			ShortName:          def.ShortName,
			Enabled:            enabled,
			Status:             normalizeCommandCenterStatus(status),
			Inspected:          int64(firstNumber(summary, "total_requests", "inspected_requests", "requests_analyzed", "total")),
			Enforced:           int64(sectionEnforcedCount(def.ID, summary, dashboard)),
			Detected:           int64(firstNumber(summary, "detected_signals", "detected_only_attacks", "detected_threats", "detected_bots", "detected", "alerts", "logged")),
			EventCount:         len(commandCenterEvents(dashboard)),
			ConfigState:        configState,
			TelemetryFreshness: freshness,
			P95LatencyMs:       firstNumber(summary, "p95_latency_ms", "p95_inspection_ms", "p95_overhead_ms"),
			TopSignal:          commandCenterTopSignal(dashboard),
			Message:            message,
		}
		out = append(out, posture)
	}
	return out
}

func buildCommandCenterPostureSummary(sections []CommandCenterSectionPosture, dashboards map[string]map[string]any, window string) CommandCenterPostureSummary {
	var inspected, enforced, detected, dropped int64
	var active int
	var p95, avg float64
	status := "healthy"
	for _, section := range sections {
		inspected += section.Inspected
		enforced += section.Enforced
		detected += section.Detected
		if section.Enabled {
			active++
		}
		if section.P95LatencyMs > p95 {
			p95 = section.P95LatencyMs
		}
		if section.Status == "unhealthy" {
			status = "unhealthy"
		} else if section.Status == "degraded" && status == "healthy" {
			status = "degraded"
		}
		summary := mapValue(dashboards[section.ID], "summary")
		avg = maxFloat(avg, firstNumber(summary, "avg_latency_ms", "avg_inspection_ms", "avg_overhead_ms"))
		dropped += int64(firstNumber(summary, "dropped_events"))
	}
	_ = dropped
	return CommandCenterPostureSummary{
		InspectedTraffic: inspected,
		EnforcedActions:  enforced,
		DetectedSignals:  detected,
		ActiveSections:   active,
		TotalSections:    len(sections),
		PlatformHealth:   status,
		P95OverheadMs:    p95,
		AvgOverheadMs:    avg,
		Window:           window,
	}
}

func buildCommandCenterIncidentQueue(dashboards map[string]map[string]any, limit int) []CommandCenterIncident {
	incidents := []CommandCenterIncident{}
	for _, def := range commandCenterSections {
		for _, event := range commandCenterEvents(dashboards[def.ID]) {
			action := stringValue(event["action"], "detect")
			signal := firstString(event, "rule_name", "threat_type", "rule_type", "severity", "reason", "function")
			target := strings.TrimSpace(firstString(event, "method") + " " + firstString(event, "path"))
			if target == "" {
				target = "-"
			}
			ts := int64(firstNumber(event, "timestamp"))
			incidents = append(incidents, CommandCenterIncident{
				Priority:  commandCenterEventPriority(action, firstString(event, "severity")),
				SectionID: def.ID,
				Section:   def.Name,
				Signal:    firstNonEmpty(signal, "Security signal"),
				Action:    action,
				Source:    firstNonEmpty(firstString(event, "client_ip"), firstString(event, "ip"), "-"),
				Target:    target,
				Age:       commandCenterAge(ts),
				Timestamp: ts,
			})
		}
	}
	sort.Slice(incidents, func(i, j int) bool {
		if incidents[i].Priority != incidents[j].Priority {
			return incidents[i].Priority > incidents[j].Priority
		}
		return incidents[i].Timestamp > incidents[j].Timestamp
	})
	if limit > 0 && len(incidents) > limit {
		return incidents[:limit]
	}
	return incidents
}

func buildCommandCenterCoverageGaps(sections []CommandCenterSectionPosture) []CommandCenterAction {
	gaps := []CommandCenterAction{}
	for _, section := range sections {
		if !section.Enabled {
			gaps = append(gaps, CommandCenterAction{Severity: "warning", SectionID: section.ID, Title: section.Name + " is disabled", Detail: "Open the section config to confirm this is intentional.", Route: commandCenterRoute(section.ID), CTA: "Open Config"})
		}
		if section.ConfigState != "loaded" {
			gaps = append(gaps, CommandCenterAction{Severity: "warning", SectionID: section.ID, Title: section.Name + " config unavailable", Detail: "Command Center could not read the section configuration snapshot.", Route: commandCenterRoute(section.ID), CTA: "Open Config"})
		}
		if section.TelemetryFreshness == "unavailable" || section.TelemetryFreshness == "stale" {
			gaps = append(gaps, CommandCenterAction{Severity: "warning", SectionID: section.ID, Title: section.Name + " telemetry is " + section.TelemetryFreshness, Detail: "Fresh analytics are required for complete incident triage.", DashboardSection: section.ID, CTA: "Investigate"})
		}
		if section.Enabled && section.EventCount == 0 {
			gaps = append(gaps, CommandCenterAction{Severity: "muted", SectionID: section.ID, Title: section.Name + " has no recent events", Detail: "This can be normal, but verify telemetry if traffic should be present.", DashboardSection: section.ID, CTA: "Open Dashboard"})
		}
	}
	return gaps
}

func buildCommandCenterRecommendations(d CommandCenterDashboard) []CommandCenterAction {
	actions := []CommandCenterAction{}
	if d.PostureSummary.PlatformHealth != "healthy" {
		actions = append(actions, CommandCenterAction{Severity: "danger", Title: "Platform health is " + d.PostureSummary.PlatformHealth, Detail: "Review System Health before changing enforcement posture."})
	}
	actions = append(actions, d.CoverageGaps...)
	if d.PostureSummary.InspectedTraffic > 0 {
		rate := float64(d.PostureSummary.EnforcedActions) / float64(d.PostureSummary.InspectedTraffic)
		if rate > 0.1 {
			actions = append(actions, CommandCenterAction{Severity: "danger", Title: fmt.Sprintf("High enforcement rate: %.1f%%", rate*100), Detail: "Inspect recent events for false positives or active attack campaigns.", Route: "security_analytics", CTA: "View Events"})
		}
	}
	if len(d.IncidentQueue) == 0 {
		actions = append(actions, CommandCenterAction{Severity: "muted", Title: "No incidents in the queue", Detail: "Use section dashboards for deeper historical review.", Route: "security_analytics", CTA: "View Events"})
	}
	if len(actions) > 8 {
		return actions[:8]
	}
	return actions
}

func buildCommandCenterSignalMix(incidents []CommandCenterIncident) []CommandCenterBreakdown {
	counts := map[string]int64{"block": 0, "challenge": 0, "detect": 0, "allow": 0, "other": 0}
	for _, incident := range incidents {
		counts[normalizeCommandCenterAction(incident.Action)]++
	}
	order := []string{"block", "challenge", "detect", "allow", "other"}
	out := make([]CommandCenterBreakdown, 0, len(order))
	for _, key := range order {
		out = append(out, CommandCenterBreakdown{Key: key, Label: titleCase(key), Count: counts[key], Tone: commandCenterTone(key), Detail: commandCenterActionDetail(key)})
	}
	return out
}

func buildCommandCenterSectionActivity(sections []CommandCenterSectionPosture) []CommandCenterBreakdown {
	out := make([]CommandCenterBreakdown, 0, len(sections))
	for _, section := range sections {
		out = append(out, CommandCenterBreakdown{Key: section.ID, Label: section.ShortName, Count: int64(section.EventCount), Tone: commandCenterStatusTone(section.Status), Detail: firstNonEmpty(section.TopSignal, "No signal mix in this window")})
	}
	return out
}

func buildCommandCenterSystemHealth(health map[string]sections.HealthStatus, dashboards map[string]map[string]any, warnings []string) CommandCenterSystemHealth {
	out := CommandCenterSystemHealth{Status: "healthy", Message: "All sections healthy", Warnings: warnings}
	for _, h := range health {
		status := normalizeCommandCenterStatus(string(h.Status))
		if status == "unhealthy" {
			out.FailedChecks++
			out.Status = "unhealthy"
		} else if status == "degraded" {
			out.DegradedChecks++
			if out.Status == "healthy" {
				out.Status = "degraded"
			}
		}
	}
	for _, dashboard := range dashboards {
		out.DroppedEvents += int64(firstNumber(mapValue(dashboard, "health"), "dropped_events"))
	}
	if out.FailedChecks > 0 || out.DegradedChecks > 0 {
		out.Message = fmt.Sprintf("%d failed, %d degraded checks", out.FailedChecks, out.DegradedChecks)
	}
	return out
}

func buildCommandCenterLaunchers(sections []CommandCenterSectionPosture) []CommandCenterLauncher {
	out := make([]CommandCenterLauncher, 0, len(sections))
	for _, section := range sections {
		out = append(out, CommandCenterLauncher{
			SectionID:        section.ID,
			Name:             section.Name,
			PrimaryLabel:     "Investigate",
			DashboardSection: section.ID,
			SecondaryLabel:   "Configure",
			Route:            commandCenterRoute(section.ID),
			Detail:           fmt.Sprintf("%s - %d events - %s", titleCase(section.Status), section.EventCount, firstNonEmpty(section.TopSignal, "No recent signal")),
		})
	}
	return out
}

func commandCenterEvents(dashboard map[string]any) []map[string]any {
	eventsMap := mapValue(dashboard, "events")
	raw, ok := eventsMap["events"].([]any)
	if !ok {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if row, ok := item.(map[string]any); ok {
			out = append(out, row)
		}
	}
	return out
}

func commandCenterTopSignal(dashboard map[string]any) string {
	breakdowns := mapValue(dashboard, "breakdowns")
	for _, key := range []string{"rules", "attack_categories", "threat_types", "categories", "actions", "functions"} {
		raw, ok := breakdowns[key].([]any)
		if ok && len(raw) > 0 {
			if item, ok := raw[0].(map[string]any); ok {
				return "Top: " + firstNonEmpty(firstString(item, "label"), firstString(item, "key"), key)
			}
		}
	}
	return "No signal mix in this window"
}

func sectionEnforcedCount(section string, summary map[string]any, dashboard map[string]any) float64 {
	switch section {
	case "waf_core":
		return firstNumber(summary, "blocked_attacks", "blocked_requests", "threats_blocked")
	case "bot_protection":
		return firstNumber(summary, "mitigated_bots", "blocked_bots", "bots_blocked") + firstNumber(summary, "challenged_bots", "challenged_requests")
	case "traffic_control":
		return firstNumber(summary, "blocked_requests") + firstNumber(summary, "rate_limited") + firstNumber(summary, "challenged_requests")
	case "api_security":
		return firstNumber(summary, "blocked_threats", "blocked_requests")
	case "http_security":
		return firstNumber(summary, "blocked_requests") + firstNumber(summary, "redirects") + firstNumber(summary, "modified_responses") + firstNumber(summary, "compressed_responses") + firstNumber(summary, "injected_responses")
	default:
		return firstNumber(summary, "blocked_requests", "denied", "blocked")
	}
}

func mapValue(record map[string]any, key string) map[string]any {
	if record == nil {
		return map[string]any{}
	}
	if value, ok := record[key].(map[string]any); ok {
		return value
	}
	return map[string]any{}
}

func firstNumber(record map[string]any, keys ...string) float64 {
	for _, key := range keys {
		if value := numberFromAny(record[key]); value > 0 {
			return value
		}
	}
	return 0
}

func firstString(record map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fmt.Sprint(record[key])); value != "" && value != "<nil>" {
			return value
		}
	}
	return ""
}

func stringValue(value any, fallback string) string {
	if str := strings.TrimSpace(fmt.Sprint(value)); str != "" && str != "<nil>" {
		return str
	}
	return fallback
}

func numberFromAny(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case json.Number:
		out, _ := typed.Float64()
		return out
	case string:
		out, _ := strconv.ParseFloat(typed, 64)
		return out
	default:
		return 0
	}
}

func commandCenterEventPriority(action, severity string) int {
	action = strings.ToLower(action)
	severity = strings.ToLower(severity)
	if strings.Contains(action, "block") || strings.Contains(severity, "critical") {
		return 5
	}
	if strings.Contains(action, "challenge") || strings.Contains(severity, "high") {
		return 4
	}
	if strings.Contains(action, "deny") || strings.Contains(action, "rate") {
		return 3
	}
	if strings.Contains(action, "detect") || strings.Contains(action, "log") || strings.Contains(severity, "medium") {
		return 2
	}
	return 1
}

func commandCenterAge(timestamp int64) string {
	if timestamp <= 0 {
		return "time unknown"
	}
	age := time.Since(time.Unix(timestamp, 0))
	if age < time.Minute {
		return "just now"
	}
	if age < time.Hour {
		return fmt.Sprintf("%dm ago", int(age.Minutes()))
	}
	if age < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(age.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(age.Hours()/24))
}

func normalizeCommandCenterStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	if strings.Contains(status, "healthy") && !strings.Contains(status, "unhealthy") {
		return "healthy"
	}
	if strings.Contains(status, "degraded") || strings.Contains(status, "stale") || strings.Contains(status, "delayed") {
		return "degraded"
	}
	if strings.Contains(status, "unhealthy") || strings.Contains(status, "failed") {
		return "unhealthy"
	}
	if strings.Contains(status, "disabled") {
		return "disabled"
	}
	if status == "" {
		return "unavailable"
	}
	return status
}

func normalizeCommandCenterAction(action string) string {
	action = strings.ToLower(action)
	if strings.Contains(action, "block") || strings.Contains(action, "deny") || strings.Contains(action, "403") {
		return "block"
	}
	if strings.Contains(action, "challenge") || strings.Contains(action, "rate") {
		return "challenge"
	}
	if strings.Contains(action, "allow") || strings.Contains(action, "200") {
		return "allow"
	}
	if strings.Contains(action, "detect") || strings.Contains(action, "log") {
		return "detect"
	}
	return "other"
}

func commandCenterTone(value string) string {
	switch value {
	case "block":
		return "danger"
	case "challenge", "detect":
		return "warning"
	case "allow", "healthy":
		return "success"
	case "unhealthy":
		return "danger"
	case "degraded":
		return "warning"
	default:
		return "secondary"
	}
}

func commandCenterStatusTone(status string) string {
	return commandCenterTone(normalizeCommandCenterStatus(status))
}

func commandCenterActionDetail(action string) string {
	switch action {
	case "block":
		return "Hard enforcement"
	case "challenge":
		return "Verification or rate pressure"
	case "detect":
		return "Observed security signals"
	case "allow":
		return "Allowed outcomes"
	default:
		return "Other outcomes"
	}
}

func commandCenterRoute(sectionID string) string {
	for _, def := range commandCenterSections {
		if def.ID == sectionID {
			return def.Route
		}
	}
	return "dashboard"
}

func titleCase(value string) string {
	value = strings.ReplaceAll(value, "_", " ")
	return strings.Title(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func maxFloat(a, b float64) float64 {
	if b > a {
		return b
	}
	return a
}
