package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// securityAnalyticsSections is deliberately limited to security decision
// streams. Raw request telemetry belongs to Traffic Events, not this view.
var securityAnalyticsSections = []string{
	"waf_core",
	"bot_protection",
	"traffic_control",
	"access_control",
	"api_security",
	"http_security",
	"security_rules",
}

// These are the operator-facing protection sections. Security Rules events
// still contribute to the global dashboard, but are represented by their
// originating protection source rather than as a seventh duplicate section.
var securityAnalyticsDashboardSections = []string{
	"waf_core",
	"bot_protection",
	"traffic_control",
	"api_security",
	"http_security",
	"access_control",
}

// GetSecurityAnalyticsDashboard returns the shared Security Dashboard contract.
// It keeps the WAF dashboard wire shape so the existing operator UI can retain
// its layout while its values come from every security section.
func GetSecurityAnalyticsDashboard(q WAFAnalyticsQuery) (WAFAnalyticsDashboard, error) {
	q.Sections = append([]string{}, securityAnalyticsSections...)
	dashboard := WAFAnalyticsDashboard{
		Timeseries: []WAFTimeseriesPoint{},
		Breakdowns: map[string][]WAFBreakdownItem{},
		Events:     WAFAnalyticsEventsPage{Events: []WAFAnalyticsEvent{}},
		Warnings:   []string{},
	}

	summary, err := GetWAFAnalyticsSummary(q)
	if err != nil {
		return dashboard, err
	}
	dashboard.Summary = summary
	dashboard.Summary.DroppedEvents = DroppedEvents()

	timeseries, err := GetWAFAnalyticsTimeseries(q)
	if err != nil {
		return dashboard, err
	}
	dashboard.Timeseries = timeseries

	for _, dimension := range []string{"rules", "countries", "ips", "paths", "hosts", "actions", "sections"} {
		items, err := GetWAFAnalyticsBreakdown(q, dimension)
		if err != nil {
			return dashboard, err
		}
		if dimension == "sections" {
			for index := range items {
				items[index].Label = securityAnalyticsSectionLabel(items[index].Key)
			}
		}
		dashboard.Breakdowns[dimension] = items
	}

	categories, err := getSecurityMetadataBreakdown(q, securityBreakdownCategories)
	if err != nil {
		return dashboard, err
	}
	severities, err := getSecurityMetadataBreakdown(q, securityBreakdownSeverities)
	if err != nil {
		return dashboard, err
	}
	signals, err := getSecurityMetadataBreakdown(q, securityBreakdownSignals)
	if err != nil {
		return dashboard, err
	}
	scoreBands, err := GetWAFAnomalyScoreBands(q)
	if err != nil {
		return dashboard, err
	}

	allRules := dashboard.Breakdowns["rules"]
	dashboard.AttackIntelligence = WAFAttackIntelligence{
		Categories:        categories,
		Severities:        severities,
		AnomalyScoreBands: scoreBands,
		Trend:             timeseries,
	}
	dashboard.RuleEffectiveness = WAFRuleEffectiveness{
		TopBlockingRules:   topWAFRulesByMode(allRules, "block", 10),
		TopDetectOnlyRules: topWAFRulesByMode(allRules, "detect", 10),
		NoisyRules:         trimWAFBreakdownItems(allRules, 10),
		MatchedFields:      signals,
	}
	summary.TopAttackCategory = topBreakdownKey(categories)
	dashboard.Summary = summary
	dashboard.ProtectionSummary = buildWAFProtectionSummary(summary, map[string][]WAFBreakdownItem{
		"rules":      allRules,
		"severities": severities,
	})

	sectionAnalytics, err := getSecurityAnalyticsSectionAnalytics(q)
	if err != nil {
		return dashboard, err
	}
	dashboard.SectionAnalytics = sectionAnalytics

	events, err := GetSecurityAnalyticsEvents(q)
	if err != nil {
		return dashboard, err
	}
	dashboard.Events = events
	dashboard.Health = getSecurityAnalyticsHealth(q)
	dashboard.InspectionCoverage = WAFInspectionCoverage{
		RequestInspectedCount: summary.TotalRequests,
		DroppedEvents:         dashboard.Health.DroppedEvents,
		FreshnessStatus:       dashboard.Health.FreshnessStatus,
		Message:               dashboard.Health.Message,
	}
	return dashboard, nil
}

func getSecurityAnalyticsSectionAnalytics(q WAFAnalyticsQuery) ([]SecuritySectionAnalytics, error) {
	return getSecurityAnalyticsSourceBreakdowns(q)
}

func newSecuritySectionAnalytics(section string) SecuritySectionAnalytics {
	label := securityAnalyticsSectionLabel(section)
	cards := map[string][]SecurityAnalyticsCard{
		"waf_core": {
			{Key: "attacks_blocked", Label: "Attacks blocked", Detail: "Blocked by WAF"},
			{Key: "detected_only", Label: "Detected only", Detail: "Logged without enforcement"},
			{Key: "critical_high", Label: "Critical / high", Detail: "Severe rule matches"},
			{Key: "rule_matches", Label: "Rule matches", Detail: "Matched WAF rule signals"},
		},
		"bot_protection": {
			{Key: "bots_mitigated", Label: "Bots mitigated", Detail: "Blocked plus challenged"},
			{Key: "challenged", Label: "Challenged", Detail: "Managed challenges issued"},
			{Key: "detected_only", Label: "Detected only", Detail: "Observed without enforcement"},
			{Key: "automation_signals", Label: "Automation signals", Detail: "Headless and fingerprint signals"},
		},
		"traffic_control": {
			{Key: "requests_enforced", Label: "Requests enforced", Detail: "Blocked plus rate limited"},
			{Key: "rate_limited", Label: "Rate limited", Detail: "Throttled at the edge"},
			{Key: "challenged", Label: "Challenged", Detail: "Sent to challenge"},
			{Key: "ddos_blocks", Label: "DDoS blocks", Detail: "Connection and RPS protection"},
		},
		"api_security": {
			{Key: "threats_blocked", Label: "Threats blocked", Detail: "Stopped before upstream"},
			{Key: "detected_only", Label: "Detected only", Detail: "Observed without enforcement"},
			{Key: "critical_high", Label: "Critical / high", Detail: "High-risk API findings"},
			{Key: "schema_failures", Label: "Schema failures", Detail: "Contract validation failures"},
		},
		"http_security": {
			{Key: "requests_blocked", Label: "Requests blocked", Detail: "Request-side protections"},
			{Key: "responses_hardened", Label: "Responses hardened", Detail: "Modified, compressed, injected, or redirected"},
			{Key: "redirected", Label: "Redirected", Detail: "HTTPS and policy redirects"},
			{Key: "compressed", Label: "Compressed", Detail: "Gzip hardening outcomes"},
		},
		"access_control": {
			{Key: "access_denied", Label: "Access denied", Detail: "Denied by access policy"},
			{Key: "allowed", Label: "Allowed", Detail: "Authorized access decisions"},
			{Key: "policy_matches", Label: "Policy matches", Detail: "Access policy decisions"},
			{Key: "unique_source_ips", Label: "Unique source IPs", Detail: "Origins with access decisions"},
		},
	}
	return SecuritySectionAnalytics{Section: section, Label: label, Cards: cards[section]}
}

func securitySectionAnalyticsAddEvent(analytics *SecuritySectionAnalytics, action string, score int32, ruleID, ruleName, clientIP string, metadata map[string]string, sourceIPs map[string]struct{}) {
	action = strings.ToLower(strings.TrimSpace(action))
	matchedRule := strings.TrimSpace(ruleID) != "" || strings.TrimSpace(ruleName) != ""
	highRisk := securityAnalyticsHighRisk(score, metadata)
	matchSignal := func(values ...string) bool {
		return securityAnalyticsContains(metadata, ruleID, ruleName, values...)
	}
	switch analytics.Section {
	case "waf_core":
		if action == "block" {
			securitySectionAnalyticsAdd(analytics, "attacks_blocked", 1)
		}
		if action == "detect" {
			securitySectionAnalyticsAdd(analytics, "detected_only", 1)
		}
		if highRisk {
			securitySectionAnalyticsAdd(analytics, "critical_high", 1)
		}
		if matchedRule {
			securitySectionAnalyticsAdd(analytics, "rule_matches", 1)
		}
	case "bot_protection":
		if action == "block" || action == "challenge" {
			securitySectionAnalyticsAdd(analytics, "bots_mitigated", 1)
		}
		if action == "challenge" {
			securitySectionAnalyticsAdd(analytics, "challenged", 1)
		}
		if action == "detect" {
			securitySectionAnalyticsAdd(analytics, "detected_only", 1)
		}
		if matchSignal("automation", "headless", "fingerprint", "ja3", "ja4") {
			securitySectionAnalyticsAdd(analytics, "automation_signals", 1)
		}
	case "traffic_control":
		rateLimited := action == "ratelimit" || action == "rate_limit" || action == "throttle"
		if action == "block" || rateLimited {
			securitySectionAnalyticsAdd(analytics, "requests_enforced", 1)
		}
		if rateLimited {
			securitySectionAnalyticsAdd(analytics, "rate_limited", 1)
		}
		if action == "challenge" {
			securitySectionAnalyticsAdd(analytics, "challenged", 1)
		}
		if matchSignal("ddos") {
			securitySectionAnalyticsAdd(analytics, "ddos_blocks", 1)
		}
	case "api_security":
		if action == "block" {
			securitySectionAnalyticsAdd(analytics, "threats_blocked", 1)
		}
		if action == "detect" {
			securitySectionAnalyticsAdd(analytics, "detected_only", 1)
		}
		if highRisk {
			securitySectionAnalyticsAdd(analytics, "critical_high", 1)
		}
		if matchSignal("schema", "contract", "validation") {
			securitySectionAnalyticsAdd(analytics, "schema_failures", 1)
		}
	case "http_security":
		if action == "block" || action == "deny" {
			securitySectionAnalyticsAdd(analytics, "requests_blocked", 1)
		}
		if action == "modify" || action == "compress" || action == "inject" || action == "redirect" {
			securitySectionAnalyticsAdd(analytics, "responses_hardened", 1)
		}
		if action == "redirect" {
			securitySectionAnalyticsAdd(analytics, "redirected", 1)
		}
		if action == "compress" {
			securitySectionAnalyticsAdd(analytics, "compressed", 1)
		}
	case "access_control":
		if action == "deny" {
			securitySectionAnalyticsAdd(analytics, "access_denied", 1)
		}
		if action == "allow" {
			securitySectionAnalyticsAdd(analytics, "allowed", 1)
		}
		if matchedRule {
			securitySectionAnalyticsAdd(analytics, "policy_matches", 1)
		}
		if clientIP = strings.TrimSpace(clientIP); clientIP != "" {
			sourceIPs[clientIP] = struct{}{}
		}
	}
}

func securitySectionAnalyticsAdd(analytics *SecuritySectionAnalytics, key string, value int64) {
	for index := range analytics.Cards {
		if analytics.Cards[index].Key == key {
			analytics.Cards[index].Value += value
			return
		}
	}
}

func securityAnalyticsContains(metadata map[string]string, ruleID, ruleName string, values ...string) bool {
	haystack := strings.ToLower(strings.Join(append([]string{ruleID, ruleName}, mapValues(metadata)...), " "))
	for _, value := range values {
		if strings.Contains(haystack, strings.ToLower(value)) {
			return true
		}
	}
	return false
}

func mapValues(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func securityAnalyticsHighRisk(score int32, metadata map[string]string) bool {
	if score >= 10 {
		return true
	}
	for _, severity := range securityBreakdownValues(securityBreakdownSeverities, "", "", "", metadata) {
		switch strings.ToLower(strings.TrimSpace(severity)) {
		case "critical", "high":
			return true
		}
	}
	return false
}

type securitySourceBreakdownSpec struct {
	Key          string
	Label        string
	Dimension    string
	Action       string
	MetadataKeys []string
}

func getSecurityAnalyticsSourceBreakdowns(q WAFAnalyticsQuery) ([]SecuritySectionAnalytics, error) {
	specifications := map[string][]securitySourceBreakdownSpec{
		"waf_core": {
			{Key: "attack_types", Label: "Attack types", Dimension: "categories"},
			{Key: "attack_layers", Label: "Attack evidence layers", MetadataKeys: []string{"aux_layer"}},
			{Key: "attack_categories", Label: "Advanced attack categories", MetadataKeys: []string{"aux_category"}},
			{Key: "severities", Label: "Attack severity", Dimension: "severities"},
			{Key: "attack_payload_locations", Label: "Attack payload locations", Dimension: "signals"},
			{Key: "methods", Label: "Inspected methods", Dimension: "methods"},
			{Key: "hosts", Label: "Protected hosts", Dimension: "hosts"},
			{Key: "policies", Label: "Active policy sources", MetadataKeys: []string{"policy_name", "policy_id", "policy"}},
			{Key: "paths", Label: "Targeted paths", Dimension: "paths"},
			{Key: "countries", Label: "Source countries", Dimension: "countries"},
			{Key: "ips", Label: "Source IPs", Dimension: "ips"},
			{Key: "user_agents", Label: "User agents", Dimension: "user_agents"},
			{Key: "status", Label: "HTTP status codes", Dimension: "status"},
			{Key: "actions", Label: "WAF outcomes", Dimension: "actions"},
			{Key: "score_bands", Label: "Anomaly score bands", Dimension: "score_bands"},
			{Key: "response_inspection", Label: "Response inspection coverage", MetadataKeys: []string{"response_inspection_coverage"}},
		},
		"bot_protection": {
			{Key: "categories", Label: "Bot categories", Dimension: "categories"},
			{Key: "signals", Label: "Automation signals", Dimension: "signals"},
			{Key: "challenge_outcomes", Label: "Challenge outcomes", MetadataKeys: []string{"challenge_outcome", "challenge_result", "outcome"}},
			{Key: "ja3", Label: "JA3 fingerprints", MetadataKeys: []string{"ja3"}},
			{Key: "ja4", Label: "JA4 fingerprints", MetadataKeys: []string{"ja4"}},
			{Key: "asn", Label: "ASN clusters", MetadataKeys: []string{"asn", "asn_org"}},
			{Key: "paths", Label: "Targeted paths", Dimension: "paths"},
			{Key: "countries", Label: "Source countries", Dimension: "countries"},
			{Key: "actions", Label: "Mitigation outcomes", Dimension: "actions"},
			{Key: "challenge_types", Label: "Challenge types", MetadataKeys: []string{"challenge_type"}},
			{Key: "decision_states", Label: "Decision states", MetadataKeys: []string{"decision_state"}},
			{Key: "decision_sources", Label: "Decision sources", MetadataKeys: []string{"decision_source", "source"}},
			{Key: "reputation_bands", Label: "Reputation bands", MetadataKeys: []string{"reputation", "reputation_band"}},
			{Key: "verified_bots", Label: "Verified bot handling", MetadataKeys: []string{"verified"}},
			{Key: "header_profiles", Label: "Header profiles", MetadataKeys: []string{"header_profile"}},
			{Key: "rules", Label: "Bot rule matches", Dimension: "rules"},
		},
		"traffic_control": {
			{Key: "actions", Label: "Decision outcomes", Dimension: "actions"},
			{Key: "reasons", Label: "Enforcement reasons", MetadataKeys: []string{"reason", "reason_code", "threat_type"}},
			{Key: "ddos_triggers", Label: "DDoS triggers", MetadataKeys: []string{"ddos_reason", "ddos_trigger", "trigger"}},
			{Key: "rate_limit_triggers", Label: "Rate limit triggers", MetadataKeys: []string{"rate_limit_trigger", "limit_name", "rate_limit"}},
			{Key: "reputation", Label: "Reputation signals", MetadataKeys: []string{"reputation", "reputation_score", "threat_type"}},
			{Key: "rules", Label: "Enforced controls", Dimension: "rules"},
			{Key: "paths", Label: "Targeted paths", Dimension: "paths"},
			{Key: "countries", Label: "Source countries", Dimension: "countries"},
			{Key: "strategies", Label: "Enforcement strategies", MetadataKeys: []string{"strategy"}},
			{Key: "thresholds", Label: "Protection thresholds", MetadataKeys: []string{"threshold"}},
			{Key: "retry_after", Label: "Retry-after responses", MetadataKeys: []string{"retry_after"}},
			{Key: "protected_objects", Label: "Protected objects", MetadataKeys: []string{"protected_object"}},
			{Key: "matched_rules", Label: "Matched control rules", MetadataKeys: []string{"matched_rule"}},
			{Key: "policy_revisions", Label: "Policy revisions", MetadataKeys: []string{"policy_revision"}},
			{Key: "verified_clients", Label: "Trusted verification", MetadataKeys: []string{"verified"}},
			{Key: "hosts", Label: "Targeted hosts", Dimension: "hosts"},
		},
		"api_security": {
			{Key: "categories", Label: "Threat types", Dimension: "categories"},
			{Key: "severities", Label: "Severity", Dimension: "severities"},
			{Key: "modules", Label: "Security modules", MetadataKeys: []string{"module", "module_name", "function"}},
			{Key: "validation", Label: "Validation signals", MetadataKeys: []string{"function", "validation_error", "failed_requirement", "reason"}},
			{Key: "authorization", Label: "Authorization signals", MetadataKeys: []string{"authorization", "authorization_error", "authz", "authz_error"}},
			{Key: "paths", Label: "Risky endpoints", Dimension: "paths"},
			{Key: "hosts", Label: "Affected hosts", Dimension: "hosts"},
			{Key: "signals", Label: "Affected fields", Dimension: "signals"},
			{Key: "parameters", Label: "Affected parameters", MetadataKeys: []string{"param_name"}},
			{Key: "schema_types", Label: "Schema types", MetadataKeys: []string{"schema_type"}},
			{Key: "payload_evidence", Label: "Payload evidence", MetadataKeys: []string{"payload_snippet", "payload"}},
			{Key: "content_types", Label: "Request content types", MetadataKeys: []string{"content_type"}},
			{Key: "directions", Label: "Inspection directions", MetadataKeys: []string{"direction"}},
			{Key: "data_classes", Label: "Data classes", MetadataKeys: []string{"data_class"}},
			{Key: "response_actions", Label: "Response actions", MetadataKeys: []string{"response_action"}},
			{Key: "operations", Label: "API operations", MetadataKeys: []string{"operation_name"}},
		},
		"http_security": {
			{Key: "signals", Label: "Protection controls", Dimension: "signals"},
			{Key: "actions", Label: "Response outcomes", Dimension: "actions"},
			{Key: "content_types", Label: "Content types", MetadataKeys: []string{"content_type", "response_content_type"}},
			{Key: "methods", Label: "HTTP methods", Dimension: "methods"},
			{Key: "status", Label: "Status codes", Dimension: "status"},
			{Key: "rules", Label: "Applied rules", Dimension: "rules"},
			{Key: "paths", Label: "Targeted paths", Dimension: "paths"},
			{Key: "hosts", Label: "Affected hosts", Dimension: "hosts"},
			{Key: "functions", Label: "Security functions", MetadataKeys: []string{"function"}},
			{Key: "reasons", Label: "Decision reasons", MetadataKeys: []string{"reason"}},
			{Key: "header_evidence", Label: "Header evidence", MetadataKeys: []string{"header_name", "header_names"}},
			{Key: "content_length_bands", Label: "Content-length bands", MetadataKeys: []string{"content_length_band"}},
			{Key: "request_modifications", Label: "Request modifications", MetadataKeys: []string{"request_modification", "request_modifications"}},
			{Key: "response_modifications", Label: "Response modifications", MetadataKeys: []string{"response_modification", "response_modifications"}},
			{Key: "ips", Label: "Source IPs", Dimension: "ips"},
			{Key: "user_agents", Label: "User agents", Dimension: "user_agents"},
		},
		"access_control": {
			{Key: "actions", Label: "Access decisions", Dimension: "actions"},
			{Key: "signals", Label: "Policy outcomes", Dimension: "signals"},
			{Key: "identity_providers", Label: "Identity providers", MetadataKeys: []string{"identity_provider", "idp", "provider"}},
			{Key: "authentication", Label: "Authentication outcomes", MetadataKeys: []string{"auth_result", "authentication_result", "auth_reason"}},
			{Key: "ips", Label: "Source IPs", Dimension: "ips"},
			{Key: "countries", Label: "Source countries", Dimension: "countries"},
			{Key: "paths", Label: "Targeted paths", Dimension: "paths"},
			{Key: "hosts", Label: "Targeted applications", Dimension: "hosts"},
			{Key: "matched_policies", Label: "Matched policies", MetadataKeys: []string{"matched_policy", "policy_id"}},
			{Key: "evaluation_modes", Label: "Evaluation modes", MetadataKeys: []string{"evaluation_mode"}},
			{Key: "policy_attachments", Label: "Policy attachments", MetadataKeys: []string{"policy_attachment_id"}},
			{Key: "policy_versions", Label: "Policy versions", MetadataKeys: []string{"policy_version"}},
			{Key: "denial_reasons", Label: "Denial reasons", MetadataKeys: []string{"reason_code", "failed_requirement"}},
			{Key: "service_credential_types", Label: "Service credential types", MetadataKeys: []string{"service_credential_type"}},
			{Key: "service_credentials", Label: "Service credentials", MetadataKeys: []string{"service_credential_id"}},
			{Key: "user_agents", Label: "User agents", Dimension: "user_agents"},
		},
	}

	analytics := make([]SecuritySectionAnalytics, 0, len(securityAnalyticsDashboardSections))
	for _, section := range securityAnalyticsDashboardSections {
		sourceQuery := q
		sourceQuery.Sections = []string{section}
		sourceQuery.Section = section
		sourceQuery.Limit = 5
		source := SecuritySectionAnalytics{Section: section, Label: securityAnalyticsSectionLabel(section), Breakdowns: []SecurityAnalyticsBreakdown{}}
		for _, specification := range specifications[section] {
			breakdownQuery := sourceQuery
			if specification.Action != "" {
				breakdownQuery.Action = specification.Action
			}
			items, err := getSecurityAnalyticsSourceBreakdown(breakdownQuery, specification)
			if err != nil {
				return nil, err
			}
			source.Breakdowns = append(source.Breakdowns, SecurityAnalyticsBreakdown{
				Key:   specification.Key,
				Label: specification.Label,
				Items: items,
			})
		}
		analytics = append(analytics, source)
	}
	return analytics, nil
}

func getSecurityAnalyticsSourceBreakdown(q WAFAnalyticsQuery, specification securitySourceBreakdownSpec) ([]WAFBreakdownItem, error) {
	if len(specification.MetadataKeys) > 0 {
		return getSecurityMetadataKeyBreakdown(q, specification.MetadataKeys...)
	}
	switch specification.Dimension {
	case "score_bands":
		return GetWAFAnomalyScoreBands(q)
	case "categories":
		return getSecurityMetadataBreakdown(q, securityBreakdownCategories)
	case "severities":
		return getSecurityMetadataBreakdown(q, securityBreakdownSeverities)
	case "signals":
		return getSecurityMetadataBreakdown(q, securityBreakdownSignals)
	default:
		return GetWAFAnalyticsBreakdown(q, specification.Dimension)
	}
}

func getSecurityMetadataKeyBreakdown(q WAFAnalyticsQuery, metadataKeys ...string) ([]WAFBreakdownItem, error) {
	if DB == nil {
		return []WAFBreakdownItem{}, nil
	}
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	rows, err := DB.Query(`
		SELECT `+normalizedActionSQL()+`, toUnixTimestamp(timestamp), score, latency_ms, metadata
		FROM section_events `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := map[string]*WAFBreakdownItem{}
	var total int64
	for rows.Next() {
		var action, rawMetadata string
		var timestamp uint32
		var score int32
		var latency int64
		if err := rows.Scan(&action, &timestamp, &score, &latency, &rawMetadata); err != nil {
			return nil, err
		}
		metadata := map[string]string{}
		_ = json.Unmarshal([]byte(rawMetadata), &metadata)
		for _, value := range securityMetadataValues(metadata, metadataKeys...) {
			key := strings.ToLower(strings.TrimSpace(value))
			if key == "" {
				continue
			}
			item := items[key]
			if item == nil {
				item = &WAFBreakdownItem{Key: key, Label: formatWAFBreakdownLabel("", key)}
				items[key] = item
			}
			item.Count++
			if action == "block" {
				item.Blocked++
			}
			if action == "detect" {
				item.Detected++
			}
			if int64(timestamp) > item.LastSeen {
				item.LastSeen = int64(timestamp)
			}
			item.AvgScore += float64(score)
			item.AvgLatencyMs += float64(latency)
			total++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]WAFBreakdownItem, 0, len(items))
	for _, item := range items {
		if item.Count > 0 {
			item.BlockRate = float64(item.Blocked) / float64(item.Count) * 100
			item.AvgScore = finiteFloat(item.AvgScore / float64(item.Count))
			item.AvgLatencyMs = finiteFloat(item.AvgLatencyMs / float64(item.Count))
		}
		if total > 0 {
			item.Percent = float64(item.Count) / float64(total) * 100
		}
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Label < out[j].Label
		}
		return out[i].Count > out[j].Count
	})
	return trimWAFBreakdownItems(out, NormalizeWAFLimit(q.Limit, 5, 20)), nil
}

func securityMetadataValues(metadata map[string]string, keys ...string) []string {
	for _, key := range keys {
		value := strings.TrimSpace(metadata[key])
		if value == "" {
			continue
		}
		if values := parseStringJSONArray(value); len(values) > 0 {
			return values
		}
		return []string{value}
	}
	return []string{}
}

type securityBreakdownKind string

const (
	securityBreakdownCategories securityBreakdownKind = "categories"
	securityBreakdownSeverities securityBreakdownKind = "severities"
	securityBreakdownSignals    securityBreakdownKind = "signals"
)

func getSecurityMetadataBreakdown(q WAFAnalyticsQuery, kind securityBreakdownKind) ([]WAFBreakdownItem, error) {
	if DB == nil {
		return []WAFBreakdownItem{}, nil
	}
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	rows, err := DB.Query(`
		SELECT section, `+normalizedActionSQL()+`, toUnixTimestamp(timestamp), score, latency_ms, rule_id, rule_name, metadata
		FROM section_events `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := map[string]*WAFBreakdownItem{}
	var total int64
	for rows.Next() {
		var section, action, ruleID, ruleName, rawMetadata string
		var timestamp uint32
		var score int32
		var latency int64
		if err := rows.Scan(&section, &action, &timestamp, &score, &latency, &ruleID, &ruleName, &rawMetadata); err != nil {
			return nil, err
		}
		metadata := map[string]string{}
		_ = json.Unmarshal([]byte(rawMetadata), &metadata)
		for _, value := range securityBreakdownValues(kind, section, ruleID, ruleName, metadata) {
			key := strings.ToLower(strings.TrimSpace(value))
			if key == "" {
				continue
			}
			item := items[key]
			if item == nil {
				item = &WAFBreakdownItem{Key: key, Label: formatSecurityBreakdownLabel(kind, key)}
				items[key] = item
			}
			item.Count++
			if action == "block" {
				item.Blocked++
			}
			if action == "detect" {
				item.Detected++
			}
			if int64(timestamp) > item.LastSeen {
				item.LastSeen = int64(timestamp)
			}
			item.AvgScore += float64(score)
			item.AvgLatencyMs += float64(latency)
			total++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]WAFBreakdownItem, 0, len(items))
	for _, item := range items {
		if item.Count > 0 {
			item.BlockRate = float64(item.Blocked) / float64(item.Count) * 100
			item.AvgScore = finiteFloat(item.AvgScore / float64(item.Count))
			item.AvgLatencyMs = finiteFloat(item.AvgLatencyMs / float64(item.Count))
		}
		if total > 0 {
			item.Percent = float64(item.Count) / float64(total) * 100
		}
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Label < out[j].Label
		}
		return out[i].Count > out[j].Count
	})
	return trimWAFBreakdownItems(out, NormalizeWAFLimit(q.Limit, 10, 100)), nil
}

func securityBreakdownValues(kind securityBreakdownKind, section, ruleID, ruleName string, metadata map[string]string) []string {
	switch kind {
	case securityBreakdownCategories:
		values := parseStringJSONArray(metadata["categories"])
		if len(values) == 0 {
			values = firstSecurityValues(metadata, "threat_type", "category", "bot_category", "reason_code")
		}
		return values
	case securityBreakdownSeverities:
		values := parseStringJSONArray(metadata["severities"])
		if len(values) == 0 {
			values = firstSecurityValues(metadata, "severity", "threat_severity")
		}
		return values
	case securityBreakdownSignals:
		if section == "waf_core" {
			if values := parseStringJSONArray(metadata["matched_fields"]); len(values) > 0 {
				return values
			}
		}
		value := firstNonEmpty(ruleName, ruleID)
		if value == "" {
			if metadataValues := firstSecurityValues(metadata, "reason", "reason_code", "threat_type", "failed_requirement", "bot_category"); len(metadataValues) > 0 {
				value = metadataValues[0]
			}
		}
		if value == "" {
			value = section
		}
		return []string{value}
	default:
		return []string{}
	}
}

func firstSecurityValues(metadata map[string]string, keys ...string) []string {
	for _, key := range keys {
		if value := strings.TrimSpace(metadata[key]); value != "" {
			return []string{value}
		}
	}
	return []string{}
}

func formatSecurityBreakdownLabel(kind securityBreakdownKind, key string) string {
	switch kind {
	case securityBreakdownCategories:
		return formatWAFCategoryLabel(key)
	case securityBreakdownSeverities:
		return formatWAFBreakdownLabel("severities", key)
	default:
		return formatWAFBreakdownLabel("", key)
	}
}

func securityAnalyticsSectionLabel(section string) string {
	switch section {
	case "waf_core":
		return "WAF Core"
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
	case "security_rules":
		return "Security Rules"
	default:
		return strings.Title(strings.ReplaceAll(section, "_", " "))
	}
}

func GetSecurityAnalyticsEvents(q WAFAnalyticsQuery) (WAFAnalyticsEventsPage, error) {
	page := WAFAnalyticsEventsPage{Events: []WAFAnalyticsEvent{}}
	if DB == nil {
		return page, nil
	}
	limit := NormalizeWAFLimit(q.Limit, 50, 500)
	q.Limit = limit + 1
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return page, err
	}
	if q.Cursor != "" {
		cursor, err := strconv.ParseInt(q.Cursor, 10, 64)
		if err != nil {
			return page, fmt.Errorf("invalid cursor")
		}
		if strings.EqualFold(q.Sort, "asc") {
			where += " AND timestamp > ?"
		} else {
			where += " AND timestamp < ?"
		}
		args = append(args, time.Unix(cursor, 0).UTC())
	}
	order := "DESC"
	if strings.EqualFold(q.Sort, "asc") {
		order = "ASC"
	}
	args = append(args, q.Limit)
	rows, err := DB.Query(`
		SELECT id, toUnixTimestamp(timestamp), section, client_ip, country, method, path, status_code, `+normalizedActionSQL()+`, user_agent,
		       rule_id, rule_name, score, latency_ms, request_id, user_agent_family, metadata
		FROM section_events `+where+`
		ORDER BY timestamp `+order+`
		LIMIT ?`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		event, err := scanSecurityAnalyticsEvent(rows)
		if err != nil {
			return page, err
		}
		page.Events = append(page.Events, event)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(page.Events) > limit {
		page.NextCursor = strconv.FormatInt(page.Events[limit-1].Timestamp, 10)
		page.Events = page.Events[:limit]
	}
	page.Count = len(page.Events)
	return page, nil
}

func GetSecurityAnalyticsEvent(id string) (*WAFAnalyticsEvent, error) {
	if DB == nil {
		return nil, nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("missing event id")
	}
	placeholders := make([]string, 0, len(securityAnalyticsSections))
	args := make([]any, 0, len(securityAnalyticsSections)+1)
	for _, section := range securityAnalyticsSections {
		placeholders = append(placeholders, "?")
		args = append(args, section)
	}
	args = append(args, id)
	row := DB.QueryRow(`
		SELECT id, toUnixTimestamp(timestamp), section, client_ip, country, method, path, status_code, `+normalizedActionSQL()+`, user_agent,
		       rule_id, rule_name, score, latency_ms, request_id, user_agent_family, metadata
		FROM section_events
		WHERE section IN (`+strings.Join(placeholders, ", ")+`) AND id = ?
		LIMIT 1`, args...)
	event, err := scanSecurityAnalyticsEvent(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func scanSecurityAnalyticsEvent(row sqlScanner) (WAFAnalyticsEvent, error) {
	var event WAFAnalyticsEvent
	var timestamp uint32
	var status uint16
	var score int32
	var rawMetadata string
	if err := row.Scan(&event.ID, &timestamp, &event.Section, &event.ClientIP, &event.Country, &event.Method, &event.Path, &status, &event.Action, &event.UserAgent, &event.RuleID, &event.RuleName, &score, &event.LatencyMs, &event.RequestID, &event.UserAgentFamily, &rawMetadata); err != nil {
		return event, err
	}
	event.Timestamp = int64(timestamp)
	event.StatusCode = int(status)
	event.AnomalyScore = int(score)
	applyWAFEventMetadata(&event, rawMetadata)
	if len(event.Categories) == 0 {
		event.Categories = firstSecurityValues(event.Metadata, "threat_type", "category", "bot_category", "reason_code")
	}
	if len(event.Severities) == 0 {
		event.Severities = firstSecurityValues(event.Metadata, "severity", "threat_severity")
	}
	if len(event.MatchedFields) == 0 {
		event.MatchedFields = firstSecurityValues(event.Metadata, "reason", "reason_code", "failed_requirement")
	}
	return event, nil
}

func getSecurityAnalyticsHealth(q WAFAnalyticsQuery) WAFAnalyticsHealth {
	health := WAFAnalyticsHealth{
		DBAvailable:     DB != nil,
		DroppedEvents:   DroppedEvents(),
		FreshnessStatus: "unavailable",
		Message:         "",
	}
	if DB == nil {
		return health
	}
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		health.Message = "Unable to read security analytics filters"
		return health
	}
	var count uint64
	var last uint32
	if err := DB.QueryRow(`SELECT count(), toUnixTimestamp(max(timestamp)) FROM section_events `+where, args...).Scan(&count, &last); err != nil {
		health.Message = "Unable to read security analytics freshness"
		return health
	}
	if count == 0 || last == 0 {
		health.FreshnessStatus = "empty"
		health.Message = "No security events have been recorded yet"
		return health
	}
	health.LastEventTimestamp = int64(last)
	health.IngestionLagSeconds = int64(time.Since(time.Unix(int64(last), 0).UTC()).Seconds())
	switch {
	case health.IngestionLagSeconds <= 120:
		health.FreshnessStatus = "fresh"
		health.Message = "Security analytics are current"
	case health.IngestionLagSeconds <= 900:
		health.FreshnessStatus = "delayed"
		health.Message = "Security analytics are slightly delayed"
	default:
		health.FreshnessStatus = "stale"
		health.Message = "Security analytics have not received recent events"
	}
	return health
}
