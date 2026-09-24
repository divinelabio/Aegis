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

type APISecurityAnalyticsQuery struct {
	Window         string
	Interval       string
	Action         string
	Module         string
	Function       string
	ThreatType     string
	Severity       string
	Mode           string
	Direction      string
	DataClass      string
	IP             string
	Path           string
	Method         string
	Host           string
	Status         string
	ResponseAction string
	UserAgent      string
	RuleID         string
	RequestID      string
	Limit          int
	Cursor         string
	Sort           string
}

type APISecurityAnalyticsSummary struct {
	TotalRequests            int64   `json:"total_requests"`
	BlockedThreats           int64   `json:"blocked_threats"`
	DetectedThreats          int64   `json:"detected_threats"`
	AllowedRequests          int64   `json:"allowed_requests"`
	SchemaValidationFailures int64   `json:"schema_validation_failures"`
	ErrorRequests            int64   `json:"error_requests"`
	BlockRate                float64 `json:"block_rate"`
	DetectionRate            float64 `json:"detection_rate"`
	AvgLatencyMs             float64 `json:"avg_latency_ms"`
	P95LatencyMs             float64 `json:"p95_latency_ms"`
	UniqueSourceIPs          int64   `json:"unique_source_ips"`
	UniqueHosts              int64   `json:"unique_hosts"`
	TopThreatType            string  `json:"top_threat_type"`
	DroppedEvents            int64   `json:"dropped_events"`
	Window                   string  `json:"window"`
}

type APISecurityTimeseriesPoint struct {
	Timestamp    int64            `json:"timestamp"`
	Counts       map[string]int64 `json:"counts"`
	AvgLatencyMs float64          `json:"avg_latency_ms"`
	P95LatencyMs float64          `json:"p95_latency_ms"`
}

type APISecurityBreakdownItem struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	Count        int64   `json:"count"`
	Blocked      int64   `json:"blocked"`
	Detected     int64   `json:"detected"`
	BlockRate    float64 `json:"block_rate"`
	Percent      float64 `json:"percent"`
	LastSeen     int64   `json:"last_seen"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

type APISecurityAnalyticsEvent struct {
	ID              string            `json:"id"`
	Timestamp       int64             `json:"timestamp"`
	ClientIP        string            `json:"client_ip"`
	Country         string            `json:"country"`
	Method          string            `json:"method"`
	Host            string            `json:"host"`
	Path            string            `json:"path"`
	QueryString     string            `json:"query_string"`
	StatusCode      int               `json:"status_code"`
	Action          string            `json:"action"`
	UserAgent       string            `json:"user_agent"`
	UserAgentFamily string            `json:"user_agent_family"`
	RuleID          string            `json:"rule_id"`
	RuleName        string            `json:"rule_name"`
	RuleType        string            `json:"rule_type"`
	LatencyMs       int64             `json:"latency_ms"`
	RequestID       string            `json:"request_id"`
	Function        string            `json:"function"`
	ThreatType      string            `json:"threat_type"`
	Severity        string            `json:"severity"`
	ParamName       string            `json:"param_name"`
	PayloadSnippet  string            `json:"payload_snippet"`
	SchemaType      string            `json:"schema_type"`
	ValidationError string            `json:"validation_error"`
	EndpointID      string            `json:"endpoint_id"`
	ContentType     string            `json:"content_type"`
	Mode            string            `json:"mode"`
	Reason          string            `json:"reason"`
	Direction       string            `json:"direction"`
	DataClass       string            `json:"data_class"`
	ResponseAction  string            `json:"response_action"`
	OperationName   string            `json:"operation_name"`
	OperationType   string            `json:"operation_type"`
	ClaimName       string            `json:"claim_name"`
	ProtectedField  string            `json:"protected_field"`
	Count           int64             `json:"count"`
	Threshold       int64             `json:"threshold"`
	WindowSeconds   int64             `json:"window_seconds"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type APISecurityAnalyticsEventsPage struct {
	Events     []APISecurityAnalyticsEvent `json:"events"`
	NextCursor string                      `json:"next_cursor,omitempty"`
	Count      int                         `json:"count"`
}

type APISecurityInventoryCoverage struct {
	TotalEndpoints         int64   `json:"total_endpoints"`
	ActiveEndpoints        int64   `json:"active_endpoints"`
	EndpointsWithSchema    int64   `json:"endpoints_with_schema"`
	EndpointsWithoutSchema int64   `json:"endpoints_without_schema"`
	SchemaCoverage         float64 `json:"schema_coverage"`
	OpenAPISchemas         int64   `json:"openapi_schemas"`
	GraphQLSchemas         int64   `json:"graphql_schemas"`
}

type APISecurityAnalyticsHealth struct {
	DBAvailable         bool   `json:"db_available"`
	LastEventTimestamp  int64  `json:"last_event_timestamp"`
	IngestionLagSeconds int64  `json:"ingestion_lag_seconds"`
	DroppedEvents       int64  `json:"dropped_events"`
	FreshnessStatus     string `json:"freshness_status"`
	Message             string `json:"message"`
}

type APISecurityProtectionSummary struct {
	BlockedThreats           int64   `json:"blocked_threats"`
	DetectedOnlyThreats      int64   `json:"detected_only_threats"`
	SchemaValidationFailures int64   `json:"schema_validation_failures"`
	APIRuleMatches           int64   `json:"api_rule_matches"`
	CriticalHighFindings     int64   `json:"critical_high_findings"`
	EnforcedBlockRate        float64 `json:"enforced_block_rate"`
	TopThreatType            string  `json:"top_threat_type"`
	Window                   string  `json:"window"`
}

type APISecurityEndpointRisk struct {
	TotalEndpoints         int64                      `json:"total_endpoints"`
	ActiveEndpoints        int64                      `json:"active_endpoints"`
	EndpointsWithSchema    int64                      `json:"endpoints_with_schema"`
	EndpointsWithoutSchema int64                      `json:"endpoints_without_schema"`
	SchemaCoverage         float64                    `json:"schema_coverage"`
	TopRiskyEndpoints      []APISecurityBreakdownItem `json:"top_risky_endpoints"`
	TopAffectedHosts       []APISecurityBreakdownItem `json:"top_affected_hosts"`
	NewlyDiscovered        []APISecurityBreakdownItem `json:"newly_discovered"`
}

type APISecurityFunctionEffectiveness struct {
	Functions           []APISecurityBreakdownItem `json:"functions"`
	TopBlocking         []APISecurityBreakdownItem `json:"top_blocking"`
	DetectOnly          []APISecurityBreakdownItem `json:"detect_only"`
	NoisyFunctions      []APISecurityBreakdownItem `json:"noisy_functions"`
	BOLADetections      int64                      `json:"bola_detections"`
	InjectionDetections int64                      `json:"injection_detections"`
	ValidationFailures  int64                      `json:"validation_failures"`
}

type APISecurityAttackIntelligence struct {
	ThreatTypes        []APISecurityBreakdownItem `json:"threat_types"`
	Severities         []APISecurityBreakdownItem `json:"severities"`
	HighRiskPayloads   []APISecurityBreakdownItem `json:"high_risk_payloads"`
	AffectedParameters []APISecurityBreakdownItem `json:"affected_parameters"`
}

type APISecuritySchemaContractHealth struct {
	OpenAPISchemas        int64                      `json:"openapi_schemas"`
	GraphQLSchemas        int64                      `json:"graphql_schemas"`
	SchemaCoverage        float64                    `json:"schema_coverage"`
	ValidationErrors      []APISecurityBreakdownItem `json:"validation_errors"`
	SchemaTypes           []APISecurityBreakdownItem `json:"schema_types"`
	ContentTypeMismatches []APISecurityBreakdownItem `json:"content_type_mismatches"`
	MissingSchemaMessage  string                     `json:"missing_schema_message"`
	ContractDriftMessage  string                     `json:"contract_drift_message"`
}

type APISecurityPolicyHealth struct {
	Status               string `json:"status"`
	SchemaInventoryState string `json:"schema_inventory_state"`
	TelemetryFreshness   string `json:"telemetry_freshness"`
	DroppedEvents        int64  `json:"dropped_events"`
	ConfigMessage        string `json:"config_message"`
}

type APISecurityModuleSummary struct {
	Findings      int64    `json:"findings"`
	Blocks        int64    `json:"blocks"`
	Detects       int64    `json:"detects"`
	TopThreatType string   `json:"top_threat_type"`
	TopEndpoint   string   `json:"top_endpoint"`
	LastSeen      int64    `json:"last_seen"`
	Functions     []string `json:"functions"`
}

type APISecurityAnalyticsDashboard struct {
	Summary               APISecurityAnalyticsSummary           `json:"summary"`
	Timeseries            []APISecurityTimeseriesPoint          `json:"timeseries"`
	Breakdowns            map[string][]APISecurityBreakdownItem `json:"breakdowns"`
	Events                APISecurityAnalyticsEventsPage        `json:"events"`
	Inventory             APISecurityInventoryCoverage          `json:"inventory"`
	ModuleSummary         map[string]APISecurityModuleSummary   `json:"module_summary"`
	Health                APISecurityAnalyticsHealth            `json:"health"`
	ProtectionSummary     APISecurityProtectionSummary          `json:"protection_summary"`
	EndpointRisk          APISecurityEndpointRisk               `json:"endpoint_risk"`
	FunctionEffectiveness APISecurityFunctionEffectiveness      `json:"function_effectiveness"`
	AttackIntelligence    APISecurityAttackIntelligence         `json:"attack_intelligence"`
	SchemaContractHealth  APISecuritySchemaContractHealth       `json:"schema_contract_health"`
	PolicyHealth          APISecurityPolicyHealth               `json:"policy_health"`
	Warnings              []string                              `json:"warnings"`
}

type apiSecuritySignalModule struct {
	Key       string
	Label     string
	Functions []string
}

var apiSecuritySignalModules = []apiSecuritySignalModule{
	{Key: "runtime_blocking", Label: "Runtime Blocking", Functions: []string{"injection", "ssrf", "payload_abuse"}},
	{Key: "contract_enforcement", Label: "Contract Enforcement", Functions: []string{"validation"}},
	{Key: "authorization", Label: "Authorization", Functions: []string{"auth_tokens", "bfla", "mass_assignment", "bola"}},
	{Key: "graphql", Label: "GraphQL", Functions: []string{"graphql"}},
	{Key: "abuse_automation", Label: "Abuse And Automation", Functions: []string{"automation_abuse"}},
	{Key: "data_exposure", Label: "Data Exposure", Functions: []string{"data_exposure"}},
	{Key: "inventory", Label: "Inventory", Functions: []string{"discovery"}},
}

var apiSecurityFunctionModule = buildAPISecurityFunctionModuleCatalog()

var apiSecurityThreatLabels = map[string]string{
	"sqli":                     "SQL Injection",
	"nosqli":                   "NoSQL Injection",
	"cmdi":                     "Command Injection",
	"xss":                      "Cross-Site Scripting",
	"ssrf":                     "SSRF Payload",
	"resource_abuse":           "Resource Abuse",
	"malformed_json":           "Malformed JSON",
	"malformed_xml":            "Malformed XML",
	"xxe":                      "XML External Entity",
	"schema_mismatch":          "Schema Mismatch",
	"unknown_endpoint":         "Unknown Endpoint",
	"invalid_method":           "Invalid Method",
	"invalid_content_type":     "Invalid Content Type",
	"malformed_graphql":        "Malformed GraphQL",
	"graphql_policy_violation": "GraphQL Policy Violation",
	"graphql_introspection":    "GraphQL Introspection",
	"graphql_depth":            "GraphQL Depth",
	"graphql_alias_flood":      "GraphQL Alias Flood",
	"graphql_batch_flood":      "GraphQL Batch Flood",
	"graphql_complexity":       "GraphQL Complexity",
	"missing_token":            "Missing Token",
	"malformed_jwt":            "Malformed JWT",
	"expired_token":            "Expired Token",
	"not_yet_valid_token":      "Not-Yet-Valid Token",
	"bad_issuer":               "Bad Issuer",
	"bad_audience":             "Bad Audience",
	"disallowed_algorithm":     "Disallowed Algorithm",
	"invalid_signature":        "Invalid Signature",
	"bfla_violation":           "BFLA Violation",
	"mass_assignment":          "Mass Assignment",
	"bola_ownership":           "BOLA Ownership",
	"bola_tenant":              "BOLA Tenant",
	"idor_enumeration":         "IDOR Enumeration",
	"credential_stuffing":      "Credential Stuffing",
	"brute_force_login":        "Login Brute Force",
	"otp_bruteforce":           "OTP Brute Force",
	"forced_browsing":          "Forced Browsing",
	"user_enumeration":         "User Enumeration",
	"object_id_enumeration":    "Object ID Enumeration",
	"scraping_burst":           "Scraping Burst",
	"expensive_query_abuse":    "Expensive Query Abuse",
	"secret_exposure":          "Secret Exposure",
	"token_exposure":           "Token Exposure",
	"payment_data_exposure":    "Payment Data Exposure",
	"pii_exposure":             "PII Exposure",
	"debug_data_exposure":      "Debug Data Exposure",
	"internal_data_exposure":   "Internal Data Exposure",
	"source_code_exposure":     "Source Code Exposure",
	"config_leakage":           "Config Leakage",
	"shadow_api":               "Shadow API",
	"zombie_api":               "Zombie API",
}

var apiSecurityThreatDefaultSeverity = map[string]string{
	"sqli":                   "critical",
	"nosqli":                 "critical",
	"cmdi":                   "critical",
	"xss":                    "high",
	"ssrf":                   "high",
	"resource_abuse":         "medium",
	"schema_mismatch":        "medium",
	"unknown_endpoint":       "medium",
	"invalid_method":         "medium",
	"invalid_content_type":   "medium",
	"malformed_graphql":      "medium",
	"graphql_introspection":  "medium",
	"graphql_depth":          "high",
	"graphql_alias_flood":    "high",
	"graphql_batch_flood":    "high",
	"graphql_complexity":     "high",
	"missing_token":          "medium",
	"malformed_jwt":          "medium",
	"expired_token":          "medium",
	"not_yet_valid_token":    "medium",
	"bad_issuer":             "high",
	"bad_audience":           "high",
	"disallowed_algorithm":   "high",
	"invalid_signature":      "critical",
	"bfla_violation":         "high",
	"mass_assignment":        "high",
	"bola_ownership":         "critical",
	"bola_tenant":            "critical",
	"idor_enumeration":       "high",
	"credential_stuffing":    "high",
	"brute_force_login":      "high",
	"otp_bruteforce":         "high",
	"forced_browsing":        "medium",
	"user_enumeration":       "medium",
	"object_id_enumeration":  "high",
	"scraping_burst":         "medium",
	"expensive_query_abuse":  "medium",
	"secret_exposure":        "critical",
	"token_exposure":         "critical",
	"payment_data_exposure":  "critical",
	"pii_exposure":           "high",
	"debug_data_exposure":    "medium",
	"internal_data_exposure": "medium",
	"source_code_exposure":   "high",
	"config_leakage":         "high",
	"shadow_api":             "medium",
	"zombie_api":             "medium",
}

var apiSecurityFunctionLabels = map[string]string{
	"discovery":        "Discovery",
	"validation":       "Contract Enforcement",
	"injection":        "Injection Blocking",
	"ssrf":             "SSRF Payload Blocking",
	"payload_abuse":    "Payload Abuse Blocking",
	"auth_tokens":      "Auth Token Validation",
	"bfla":             "BFLA Policy",
	"mass_assignment":  "Mass Assignment",
	"bola":             "BOLA / IDOR",
	"graphql":          "GraphQL Protection",
	"automation_abuse": "Automation Abuse",
	"data_exposure":    "Data Exposure",
}

func buildAPISecurityFunctionModuleCatalog() map[string]string {
	out := map[string]string{}
	for _, module := range apiSecuritySignalModules {
		for _, function := range module.Functions {
			out[function] = module.Key
		}
	}
	return out
}

func GetAPISecurityAnalyticsDashboard(q APISecurityAnalyticsQuery) (APISecurityAnalyticsDashboard, error) {
	dashboard := APISecurityAnalyticsDashboard{
		Timeseries:    []APISecurityTimeseriesPoint{},
		Breakdowns:    map[string][]APISecurityBreakdownItem{},
		Events:        APISecurityAnalyticsEventsPage{Events: []APISecurityAnalyticsEvent{}},
		ModuleSummary: emptyAPISecurityModuleSummary(),
		Warnings:      []string{},
	}
	if _, _, err := buildAPISecurityAnalyticsWhere(q); err != nil {
		return dashboard, err
	}
	if _, err := ResolveWAFAnalyticsInterval(q.Window, q.Interval); err != nil {
		return dashboard, err
	}
	if summary, err := GetAPISecurityAnalyticsSummary(q); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "summary unavailable")
	} else {
		dashboard.Summary = summary
	}
	if points, err := GetAPISecurityAnalyticsTimeseries(q); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "timeseries unavailable")
	} else {
		dashboard.Timeseries = points
	}
	breakdownQuery := q
	breakdownQuery.Limit = NormalizeWAFLimit(q.Limit, 10, 100)
	for _, dimension := range apiSecurityDashboardBreakdownDimensions() {
		items, err := GetAPISecurityAnalyticsBreakdown(breakdownQuery, dimension)
		if err != nil {
			dashboard.Warnings = append(dashboard.Warnings, dimension+" breakdown unavailable")
			dashboard.Breakdowns[dimension] = []APISecurityBreakdownItem{}
			continue
		}
		dashboard.Breakdowns[dimension] = items
	}
	if moduleSummary, err := GetAPISecurityAnalyticsModuleSummary(q); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "module summary unavailable")
	} else {
		dashboard.ModuleSummary = moduleSummary
	}
	eventQuery := q
	eventQuery.Limit = NormalizeWAFLimit(q.Limit, 50, 500)
	if events, err := GetAPISecurityAnalyticsEvents(eventQuery); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "events unavailable")
	} else {
		dashboard.Events = events
	}
	if inventory, err := GetAPISecurityInventoryCoverage(); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "inventory coverage unavailable")
	} else {
		dashboard.Inventory = inventory
	}
	if dashboard.Summary.TopThreatType == "" {
		dashboard.Summary.TopThreatType = topAPISecurityBreakdownKey(dashboard.Breakdowns["threat_types"])
	}
	dashboard.Health = GetAPISecurityAnalyticsHealth()
	PopulateAPISecurityAnalyticsDashboardGroups(&dashboard)
	return dashboard, nil
}

func PopulateAPISecurityAnalyticsDashboardGroups(dashboard *APISecurityAnalyticsDashboard) {
	if dashboard == nil {
		return
	}
	breakdowns := dashboard.Breakdowns
	if breakdowns == nil {
		breakdowns = map[string][]APISecurityBreakdownItem{}
		dashboard.Breakdowns = breakdowns
	}
	if dashboard.ModuleSummary == nil {
		dashboard.ModuleSummary = emptyAPISecurityModuleSummary()
	}
	summary := dashboard.Summary
	inventory := dashboard.Inventory
	health := dashboard.Health
	severities := safeAPISecurityBreakdown(breakdowns, "severities")
	functions := safeAPISecurityBreakdown(breakdowns, "functions")

	dashboard.ProtectionSummary = APISecurityProtectionSummary{
		BlockedThreats:           summary.BlockedThreats,
		DetectedOnlyThreats:      summary.DetectedThreats,
		SchemaValidationFailures: summary.SchemaValidationFailures,
		APIRuleMatches:           sumAPISecurityBreakdown(safeAPISecurityBreakdown(breakdowns, "rules")),
		CriticalHighFindings:     countAPISecuritySeverity(severities, "critical", "high"),
		EnforcedBlockRate:        summary.BlockRate,
		TopThreatType:            summary.TopThreatType,
		Window:                   summary.Window,
	}
	dashboard.EndpointRisk = APISecurityEndpointRisk{
		TotalEndpoints:         inventory.TotalEndpoints,
		ActiveEndpoints:        inventory.ActiveEndpoints,
		EndpointsWithSchema:    inventory.EndpointsWithSchema,
		EndpointsWithoutSchema: inventory.EndpointsWithoutSchema,
		SchemaCoverage:         inventory.SchemaCoverage,
		TopRiskyEndpoints:      safeAPISecurityBreakdown(breakdowns, "endpoints"),
		TopAffectedHosts:       safeAPISecurityBreakdown(breakdowns, "hosts"),
		NewlyDiscovered:        []APISecurityBreakdownItem{},
	}
	dashboard.FunctionEffectiveness = APISecurityFunctionEffectiveness{
		Functions:           functions,
		TopBlocking:         filterAPISecurityBreakdowns(functions, func(item APISecurityBreakdownItem) bool { return item.Blocked > 0 }),
		DetectOnly:          filterAPISecurityBreakdowns(functions, func(item APISecurityBreakdownItem) bool { return item.Detected > 0 && item.Blocked == 0 }),
		NoisyFunctions:      filterAPISecurityBreakdowns(functions, func(item APISecurityBreakdownItem) bool { return item.Detected > item.Blocked }),
		BOLADetections:      countAPISecurityKey(functions, "bola"),
		InjectionDetections: countAPISecurityKey(functions, "injection"),
		ValidationFailures:  summary.SchemaValidationFailures,
	}
	dashboard.AttackIntelligence = APISecurityAttackIntelligence{
		ThreatTypes:        safeAPISecurityBreakdown(breakdowns, "threat_types"),
		Severities:         severities,
		HighRiskPayloads:   safeAPISecurityBreakdown(breakdowns, "payloads"),
		AffectedParameters: safeAPISecurityBreakdown(breakdowns, "parameters"),
	}
	dashboard.SchemaContractHealth = APISecuritySchemaContractHealth{
		OpenAPISchemas:        inventory.OpenAPISchemas,
		GraphQLSchemas:        inventory.GraphQLSchemas,
		SchemaCoverage:        inventory.SchemaCoverage,
		ValidationErrors:      safeAPISecurityBreakdown(breakdowns, "validation_errors"),
		SchemaTypes:           safeAPISecurityBreakdown(breakdowns, "schema_types"),
		ContentTypeMismatches: safeAPISecurityBreakdown(breakdowns, "content_types"),
		MissingSchemaMessage:  missingAPISecuritySchemaMessage(inventory),
		ContractDriftMessage:  "Contract drift telemetry unavailable",
	}
	dashboard.PolicyHealth = APISecurityPolicyHealth{
		Status:               apiSecurityPolicyStatus(health),
		SchemaInventoryState: apiSecurityInventoryState(inventory),
		TelemetryFreshness:   health.FreshnessStatus,
		DroppedEvents:        health.DroppedEvents,
		ConfigMessage:        health.Message,
	}
}

func safeAPISecurityBreakdown(breakdowns map[string][]APISecurityBreakdownItem, key string) []APISecurityBreakdownItem {
	if items, ok := breakdowns[key]; ok && items != nil {
		return items
	}
	return []APISecurityBreakdownItem{}
}

func sumAPISecurityBreakdown(items []APISecurityBreakdownItem) int64 {
	var total int64
	for _, item := range items {
		total += item.Count
	}
	return total
}

func countAPISecuritySeverity(items []APISecurityBreakdownItem, severities ...string) int64 {
	allowed := map[string]bool{}
	for _, severity := range severities {
		allowed[strings.ToLower(severity)] = true
	}
	var total int64
	for _, item := range items {
		if allowed[strings.ToLower(firstNonEmptyString(item.Key, item.Label))] {
			total += item.Count
		}
	}
	return total
}

func countAPISecurityKey(items []APISecurityBreakdownItem, key string) int64 {
	var total int64
	for _, item := range items {
		value := strings.ToLower(firstNonEmptyString(item.Key, item.Label))
		if strings.Contains(value, strings.ToLower(key)) {
			total += item.Count
		}
	}
	return total
}

func filterAPISecurityBreakdowns(items []APISecurityBreakdownItem, keep func(APISecurityBreakdownItem) bool) []APISecurityBreakdownItem {
	out := []APISecurityBreakdownItem{}
	for _, item := range items {
		if keep(item) {
			out = append(out, item)
		}
	}
	return out
}

func missingAPISecuritySchemaMessage(inventory APISecurityInventoryCoverage) string {
	if inventory.ActiveEndpoints == 0 {
		return "No active API endpoints observed"
	}
	if inventory.EndpointsWithoutSchema == 0 {
		return "All active API endpoints have schemas"
	}
	return fmt.Sprintf("%d active API endpoints are missing schemas", inventory.EndpointsWithoutSchema)
}

func apiSecurityPolicyStatus(health APISecurityAnalyticsHealth) string {
	if !health.DBAvailable {
		return "unavailable"
	}
	if health.FreshnessStatus == "fresh" {
		return "healthy"
	}
	return health.FreshnessStatus
}

func apiSecurityInventoryState(inventory APISecurityInventoryCoverage) string {
	if inventory.ActiveEndpoints == 0 {
		return "unavailable"
	}
	if inventory.EndpointsWithoutSchema > 0 {
		return "partial"
	}
	return "covered"
}

func GetAPISecurityAnalyticsSummary(q APISecurityAnalyticsQuery) (APISecurityAnalyticsSummary, error) {
	summary := APISecurityAnalyticsSummary{Window: defaultWindow(q.Window), DroppedEvents: DroppedEvents()}
	if DB == nil {
		return summary, nil
	}
	where, args, err := buildAPISecurityAnalyticsWhere(q)
	if err != nil {
		return summary, err
	}
	row := DB.QueryRow(`
		SELECT count(),
			countIf(`+normalizedAPISecurityActionSQL()+` = 'block'),
			countIf(`+normalizedAPISecurityActionSQL()+` = 'detect'),
			countIf(`+normalizedAPISecurityActionSQL()+` = 'allow'),
			countIf(JSONExtractString(metadata, 'function') = 'validation' AND `+normalizedAPISecurityActionSQL()+` IN ('block', 'detect')),
			countIf(status_code >= 400 AND `+normalizedAPISecurityActionSQL()+` != 'block'),
			COALESCE(avg(latency_ms), 0),
			COALESCE(quantile(0.95)(latency_ms), 0),
			uniqExact(client_ip),
			uniqExactIf(JSONExtractString(metadata, 'host'), JSONExtractString(metadata, 'host') != '')
		FROM section_events `+where, args...)
	var total, blocked, detected, allowed, validationFailures, errors, uniqueIPs, uniqueHosts uint64
	if err := row.Scan(&total, &blocked, &detected, &allowed, &validationFailures, &errors, &summary.AvgLatencyMs, &summary.P95LatencyMs, &uniqueIPs, &uniqueHosts); err != nil {
		return summary, err
	}
	summary.TotalRequests = int64(total)
	summary.BlockedThreats = int64(blocked)
	summary.DetectedThreats = int64(detected)
	summary.AllowedRequests = int64(allowed)
	summary.SchemaValidationFailures = int64(validationFailures)
	summary.ErrorRequests = int64(errors)
	summary.UniqueSourceIPs = int64(uniqueIPs)
	summary.UniqueHosts = int64(uniqueHosts)
	if total > 0 {
		summary.BlockRate = float64(blocked) / float64(total) * 100
		summary.DetectionRate = float64(blocked+detected) / float64(total) * 100
	}
	summary.AvgLatencyMs = finiteFloat(summary.AvgLatencyMs)
	summary.P95LatencyMs = finiteFloat(summary.P95LatencyMs)
	return summary, nil
}

func GetAPISecurityAnalyticsTimeseries(q APISecurityAnalyticsQuery) ([]APISecurityTimeseriesPoint, error) {
	if DB == nil {
		return []APISecurityTimeseriesPoint{}, nil
	}
	where, args, err := buildAPISecurityAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	interval, err := ResolveWAFAnalyticsInterval(q.Window, q.Interval)
	if err != nil {
		return nil, err
	}
	rows, err := DB.Query(`
		SELECT toUnixTimestamp(bucket), action, count(), COALESCE(avg(latency_ms), 0), COALESCE(quantile(0.95)(latency_ms), 0)
		FROM (
			SELECT `+bucketExpression(interval)+` AS bucket, `+normalizedAPISecurityActionSQL()+` AS action, latency_ms
			FROM section_events `+where+`
		)
		GROUP BY bucket, action
		ORDER BY bucket ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byBucket := map[int64]*APISecurityTimeseriesPoint{}
	for rows.Next() {
		var ts uint32
		var action string
		var count uint64
		var avgLatency, p95Latency float64
		if err := rows.Scan(&ts, &action, &count, &avgLatency, &p95Latency); err != nil {
			return nil, err
		}
		key := int64(ts)
		point := byBucket[key]
		if point == nil {
			point = &APISecurityTimeseriesPoint{Timestamp: key, Counts: map[string]int64{}}
			byBucket[key] = point
		}
		point.Counts[action] = int64(count)
		point.AvgLatencyMs = finiteFloat(avgLatency)
		point.P95LatencyMs = finiteFloat(p95Latency)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	keys := make([]int64, 0, len(byBucket))
	for key := range byBucket {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]APISecurityTimeseriesPoint, 0, len(keys))
	for _, key := range keys {
		out = append(out, *byBucket[key])
	}
	return out, nil
}

func GetAPISecurityAnalyticsBreakdown(q APISecurityAnalyticsQuery, dimension string) ([]APISecurityBreakdownItem, error) {
	dimension = strings.ToLower(strings.TrimSpace(dimension))
	if err := ValidateAPISecurityBreakdownDimension(dimension); err != nil {
		return nil, err
	}
	if DB == nil {
		return []APISecurityBreakdownItem{}, nil
	}
	where, args, err := buildAPISecurityAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	expr, labelExpr := apiSecurityBreakdownExpression(dimension)
	limit := NormalizeWAFLimit(q.Limit, 10, 100)
	args = append(args, limit)
	findingFilter := ""
	if apiSecurityBreakdownRequiresFindingAction(dimension) {
		findingFilter = " AND " + apiSecurityFindingActionSQL()
	}
	rows, err := DB.Query(fmt.Sprintf(`
		SELECT %s AS key, %s AS label, count(),
			countIf(%s = 'block'),
			countIf(%s = 'detect'),
			toUnixTimestamp(max(timestamp)),
			COALESCE(avg(latency_ms), 0)
		FROM section_events %s%s AND %s != ''
		GROUP BY key, label
		ORDER BY count() DESC
		LIMIT ?`, expr, labelExpr, normalizedAPISecurityActionSQL(), normalizedAPISecurityActionSQL(), where, findingFilter, expr), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]APISecurityBreakdownItem, 0, limit)
	var total int64
	for rows.Next() {
		var item APISecurityBreakdownItem
		var count, blocked, detected uint64
		var lastSeen uint32
		if err := rows.Scan(&item.Key, &item.Label, &count, &blocked, &detected, &lastSeen, &item.AvgLatencyMs); err != nil {
			return nil, err
		}
		item.Count = int64(count)
		item.Blocked = int64(blocked)
		item.Detected = int64(detected)
		item.LastSeen = int64(lastSeen)
		if count > 0 {
			item.BlockRate = float64(blocked) / float64(count) * 100
		}
		item.AvgLatencyMs = finiteFloat(item.AvgLatencyMs)
		item.Label = formatAPISecurityBreakdownLabel(dimension, item.Label)
		total += item.Count
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range items {
		if total > 0 {
			items[i].Percent = float64(items[i].Count) / float64(total) * 100
		}
	}
	return items, nil
}

func GetAPISecurityAnalyticsModuleSummary(q APISecurityAnalyticsQuery) (map[string]APISecurityModuleSummary, error) {
	summaries := emptyAPISecurityModuleSummary()
	if DB == nil {
		return summaries, nil
	}
	where, args, err := buildAPISecurityAnalyticsWhere(q)
	if err != nil {
		return summaries, err
	}
	functionExpr := "JSONExtractString(metadata, 'function')"
	moduleExpr := apiSecurityModuleSQLExpression(functionExpr)
	threatExpr := "JSONExtractString(metadata, 'threat_type')"
	endpointExpr := "if(JSONExtractString(metadata, 'endpoint_id') != '', JSONExtractString(metadata, 'endpoint_id'), concat(method, ' ', path))"
	rows, err := DB.Query(fmt.Sprintf(`
		SELECT %s AS module, %s AS function, %s AS threat_type, %s AS endpoint,
			count(),
			countIf(%s = 'block'),
			countIf(%s = 'detect'),
			toUnixTimestamp(max(timestamp))
		FROM section_events %s AND %s AND %s != ''
		GROUP BY module, function, threat_type, endpoint`, moduleExpr, functionExpr, threatExpr, endpointExpr, normalizedAPISecurityActionSQL(), normalizedAPISecurityActionSQL(), where, apiSecurityFindingActionSQL(), moduleExpr), args...)
	if err != nil {
		return summaries, err
	}
	defer rows.Close()

	type moduleAccumulator struct {
		summary       APISecurityModuleSummary
		functions     map[string]bool
		threatCounts  map[string]int64
		endpointCount map[string]int64
	}
	accumulators := map[string]*moduleAccumulator{}
	for _, module := range apiSecuritySignalModules {
		accumulators[module.Key] = &moduleAccumulator{
			summary:       summaries[module.Key],
			functions:     map[string]bool{},
			threatCounts:  map[string]int64{},
			endpointCount: map[string]int64{},
		}
	}
	for rows.Next() {
		var module, function, threatType, endpoint string
		var count, blocks, detects uint64
		var lastSeen uint32
		if err := rows.Scan(&module, &function, &threatType, &endpoint, &count, &blocks, &detects, &lastSeen); err != nil {
			return summaries, err
		}
		acc := accumulators[module]
		if acc == nil {
			continue
		}
		acc.summary.Findings += int64(count)
		acc.summary.Blocks += int64(blocks)
		acc.summary.Detects += int64(detects)
		if int64(lastSeen) > acc.summary.LastSeen {
			acc.summary.LastSeen = int64(lastSeen)
		}
		function = strings.TrimSpace(function)
		if function != "" {
			acc.functions[function] = true
		}
		threatType = strings.TrimSpace(threatType)
		if threatType != "" {
			acc.threatCounts[threatType] += int64(count)
		}
		endpoint = strings.TrimSpace(endpoint)
		if endpoint != "" {
			acc.endpointCount[endpoint] += int64(count)
		}
	}
	if err := rows.Err(); err != nil {
		return summaries, err
	}
	for _, module := range apiSecuritySignalModules {
		acc := accumulators[module.Key]
		if acc == nil {
			continue
		}
		acc.summary.Functions = sortedAPISecurityKeys(acc.functions)
		acc.summary.TopThreatType = formatAPISecurityBreakdownLabel("threat_types", topAPISecurityCountKey(acc.threatCounts))
		acc.summary.TopEndpoint = topAPISecurityCountKey(acc.endpointCount)
		summaries[module.Key] = acc.summary
	}
	return summaries, nil
}

func GetAPISecurityAnalyticsEvents(q APISecurityAnalyticsQuery) (APISecurityAnalyticsEventsPage, error) {
	page := APISecurityAnalyticsEventsPage{Events: []APISecurityAnalyticsEvent{}}
	if DB == nil {
		return page, nil
	}
	limit := NormalizeWAFLimit(q.Limit, 50, 500)
	q.Limit = limit + 1
	where, args, err := buildAPISecurityAnalyticsWhere(q)
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
		SELECT id, toUnixTimestamp(timestamp), client_ip, country, method, path, status_code, `+normalizedAPISecurityActionSQL()+`, user_agent,
		       user_agent_family, rule_id, rule_name, rule_type, latency_ms, request_id, metadata
		FROM section_events `+where+`
		ORDER BY timestamp `+order+`
		LIMIT ?`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		event, err := scanAPISecurityAnalyticsEvent(rows)
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

func GetAPISecurityAnalyticsEvent(id string) (*APISecurityAnalyticsEvent, error) {
	if DB == nil {
		return nil, nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("missing event id")
	}
	row := DB.QueryRow(`
		SELECT id, toUnixTimestamp(timestamp), client_ip, country, method, path, status_code, `+normalizedAPISecurityActionSQL()+`, user_agent,
		       user_agent_family, rule_id, rule_name, rule_type, latency_ms, request_id, metadata
		FROM section_events
		WHERE section = 'api_security' AND id = ?
		LIMIT 1`, id)
	event, err := scanAPISecurityAnalyticsEvent(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func GetAPISecurityInventoryCoverage() (APISecurityInventoryCoverage, error) {
	coverage := APISecurityInventoryCoverage{}
	if DB == nil {
		return coverage, nil
	}
	row := DB.QueryRow(`
		SELECT
			(SELECT countDistinct(id) FROM endpoints),
			(SELECT countDistinctIf(id, is_active = 1) FROM endpoints),
			(SELECT countDistinct(endpoint_id) FROM schemas WHERE is_active = 1),
			(SELECT countDistinctIf(id, type IN ('openapi', 'rest')) FROM schemas WHERE is_active = 1),
			(SELECT countDistinctIf(id, type = 'graphql') FROM schemas WHERE is_active = 1)
	`)
	var total, active, withSchema, openapi, graphql uint64
	if err := row.Scan(&total, &active, &withSchema, &openapi, &graphql); err != nil {
		return coverage, err
	}
	coverage.TotalEndpoints = int64(total)
	coverage.ActiveEndpoints = int64(active)
	coverage.EndpointsWithSchema = int64(withSchema)
	if active > withSchema {
		coverage.EndpointsWithoutSchema = int64(active - withSchema)
	}
	if active > 0 {
		coverage.SchemaCoverage = float64(withSchema) / float64(active) * 100
	}
	coverage.OpenAPISchemas = int64(openapi)
	coverage.GraphQLSchemas = int64(graphql)
	return coverage, nil
}

func GetAPISecurityAnalyticsHealth() APISecurityAnalyticsHealth {
	health := APISecurityAnalyticsHealth{DBAvailable: DB != nil, DroppedEvents: DroppedEvents(), FreshnessStatus: "unavailable", Message: ""}
	if DB == nil {
		return health
	}
	health.Message = "No API Security analytics events have been recorded yet"
	var count uint64
	var last uint32
	err := DB.QueryRow(`SELECT count(), toUnixTimestamp(max(timestamp)) FROM section_events WHERE section = 'api_security'`).Scan(&count, &last)
	if err != nil {
		health.Message = "Unable to read API Security analytics freshness"
		return health
	}
	if count == 0 || last == 0 {
		health.FreshnessStatus = "empty"
		return health
	}
	health.LastEventTimestamp = int64(last)
	health.IngestionLagSeconds = int64(time.Since(time.Unix(int64(last), 0).UTC()).Seconds())
	switch {
	case health.IngestionLagSeconds <= 120:
		health.FreshnessStatus = "fresh"
		health.Message = "API Security analytics are current"
	case health.IngestionLagSeconds <= 900:
		health.FreshnessStatus = "delayed"
		health.Message = "API Security analytics are slightly delayed"
	default:
		health.FreshnessStatus = "stale"
		health.Message = "API Security analytics have not received recent events"
	}
	return health
}

func apiSecurityDashboardBreakdownDimensions() []string {
	return []string{
		"actions",
		"functions",
		"threat_types",
		"severities",
		"endpoints",
		"paths",
		"methods",
		"hosts",
		"ips",
		"status",
		"user_agent_families",
		"parameters",
		"validation_errors",
		"schema_types",
		"content_types",
		"rules",
		"payloads",
		"modes",
		"directions",
		"data_classes",
		"response_actions",
		"modules",
	}
}

func emptyAPISecurityModuleSummary() map[string]APISecurityModuleSummary {
	out := map[string]APISecurityModuleSummary{}
	for _, module := range apiSecuritySignalModules {
		out[module.Key] = APISecurityModuleSummary{Functions: []string{}}
	}
	return out
}

func normalizeAPISecurityModuleKey(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_"), " ", "_")
}

func apiSecurityFunctionsForModule(moduleKey string) ([]string, error) {
	normalized := normalizeAPISecurityModuleKey(moduleKey)
	for _, module := range apiSecuritySignalModules {
		if module.Key == normalized {
			return append([]string{}, module.Functions...), nil
		}
	}
	return nil, fmt.Errorf("invalid API Security module %q", moduleKey)
}

func ValidateAPISecurityModule(moduleKey string) error {
	if strings.TrimSpace(moduleKey) == "" {
		return nil
	}
	_, err := apiSecurityFunctionsForModule(moduleKey)
	return err
}

func ValidateAPISecurityBreakdownDimension(dimension string) error {
	switch strings.ToLower(strings.TrimSpace(dimension)) {
	case "actions", "functions", "threat_types", "severities", "endpoints", "paths", "methods", "hosts", "ips", "status", "user_agent_families", "user_agents", "parameters", "validation_errors", "schema_types", "content_types", "rules", "payloads", "modes", "directions", "data_classes", "response_actions", "modules":
		return nil
	default:
		return fmt.Errorf("unsupported breakdown dimension %q", dimension)
	}
}

func buildAPISecurityAnalyticsWhere(q APISecurityAnalyticsQuery) (string, []any, error) {
	since, err := windowStart(defaultWindow(q.Window))
	if err != nil {
		return "", nil, err
	}
	clauses := []string{"section = 'api_security'", "timestamp >= ?"}
	args := []any{since}
	add := func(clause string, value any) { clauses = append(clauses, clause); args = append(args, value) }
	if q.Action != "" {
		add(normalizedAPISecurityActionSQL()+" = ?", normalizeAPISecurityAction(q.Action))
	}
	if q.Module != "" {
		functions, err := apiSecurityFunctionsForModule(q.Module)
		if err != nil {
			return "", nil, err
		}
		placeholders := make([]string, 0, len(functions))
		for _, function := range functions {
			placeholders = append(placeholders, "?")
			args = append(args, function)
		}
		clauses = append(clauses, "JSONExtractString(metadata, 'function') IN ("+strings.Join(placeholders, ", ")+")")
	}
	if q.Function != "" {
		add("JSONExtractString(metadata, 'function') = ?", strings.TrimSpace(q.Function))
	}
	if q.ThreatType != "" {
		add("lower(JSONExtractString(metadata, 'threat_type')) = ?", strings.ToLower(strings.TrimSpace(q.ThreatType)))
	}
	if q.Severity != "" {
		add("lower(JSONExtractString(metadata, 'severity')) = ?", strings.ToLower(strings.TrimSpace(q.Severity)))
	}
	if q.Mode != "" {
		add("lower(JSONExtractString(metadata, 'mode')) = ?", strings.ToLower(strings.TrimSpace(q.Mode)))
	}
	if q.Direction != "" {
		add("lower(JSONExtractString(metadata, 'direction')) = ?", strings.ToLower(strings.TrimSpace(q.Direction)))
	}
	if q.DataClass != "" {
		add("lower(JSONExtractString(metadata, 'data_class')) = ?", strings.ToLower(strings.TrimSpace(q.DataClass)))
	}
	if q.IP != "" {
		add("client_ip = ?", strings.TrimSpace(q.IP))
	}
	if q.Path != "" {
		add("path LIKE ?", "%"+strings.TrimSpace(q.Path)+"%")
	}
	if q.Method != "" {
		add("method = ?", strings.ToUpper(strings.TrimSpace(q.Method)))
	}
	if q.Host != "" {
		add("JSONExtractString(metadata, 'host') = ?", strings.TrimSpace(q.Host))
	}
	if q.Status != "" {
		status, err := strconv.Atoi(strings.TrimSpace(q.Status))
		if err != nil || status < 100 || status > 599 {
			return "", nil, fmt.Errorf("invalid status")
		}
		add("status_code = ?", status)
	}
	if q.ResponseAction != "" {
		add("lower(JSONExtractString(metadata, 'response_action')) = ?", strings.ToLower(strings.TrimSpace(q.ResponseAction)))
	}
	if q.UserAgent != "" {
		add("user_agent LIKE ?", "%"+strings.TrimSpace(q.UserAgent)+"%")
	}
	if q.RuleID != "" {
		add("rule_id = ?", strings.TrimSpace(q.RuleID))
	}
	if q.RequestID != "" {
		add("request_id = ?", strings.TrimSpace(q.RequestID))
	}
	return "WHERE " + strings.Join(clauses, " AND "), args, nil
}

func normalizedAPISecurityActionSQL() string {
	return "if(action IN ('pass', 'allowed'), 'allow', if(action IN ('log', 'detected'), 'detect', action))"
}

func apiSecurityFindingActionSQL() string {
	return normalizedAPISecurityActionSQL() + " IN ('block', 'detect')"
}

func apiSecurityBreakdownRequiresFindingAction(dimension string) bool {
	switch strings.ToLower(strings.TrimSpace(dimension)) {
	case "functions", "threat_types", "severities", "parameters", "validation_errors", "schema_types", "content_types", "rules", "payloads", "modes", "directions", "data_classes", "response_actions", "modules":
		return true
	default:
		return false
	}
}

func normalizeAPISecurityAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "pass", "allowed":
		return "allow"
	case "blocked", "deny":
		return "block"
	case "log", "detected":
		return "detect"
	default:
		return strings.ToLower(strings.TrimSpace(action))
	}
}

func apiSecurityBreakdownExpression(dimension string) (string, string) {
	switch dimension {
	case "actions":
		expr := normalizedAPISecurityActionSQL()
		return expr, expr
	case "functions":
		expr := "JSONExtractString(metadata, 'function')"
		return expr, expr
	case "threat_types":
		expr := "JSONExtractString(metadata, 'threat_type')"
		return expr, expr
	case "severities":
		expr := "JSONExtractString(metadata, 'severity')"
		return expr, expr
	case "endpoints":
		expr := "JSONExtractString(metadata, 'endpoint_id')"
		return expr, "path"
	case "paths":
		return "path", "path"
	case "methods":
		return "method", "method"
	case "hosts":
		expr := "JSONExtractString(metadata, 'host')"
		return expr, expr
	case "ips":
		return "client_ip", "client_ip"
	case "status":
		expr := "toString(status_code)"
		return expr, expr
	case "user_agent_families", "user_agents":
		return "user_agent", "user_agent"
	case "parameters":
		expr := "JSONExtractString(metadata, 'param_name')"
		return expr, expr
	case "validation_errors":
		expr := "JSONExtractString(metadata, 'validation_error')"
		return expr, expr
	case "schema_types":
		expr := "JSONExtractString(metadata, 'schema_type')"
		return expr, expr
	case "content_types":
		expr := "JSONExtractString(metadata, 'content_type')"
		return expr, expr
	case "rules":
		return "rule_id", "rule_name"
	case "payloads":
		expr := "JSONExtractString(metadata, 'payload_snippet')"
		return expr, expr
	case "modes":
		expr := "JSONExtractString(metadata, 'mode')"
		return expr, expr
	case "directions":
		expr := "JSONExtractString(metadata, 'direction')"
		return expr, expr
	case "data_classes":
		expr := "JSONExtractString(metadata, 'data_class')"
		return expr, expr
	case "response_actions":
		expr := "JSONExtractString(metadata, 'response_action')"
		return expr, expr
	case "modules":
		functionExpr := "JSONExtractString(metadata, 'function')"
		expr := apiSecurityModuleSQLExpression(functionExpr)
		return expr, expr
	default:
		return "path", "path"
	}
}

func apiSecurityModuleSQLExpression(functionExpr string) string {
	parts := []string{}
	for _, module := range apiSecuritySignalModules {
		functions := make([]string, 0, len(module.Functions))
		for _, function := range module.Functions {
			functions = append(functions, "'"+strings.ReplaceAll(function, "'", "''")+"'")
		}
		parts = append(parts, fmt.Sprintf("%s IN (%s)", functionExpr, strings.Join(functions, ", ")))
		parts = append(parts, "'"+strings.ReplaceAll(module.Key, "'", "''")+"'")
	}
	parts = append(parts, "''")
	return "multiIf(" + strings.Join(parts, ", ") + ")"
}

func scanAPISecurityAnalyticsEvent(row sqlScanner) (APISecurityAnalyticsEvent, error) {
	var event APISecurityAnalyticsEvent
	var ts uint32
	var status uint16
	var metadata string
	if err := row.Scan(&event.ID, &ts, &event.ClientIP, &event.Country, &event.Method, &event.Path, &status, &event.Action, &event.UserAgent, &event.UserAgentFamily, &event.RuleID, &event.RuleName, &event.RuleType, &event.LatencyMs, &event.RequestID, &metadata); err != nil {
		return event, err
	}
	event.Timestamp = int64(ts)
	event.StatusCode = int(status)
	applyAPISecurityEventMetadata(&event, metadata)
	return event, nil
}

func applyAPISecurityEventMetadata(event *APISecurityAnalyticsEvent, raw string) {
	var meta map[string]string
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return
	}
	event.Metadata = meta
	event.Function = firstMetadataValue(meta, "function")
	event.ThreatType = firstMetadataValue(meta, "threat_type")
	event.Severity = firstMetadataValue(meta, "severity")
	event.ParamName = firstMetadataValue(meta, "param_name")
	event.PayloadSnippet = firstMetadataValue(meta, "payload_snippet")
	event.SchemaType = firstMetadataValue(meta, "schema_type")
	event.ValidationError = firstMetadataValue(meta, "validation_error")
	event.EndpointID = firstMetadataValue(meta, "endpoint_id")
	event.Host = firstMetadataValue(meta, "host")
	event.QueryString = firstMetadataValue(meta, "query_string")
	event.ContentType = firstMetadataValue(meta, "content_type")
	event.Mode = firstMetadataValue(meta, "mode")
	event.Reason = firstMetadataValue(meta, "reason")
	event.Direction = firstMetadataValue(meta, "direction")
	event.DataClass = firstMetadataValue(meta, "data_class")
	event.ResponseAction = firstMetadataValue(meta, "response_action")
	event.OperationName = firstMetadataValue(meta, "operation_name")
	event.OperationType = firstMetadataValue(meta, "operation_type")
	event.ClaimName = firstMetadataValue(meta, "claim_name")
	event.ProtectedField = firstMetadataValue(meta, "protected_field")
	if ruleName := firstMetadataValue(meta, "rule_name"); ruleName != "" {
		event.RuleName = ruleName
	}
	event.Count = parseAPISecurityMetadataInt(meta, "count")
	event.Threshold = parseAPISecurityMetadataInt(meta, "threshold")
	event.WindowSeconds = parseAPISecurityMetadataInt(meta, "window_seconds")
	if event.Severity == "" {
		event.Severity = apiSecurityThreatDefaultSeverity[strings.ToLower(event.ThreatType)]
	}
}

func formatAPISecurityBreakdownLabel(dimension, value string) string {
	if value == "" {
		return value
	}
	switch dimension {
	case "actions":
		switch normalizeAPISecurityAction(value) {
		case "allow":
			return "Allowed"
		case "block":
			return "Blocked"
		case "detect":
			return "Detected"
		case "challenge":
			return "Challenged"
		case "error":
			return "Errors"
		}
	case "functions":
		if label := apiSecurityFunctionLabels[strings.ToLower(value)]; label != "" {
			return label
		}
	case "threat_types":
		if label := apiSecurityThreatLabels[strings.ToLower(value)]; label != "" {
			return label
		}
	case "modules":
		for _, module := range apiSecuritySignalModules {
			if module.Key == strings.ToLower(value) {
				return module.Label
			}
		}
	}
	return strings.Title(strings.ReplaceAll(value, "_", " "))
}

func parseAPISecurityMetadataInt(meta map[string]string, key string) int64 {
	raw := strings.TrimSpace(meta[key])
	if raw == "" {
		return 0
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func sortedAPISecurityKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func topAPISecurityCountKey(counts map[string]int64) string {
	var key string
	var count int64
	for candidate, candidateCount := range counts {
		if candidateCount > count || (candidateCount == count && (key == "" || candidate < key)) {
			key = candidate
			count = candidateCount
		}
	}
	return key
}

func topAPISecurityBreakdownKey(items []APISecurityBreakdownItem) string {
	if len(items) == 0 {
		return ""
	}
	if items[0].Label != "" {
		return items[0].Label
	}
	return items[0].Key
}
