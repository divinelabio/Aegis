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

type BotAnalyticsQuery struct {
	Window          string
	Interval        string
	Action          string
	Category        string
	RuleID          string
	IP              string
	Path            string
	Method          string
	Country         string
	Status          string
	UserAgent       string
	RequestID       string
	Verified        string
	Headless        string
	Reputation      string
	ASN             string
	JA3             string
	JA4             string
	HeaderProfile   string
	DecisionState   string
	ChallengeType   string
	ChallengeResult string
	ScoreVersion    string
	MinScore        *int
	MaxScore        *int
	Limit           int
	Cursor          string
	Sort            string
}

type BotAnalyticsSummary struct {
	TotalRequests      int64   `json:"total_requests"`
	BlockedRequests    int64   `json:"blocked_requests"`
	ChallengedRequests int64   `json:"challenged_requests"`
	DetectedRequests   int64   `json:"detected_requests"`
	AllowedRequests    int64   `json:"allowed_requests"`
	ErrorRequests      int64   `json:"error_requests"`
	BotRate            float64 `json:"bot_rate"`
	EnforcementRate    float64 `json:"enforcement_rate"`
	AvgScore           float64 `json:"avg_score"`
	MaxScore           int     `json:"max_score"`
	AvgLatencyMs       float64 `json:"avg_latency_ms"`
	P95LatencyMs       float64 `json:"p95_latency_ms"`
	UniqueSourceIPs    int64   `json:"unique_source_ips"`
	UniqueCountries    int64   `json:"unique_countries"`
	TopBotCategory     string  `json:"top_bot_category"`
	VerifiedBots       int64   `json:"verified_bots"`
	HeadlessRequests   int64   `json:"headless_requests"`
	UniqueJA3          int64   `json:"unique_ja3"`
	UniqueJA4          int64   `json:"unique_ja4"`
	UniqueASNs         int64   `json:"unique_asns"`
	DroppedEvents      int64   `json:"dropped_events"`
	Window             string  `json:"window"`
}

type BotTimeseriesPoint struct {
	Timestamp    int64            `json:"timestamp"`
	Counts       map[string]int64 `json:"counts"`
	AvgScore     float64          `json:"avg_score"`
	AvgLatencyMs float64          `json:"avg_latency_ms"`
	P95LatencyMs float64          `json:"p95_latency_ms"`
}

type BotBreakdownItem struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	Count        int64   `json:"count"`
	Blocked      int64   `json:"blocked"`
	Challenged   int64   `json:"challenged"`
	Detected     int64   `json:"detected"`
	BlockRate    float64 `json:"block_rate"`
	Percent      float64 `json:"percent"`
	LastSeen     int64   `json:"last_seen"`
	AvgScore     float64 `json:"avg_score"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

type BotAnalyticsEvent struct {
	ID                  string            `json:"id"`
	Timestamp           int64             `json:"timestamp"`
	ClientIP            string            `json:"client_ip"`
	Country             string            `json:"country"`
	Method              string            `json:"method"`
	Path                string            `json:"path"`
	StatusCode          int               `json:"status_code"`
	Action              string            `json:"action"`
	UserAgent           string            `json:"user_agent"`
	UserAgentFamily     string            `json:"user_agent_family"`
	RuleID              string            `json:"rule_id"`
	RuleName            string            `json:"rule_name"`
	RuleType            string            `json:"rule_type"`
	Score               int               `json:"score"`
	LatencyMs           int64             `json:"latency_ms"`
	RequestID           string            `json:"request_id"`
	BotCategory         string            `json:"bot_category"`
	BotVerified         bool              `json:"bot_verified"`
	BotHeadless         bool              `json:"bot_headless"`
	IPReputation        int               `json:"ip_reputation"`
	ASN                 string            `json:"asn"`
	ASNOrg              string            `json:"asn_org"`
	JA3                 string            `json:"ja3"`
	JA4                 string            `json:"ja4"`
	HeaderProfile       string            `json:"header_profile"`
	RepeatHeaderProfile int               `json:"repeat_header_profile"`
	TLSVersion          string            `json:"tls_version"`
	FingerprintID       string            `json:"fingerprint_id"`
	ScoreVersion        string            `json:"score_version"`
	ScoreConfidence     int               `json:"score_confidence"`
	BotScoreV2          int               `json:"bot_score_v2"`
	RecommendedAction   string            `json:"recommended_action"`
	ModelDrift          bool              `json:"model_drift"`
	ScoreFactors        []BotScoreFactor  `json:"score_factors,omitempty"`
	Reason              string            `json:"reason"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

type BotScoreFactor struct {
	Name   string `json:"name"`
	Value  int    `json:"value"`
	Detail string `json:"detail,omitempty"`
}

type BotAnalyticsEventsPage struct {
	Events     []BotAnalyticsEvent `json:"events"`
	NextCursor string              `json:"next_cursor,omitempty"`
	Count      int                 `json:"count"`
}

type BotAnalyticsHealth struct {
	DBAvailable         bool   `json:"db_available"`
	LastEventTimestamp  int64  `json:"last_event_timestamp"`
	IngestionLagSeconds int64  `json:"ingestion_lag_seconds"`
	DroppedEvents       int64  `json:"dropped_events"`
	FreshnessStatus     string `json:"freshness_status"`
	Message             string `json:"message"`
}

type BotAnalyticsConfigSnapshot struct {
	Enabled                bool   `json:"enabled"`
	Mode                   string `json:"mode"`
	Strictness             string `json:"strictness"`
	ResponseMode           string `json:"response_mode"`
	EnforcementMode        string `json:"enforcement_mode"`
	RiskProfile            string `json:"risk_profile"`
	ScoringProfile         string `json:"scoring_profile"`
	ObserveThreshold       int    `json:"observe_threshold"`
	ChallengeThreshold     int    `json:"challenge_threshold"`
	BlockThreshold         int    `json:"block_threshold"`
	RepeatOffender         int    `json:"repeat_offender"`
	ChallengeLadderEnabled bool   `json:"challenge_ladder_enabled"`
	TLSIntelligenceEnabled bool   `json:"tls_intelligence_enabled"`
	JA3Enabled             bool   `json:"ja3_enabled"`
	JA4Enabled             bool   `json:"ja4_enabled"`
	ModuleTier             string `json:"module_tier"`
	ProReady               bool   `json:"pro_ready"`
	JSDetectionEnabled     bool   `json:"js_detection_enabled"`
	BaselinesEnabled       bool   `json:"baselines_enabled"`
	SequenceEnabled        bool   `json:"sequence_detection_enabled"`
	RouteProfilesEnabled   bool   `json:"route_profiles_enabled"`
	ExplainabilityEnabled  bool   `json:"explainability_enabled"`
}

type BotAnalyticsShadowSummary struct {
	ShadowEvents             int64   `json:"shadow_events"`
	DriftEvents              int64   `json:"drift_events"`
	DriftRate                float64 `json:"drift_rate"`
	BlockRecommendations     int64   `json:"block_recommendations"`
	ChallengeRecommendations int64   `json:"challenge_recommendations"`
	DetectRecommendations    int64   `json:"detect_recommendations"`
	AvgShadowScore           float64 `json:"avg_shadow_score"`
}

type BotScoreBucket struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

type BotAnalyticsWatchItem struct {
	Label  string  `json:"label"`
	Key    string  `json:"key"`
	Count  int64   `json:"count"`
	Rate   float64 `json:"rate"`
	Detail string  `json:"detail"`
	Filter string  `json:"filter"`
	Value  string  `json:"value"`
}

type BotAnalyticsIntelligence struct {
	Shadow                  BotAnalyticsShadowSummary `json:"shadow"`
	ScoreDistribution       []BotScoreBucket          `json:"score_distribution"`
	TopChallengedPassed     []BotAnalyticsWatchItem   `json:"top_challenged_passed"`
	TopBlockedVerified      []BotAnalyticsWatchItem   `json:"top_blocked_verified"`
	FalsePositiveCandidates []BotAnalyticsWatchItem   `json:"false_positive_candidates"`
}

type BotProtectionSummary struct {
	BlockedBots      int64   `json:"blocked_bots"`
	ChallengedBots   int64   `json:"challenged_bots"`
	DetectedOnlyBots int64   `json:"detected_only_bots"`
	MitigatedTotal   int64   `json:"mitigated_total"`
	EnforcementRate  float64 `json:"enforcement_rate"`
	BotRate          float64 `json:"bot_rate"`
	AvgScore         float64 `json:"avg_score"`
	MaxScore         int     `json:"max_score"`
	TopBotCategory   string  `json:"top_bot_category"`
	Window           string  `json:"window"`
}

type BotIntelligenceSummary struct {
	Categories        []BotBreakdownItem `json:"categories"`
	ScoreDistribution []BotScoreBucket   `json:"score_distribution"`
	Verified          []BotBreakdownItem `json:"verified"`
	Headless          []BotBreakdownItem `json:"headless"`
	ReputationBands   []BotBreakdownItem `json:"reputation_bands"`
}

type BotAutomationFingerprints struct {
	JA3             []BotBreakdownItem `json:"ja3"`
	JA4             []BotBreakdownItem `json:"ja4"`
	ASN             []BotBreakdownItem `json:"asn"`
	HeaderProfiles  []BotBreakdownItem `json:"header_profiles"`
	ReputationBands []BotBreakdownItem `json:"reputation_bands"`
	Headless        []BotBreakdownItem `json:"headless"`
	UniqueJA3       int64              `json:"unique_ja3"`
	UniqueJA4       int64              `json:"unique_ja4"`
	UniqueASNs      int64              `json:"unique_asns"`
}

type BotChallengeEffectiveness struct {
	ChallengeTypes      []BotBreakdownItem      `json:"challenge_types"`
	ChallengeOutcomes   []BotBreakdownItem      `json:"challenge_outcomes"`
	DecisionStates      []BotBreakdownItem      `json:"decision_states"`
	DecisionSources     []BotBreakdownItem      `json:"decision_sources"`
	TopChallengedPassed []BotAnalyticsWatchItem `json:"top_challenged_passed"`
	ChallengedTotal     int64                   `json:"challenged_total"`
	ChallengePassRate   float64                 `json:"challenge_pass_rate"`
}

type BotModelHealth struct {
	Shadow                  BotAnalyticsShadowSummary `json:"shadow"`
	TopBlockedVerified      []BotAnalyticsWatchItem   `json:"top_blocked_verified"`
	FalsePositiveCandidates []BotAnalyticsWatchItem   `json:"false_positive_candidates"`
}

type BotPolicyHealth struct {
	Enabled                bool   `json:"enabled"`
	Mode                   string `json:"mode"`
	Strictness             string `json:"strictness"`
	ResponseMode           string `json:"response_mode"`
	EnforcementMode        string `json:"enforcement_mode"`
	RiskProfile            string `json:"risk_profile"`
	ScoringProfile         string `json:"scoring_profile"`
	ObserveThreshold       int    `json:"observe_threshold"`
	ChallengeThreshold     int    `json:"challenge_threshold"`
	BlockThreshold         int    `json:"block_threshold"`
	ChallengeLadderEnabled bool   `json:"challenge_ladder_enabled"`
	TLSIntelligenceEnabled bool   `json:"tls_intelligence_enabled"`
	JA3Enabled             bool   `json:"ja3_enabled"`
	JA4Enabled             bool   `json:"ja4_enabled"`
	Message                string `json:"message"`
}

type BotAnalyticsDashboard struct {
	Summary                BotAnalyticsSummary           `json:"summary"`
	Timeseries             []BotTimeseriesPoint          `json:"timeseries"`
	Breakdowns             map[string][]BotBreakdownItem `json:"breakdowns"`
	Events                 BotAnalyticsEventsPage        `json:"events"`
	Health                 BotAnalyticsHealth            `json:"health"`
	Config                 BotAnalyticsConfigSnapshot    `json:"config_snapshot"`
	Intelligence           BotAnalyticsIntelligence      `json:"intelligence"`
	ProtectionSummary      BotProtectionSummary          `json:"protection_summary"`
	BotIntelligence        BotIntelligenceSummary        `json:"bot_intelligence"`
	AutomationFingerprints BotAutomationFingerprints     `json:"automation_fingerprints"`
	ChallengeEffectiveness BotChallengeEffectiveness     `json:"challenge_effectiveness"`
	ModelHealth            BotModelHealth                `json:"model_health"`
	PolicyHealth           BotPolicyHealth               `json:"policy_health"`
	Warnings               []string                      `json:"warnings"`
}

func GetBotAnalyticsDashboard(q BotAnalyticsQuery) (BotAnalyticsDashboard, error) {
	dashboard := BotAnalyticsDashboard{
		Timeseries: []BotTimeseriesPoint{},
		Breakdowns: map[string][]BotBreakdownItem{},
		Events:     BotAnalyticsEventsPage{Events: []BotAnalyticsEvent{}},
		Intelligence: BotAnalyticsIntelligence{
			ScoreDistribution:       []BotScoreBucket{},
			TopChallengedPassed:     []BotAnalyticsWatchItem{},
			TopBlockedVerified:      []BotAnalyticsWatchItem{},
			FalsePositiveCandidates: []BotAnalyticsWatchItem{},
		},
		Warnings: []string{},
	}
	if _, _, err := buildBotAnalyticsWhere(q); err != nil {
		return dashboard, err
	}
	if _, err := ResolveWAFAnalyticsInterval(q.Window, q.Interval); err != nil {
		return dashboard, err
	}

	if summary, err := GetBotAnalyticsSummary(q); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "summary unavailable")
	} else {
		dashboard.Summary = summary
	}
	if points, err := GetBotAnalyticsTimeseries(q); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "timeseries unavailable")
	} else {
		dashboard.Timeseries = points
	}

	breakdownQuery := q
	breakdownQuery.Limit = 100
	for _, dimension := range []string{"actions", "categories", "rules", "countries", "ips", "paths", "methods", "status", "user_agent_families", "verified", "headless", "reputation_bands", "ja3", "ja4", "asn", "header_profiles", "decision_sources", "decision_states", "challenge_types", "challenge_outcomes"} {
		items, err := GetBotAnalyticsBreakdown(breakdownQuery, dimension)
		if err != nil {
			dashboard.Warnings = append(dashboard.Warnings, dimension+" breakdown unavailable")
			dashboard.Breakdowns[dimension] = []BotBreakdownItem{}
			continue
		}
		dashboard.Breakdowns[dimension] = items
	}

	eventQuery := q
	eventQuery.Limit = NormalizeWAFLimit(q.Limit, 50, 500)
	if events, err := GetBotAnalyticsEvents(eventQuery); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "events unavailable")
	} else {
		dashboard.Events = events
	}
	intelQuery := q
	intelQuery.Limit = 250
	if intelligence, err := GetBotAnalyticsIntelligence(intelQuery); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "shadow intelligence unavailable")
	} else {
		dashboard.Intelligence = intelligence
	}
	if dashboard.Summary.TopBotCategory == "" {
		dashboard.Summary.TopBotCategory = topBotBreakdownKey(dashboard.Breakdowns["categories"])
	}
	dashboard.Health = GetBotAnalyticsHealth()
	PopulateBotAnalyticsDashboardGroups(&dashboard)
	return dashboard, nil
}

func PopulateBotAnalyticsDashboardGroups(dashboard *BotAnalyticsDashboard) {
	if dashboard == nil {
		return
	}
	summary := dashboard.Summary
	breakdowns := dashboard.Breakdowns
	if breakdowns == nil {
		breakdowns = map[string][]BotBreakdownItem{}
		dashboard.Breakdowns = breakdowns
	}
	intelligence := dashboard.Intelligence
	dashboard.ProtectionSummary = BotProtectionSummary{
		BlockedBots:      summary.BlockedRequests,
		ChallengedBots:   summary.ChallengedRequests,
		DetectedOnlyBots: summary.DetectedRequests,
		MitigatedTotal:   summary.BlockedRequests + summary.ChallengedRequests,
		EnforcementRate:  summary.EnforcementRate,
		BotRate:          summary.BotRate,
		AvgScore:         summary.AvgScore,
		MaxScore:         summary.MaxScore,
		TopBotCategory:   summary.TopBotCategory,
		Window:           summary.Window,
	}
	dashboard.BotIntelligence = BotIntelligenceSummary{
		Categories:        safeBotBreakdown(breakdowns, "categories"),
		ScoreDistribution: safeBotScoreBuckets(intelligence.ScoreDistribution),
		Verified:          safeBotBreakdown(breakdowns, "verified"),
		Headless:          safeBotBreakdown(breakdowns, "headless"),
		ReputationBands:   safeBotBreakdown(breakdowns, "reputation_bands"),
	}
	dashboard.AutomationFingerprints = BotAutomationFingerprints{
		JA3:             safeBotBreakdown(breakdowns, "ja3"),
		JA4:             safeBotBreakdown(breakdowns, "ja4"),
		ASN:             safeBotBreakdown(breakdowns, "asn"),
		HeaderProfiles:  safeBotBreakdown(breakdowns, "header_profiles"),
		ReputationBands: safeBotBreakdown(breakdowns, "reputation_bands"),
		Headless:        safeBotBreakdown(breakdowns, "headless"),
		UniqueJA3:       summary.UniqueJA3,
		UniqueJA4:       summary.UniqueJA4,
		UniqueASNs:      summary.UniqueASNs,
	}
	challengeOutcomes := safeBotBreakdown(breakdowns, "challenge_outcomes")
	dashboard.ChallengeEffectiveness = BotChallengeEffectiveness{
		ChallengeTypes:      safeBotBreakdown(breakdowns, "challenge_types"),
		ChallengeOutcomes:   challengeOutcomes,
		DecisionStates:      safeBotBreakdown(breakdowns, "decision_states"),
		DecisionSources:     safeBotBreakdown(breakdowns, "decision_sources"),
		TopChallengedPassed: safeBotWatchItems(intelligence.TopChallengedPassed),
		ChallengedTotal:     summary.ChallengedRequests,
		ChallengePassRate:   botChallengePassRate(challengeOutcomes),
	}
	dashboard.ModelHealth = BotModelHealth{
		Shadow:                  intelligence.Shadow,
		TopBlockedVerified:      safeBotWatchItems(intelligence.TopBlockedVerified),
		FalsePositiveCandidates: safeBotWatchItems(intelligence.FalsePositiveCandidates),
	}
	dashboard.PolicyHealth = BotPolicyHealth{
		Enabled:                dashboard.Config.Enabled,
		Mode:                   dashboard.Config.Mode,
		Strictness:             dashboard.Config.Strictness,
		ResponseMode:           dashboard.Config.ResponseMode,
		EnforcementMode:        dashboard.Config.EnforcementMode,
		RiskProfile:            dashboard.Config.RiskProfile,
		ScoringProfile:         dashboard.Config.ScoringProfile,
		ObserveThreshold:       dashboard.Config.ObserveThreshold,
		ChallengeThreshold:     dashboard.Config.ChallengeThreshold,
		BlockThreshold:         dashboard.Config.BlockThreshold,
		ChallengeLadderEnabled: dashboard.Config.ChallengeLadderEnabled,
		TLSIntelligenceEnabled: dashboard.Config.TLSIntelligenceEnabled,
		JA3Enabled:             dashboard.Config.JA3Enabled,
		JA4Enabled:             dashboard.Config.JA4Enabled,
		Message:                botPolicyHealthMessage(dashboard.Config),
	}
}

func safeBotBreakdown(breakdowns map[string][]BotBreakdownItem, key string) []BotBreakdownItem {
	if items, ok := breakdowns[key]; ok && items != nil {
		return items
	}
	return []BotBreakdownItem{}
}

func safeBotScoreBuckets(items []BotScoreBucket) []BotScoreBucket {
	if items != nil {
		return items
	}
	return []BotScoreBucket{}
}

func safeBotWatchItems(items []BotAnalyticsWatchItem) []BotAnalyticsWatchItem {
	if items != nil {
		return items
	}
	return []BotAnalyticsWatchItem{}
}

func botChallengePassRate(items []BotBreakdownItem) float64 {
	var total int64
	var passed int64
	for _, item := range items {
		total += item.Count
		key := strings.ToLower(item.Key + " " + item.Label)
		if strings.Contains(key, "pass") || strings.Contains(key, "solved") {
			passed += item.Count
		}
	}
	if total == 0 {
		return 0
	}
	return float64(passed) / float64(total) * 100
}

func botPolicyHealthMessage(config BotAnalyticsConfigSnapshot) string {
	if !config.Enabled {
		return "Bot Protection is disabled"
	}
	if config.Mode == "" && config.ResponseMode == "" && config.EnforcementMode == "" {
		return "Policy telemetry has not been observed"
	}
	return "Policy telemetry available"
}

func GetBotAnalyticsIntelligence(q BotAnalyticsQuery) (BotAnalyticsIntelligence, error) {
	intel := BotAnalyticsIntelligence{
		ScoreDistribution:       []BotScoreBucket{},
		TopChallengedPassed:     []BotAnalyticsWatchItem{},
		TopBlockedVerified:      []BotAnalyticsWatchItem{},
		FalsePositiveCandidates: []BotAnalyticsWatchItem{},
	}
	page, err := GetBotAnalyticsEvents(q)
	if err != nil {
		return intel, err
	}
	events := page.Events
	if len(events) == 0 {
		return intel, nil
	}

	buckets := []struct {
		label string
		min   int
		max   int
	}{
		{"0-24", 0, 24},
		{"25-49", 25, 49},
		{"50-74", 50, 74},
		{"75-89", 75, 89},
		{"90-100", 90, 100},
	}
	counts := map[string]int64{}
	var shadowEvents, driftEvents, blockRecs, challengeRecs, detectRecs, totalShadowScore int64
	passedChallenges := map[string]*BotAnalyticsWatchItem{}
	blockedVerified := map[string]*BotAnalyticsWatchItem{}
	falsePositive := map[string]*BotAnalyticsWatchItem{}

	for _, event := range events {
		if event.ScoreVersion != "" {
			shadowEvents++
			totalShadowScore += int64(event.BotScoreV2)
			if event.ModelDrift {
				driftEvents++
			}
			switch normalizeIntelAction(event.RecommendedAction) {
			case "block":
				blockRecs++
			case "challenge":
				challengeRecs++
			case "detect":
				detectRecs++
			}
			for _, bucket := range buckets {
				if event.BotScoreV2 >= bucket.min && event.BotScoreV2 <= bucket.max {
					counts[bucket.label]++
					break
				}
			}
		}
		if event.Action == "challenge_passed" {
			key := firstNonEmptyString(event.Path, event.ClientIP, event.JA3)
			item := ensureIntelItem(passedChallenges, key, key, "path", key)
			item.Count++
			item.Detail = firstNonEmptyString(event.ChallengeDetail(), event.JA3, event.JA4)
		}
		if event.Action == "block" && event.BotVerified {
			label := firstNonEmptyString(event.UserAgentFamily, event.UserAgent, event.ClientIP)
			item := ensureIntelItem(blockedVerified, label, label, "user_agent", label)
			item.Count++
			item.Detail = firstNonEmptyString(event.Reason, event.ASN, event.ClientIP)
		}
		if (event.Action == "challenge_passed" || event.Action == "allow") && event.ModelDrift && event.BotScoreV2 >= 75 {
			label := firstNonEmptyString(event.Path, event.UserAgentFamily, event.ClientIP)
			item := ensureIntelItem(falsePositive, label, label, "path", label)
			item.Count++
			item.Detail = firstNonEmptyString(event.Reason, event.RecommendedAction, event.ScoreVersion)
		}
	}

	for _, bucket := range buckets {
		intel.ScoreDistribution = append(intel.ScoreDistribution, BotScoreBucket{Label: bucket.label, Count: counts[bucket.label]})
	}
	intel.Shadow = BotAnalyticsShadowSummary{
		ShadowEvents:             shadowEvents,
		DriftEvents:              driftEvents,
		BlockRecommendations:     blockRecs,
		ChallengeRecommendations: challengeRecs,
		DetectRecommendations:    detectRecs,
	}
	if shadowEvents > 0 {
		intel.Shadow.DriftRate = float64(driftEvents) / float64(shadowEvents) * 100
		intel.Shadow.AvgShadowScore = float64(totalShadowScore) / float64(shadowEvents)
	}
	intel.TopChallengedPassed = topIntelItems(passedChallenges, 5, len(events))
	intel.TopBlockedVerified = topIntelItems(blockedVerified, 5, len(events))
	intel.FalsePositiveCandidates = topIntelItems(falsePositive, 5, len(events))
	return intel, nil
}

func GetBotAnalyticsSummary(q BotAnalyticsQuery) (BotAnalyticsSummary, error) {
	summary := BotAnalyticsSummary{
		Window:        defaultWindow(q.Window),
		DroppedEvents: DroppedEvents(),
	}
	if DB == nil {
		return summary, nil
	}
	where, args, err := buildBotAnalyticsWhere(q)
	if err != nil {
		return summary, err
	}
	row := DB.QueryRow(`
		SELECT
			count(),
			countIf(`+normalizedBotActionSQL()+` = 'block'),
			countIf(`+normalizedBotActionSQL()+` = 'challenge'),
			countIf(`+normalizedBotActionSQL()+` = 'detect'),
			countIf(`+normalizedBotActionSQL()+` = 'allow'),
			countIf(`+normalizedBotActionSQL()+` = 'error'),
			COALESCE(avg(score), 0),
			COALESCE(max(score), 0),
			COALESCE(avg(latency_ms), 0),
			COALESCE(quantile(0.95)(latency_ms), 0),
			uniqExact(client_ip),
			uniqExactIf(country, country != ''),
			countIf(`+botBoolMetadataSQL("bot_verified")+` = 1),
			countIf(`+botBoolMetadataSQL("bot_headless")+` = 1),
			uniqExactIf(JSONExtractString(metadata, 'tls_ja3'), JSONExtractString(metadata, 'tls_ja3') != ''),
			uniqExactIf(JSONExtractString(metadata, 'tls_ja4'), JSONExtractString(metadata, 'tls_ja4') != ''),
			uniqExactIf(JSONExtractString(metadata, 'asn'), JSONExtractString(metadata, 'asn') != '')
		FROM section_events `+where, args...)

	var total, blocked, challenged, detected, allowed, errors, uniqueIPs, uniqueCountries, verified, headless, uniqueJA3, uniqueJA4, uniqueASNs uint64
	var maxScore int32
	if err := row.Scan(&total, &blocked, &challenged, &detected, &allowed, &errors, &summary.AvgScore, &maxScore, &summary.AvgLatencyMs, &summary.P95LatencyMs, &uniqueIPs, &uniqueCountries, &verified, &headless, &uniqueJA3, &uniqueJA4, &uniqueASNs); err != nil {
		return summary, err
	}
	summary.TotalRequests = int64(total)
	summary.BlockedRequests = int64(blocked)
	summary.ChallengedRequests = int64(challenged)
	summary.DetectedRequests = int64(detected)
	summary.AllowedRequests = int64(allowed)
	summary.ErrorRequests = int64(errors)
	summary.MaxScore = int(maxScore)
	summary.UniqueSourceIPs = int64(uniqueIPs)
	summary.UniqueCountries = int64(uniqueCountries)
	summary.VerifiedBots = int64(verified)
	summary.HeadlessRequests = int64(headless)
	summary.UniqueJA3 = int64(uniqueJA3)
	summary.UniqueJA4 = int64(uniqueJA4)
	summary.UniqueASNs = int64(uniqueASNs)
	if total > 0 {
		summary.BotRate = float64(blocked+challenged+detected) / float64(total) * 100
		summary.EnforcementRate = float64(blocked+challenged) / float64(total) * 100
	}
	summary.AvgScore = finiteFloat(summary.AvgScore)
	summary.AvgLatencyMs = finiteFloat(summary.AvgLatencyMs)
	summary.P95LatencyMs = finiteFloat(summary.P95LatencyMs)
	return summary, nil
}

func GetBotAnalyticsTimeseries(q BotAnalyticsQuery) ([]BotTimeseriesPoint, error) {
	if DB == nil {
		return []BotTimeseriesPoint{}, nil
	}
	where, args, err := buildBotAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	interval, err := ResolveWAFAnalyticsInterval(q.Window, q.Interval)
	if err != nil {
		return nil, err
	}
	rows, err := DB.Query(`
		SELECT
			toUnixTimestamp(bucket),
			action,
			count(),
			COALESCE(avg(score), 0),
			COALESCE(avg(latency_ms), 0),
			COALESCE(quantile(0.95)(latency_ms), 0)
		FROM (
			SELECT
				`+bucketExpression(interval)+` AS bucket,
				`+normalizedBotActionSQL()+` AS action,
				score,
				latency_ms
			FROM section_events `+where+`
		)
		GROUP BY bucket, action
		ORDER BY bucket ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byBucket := map[int64]*BotTimeseriesPoint{}
	for rows.Next() {
		var ts uint32
		var action string
		var count uint64
		var avgScore, avgLatency, p95Latency float64
		if err := rows.Scan(&ts, &action, &count, &avgScore, &avgLatency, &p95Latency); err != nil {
			return nil, err
		}
		key := int64(ts)
		point := byBucket[key]
		if point == nil {
			point = &BotTimeseriesPoint{Timestamp: key, Counts: map[string]int64{}}
			byBucket[key] = point
		}
		point.Counts[action] = int64(count)
		point.AvgScore = finiteFloat(avgScore)
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
	out := make([]BotTimeseriesPoint, 0, len(keys))
	for _, key := range keys {
		out = append(out, *byBucket[key])
	}
	return out, nil
}

func GetBotAnalyticsBreakdown(q BotAnalyticsQuery, dimension string) ([]BotBreakdownItem, error) {
	dimension = strings.ToLower(strings.TrimSpace(dimension))
	if err := ValidateBotBreakdownDimension(dimension); err != nil {
		return nil, err
	}
	if DB == nil {
		return []BotBreakdownItem{}, nil
	}
	where, args, err := buildBotAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	expr, labelExpr := botBreakdownExpression(dimension)
	limit := NormalizeWAFLimit(q.Limit, 10, 100)
	args = append(args, limit)
	rows, err := DB.Query(fmt.Sprintf(`
		SELECT
			%s AS key,
			%s AS label,
			count(),
			countIf(%s = 'block'),
			countIf(%s = 'challenge'),
			countIf(%s = 'detect'),
			toUnixTimestamp(max(timestamp)),
			COALESCE(avg(score), 0),
			COALESCE(avg(latency_ms), 0)
		FROM section_events %s AND %s != ''
		GROUP BY key, label
		ORDER BY count() DESC
		LIMIT ?`, expr, labelExpr, normalizedBotActionSQL(), normalizedBotActionSQL(), normalizedBotActionSQL(), where, expr), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]BotBreakdownItem, 0, limit)
	var total int64
	for rows.Next() {
		var item BotBreakdownItem
		var count, blocked, challenged, detected uint64
		var lastSeen uint32
		if err := rows.Scan(&item.Key, &item.Label, &count, &blocked, &challenged, &detected, &lastSeen, &item.AvgScore, &item.AvgLatencyMs); err != nil {
			return nil, err
		}
		item.Count = int64(count)
		item.Blocked = int64(blocked)
		item.Challenged = int64(challenged)
		item.Detected = int64(detected)
		item.LastSeen = int64(lastSeen)
		if count > 0 {
			item.BlockRate = float64(blocked+challenged) / float64(count) * 100
		}
		item.AvgScore = finiteFloat(item.AvgScore)
		item.AvgLatencyMs = finiteFloat(item.AvgLatencyMs)
		item.Label = formatBotBreakdownLabel(dimension, item.Label)
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

func GetBotAnalyticsEvents(q BotAnalyticsQuery) (BotAnalyticsEventsPage, error) {
	page := BotAnalyticsEventsPage{Events: []BotAnalyticsEvent{}}
	if DB == nil {
		return page, nil
	}
	limit := NormalizeWAFLimit(q.Limit, 50, 500)
	q.Limit = limit + 1
	where, args, err := buildBotAnalyticsWhere(q)
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
		SELECT id, toUnixTimestamp(timestamp), client_ip, country, method, path, status_code, `+normalizedBotActionSQL()+`, user_agent,
		       user_agent_family, rule_id, rule_name, rule_type, score, latency_ms, request_id, metadata
		FROM section_events `+where+`
		ORDER BY timestamp `+order+`
		LIMIT ?`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()

	for rows.Next() {
		event, err := scanBotAnalyticsEvent(rows)
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

func GetBotAnalyticsEvent(id string) (*BotAnalyticsEvent, error) {
	if DB == nil {
		return nil, nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("missing event id")
	}
	row := DB.QueryRow(`
		SELECT id, toUnixTimestamp(timestamp), client_ip, country, method, path, status_code, `+normalizedBotActionSQL()+`, user_agent,
		       user_agent_family, rule_id, rule_name, rule_type, score, latency_ms, request_id, metadata
		FROM section_events
		WHERE (section IN ('bot_protection', 'bot') OR rule_type = 'bot') AND id = ?
		LIMIT 1`, id)
	event, err := scanBotAnalyticsEvent(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func GetBotAnalyticsHealth() BotAnalyticsHealth {
	health := BotAnalyticsHealth{
		DBAvailable:     DB != nil,
		DroppedEvents:   DroppedEvents(),
		FreshnessStatus: "unavailable",
		Message:         "",
	}
	if DB == nil {
		return health
	}
	health.Message = "No Bot Protection analytics events have been recorded yet"
	var count uint64
	var last uint32
	err := DB.QueryRow(`
		SELECT count(), toUnixTimestamp(max(timestamp))
		FROM section_events
		WHERE section IN ('bot_protection', 'bot') OR rule_type = 'bot'`).Scan(&count, &last)
	if err != nil {
		health.Message = "Unable to read Bot Protection analytics freshness"
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
		health.Message = "Bot Protection analytics are current"
	case health.IngestionLagSeconds <= 900:
		health.FreshnessStatus = "delayed"
		health.Message = "Bot Protection analytics are slightly delayed"
	default:
		health.FreshnessStatus = "stale"
		health.Message = "Bot Protection analytics have not received recent events"
	}
	return health
}

func ValidateBotBreakdownDimension(dimension string) error {
	switch strings.ToLower(strings.TrimSpace(dimension)) {
	case "actions", "categories", "rules", "countries", "ips", "paths", "methods", "status", "user_agent_families", "user_agents", "verified", "headless", "reputation_bands", "ja3", "ja4", "asn", "header_profiles", "decision_sources", "decision_states", "challenge_types", "challenge_outcomes":
		return nil
	default:
		return fmt.Errorf("unsupported breakdown dimension %q", dimension)
	}
}

func buildBotAnalyticsWhere(q BotAnalyticsQuery) (string, []any, error) {
	since, err := windowStart(defaultWindow(q.Window))
	if err != nil {
		return "", nil, err
	}
	clauses := []string{"(section IN ('bot_protection', 'bot') OR rule_type = 'bot')", "timestamp >= ?"}
	args := []any{since}
	add := func(clause string, value any) {
		clauses = append(clauses, clause)
		args = append(args, value)
	}
	if action := strings.TrimSpace(q.Action); action != "" {
		add(normalizedBotActionSQL()+" = ?", normalizeBotAction(action))
	}
	if q.Category != "" {
		add("lower(JSONExtractString(metadata, 'bot_category')) LIKE ?", "%"+strings.ToLower(strings.TrimSpace(q.Category))+"%")
	}
	if q.RuleID != "" {
		add("rule_id = ?", strings.TrimSpace(q.RuleID))
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
	if q.Country != "" {
		add("country = ?", strings.ToUpper(strings.TrimSpace(q.Country)))
	}
	if q.Status != "" {
		status, err := strconv.Atoi(strings.TrimSpace(q.Status))
		if err != nil || status < 100 || status > 599 {
			return "", nil, fmt.Errorf("invalid status")
		}
		add("status_code = ?", status)
	}
	if q.UserAgent != "" {
		add("user_agent LIKE ?", "%"+strings.TrimSpace(q.UserAgent)+"%")
	}
	if q.RequestID != "" {
		add("request_id = ?", strings.TrimSpace(q.RequestID))
	}
	if q.Verified != "" {
		value, err := parseBotBoolFilter(q.Verified)
		if err != nil {
			return "", nil, err
		}
		add(botBoolMetadataSQL("bot_verified")+" = ?", value)
	}
	if q.Headless != "" {
		value, err := parseBotBoolFilter(q.Headless)
		if err != nil {
			return "", nil, err
		}
		add(botBoolMetadataSQL("bot_headless")+" = ?", value)
	}
	if q.Reputation != "" {
		add(botReputationBandSQL()+" = ?", strings.ToLower(strings.TrimSpace(q.Reputation)))
	}
	if q.ASN != "" {
		add("JSONExtractString(metadata, 'asn') = ?", strings.TrimSpace(q.ASN))
	}
	if q.JA3 != "" {
		add("JSONExtractString(metadata, 'tls_ja3') = ?", strings.TrimSpace(q.JA3))
	}
	if q.JA4 != "" {
		add("JSONExtractString(metadata, 'tls_ja4') = ?", strings.TrimSpace(q.JA4))
	}
	if q.HeaderProfile != "" {
		add("JSONExtractString(metadata, 'header_value_signature') = ?", strings.TrimSpace(q.HeaderProfile))
	}
	if q.DecisionState != "" {
		add("lower(JSONExtractString(metadata, 'decision_state')) = ?", strings.ToLower(strings.TrimSpace(q.DecisionState)))
	}
	if q.ChallengeType != "" {
		add("lower(JSONExtractString(metadata, 'challenge_type')) = ?", strings.ToLower(strings.TrimSpace(q.ChallengeType)))
	}
	if q.ChallengeResult != "" {
		add("lower(JSONExtractString(metadata, 'challenge_outcome')) = ?", strings.ToLower(strings.TrimSpace(q.ChallengeResult)))
	}
	if q.ScoreVersion != "" {
		add("lower(JSONExtractString(metadata, 'score_version')) = ?", strings.ToLower(strings.TrimSpace(q.ScoreVersion)))
	}
	if q.MinScore != nil {
		add("score >= ?", *q.MinScore)
	}
	if q.MaxScore != nil {
		add("score <= ?", *q.MaxScore)
	}
	return "WHERE " + strings.Join(clauses, " AND "), args, nil
}

func normalizedBotActionSQL() string {
	return "if(action = 'pass', 'allow', if(action = 'log', 'detect', if(action = 'blocked', 'block', if(action = 'deny', 'block', action))))"
}

func normalizeBotAction(action string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "pass", "allowed":
		return "allow"
	case "log", "logged", "detect", "detected":
		return "detect"
	case "blocked", "deny", "denied":
		return "block"
	case "challenged":
		return "challenge"
	default:
		return action
	}
}

func botBreakdownExpression(dimension string) (string, string) {
	switch dimension {
	case "actions":
		expr := normalizedBotActionSQL()
		return expr, expr
	case "categories":
		expr := "JSONExtractString(metadata, 'bot_category')"
		return expr, expr
	case "rules":
		return "rule_id", "rule_name"
	case "countries":
		return "country", "country"
	case "ips":
		return "client_ip", "client_ip"
	case "paths":
		return "path", "path"
	case "methods":
		return "method", "method"
	case "status":
		expr := "toString(status_code)"
		return expr, expr
	case "user_agent_families", "user_agents":
		return "user_agent", "user_agent"
	case "ja3":
		expr := "JSONExtractString(metadata, 'tls_ja3')"
		return expr, expr
	case "ja4":
		expr := "JSONExtractString(metadata, 'tls_ja4')"
		return expr, expr
	case "asn":
		expr := "JSONExtractString(metadata, 'asn')"
		label := "if(JSONExtractString(metadata, 'asn_org') != '', concat(JSONExtractString(metadata, 'asn'), ' · ', JSONExtractString(metadata, 'asn_org')), JSONExtractString(metadata, 'asn'))"
		return expr, label
	case "header_profiles":
		expr := "JSONExtractString(metadata, 'header_value_signature')"
		return expr, expr
	case "decision_sources":
		expr := "JSONExtractString(metadata, 'decision_source')"
		return expr, expr
	case "decision_states":
		expr := "JSONExtractString(metadata, 'decision_state')"
		return expr, expr
	case "challenge_types":
		expr := "JSONExtractString(metadata, 'challenge_type')"
		return expr, expr
	case "challenge_outcomes":
		expr := "JSONExtractString(metadata, 'challenge_outcome')"
		return expr, expr
	case "verified":
		expr := "if(" + botBoolMetadataSQL("bot_verified") + " = 1, 'verified', 'unverified')"
		return expr, expr
	case "headless":
		expr := "if(" + botBoolMetadataSQL("bot_headless") + " = 1, 'headless', 'browser')"
		return expr, expr
	case "reputation_bands":
		expr := botReputationBandSQL()
		return expr, expr
	default:
		return "path", "path"
	}
}

func botBoolMetadataSQL(key string) string {
	return "if(lower(JSONExtractString(metadata, '" + key + "')) IN ('true', '1', 'yes'), 1, 0)"
}

func botReputationBandSQL() string {
	value := "toInt32OrZero(JSONExtractString(metadata, 'ip_reputation'))"
	return "if(" + value + " >= 80, 'trusted', if(" + value + " >= 40, 'neutral', if(" + value + " > 0, 'risky', 'unknown')))"
}

func parseBotBoolFilter(raw string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "verified", "headless":
		return 1, nil
	case "false", "0", "no", "unverified", "browser":
		return 0, nil
	default:
		return 0, fmt.Errorf("invalid boolean filter")
	}
}

func scanBotAnalyticsEvent(row sqlScanner) (BotAnalyticsEvent, error) {
	var event BotAnalyticsEvent
	var ts uint32
	var status uint16
	var score int32
	var metadata string
	if err := row.Scan(&event.ID, &ts, &event.ClientIP, &event.Country, &event.Method, &event.Path, &status, &event.Action, &event.UserAgent, &event.UserAgentFamily, &event.RuleID, &event.RuleName, &event.RuleType, &score, &event.LatencyMs, &event.RequestID, &metadata); err != nil {
		return event, err
	}
	event.Timestamp = int64(ts)
	event.StatusCode = int(status)
	event.Score = int(score)
	applyBotEventMetadata(&event, metadata)
	return event, nil
}

func applyBotEventMetadata(event *BotAnalyticsEvent, raw string) {
	var meta map[string]string
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return
	}
	event.Metadata = meta
	event.BotCategory = firstMetadataValue(meta, "bot_category", "category", "bot_type")
	event.BotVerified = parseMetadataBool(firstMetadataValue(meta, "bot_verified", "verified"))
	event.BotHeadless = parseMetadataBool(firstMetadataValue(meta, "bot_headless", "headless", "is_headless"))
	event.IPReputation = int(parseInt64(firstMetadataValue(meta, "ip_reputation", "reputation")))
	event.ASN = firstMetadataValue(meta, "asn")
	event.ASNOrg = firstMetadataValue(meta, "asn_org")
	event.JA3 = firstMetadataValue(meta, "ja3", "tls_ja3")
	event.JA4 = firstMetadataValue(meta, "ja4", "tls_ja4")
	event.HeaderProfile = firstMetadataValue(meta, "header_profile", "header_value_signature")
	event.RepeatHeaderProfile = int(parseInt64(firstMetadataValue(meta, "repeat_header_profile")))
	event.TLSVersion = firstMetadataValue(meta, "tls_version")
	event.FingerprintID = firstMetadataValue(meta, "fingerprint_id")
	event.ScoreVersion = firstMetadataValue(meta, "score_version")
	event.ScoreConfidence = int(parseInt64(firstMetadataValue(meta, "score_confidence")))
	event.BotScoreV2 = int(parseInt64(firstMetadataValue(meta, "bot_score_v2")))
	event.RecommendedAction = firstMetadataValue(meta, "recommended_action", "v2_recommended_action")
	event.ModelDrift = parseMetadataBool(firstMetadataValue(meta, "model_drift"))
	event.ScoreFactors = parseBotScoreFactors(firstMetadataValue(meta, "score_factors"))
	event.Reason = firstMetadataValue(meta, "reason")
}

func firstMetadataValue(meta map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(meta[key]); value != "" {
			return value
		}
	}
	return ""
}

func parseMetadataBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}

func parseBotScoreFactors(raw string) []BotScoreFactor {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var factors []BotScoreFactor
	if err := json.Unmarshal([]byte(raw), &factors); err != nil {
		return nil
	}
	return factors
}

func (event BotAnalyticsEvent) ChallengeDetail() string {
	if event.Metadata == nil {
		return ""
	}
	if value := strings.TrimSpace(event.Metadata["challenge_type"]); value != "" {
		return value
	}
	return strings.TrimSpace(event.Metadata["challenge_outcome"])
}

func ensureIntelItem(target map[string]*BotAnalyticsWatchItem, key, label, filter, value string) *BotAnalyticsWatchItem {
	item := target[key]
	if item == nil {
		item = &BotAnalyticsWatchItem{
			Key:    key,
			Label:  label,
			Filter: filter,
			Value:  value,
		}
		target[key] = item
	}
	return item
}

func topIntelItems(items map[string]*BotAnalyticsWatchItem, limit int, total int) []BotAnalyticsWatchItem {
	if len(items) == 0 {
		return []BotAnalyticsWatchItem{}
	}
	list := make([]BotAnalyticsWatchItem, 0, len(items))
	for _, item := range items {
		if total > 0 {
			item.Rate = float64(item.Count) / float64(total) * 100
		}
		list = append(list, *item)
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Count == list[j].Count {
			return list[i].Label < list[j].Label
		}
		return list[i].Count > list[j].Count
	})
	if len(list) > limit {
		list = list[:limit]
	}
	return list
}

func normalizeIntelAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "managed_challenge":
		return "challenge"
	case "observe", "detect", "log":
		return "detect"
	case "deny", "blocked":
		return "block"
	default:
		return strings.ToLower(strings.TrimSpace(action))
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func formatBotBreakdownLabel(dimension, value string) string {
	if value == "" {
		return value
	}
	switch dimension {
	case "actions":
		switch normalizeBotAction(value) {
		case "allow":
			return "Allowed"
		case "detect":
			return "Detected"
		case "challenge":
			return "Challenged"
		case "block":
			return "Blocked"
		case "error":
			return "Errors"
		}
	case "categories":
		switch strings.ToLower(value) {
		case "ai_crawler", "ai crawler":
			return "AI Crawler"
		case "search_engine", "search engine":
			return "Search Engine"
		case "scraper":
			return "Scraper"
		case "headless", "headless_browser":
			return "Headless Browser"
		case "unknown":
			return "Unknown Bot"
		}
	case "verified":
		if value == "verified" {
			return "Verified Bots"
		}
		return "Unverified"
	case "headless":
		if value == "headless" {
			return "Headless"
		}
		return "Browser-like"
	case "reputation_bands":
		switch value {
		case "trusted":
			return "Trusted"
		case "neutral":
			return "Neutral"
		case "risky":
			return "Risky"
		case "unknown":
			return "Unknown"
		}
	}
	return strings.Title(strings.ReplaceAll(value, "_", " "))
}

func topBotBreakdownKey(items []BotBreakdownItem) string {
	if len(items) == 0 {
		return ""
	}
	if items[0].Label != "" {
		return items[0].Label
	}
	return items[0].Key
}
