// Package wafbasic contains the public Coraza/OWASP CRS implementation. Deep
// body, upload, GraphQL, leak, and auxiliary policy engines live only in the
// commercial overlay.
package wafbasic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/requestctx"
	"github.com/divinelab-io/aegis/internal/infra/storage"
	"github.com/divinelab-io/aegis/internal/infra/transport"
	"github.com/divinelab-io/aegis/internal/sections"
	"github.com/google/uuid"
	"github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
)

const (
	SectionID   = "waf_core"
	SectionName = "WAF Core"
)

var paidConfigKeys = []string{"leak_protection", "auxiliary", "request_body_guard", "graphql"}

type Config struct {
	Mode   string `json:"mode" mapstructure:"mode"`
	Engine struct {
		ParanoiaLevel    int    `json:"paranoia_level" mapstructure:"paranoia_level"`
		AnomalyThreshold int    `json:"anomaly_threshold" mapstructure:"anomaly_threshold"`
		EnableCRS        bool   `json:"enable_crs" mapstructure:"enable_crs"`
		CRSPath          string `json:"crs_path" mapstructure:"crs_path"`
		CRSSetupPath     string `json:"crs_setup_path" mapstructure:"crs_setup_path"`
	} `json:"engine" mapstructure:"engine"`
	Validation struct {
		MaxBodySize int64 `json:"max_body_size" mapstructure:"max_body_size"`
	} `json:"validation" mapstructure:"validation"`
	ResponseInspection bool     `json:"response_inspection" mapstructure:"response_inspection"`
	MaxResponseBody    int64    `json:"max_response_body_size" mapstructure:"max_response_body_size"`
	ExcludedPaths      []string `json:"excluded_paths" mapstructure:"excluded_paths"`
	ExcludedRuleIDs    []int    `json:"excluded_rule_ids" mapstructure:"excluded_rule_ids"`
	CustomRules        []string `json:"custom_rules" mapstructure:"custom_rules"`
	DisabledCRS        []string `json:"disabled_crs" mapstructure:"disabled_crs"`
}

type CommunityRule struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Severity string                 `json:"severity,omitempty"`
	Action   string                 `json:"action,omitempty"`
	Message  string                 `json:"message,omitempty"`
	Phase    int                    `json:"phase,omitempty"`
	Targets  []CommunityRuleTarget  `json:"targets,omitempty"`
	RawRule  string                 `json:"raw_rule,omitempty"`
	Extra    map[string]interface{} `json:"-"`
}

type CommunityRuleTarget struct {
	Zone       string   `json:"zone"`
	Field      string   `json:"field,omitempty"`
	Patterns   []string `json:"patterns,omitempty"`
	Negate     bool     `json:"negate,omitempty"`
	Operator   string   `json:"operator,omitempty"`
	Transforms []string `json:"transforms,omitempty"`
}

type CommunityExclusion struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id,omitempty"`
	Paths       []string  `json:"paths,omitempty"`
	Params      []string  `json:"params,omitempty"`
	IPs         []string  `json:"ips,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Description string    `json:"description,omitempty"`
	ExpiresAt   string    `json:"expires_at,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

type Section struct {
	logger      *zap.Logger
	mu          sync.RWMutex
	enabled     bool
	protection  int
	config      Config
	settings    map[string]interface{}
	waf         coraza.WAF
	started     atomic.Bool
	total       atomic.Int64
	blocked     atomic.Int64
	allowed     atomic.Int64
	lastError   string
	lastReload  time.Time
	customRules []CommunityRule
	exclusions  []CommunityExclusion
	persist     sections.SectionConfigPersister
}

func New(logger *zap.Logger, persisters ...sections.SectionConfigPersister) *Section {
	if logger == nil {
		logger = zap.NewNop()
	}
	section := &Section{
		logger:      logger,
		enabled:     true,
		protection:  3,
		config:      defaultConfig(),
		settings:    map[string]interface{}{},
		customRules: []CommunityRule{},
		exclusions:  []CommunityExclusion{},
	}
	if len(persisters) > 0 {
		section.persist = persisters[0]
	}
	return section
}

func (*Section) AlwaysInstallMiddleware() bool { return true }

func defaultConfig() Config {
	var config Config
	config.Mode = "blocking"
	config.Engine.ParanoiaLevel = 1
	config.Engine.AnomalyThreshold = 5
	config.Engine.EnableCRS = true
	config.Engine.CRSPath = "data/rules/crs"
	config.Engine.CRSSetupPath = "data/rules/crs-setup.conf"
	config.Validation.MaxBodySize = 10 << 20
	config.MaxResponseBody = 10 << 20
	return config
}

func (s *Section) Name() string { return SectionName }
func (s *Section) ID() string   { return SectionID }
func (s *Section) Description() string {
	return "Coraza WAF with OWASP CRS, custom rules, and exclusions"
}
func (s *Section) Icon() string          { return "shield" }
func (s *Section) Enabled() bool         { s.mu.RLock(); defer s.mu.RUnlock(); return s.enabled }
func (s *Section) SetEnabled(value bool) { s.mu.Lock(); s.enabled = value; s.mu.Unlock() }

func (s *Section) Init(input sections.SectionConfig) error {
	config := defaultConfig()
	if err := mapstructure.Decode(input.Settings, &config); err != nil {
		return err
	}
	if config.Mode == "" {
		config.Mode = "blocking"
	}
	if config.Engine.ParanoiaLevel < 1 {
		config.Engine.ParanoiaLevel = 1
	}
	if config.Engine.AnomalyThreshold < 1 {
		config.Engine.AnomalyThreshold = 5
	}
	if config.Engine.CRSPath == "" || config.Engine.CRSPath == "rules/crs" {
		if _, err := os.Stat("rules/crs"); err == nil {
			config.Engine.CRSPath = "rules/crs"
		} else {
			config.Engine.CRSPath = "data/rules/crs"
		}
	}
	if config.Engine.CRSSetupPath == "" || config.Engine.CRSSetupPath == "rules/crs-setup.conf" {
		if _, err := os.Stat("rules/crs-setup.conf"); err == nil {
			config.Engine.CRSSetupPath = "rules/crs-setup.conf"
		} else {
			config.Engine.CRSSetupPath = "data/rules/crs-setup.conf"
		}
	}
	if config.Validation.MaxBodySize <= 0 {
		config.Validation.MaxBodySize = 10 << 20
	}
	if config.MaxResponseBody <= 0 {
		config.MaxResponseBody = 10 << 20
	}
	if err := validateConfig(config); err != nil {
		return err
	}
	engine, err := buildWAF(config, s.logger)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.enabled, s.protection, s.config, s.waf = input.Enabled, input.ProtectionLevel, config, engine
	s.settings = cloneMap(input.Settings)
	s.lastError, s.lastReload = "", time.Now().UTC()

	// Restore stored community custom rules and exclusions if present in settings
	if rawRules, ok := input.Settings["custom_rules_data"]; ok {
		var restored []CommunityRule
		if err := mapstructure.Decode(rawRules, &restored); err == nil && len(restored) > 0 {
			s.customRules = restored
		}
	}
	if rawExcls, ok := input.Settings["exclusions_data"]; ok {
		var restored []CommunityExclusion
		if err := mapstructure.Decode(rawExcls, &restored); err == nil && len(restored) > 0 {
			s.exclusions = restored
		}
	}
	s.mu.Unlock()
	return nil
}

func (s *Section) Start(context.Context) error                { s.started.Store(true); return nil }
func (s *Section) Stop(context.Context) error                 { s.started.Store(false); return nil }
func (s *Section) Reload(config sections.SectionConfig) error { return s.UpdateConfig(config) }

func (s *Section) GetConfig() sections.SectionConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sections.SectionConfig{Enabled: s.enabled, ProtectionLevel: s.protection, Settings: cloneMap(s.settings)}
}

func (s *Section) UpdateConfig(input sections.SectionConfig) error {
	s.mu.RLock()
	current := cloneMap(s.settings)
	s.mu.RUnlock()
	for _, key := range paidConfigKeys {
		if value, exists := input.Settings[key]; exists && !jsonEqual(value, current[key]) {
			return sections.ErrFeatureNotEntitled
		}
	}
	if err := s.Init(input); err != nil {
		s.mu.Lock()
		s.lastError = err.Error()
		s.mu.Unlock()
		return err
	}
	return s.persistCurrentConfig()
}

func (s *Section) persistCurrentConfig() error {
	if s.persist == nil {
		return nil
	}
	s.mu.RLock()
	settings := cloneMap(s.settings)
	if len(s.customRules) > 0 {
		settings["custom_rules_data"] = s.customRules
	} else {
		delete(settings, "custom_rules_data")
	}
	if len(s.exclusions) > 0 {
		settings["exclusions_data"] = s.exclusions
	} else {
		delete(settings, "exclusions_data")
	}
	enabled := s.enabled
	protection := s.protection
	s.mu.RUnlock()

	return s.persist(SectionID, sections.SectionConfig{
		Enabled:         enabled,
		ProtectionLevel: protection,
		Settings:        settings,
	})
}

func validateConfig(config Config) error {
	if config.Mode != "blocking" && config.Mode != "detection" && config.Mode != "off" {
		return errors.New("WAF mode must be blocking, detection, or off")
	}
	if config.Engine.ParanoiaLevel < 1 || config.Engine.ParanoiaLevel > 4 || config.Engine.AnomalyThreshold < 1 {
		return errors.New("WAF paranoia level or anomaly threshold is invalid")
	}
	if config.Validation.MaxBodySize < 0 || config.MaxResponseBody < 0 {
		return errors.New("WAF body limits cannot be negative")
	}
	for _, rule := range config.CustomRules {
		if len(rule) > 64<<10 || !strings.HasPrefix(strings.TrimSpace(rule), "SecRule ") {
			return errors.New("custom WAF rules must be bounded SecRule directives")
		}
	}
	return nil
}

func buildWAF(config Config, logger *zap.Logger) (coraza.WAF, error) {
	builder := coraza.NewWAFConfig().WithErrorCallback(func(rule corazatypes.MatchedRule) {
		logger.Debug("Coraza rule error", zap.Int("rule_id", rule.Rule().ID()), zap.String("message", rule.Message()))
	}).WithRequestBodyAccess().WithResponseBodyAccess()
	ruleEngine := "On"
	if config.Mode == "detection" {
		ruleEngine = "DetectionOnly"
	} else if config.Mode == "off" {
		ruleEngine = "Off"
	}
	outboundThreshold := config.Engine.AnomalyThreshold
	if outboundThreshold == 5 {
		outboundThreshold = 4
	}
	directives := []string{
		"SecRuleEngine " + ruleEngine,
		"SecRequestBodyAccess On",
		"SecResponseBodyAccess On",
		"SecResponseBodyMimeType text/plain text/html text/xml application/json",
		"SecRequestBodyLimit " + strconv.FormatInt(config.Validation.MaxBodySize, 10),
		"SecResponseBodyLimit " + strconv.FormatInt(config.MaxResponseBody, 10),
		"SecAction \"id:900000,phase:1,pass,nolog,setvar:tx.paranoia_level=" + strconv.Itoa(config.Engine.ParanoiaLevel) + "\"",
		"SecAction \"id:900001,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=" + strconv.Itoa(config.Engine.AnomalyThreshold) + ",setvar:tx.outbound_anomaly_score_threshold=" + strconv.Itoa(outboundThreshold) + "\"",
	}
	for _, id := range config.ExcludedRuleIDs {
		directives = append(directives, "SecRuleRemoveById "+strconv.Itoa(id))
	}
	directives = append(directives, config.CustomRules...)
	for _, directive := range directives {
		builder = builder.WithDirectives(directive)
	}
	if config.Engine.EnableCRS {
		setupPath := config.Engine.CRSSetupPath
		if _, err := os.Stat(setupPath); os.IsNotExist(err) {
			if _, err := os.Stat("data/rules/crs-setup.conf"); err == nil {
				setupPath = "data/rules/crs-setup.conf"
			} else if _, err := os.Stat("rules/crs-setup.conf"); err == nil {
				setupPath = "rules/crs-setup.conf"
			}
		}
		if info, err := os.Stat(setupPath); err == nil && !info.IsDir() {
			builder = builder.WithDirectivesFromFile(setupPath)
		}
		crsPath := config.Engine.CRSPath
		if _, err := os.Stat(crsPath); os.IsNotExist(err) {
			if _, err := os.Stat("data/rules/crs"); err == nil {
				crsPath = "data/rules/crs"
			} else if _, err := os.Stat("rules/crs"); err == nil {
				crsPath = "rules/crs"
			}
		}
		files, err := ruleFiles(crsPath, config.DisabledCRS)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for _, file := range files {
			builder = builder.WithDirectivesFromFile(file)
		}
	}
	return coraza.NewWAF(builder)
}

func ruleFiles(root string, disabled []string) ([]string, error) {
	files := []string{}
	disabledSet := make(map[string]struct{}, len(disabled))
	for _, name := range disabled {
		disabledSet[filepath.Base(name)] = struct{}{}
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".conf") {
			if _, disabled := disabledSet[info.Name()]; disabled {
				return nil
			}
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func (s *Section) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		enabled, engine, config := s.enabled, s.waf, s.config
		s.mu.RUnlock()
		if !enabled || engine == nil || pathExcluded(r.URL.Path, config.ExcludedPaths) || s.excluded(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !transport.RouteAllowsSection(r, SectionID) {
			next.ServeHTTP(w, r)
			return
		}
		s.total.Add(1)
		tx := engine.NewTransaction()
		defer tx.Close()
		clientIP := requestctx.ClientIP(r)
		if clientIP == "" {
			clientIP = remoteHost(r.RemoteAddr)
		}
		tx.ProcessConnection(clientIP, 0, "", 0)
		tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
		if r.Host != "" {
			tx.AddRequestHeader("Host", r.Host)
		}
		for key, values := range r.Header {
			for _, value := range values {
				tx.AddRequestHeader(key, value)
			}
		}
		if interruption := tx.ProcessRequestHeaders(); interruption != nil {
			s.block(w, r, interruption, tx)
			return
		}
		if r.Body != nil && config.Validation.MaxBodySize > 0 {
			peeked, err := io.ReadAll(io.LimitReader(r.Body, config.Validation.MaxBodySize+1))
			if err != nil {
				http.Error(w, "Could not inspect request", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(peeked), r.Body))
			inspected := peeked
			if int64(len(inspected)) > config.Validation.MaxBodySize {
				inspected = inspected[:config.Validation.MaxBodySize]
			}
			_, _, _ = tx.WriteRequestBody(inspected)
			if interruption, _ := tx.ProcessRequestBody(); interruption != nil {
				s.block(w, r, interruption, tx)
				return
			}
		}
		if config.ResponseInspection {
			writer := newResponseInspector(w, tx, config.MaxResponseBody)
			next.ServeHTTP(writer, r)
			if writer.finalize(r) {
				s.blocked.Add(1)
			} else {
				s.allowed.Add(1)
			}
			tx.ProcessLogging()
			return
		}
		s.allowed.Add(1)
		next.ServeHTTP(w, r)
		tx.ProcessLogging()
	})
}

func (s *Section) block(w http.ResponseWriter, r *http.Request, interruption *corazatypes.Interruption, tx corazatypes.Transaction) {
	s.blocked.Add(1)
	if tx != nil {
		tx.ProcessLogging()
	}
	status := interruption.Status
	if status < 400 {
		status = http.StatusForbidden
	}
	w.Header().Set("X-Aegis-WAF", "blocked")

	clientIP := requestctx.ClientIP(r)
	if clientIP == "" {
		clientIP = remoteHost(r.RemoteAddr)
	}
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = uuid.NewString()
	}

	var ruleIDs []string
	var ruleMessages []string
	var severities []string
	if tx != nil {
		for _, mr := range tx.MatchedRules() {
			if mr.Rule() != nil {
				ruleIDs = append(ruleIDs, strconv.Itoa(mr.Rule().ID()))
				severities = append(severities, mr.Rule().Severity().String())
			}
			if mr.Message() != "" {
				ruleMessages = append(ruleMessages, mr.Message())
			}
		}
	}
	ruleIDsJSON, _ := json.Marshal(ruleIDs)
	ruleMessagesJSON, _ := json.Marshal(ruleMessages)
	severitiesJSON, _ := json.Marshal(severities)

	storage.LogWAFEvent(storage.WAFEventLog{
		EventID:      uuid.NewString(),
		Timestamp:    time.Now().Unix(),
		IP:           clientIP,
		Method:       r.Method,
		Path:         r.URL.Path,
		QueryString:  r.URL.RawQuery,
		UserAgent:    r.UserAgent(),
		Host:         r.Host,
		StatusCode:   status,
		Action:       "block",
		RuleIDs:      string(ruleIDsJSON),
		RuleMessages: string(ruleMessagesJSON),
		Severities:   string(severitiesJSON),
		RequestID:    reqID,
	})

	if !transport.WriteConfiguredErrorPage(w, r, status) {
		http.Error(w, "Forbidden - WAF", status)
	}
}

type responseInspector struct {
	underlying http.ResponseWriter
	tx         corazatypes.Transaction
	status     int
	limit      int64
	body       bytes.Buffer
	overflow   bool
}

func newResponseInspector(w http.ResponseWriter, tx corazatypes.Transaction, limit int64) *responseInspector {
	if limit <= 0 {
		limit = 10 << 20
	}
	return &responseInspector{underlying: w, tx: tx, status: http.StatusOK, limit: limit}
}
func (w *responseInspector) Header() http.Header { return w.underlying.Header() }
func (w *responseInspector) WriteHeader(status int) {
	if w.status == http.StatusOK {
		w.status = status
	}
}
func (w *responseInspector) Write(data []byte) (int, error) {
	if int64(w.body.Len()+len(data)) > w.limit {
		w.overflow = true
		return len(data), nil
	}
	return w.body.Write(data)
}
func (w *responseInspector) finalize(r *http.Request) bool {
	for key, values := range w.Header() {
		for _, value := range values {
			w.tx.AddResponseHeader(key, value)
		}
	}
	if interruption := w.tx.ProcessResponseHeaders(w.status, "HTTP/1.1"); interruption != nil {
		status := interruption.Status
		if status < 400 {
			status = http.StatusForbidden
		}
		w.Header().Set("X-Aegis-WAF", "blocked")
		if !transport.WriteConfiguredErrorPage(w.underlying, r, status) {
			w.underlying.WriteHeader(status)
			_, _ = w.underlying.Write([]byte("Forbidden - WAF\n"))
		}
		return true
	}
	if w.body.Len() > 0 {
		_, _, _ = w.tx.WriteResponseBody(w.body.Bytes())
	}
	if interruption, _ := w.tx.ProcessResponseBody(); interruption != nil {
		status := interruption.Status
		if status < 400 {
			status = http.StatusForbidden
		}
		w.Header().Set("X-Aegis-WAF", "blocked")
		if !transport.WriteConfiguredErrorPage(w.underlying, r, status) {
			w.underlying.WriteHeader(status)
			_, _ = w.underlying.Write([]byte("Forbidden - WAF\n"))
		}
		return true
	}
	if w.overflow {
		w.Header().Set("X-Aegis-WAF-Inspection", "response-size-exceeded")
		w.underlying.WriteHeader(http.StatusBadGateway)
		_, _ = w.underlying.Write([]byte("502 Bad Gateway - Response inspection limit exceeded\n"))
		return true
	}
	w.underlying.WriteHeader(w.status)
	_, _ = w.underlying.Write(w.body.Bytes())
	return false
}

func (s *Section) Stats() sections.SectionStats {
	return sections.SectionStats{Name: SectionName, Enabled: s.Enabled(), TotalRequests: s.total.Load(), BlockedRequests: s.blocked.Load(), AllowedRequests: s.allowed.Load(), UpdatedAt: time.Now().UTC()}
}
func (s *Section) Health() sections.HealthStatus {
	s.mu.RLock()
	lastError := s.lastError
	reload := s.lastReload
	s.mu.RUnlock()
	state, message := sections.HealthStateHealthy, "Coraza WAF is operational"
	if lastError != "" {
		state, message = sections.HealthStateDegraded, lastError
	}
	return sections.HealthStatus{Status: state, Message: message, Details: map[string]interface{}{"last_reload": reload}, CheckedAt: time.Now().UTC()}
}

func (s *Section) RegisterRoutes(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(prefix+"/config", s.handleConfig)
	mux.HandleFunc(prefix+"/stats", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.Stats()) })
	mux.HandleFunc(prefix+"/schema", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.GetConfigSchema()) })
	mux.HandleFunc(prefix+"/dashboard", s.handleDashboard)
	mux.HandleFunc(prefix+"/analytics", s.handleAnalytics)
	mux.HandleFunc(prefix+"/analytics/", s.handleAnalytics)
	mux.HandleFunc(prefix+"/events", s.handleAnalytics)
	mux.HandleFunc(prefix+"/db-stats", s.handleDashboard)
	mux.HandleFunc(prefix+"/rules", s.handleCustomRules)
	mux.HandleFunc(prefix+"/rules/custom", s.handleCustomRules)
	mux.HandleFunc(prefix+"/rules/custom/test", s.handleConfigTest)
	mux.HandleFunc(prefix+"/rules/custom/", s.handleCustomRule)
	mux.HandleFunc(prefix+"/rules/crs", s.handleCRSRules)
	mux.HandleFunc(prefix+"/rules/crs/bulk", s.handleCRSRulesBulk)
	mux.HandleFunc(prefix+"/profiles", s.handleProfiles)
	mux.HandleFunc(prefix+"/profiles/", s.handleProfiles)
	mux.HandleFunc(prefix+"/policies", s.handleProfiles)
	mux.HandleFunc(prefix+"/policies/", s.handleProfiles)
	mux.HandleFunc(prefix+"/exclusions", s.handleExclusions)
	mux.HandleFunc(prefix+"/exclusions/suggest", s.handleExclusionSuggest)
	mux.HandleFunc(prefix+"/exclusions/", s.handleExclusion)
	mux.HandleFunc(prefix+"/health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.Health()) })
	mux.HandleFunc(prefix+"/config/test", s.handleConfigTest)
	mux.HandleFunc(prefix+"/test_payload", s.handleConfigTest)
	mux.HandleFunc(prefix+"/test-payload", s.handleConfigTest)
	mux.HandleFunc(prefix+"/leak-protection/", paidFeatureHandler)
	mux.HandleFunc(prefix+"/auxiliary/", paidFeatureHandler)
	mux.HandleFunc(prefix+"/editor/", paidFeatureHandler)
	mux.HandleFunc(prefix+"/upload-protection/", paidFeatureHandler)
	mux.HandleFunc(prefix+"/body-guard/", paidFeatureHandler)
}

func (s *Section) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		config := s.GetConfig()
		response := cloneMap(config.Settings)
		for _, legacyKey := range []string{"Enabled", "Mode", "ProtectionLevel", "Engine", "GraphQL", "Upload", "Validation"} {
			delete(response, legacyKey)
		}
		response["enabled"] = config.Enabled
		response["protection_level"] = config.ProtectionLevel
		writeJSON(w, map[string]interface{}{"config": response, "health": s.Health()})
		return
	}
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var incoming map[string]interface{}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&incoming); err != nil {
		http.Error(w, "invalid configuration", http.StatusBadRequest)
		return
	}
	current := s.GetConfig()
	input := sections.SectionConfig{Enabled: current.Enabled, ProtectionLevel: current.ProtectionLevel, Settings: cloneMap(current.Settings)}
	if enabled, ok := incoming["enabled"].(bool); ok {
		input.Enabled = enabled
		delete(incoming, "enabled")
	}
	if level, ok := numberAsInt(incoming["protection_level"]); ok {
		input.ProtectionLevel = level
		delete(incoming, "protection_level")
	}
	for key, value := range incoming {
		input.Settings[key] = value
	}
	if err := s.UpdateConfig(input); err != nil {
		if errors.Is(err, sections.ErrFeatureNotEntitled) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "feature_not_entitled"})
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{"success": true, "config": incoming, "health": s.Health()})
}

func (s *Section) GetConfigSchema() sections.ConfigSchema {
	return sections.ConfigSchema{Groups: []sections.ConfigGroup{{ID: "engine", Name: "Coraza and OWASP CRS", Fields: []sections.ConfigField{{ID: "mode", Key: "mode", Label: "Mode", Type: sections.ConfigTypeSelect, Default: "blocking", Options: []sections.ConfigOption{{Value: "blocking", Label: "Blocking"}, {Value: "detection", Label: "Detection"}}}, {ID: "paranoia", Key: "engine.paranoia_level", Label: "CRS paranoia level", Type: sections.ConfigTypeNumber, Default: 1, Min: 1, Max: 4}, {ID: "crs", Key: "engine.enable_crs", Label: "Enable OWASP CRS", Type: sections.ConfigTypeToggle, Default: true}}}}}
}
func (s *Section) GetPolicies() []sections.Policy      { return nil }
func (s *Section) SetPolicies([]sections.Policy) error { return nil }
func (s *Section) GetRules() []sections.Rule           { return nil }
func (s *Section) SetRules([]sections.Rule) error      { return nil }
func (s *Section) ValidateRule(sections.Rule) error    { return nil }
func (s *Section) ListFunctions() []sections.FunctionInfo {
	return []sections.FunctionInfo{{ID: "coraza", Name: "Coraza", Description: "Request and response inspection", Enabled: true, Category: "community"}, {ID: "crs", Name: "OWASP CRS", Enabled: true, Category: "community"}}
}
func (s *Section) GetFunction(string) sections.Function { return nil }

func pathExcluded(urlPath string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := path.Match(pattern, urlPath); matched || strings.HasPrefix(urlPath, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}
func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return strings.TrimSpace(address)
}
func cloneMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return map[string]interface{}{}
	}
	data, _ := json.Marshal(input)
	var output map[string]interface{}
	_ = json.Unmarshal(data, &output)
	return output
}
func jsonEqual(left, right interface{}) bool {
	l, _ := json.Marshal(left)
	r, _ := json.Marshal(right)
	return bytes.Equal(l, r)
}
func writeJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

var _ = fmt.Sprintf
