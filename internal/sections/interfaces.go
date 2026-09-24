// Package sections provides the core interfaces and types for the section-centric architecture.
// Sections are the primary security components that contain internal functions (microservices).
package sections

import (
	"context"
	"net/http"
	"time"
)

// =============================================================================
// SECTION INTERFACE - Primary Security Component
// =============================================================================

// Section is the primary security component in Aegis v2.0
// Each section contains multiple internal functions that work together
type Section interface {
	// Identity
	Name() string
	ID() string
	Description() string
	Icon() string

	// Lifecycle
	Init(cfg SectionConfig) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Reload(cfg SectionConfig) error

	// State
	Enabled() bool
	SetEnabled(enabled bool)

	// Configuration
	GetConfig() SectionConfig
	UpdateConfig(cfg SectionConfig) error
	GetConfigSchema() ConfigSchema

	// Policies & Rules
	GetPolicies() []Policy
	SetPolicies(policies []Policy) error
	GetRules() []Rule
	SetRules(rules []Rule) error
	ValidateRule(rule Rule) error

	// Middleware - processes requests through this section
	Middleware(next http.Handler) http.Handler

	// Stats & Health
	Stats() SectionStats
	Health() HealthStatus

	// API
	RegisterRoutes(mux *http.ServeMux, prefix string)

	// Internal Functions
	ListFunctions() []FunctionInfo
	GetFunction(name string) Function
}

// =============================================================================
// FUNCTION INTERFACE - Internal Capabilities
// =============================================================================

// Function is an internal capability within a section (ex-module)
// Functions are not user-configurable; they are orchestrated by their parent section
type Function interface {
	// Identity
	Name() string
	ID() string
	Description() string

	// Lifecycle
	Init(cfg FunctionConfig) error
	Start() error
	Stop() error

	// Enabled state (controlled by parent section, not user)
	Enabled() bool
	SetEnabled(enabled bool)

	// Execute processes a request through this function
	// Returns a result with action, score, and signals
	Execute(ctx *RequestContext) *FunctionResult

	// Stats for this specific function
	Stats() FunctionStats
}

// =============================================================================
// REQUEST CONTEXT - Shared Request State
// =============================================================================

// RequestContext carries request data through the section pipeline
type RequestContext struct {
	// Original request/response
	Request  *http.Request
	Response http.ResponseWriter

	// Parsed request data
	ClientIP  string
	UserAgent string
	Path      string
	Method    string
	Host      string

	// Session data
	SessionID string

	// For cross-section communication
	Metadata map[string]interface{}

	// Timestamps
	StartTime time.Time

	// Cancellation
	Ctx context.Context
}

// NewRequestContext creates a new RequestContext from an HTTP request

// SetMetadata sets a metadata value
func (rc *RequestContext) SetMetadata(key string, value interface{}) {
	if rc.Metadata == nil {
		rc.Metadata = make(map[string]interface{})
	}
	rc.Metadata[key] = value
}

// GetMetadata gets a metadata value
func (rc *RequestContext) GetMetadata(key string) (interface{}, bool) {
	if rc.Metadata == nil {
		return nil, false
	}
	v, ok := rc.Metadata[key]
	return v, ok
}

// =============================================================================
// FUNCTION RESULT - Output from Function Execution
// =============================================================================

// FunctionResult is returned by each function after processing
type FunctionResult struct {
	// Action to take
	Action Action

	// Score contribution (0-100)
	Score int

	// Human-readable reason for the action/score
	Reason string

	// Headers to add/modify on the response
	Headers map[string]string

	// Data to pass to subsequent functions
	Data map[string]interface{}

	// Whether processing should continue
	Continue bool
}

// =============================================================================
// ACTION TYPES
// =============================================================================

// Action represents what to do with a request
type Action int

const (
	// ActionAllow lets the request continue
	ActionAllow Action = iota
	// ActionBlock denies the request with 403
	ActionBlock
	// ActionChallenge presents a CAPTCHA or JS challenge
	ActionChallenge
	// ActionRateLimit applies rate limiting
	ActionRateLimit
	// ActionRedirect redirects the request
	ActionRedirect
	// ActionLog just logs without action
	ActionLog
	// ActionTarpit slows down the response
	ActionTarpit
)

// String returns the string representation of an action
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionBlock:
		return "block"
	case ActionChallenge:
		return "challenge"
	case ActionRateLimit:
		return "ratelimit"
	case ActionRedirect:
		return "redirect"
	case ActionLog:
		return "log"
	case ActionTarpit:
		return "tarpit"
	default:
		return "unknown"
	}
}

// =============================================================================
// CONFIGURATION TYPES
// =============================================================================

// SectionConfig is the base configuration for a section
type SectionConfig struct {
	// Whether the section is enabled
	Enabled bool `json:"enabled" mapstructure:"enabled"`

	// Protection level 1-5 (section-specific interpretation)
	ProtectionLevel int `json:"protection_level" mapstructure:"protection_level"`

	// Section-specific settings (parsed by each section)
	Settings map[string]interface{} `json:"settings" mapstructure:"settings"`
}

// SectionConfigPersister stores a complete section configuration before the
// corresponding runtime state is replaced.
type SectionConfigPersister func(sectionID string, config SectionConfig) error

// GetSetting retrieves a setting value with type assertion
func (sc *SectionConfig) GetSetting(key string, defaultVal interface{}) interface{} {
	if sc.Settings == nil {
		return defaultVal
	}
	if v, ok := sc.Settings[key]; ok {
		return v
	}
	return defaultVal
}

// GetBool retrieves a boolean setting
func (sc *SectionConfig) GetBool(key string, defaultVal bool) bool {
	v := sc.GetSetting(key, defaultVal)
	if b, ok := v.(bool); ok {
		return b
	}
	return defaultVal
}

// GetInt retrieves an integer setting
func (sc *SectionConfig) GetInt(key string, defaultVal int) int {
	v := sc.GetSetting(key, defaultVal)
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	}
	return defaultVal
}

// GetString retrieves a string setting
func (sc *SectionConfig) GetString(key string, defaultVal string) string {
	v := sc.GetSetting(key, defaultVal)
	if s, ok := v.(string); ok {
		return s
	}
	return defaultVal
}

// GetDuration retrieves a duration setting
func (sc *SectionConfig) GetDuration(key string, defaultVal time.Duration) time.Duration {
	v := sc.GetSetting(key, "")
	if s, ok := v.(string); ok {
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
	}
	return defaultVal
}

// FunctionConfig is the configuration for a function
type FunctionConfig struct {
	Enabled  bool                   `json:"enabled" mapstructure:"enabled"`
	Settings map[string]interface{} `json:"settings" mapstructure:"settings"`
}

// =============================================================================
// CONFIG SCHEMA - For Dynamic UI Generation
// =============================================================================

// ConfigSchema describes the configuration options for UI rendering
type ConfigSchema struct {
	// Groups of related settings
	Groups []ConfigGroup `json:"groups"`
}

// ConfigGroup is a logical grouping of config fields
type ConfigGroup struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Icon        string        `json:"icon"`
	Fields      []ConfigField `json:"fields"`
}

// ConfigField describes a single configuration field
type ConfigField struct {
	ID          string         `json:"id"`
	Key         string         `json:"key"`
	Label       string         `json:"label"`
	Description string         `json:"description"`
	Type        ConfigType     `json:"type"`
	Default     interface{}    `json:"default"`
	Required    bool           `json:"required"`
	Min         interface{}    `json:"min,omitempty"`
	Max         interface{}    `json:"max,omitempty"`
	Options     []ConfigOption `json:"options,omitempty"`
	Placeholder string         `json:"placeholder,omitempty"`
	Hint        string         `json:"hint,omitempty"`
	Validation  string         `json:"validation,omitempty"` // regex pattern
	DependsOn   string         `json:"depends_on,omitempty"` // field that enables this
}

// ConfigType is the type of a config field
type ConfigType string

const (
	ConfigTypeToggle   ConfigType = "toggle"
	ConfigTypeNumber   ConfigType = "number"
	ConfigTypeSlider   ConfigType = "slider"
	ConfigTypeText     ConfigType = "text"
	ConfigTypeTextarea ConfigType = "textarea"
	ConfigTypeSelect   ConfigType = "select"
	ConfigTypeTags     ConfigType = "tags"
	ConfigTypeIPList   ConfigType = "iplist"
	ConfigTypeKeyValue ConfigType = "keyvalue"
	ConfigTypeDuration ConfigType = "duration"
	ConfigTypeSecret   ConfigType = "secret"
)

// ConfigOption is an option for select fields
type ConfigOption struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

// =============================================================================
// POLICY TYPES
// =============================================================================

// Policy is a named configuration preset
type Policy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Builtin     bool                   `json:"builtin"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Settings    map[string]interface{} `json:"settings"`
}

// =============================================================================
// RULE TYPES
// =============================================================================

// Rule is a conditional action configuration
type Rule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Conditions  []Condition            `json:"conditions"`
	Action      Action                 `json:"action"`
	ActionData  map[string]interface{} `json:"action_data,omitempty"`
}

// Condition is a single condition in a rule
type Condition struct {
	Field    string      `json:"field"`
	Operator Operator    `json:"operator"`
	Value    interface{} `json:"value"`
	Negate   bool        `json:"negate,omitempty"`
}

// Operator is the comparison operator for conditions
type Operator string

const (
	OpEquals      Operator = "equals"
	OpNotEquals   Operator = "not_equals"
	OpContains    Operator = "contains"
	OpNotContains Operator = "not_contains"
	OpStartsWith  Operator = "starts_with"
	OpEndsWith    Operator = "ends_with"
	OpMatches     Operator = "matches" // regex
	OpInList      Operator = "in_list"
	OpNotInList   Operator = "not_in_list"
	OpGreaterThan Operator = "greater_than"
	OpLessThan    Operator = "less_than"
	OpExists      Operator = "exists"
	OpNotExists   Operator = "not_exists"
)

// Match evaluates the condition against a value
func (c *Condition) Match(value interface{}) bool {
	// Implementation will handle type coercion and matching
	// This is a placeholder - full implementation in rule engine
	return false
}

// =============================================================================
// STATS & HEALTH TYPES
// =============================================================================

// SectionStats contains statistics for a section
type SectionStats struct {
	// Section identity
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`

	// Request counts
	TotalRequests   int64 `json:"total_requests"`
	BlockedRequests int64 `json:"blocked_requests"`
	AllowedRequests int64 `json:"allowed_requests"`

	// Timing
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	P99LatencyMs float64 `json:"p99_latency_ms"`

	// Function stats
	FunctionStats map[string]FunctionStats `json:"function_stats"`

	// Custom stats
	Custom map[string]interface{} `json:"custom,omitempty"`

	// Timestamp
	UpdatedAt time.Time `json:"updated_at"`
}

// FunctionStats contains statistics for a function
type FunctionStats struct {
	Name           string                 `json:"name"`
	Enabled        bool                   `json:"enabled"`
	ExecutionCount int64                  `json:"execution_count"`
	MatchCount     int64                  `json:"match_count"`
	AvgLatencyUs   float64                `json:"avg_latency_us"`
	Custom         map[string]interface{} `json:"custom,omitempty"`
}

// FunctionInfo provides metadata about a function
type FunctionInfo struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Enabled     bool                `json:"enabled"`
	Category    string              `json:"category"`
	Capability  *FunctionCapability `json:"capability,omitempty"`
}

// FunctionCapability describes edition/runtime support for a section function.
type FunctionCapability struct {
	Area               string   `json:"area"`
	Status             string   `json:"status"`
	ConfigSupported    bool     `json:"config_supported"`
	RuntimeImplemented bool     `json:"runtime_implemented"`
	ToggleSupported    bool     `json:"toggle_supported"`
	UpgradeFeature     string   `json:"upgrade_feature,omitempty"`
	Reason             string   `json:"reason,omitempty"`
	ConfigKeys         []string `json:"config_keys,omitempty"`
}

// HealthStatus represents the health of a section
type HealthStatus struct {
	Status    HealthState            `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	CheckedAt time.Time              `json:"checked_at"`
}

// HealthState is the state of health
type HealthState string

const (
	HealthStateHealthy   HealthState = "healthy"
	HealthStateDegraded  HealthState = "degraded"
	HealthStateUnhealthy HealthState = "unhealthy"
)
