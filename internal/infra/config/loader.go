package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/storage"
	"github.com/divinelab-io/aegis/internal/sections"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server         ServerConfig          `mapstructure:"server"`
	License        LicenseConfig         `mapstructure:"license" json:"license"`
	Updater        UpdaterConfig         `mapstructure:"updater" json:"updater"`
	Storage        storage.StorageConfig `mapstructure:"storage" json:"storage"`
	AccessLog      AccessLogConfig       `mapstructure:"access_log" json:"access_log"`
	Telemetry      TelemetryConfig       `mapstructure:"telemetry" json:"telemetry"`
	Infrastructure InfrastructureConfig  `mapstructure:"infrastructure" json:"infrastructure"`
	SecurityTXT    SecurityTXTConfig     `mapstructure:"security_txt" json:"security_txt"`

	Access AccessConfig `json:"access" mapstructure:"access"`
	Threat ThreatConfig `json:"threat" mapstructure:"threat"`

	// Shared Modules
	Modules ModulesConfig `json:"modules" mapstructure:"modules"`

	Sections SectionsConfig `mapstructure:"sections"` // New section-based config
	Log      LogConfig      `mapstructure:"log"`
	Upstream UpstreamConfig `mapstructure:"upstream"`
}

type LicenseConfig struct {
	StateDir string `mapstructure:"state_dir" json:"state_dir"`
	APIURL   string `mapstructure:"api_url" json:"api_url"`
}

// GetLicenseConfig exposes only the runtime-safe licensing settings needed by
// commercial builds. Entitlement trust keys remain embedded at build time.
func (c *Config) GetLicenseConfig() (apiURL, stateDir string) {
	if c == nil {
		return "", ""
	}
	return c.License.APIURL, c.License.StateDir
}

type UpdaterConfig struct {
	SocketPath string `mapstructure:"socket_path" json:"socket_path"`
}

type ServerConfig struct {
	Port              int         `mapstructure:"port"`
	ReadTimeout       string      `mapstructure:"read_timeout"`
	WriteTimeout      string      `mapstructure:"write_timeout"`
	ReadHeaderTimeout string      `mapstructure:"read_header_timeout"`
	IdleTimeout       string      `mapstructure:"idle_timeout"`
	MaxHeaderBytes    int         `mapstructure:"max_header_bytes"`
	EnableHTTP3       bool        `mapstructure:"enable_http3"`
	Admin             AdminConfig `mapstructure:"admin"`
	TLS               TLSConfig   `mapstructure:"tls"`
	SMTP              SMTPConfig  `mapstructure:"smtp"`
}

// AccessConfig for access control
type AccessConfig struct {
	Enabled bool `json:"enabled" mapstructure:"enabled"`
}

// ThreatConfig for threat intelligence
type ThreatConfig struct {
	Enabled bool `json:"enabled" mapstructure:"enabled"`
}

// ModulesConfig holds configuration for shared plugins
type ModulesConfig struct {
	Captcha    CaptchaConfig    `json:"captcha" mapstructure:"captcha"`
	ErrorPages ErrorPagesConfig `json:"errorpages" mapstructure:"errorpages"`
}

// CaptchaConfig for shared captcha module
type CaptchaConfig struct {
	Enabled      bool   `json:"enabled" mapstructure:"enabled"`
	ProviderName string `json:"provider_name" mapstructure:"provider_name"`
	SiteKey      string `json:"site_key" mapstructure:"site_key"`
	// SecretKey is the legacy clear-text setting. It is read only to support a
	// controlled migration and is never emitted or written by new code.
	SecretKey      string  `json:"-" mapstructure:"secret_key"`
	SecretKeyRef   string  `json:"secret_key_ref" mapstructure:"secret_key_ref"`
	ScoreThreshold float64 `json:"score_threshold" mapstructure:"score_threshold"`
}

// MaxErrorPageBytes bounds each operator-supplied HTML document. Error pages
// are only written on error paths, but an unbounded document would still let a
// configuration mistake amplify every failed request.
const MaxErrorPageBytes = 64 * 1024
const MaxErrorPageTemplates = 12

var builtInErrorPageTemplateIDs = map[string]struct{}{
	"aegis":   {},
	"minimal": {},
	"status":  {},
}

// ErrorPageTemplate is an operator-authored HTML template applied uniformly to
// all browser error responses when selected in the admin UI.
type ErrorPageTemplate struct {
	ID   string `json:"id" mapstructure:"id" yaml:"id"`
	Name string `json:"name" mapstructure:"name" yaml:"name"`
	HTML string `json:"html" mapstructure:"html" yaml:"html"`
}

// ErrorPagesConfig controls optional browser-facing error documents served by
// the public proxy. API and admin responses retain their native formats. The
// runtime keeps one document per response status, while the admin UI manages
// those documents as one selected template and saves them atomically.
type ErrorPagesConfig struct {
	Enabled          bool                `json:"enabled" mapstructure:"enabled" yaml:"enabled"`
	Theme            string              `json:"theme" mapstructure:"theme" yaml:"theme"`
	Page403          string              `json:"page_403" mapstructure:"page_403" yaml:"page_403"`
	Page404          string              `json:"page_404" mapstructure:"page_404" yaml:"page_404"`
	Page503          string              `json:"page_503" mapstructure:"page_503" yaml:"page_503"`
	Templates        []ErrorPageTemplate `json:"templates" mapstructure:"templates" yaml:"templates"`
	ActiveTemplateID string              `json:"active_template_id" mapstructure:"active_template_id" yaml:"active_template_id"`
}

// Validate prevents malformed configuration from turning an error response
// into an unbounded payload. It intentionally does not sanitize HTML: these
// pages are explicit administrator-authored public documents.
func (c ErrorPagesConfig) Validate() error {
	if c.Theme != "" && c.Theme != "auto" && c.Theme != "light" && c.Theme != "dark" {
		return fmt.Errorf("modules.errorpages.theme must be auto, light, or dark")
	}
	for name, page := range map[string]string{
		"modules.errorpages.page_403": c.Page403,
		"modules.errorpages.page_404": c.Page404,
		"modules.errorpages.page_503": c.Page503,
	} {
		if len(page) > MaxErrorPageBytes {
			return fmt.Errorf("%s exceeds %d bytes", name, MaxErrorPageBytes)
		}
		if strings.ContainsRune(page, '\x00') {
			return fmt.Errorf("%s contains an invalid null byte", name)
		}
	}
	if len(c.Templates) > MaxErrorPageTemplates {
		return fmt.Errorf("modules.errorpages.templates exceeds the maximum of %d templates", MaxErrorPageTemplates)
	}
	seenIDs := make(map[string]struct{}, len(c.Templates))
	for _, template := range c.Templates {
		id := strings.TrimSpace(template.ID)
		name := strings.TrimSpace(template.Name)
		if id == "" {
			return errors.New("modules.errorpages.templates contains a template without an id")
		}
		if strings.ContainsRune(id, '\x00') || id != template.ID {
			return fmt.Errorf("modules.errorpages.templates contains an invalid id %q", template.ID)
		}
		if _, reserved := builtInErrorPageTemplateIDs[id]; reserved {
			return fmt.Errorf("modules.errorpages.templates.%s uses a reserved built-in template id", id)
		}
		if name == "" {
			return fmt.Errorf("modules.errorpages.templates.%s is missing a name", id)
		}
		if strings.ContainsRune(name, '\x00') {
			return fmt.Errorf("modules.errorpages.templates.%s name contains an invalid null byte", id)
		}
		if len(name) > 120 {
			return fmt.Errorf("modules.errorpages.templates.%s name exceeds 120 bytes", id)
		}
		if _, exists := seenIDs[id]; exists {
			return fmt.Errorf("modules.errorpages.templates contains duplicate id %q", id)
		}
		seenIDs[id] = struct{}{}
		if len(template.HTML) > MaxErrorPageBytes {
			return fmt.Errorf("modules.errorpages.templates.%s.html exceeds %d bytes", id, MaxErrorPageBytes)
		}
		if strings.ContainsRune(template.HTML, '\x00') {
			return fmt.Errorf("modules.errorpages.templates.%s.html contains an invalid null byte", id)
		}
	}
	activeID := strings.TrimSpace(c.ActiveTemplateID)
	if activeID != "" && activeID != "aegis" && activeID != "minimal" && activeID != "status" {
		if _, exists := seenIDs[activeID]; !exists {
			return fmt.Errorf("modules.errorpages.active_template_id %q does not exist", activeID)
		}
	}
	return nil
}

type AdminConfig struct {
	Host               string `mapstructure:"host" json:"host" yaml:"host"`
	Port               int    `mapstructure:"port" json:"port" yaml:"port"`
	Username           string `mapstructure:"username" json:"username" yaml:"username"`
	Password           string `mapstructure:"password" json:"-" yaml:"-"`
	SecureCookies      bool   `mapstructure:"secure_cookies" json:"secure_cookies" yaml:"secure_cookies"`
	AuditRetentionDays int    `mapstructure:"audit_retention_days" json:"audit_retention_days" yaml:"audit_retention_days"`
	SetupCompleted     bool   `mapstructure:"setup_completed" json:"setup_completed" yaml:"setup_completed"`
}

type TLSConfig struct {
	Enabled  bool     `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	CertFile string   `mapstructure:"cert_file" json:"cert_file" yaml:"cert_file"`
	KeyFile  string   `mapstructure:"key_file" json:"key_file" yaml:"key_file"`
	CertDir  string   `mapstructure:"cert_dir" json:"cert_dir" yaml:"cert_dir"`
	CacheDir string   `mapstructure:"cache_dir" json:"cache_dir" yaml:"cache_dir"`
	Auto     bool     `mapstructure:"auto" json:"auto" yaml:"auto"`
	Domains  []string `mapstructure:"domains" json:"domains" yaml:"domains"`
	Email    string   `mapstructure:"email" json:"email" yaml:"email"`
}

type SMTPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	From     string `mapstructure:"from"`
}

type LogConfig struct {
	Level string `mapstructure:"level"`
}

type AccessLogConfig struct {
	Enabled      bool   `mapstructure:"enabled" json:"enabled"`
	Path         string `mapstructure:"path" json:"path"`
	RotateSizeMB int64  `mapstructure:"rotate_size_mb" json:"rotate_size_mb"`
	KeepFiles    int    `mapstructure:"keep_files" json:"keep_files"`
}

type TelemetryConfig struct {
	PrometheusEnabled bool   `mapstructure:"prometheus_enabled" json:"prometheus_enabled"`
	PrometheusPath    string `mapstructure:"prometheus_path" json:"prometheus_path"`
	PrometheusToken   string `mapstructure:"prometheus_token" json:"prometheus_token,omitempty"`
	RetentionDays     int    `mapstructure:"retention_days" json:"retention_days"`
	SnapshotInterval  int    `mapstructure:"snapshot_interval" json:"snapshot_interval"`
	RequestLogging    bool   `mapstructure:"request_logging" json:"request_logging"`
}

type InfrastructureConfig struct {
	Mode           string             `mapstructure:"mode" json:"mode" yaml:"mode"`
	ProxyProvider  string             `mapstructure:"proxy_provider" json:"proxy_provider" yaml:"proxy_provider"`
	PublicBaseURL  string             `mapstructure:"public_base_url" json:"public_base_url" yaml:"public_base_url"`
	AegisAddress   string             `mapstructure:"aegis_address" json:"aegis_address" yaml:"aegis_address"`
	TrustedProxies TrustedProxyConfig `mapstructure:"trusted_proxies" json:"trusted_proxies" yaml:"trusted_proxies"`
}

type TrustedProxyConfig struct {
	Enabled         bool     `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	CIDRs           []string `mapstructure:"cidrs" json:"cidrs" yaml:"cidrs"`
	RealIPHeaders   []string `mapstructure:"real_ip_headers" json:"real_ip_headers" yaml:"real_ip_headers"`
	ProtoHeader     string   `mapstructure:"proto_header" json:"proto_header" yaml:"proto_header"`
	HostHeader      string   `mapstructure:"host_header" json:"host_header" yaml:"host_header"`
	ForwardedHeader bool     `mapstructure:"forwarded_header" json:"forwarded_header" yaml:"forwarded_header"`
	Recursive       bool     `mapstructure:"recursive" json:"recursive" yaml:"recursive"`
	SourceURLs      []string `mapstructure:"source_urls" json:"source_urls" yaml:"source_urls"`
	SourceFiles     []string `mapstructure:"source_files" json:"source_files" yaml:"source_files"`
	SourceRoot      string   `mapstructure:"source_root" json:"source_root" yaml:"source_root"`
	CombinedList    string   `mapstructure:"combined_list" json:"combined_list" yaml:"combined_list"`
}

const maxConfiguredTrustedProxyCIDRs = 4096

// NormalizeInfrastructureConfig applies safe control-plane defaults while
// preserving the operator's explicit trust sources.
func NormalizeInfrastructureConfig(next InfrastructureConfig, serverPort int) InfrastructureConfig {
	next.Mode = strings.ToLower(strings.TrimSpace(next.Mode))
	if next.Mode == "" {
		next.Mode = "standalone"
	}
	next.ProxyProvider = strings.ToLower(strings.TrimSpace(next.ProxyProvider))
	if next.ProxyProvider == "" {
		next.ProxyProvider = "nginx"
	}
	next.PublicBaseURL = strings.TrimSpace(next.PublicBaseURL)
	next.AegisAddress = strings.TrimRight(strings.TrimSpace(next.AegisAddress), "/")
	if next.AegisAddress == "" {
		if serverPort <= 0 {
			serverPort = 8080
		}
		next.AegisAddress = fmt.Sprintf("http://127.0.0.1:%d", serverPort)
	}
	next.TrustedProxies.Enabled = next.Mode != "standalone"
	if len(next.TrustedProxies.RealIPHeaders) == 0 {
		next.TrustedProxies.RealIPHeaders = []string{"X-Forwarded-For", "X-Real-IP"}
	}
	if strings.TrimSpace(next.TrustedProxies.ProtoHeader) == "" {
		next.TrustedProxies.ProtoHeader = "X-Forwarded-Proto"
	}
	if strings.TrimSpace(next.TrustedProxies.HostHeader) == "" {
		next.TrustedProxies.HostHeader = "X-Forwarded-Host"
	}
	if strings.TrimSpace(next.TrustedProxies.SourceRoot) == "" {
		next.TrustedProxies.SourceRoot = "./data/trusted-proxies/sources"
	}
	if strings.TrimSpace(next.TrustedProxies.CombinedList) == "" {
		next.TrustedProxies.CombinedList = "./data/trusted-proxies/combined.list"
	}
	return next
}

// ValidateInfrastructureConfig validates values that cross the ingress trust
// boundary. It is shared by startup loading and the live admin API.
func ValidateInfrastructureConfig(infra InfrastructureConfig) error {
	switch infra.Mode {
	case "", "standalone", "behind_proxy", "sidecar", "kubernetes_ingress":
	default:
		return fmt.Errorf("invalid infrastructure.mode: %q", infra.Mode)
	}
	switch infra.ProxyProvider {
	case "", "nginx", "traefik", "apache", "caddy":
	default:
		return fmt.Errorf("invalid infrastructure.proxy_provider: %q", infra.ProxyProvider)
	}
	if infra.Mode == "standalone" && infra.TrustedProxies.Enabled {
		return errors.New("infrastructure.trusted_proxies.enabled must be false in standalone mode")
	}
	if infra.Mode != "" && infra.Mode != "standalone" && !infra.TrustedProxies.Enabled {
		return fmt.Errorf("infrastructure.trusted_proxies.enabled must be true in %s mode", infra.Mode)
	}
	if err := validateInfrastructureURL("infrastructure.public_base_url", infra.PublicBaseURL, true); err != nil {
		return err
	}
	if err := validateInfrastructureURL("infrastructure.aegis_address", infra.AegisAddress, true); err != nil {
		return err
	}
	if len(infra.TrustedProxies.CIDRs) > maxConfiguredTrustedProxyCIDRs {
		return fmt.Errorf("infrastructure.trusted_proxies.cidrs exceeds %d entries", maxConfiguredTrustedProxyCIDRs)
	}
	for _, cidr := range infra.TrustedProxies.CIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid infrastructure.trusted_proxies.cidrs entry %q: %w", cidr, err)
		}
	}
	if len(infra.TrustedProxies.RealIPHeaders) > 8 {
		return errors.New("infrastructure.trusted_proxies.real_ip_headers exceeds 8 entries")
	}
	for _, header := range append(append([]string(nil), infra.TrustedProxies.RealIPHeaders...), infra.TrustedProxies.ProtoHeader, infra.TrustedProxies.HostHeader) {
		if !validHTTPHeaderName(strings.TrimSpace(header)) {
			return fmt.Errorf("invalid trusted proxy header name %q", header)
		}
	}
	if len(infra.TrustedProxies.SourceURLs) > 64 || len(infra.TrustedProxies.SourceFiles) > 64 {
		return errors.New("trusted proxy sources exceed the 64-entry limit")
	}
	for _, sourceURL := range infra.TrustedProxies.SourceURLs {
		parsed, err := url.Parse(strings.TrimSpace(sourceURL))
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			return fmt.Errorf("trusted proxy source %q must use HTTPS without inline credentials", sourceURL)
		}
	}
	for _, path := range append(append([]string(nil), infra.TrustedProxies.SourceFiles...), infra.TrustedProxies.SourceRoot, infra.TrustedProxies.CombinedList) {
		if strings.ContainsRune(path, '\x00') {
			return errors.New("trusted proxy paths cannot contain NUL bytes")
		}
	}
	return nil
}

func validateInfrastructureURL(field, value string, allowEmpty bool) error {
	value = strings.TrimSpace(value)
	if value == "" && allowEmpty {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("%s must be an absolute HTTP(S) URL without credentials", field)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("%s must not contain a path, query, or fragment", field)
	}
	return nil
}

func validHTTPHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

type UpstreamConfig struct {
	Target             string            `mapstructure:"target" json:"target" yaml:"target"`
	Routes             map[string]string `mapstructure:"routes" json:"routes" yaml:"routes"` // Legacy: Host -> Target
	Rules              []RouteConfig     `mapstructure:"rules" json:"rules" yaml:"rules"`    // Advanced Routing
	InsecureSkipVerify bool              `mapstructure:"insecure_skip_verify" json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
	MaxIdleConns       int               `mapstructure:"max_idle_conns" json:"max_idle_conns" yaml:"max_idle_conns"`
	MaxIdlePerHost     int               `mapstructure:"max_idle_conns_per_host" json:"max_idle_conns_per_host" yaml:"max_idle_conns_per_host"`
	MaxConnsPerHost    int               `mapstructure:"max_conns_per_host" json:"max_conns_per_host" yaml:"max_conns_per_host"`
	IdleTimeout        string            `mapstructure:"idle_timeout" json:"idle_timeout" yaml:"idle_timeout"`
	TLSHandshake       string            `mapstructure:"tls_timeout" json:"tls_timeout" yaml:"tls_timeout"`
	Groups             []UpstreamGroup   `mapstructure:"groups" json:"groups" yaml:"groups"`
	// StickySecret exists only in process memory after its environment reference
	// is resolved. It must never be serialized into the administrative snapshot.
	StickySecret      string               `mapstructure:"sticky_secret" json:"-" yaml:"sticky_secret"`
	StickySecretRef   string               `mapstructure:"sticky_secret_ref" json:"-" yaml:"sticky_secret_ref"`
	HealthConcurrency int                  `mapstructure:"health_check_concurrency" json:"health_check_concurrency" yaml:"health_check_concurrency"`
	CircuitBreaker    CircuitBreakerConfig `mapstructure:"circuit_breaker" json:"circuit_breaker" yaml:"circuit_breaker"`
}

type CircuitBreakerConfig struct {
	Threshold int    `mapstructure:"threshold" json:"threshold" yaml:"threshold"` // Failures before opening (default: 5)
	Timeout   string `mapstructure:"timeout" json:"timeout" yaml:"timeout"`       // Duration before half-open probe (default: 30s)
}

type RouteConfig struct {
	ID          string              `mapstructure:"id" json:"id" yaml:"id"`
	Name        string              `mapstructure:"name" json:"name" yaml:"name"`
	Priority    int                 `mapstructure:"priority" json:"priority" yaml:"priority"`
	Hosts       []string            `mapstructure:"hosts" json:"hosts" yaml:"hosts"`
	Paths       []string            `mapstructure:"paths" json:"paths" yaml:"paths"`
	Match       RouteMatchConfig    `mapstructure:"match" json:"match" yaml:"match"`
	Action      RouteActionConfig   `mapstructure:"action" json:"action" yaml:"action"`
	Backends    []UpstreamTarget    `mapstructure:"backends" json:"backends" yaml:"backends"`
	LoadBalance string              `mapstructure:"load_balance" json:"load_balance" yaml:"load_balance"`
	StripPrefix string              `mapstructure:"strip_prefix" json:"strip_prefix" yaml:"strip_prefix"`
	Enabled     bool                `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Security    RouteSecurityConfig `mapstructure:"security" json:"security" yaml:"security"`
}

type RouteSecurityConfig struct {
	WAFCore        *bool               `mapstructure:"waf_core" json:"waf_core,omitempty" yaml:"waf_core,omitempty"`
	TrafficControl *bool               `mapstructure:"traffic_control" json:"traffic_control,omitempty" yaml:"traffic_control,omitempty"`
	HTTPSecurity   *bool               `mapstructure:"http_security" json:"http_security,omitempty" yaml:"http_security,omitempty"`
	BotProtection  *bool               `mapstructure:"bot_protection" json:"bot_protection,omitempty" yaml:"bot_protection,omitempty"`
	APISecurity    *bool               `mapstructure:"api_security" json:"api_security,omitempty" yaml:"api_security,omitempty"`
	AccessControl  *bool               `mapstructure:"access_control" json:"access_control,omitempty" yaml:"access_control,omitempty"`
	Country        *RouteCountryPolicy `mapstructure:"country" json:"country,omitempty" yaml:"country,omitempty"`
}

type RouteMatchConfig struct {
	Hosts       []string            `mapstructure:"hosts" json:"hosts" yaml:"hosts"`
	Paths       []string            `mapstructure:"paths" json:"paths" yaml:"paths"`
	Methods     []string            `mapstructure:"methods" json:"methods" yaml:"methods"`
	Headers     map[string][]string `mapstructure:"headers" json:"headers" yaml:"headers"`
	Query       map[string][]string `mapstructure:"query" json:"query" yaml:"query"`
	SourceCIDRs []string            `mapstructure:"source_cidrs" json:"source_cidrs" yaml:"source_cidrs"`
}

type RouteActionConfig struct {
	Upstream     string           `mapstructure:"upstream" json:"upstream" yaml:"upstream"`
	Backends     []UpstreamTarget `mapstructure:"backends" json:"backends" yaml:"backends"`
	Strategy     string           `mapstructure:"strategy" json:"strategy" yaml:"strategy"`
	StripPrefix  string           `mapstructure:"strip_prefix" json:"strip_prefix" yaml:"strip_prefix"`
	RewritePath  string           `mapstructure:"rewrite_path" json:"rewrite_path" yaml:"rewrite_path"`
	PreserveHost bool             `mapstructure:"preserve_host" json:"preserve_host" yaml:"preserve_host"`
	Timeout      string           `mapstructure:"timeout" json:"timeout" yaml:"timeout"`
	Retries      int              `mapstructure:"retries" json:"retries" yaml:"retries"`
}

type RouteCountryPolicy struct {
	Enabled        bool     `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	AllowCountries []string `mapstructure:"allow_countries" json:"allow_countries" yaml:"allow_countries"`
	BlockCountries []string `mapstructure:"block_countries" json:"block_countries" yaml:"block_countries"`
	Groups         []string `mapstructure:"groups" json:"groups" yaml:"groups"`
	Exceptions     []string `mapstructure:"exceptions" json:"exceptions" yaml:"exceptions"`
}

// GeoConfig is shared by the Community runtime and the standalone updater.
// Legacy fields remain readable for one compatibility release.
type GeoConfig struct {
	Enabled        bool     `mapstructure:"enabled" json:"enabled"`
	DBPath         string   `mapstructure:"db_path" json:"db_path"`
	AllowCountries []string `mapstructure:"allow_countries" json:"allow_countries"`
	BlockCountries []string `mapstructure:"block_countries" json:"block_countries"`
	Groups         []string `mapstructure:"groups" json:"groups"`
	Exceptions     []string `mapstructure:"exceptions" json:"exceptions"`
	CacheTTL       string   `mapstructure:"cache_ttl" json:"cache_ttl"`
	Mode           string   `mapstructure:"mode" json:"mode,omitempty"`
	Countries      []string `mapstructure:"countries" json:"countries,omitempty"`
	Regions        []string `mapstructure:"regions" json:"regions,omitempty"`
	AutoUpdate     bool     `mapstructure:"auto_update" json:"auto_update,omitempty"`
	UpdateInterval string   `mapstructure:"update_interval" json:"update_interval,omitempty"`
	UpdateURL      string   `mapstructure:"update_url" json:"update_url,omitempty"`
}

func (c *Config) GeoConfig() (GeoConfig, error) {
	result := GeoConfig{DBPath: "./data/dbip-country.mmdb", CacheTTL: "24h", Mode: "blocklist"}
	if raw, ok := c.Sections.TrafficControl["geo"]; ok {
		if err := mapstructure.Decode(raw, &result); err != nil {
			return result, fmt.Errorf("decode traffic geo config: %w", err)
		}
	}
	result.DBPath = strings.TrimSpace(result.DBPath)
	if result.DBPath == "" {
		result.DBPath = "./data/dbip-country.mmdb"
	}
	result.CacheTTL = strings.TrimSpace(result.CacheTTL)
	if result.CacheTTL == "" {
		result.CacheTTL = "24h"
	}
	result.Mode = strings.ToLower(strings.TrimSpace(result.Mode))
	if result.Mode == "" {
		result.Mode = "blocklist"
	}
	if len(result.AllowCountries) == 0 && len(result.BlockCountries) == 0 && len(result.Countries) > 0 {
		if result.Mode == "allowlist" {
			result.AllowCountries = append([]string(nil), result.Countries...)
		} else {
			result.BlockCountries = append([]string(nil), result.Countries...)
		}
	}
	result.Groups = append(result.Groups, result.Regions...)
	policy := &RouteCountryPolicy{Enabled: result.Enabled, AllowCountries: result.AllowCountries, BlockCountries: result.BlockCountries, Groups: result.Groups, Exceptions: result.Exceptions}
	if err := ValidateRouteCountryPolicy(policy); err != nil {
		return result, err
	}
	if _, err := time.ParseDuration(result.CacheTTL); err != nil {
		return result, fmt.Errorf("invalid geo cache_ttl: %w", err)
	}
	return result, nil
}

type UpstreamGroup struct {
	Name        string              `mapstructure:"name" json:"name" yaml:"name"`
	Strategy    string              `mapstructure:"strategy" json:"strategy" yaml:"strategy"` // round_robin, least_conn, ip_hash
	Targets     []UpstreamTarget    `mapstructure:"targets" json:"targets" yaml:"targets"`
	HealthCheck HealthCheckConfig   `mapstructure:"health_check" json:"health_check" yaml:"health_check"`
	Sticky      StickySessionConfig `mapstructure:"sticky" json:"sticky" yaml:"sticky"`
}

type StickySessionConfig struct {
	Enabled bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Cookie  string `mapstructure:"cookie" json:"cookie" yaml:"cookie"`
	TTL     string `mapstructure:"ttl" json:"ttl" yaml:"ttl"`
}

type UpstreamTarget struct {
	URL    string `mapstructure:"url" json:"url" yaml:"url"`
	Weight int    `mapstructure:"weight" json:"weight" yaml:"weight"`
}

type HealthCheckConfig struct {
	Enabled            bool              `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Interval           string            `mapstructure:"interval" json:"interval" yaml:"interval"`
	Timeout            string            `mapstructure:"timeout" json:"timeout" yaml:"timeout"`
	Path               string            `mapstructure:"path" json:"path" yaml:"path"`
	Method             string            `mapstructure:"method" json:"method" yaml:"method"`
	Headers            map[string]string `mapstructure:"headers" json:"headers" yaml:"headers"`
	ExpectedStatuses   []int             `mapstructure:"expected_statuses" json:"expected_statuses" yaml:"expected_statuses"`
	HealthyThreshold   int               `mapstructure:"healthy_threshold" json:"healthy_threshold" yaml:"healthy_threshold"`
	UnhealthyThreshold int               `mapstructure:"unhealthy_threshold" json:"unhealthy_threshold" yaml:"unhealthy_threshold"`
}

// =============================================================================
// SECTION-BASED CONFIGURATION (WAF Core Only)
// =============================================================================

// SectionsConfig contains all section configurations
type SectionsConfig struct {
	WAFCore        SectionWAFCoreConfig   `mapstructure:"waf_core"`
	HTTPSecurity   map[string]interface{} `mapstructure:"http_security"`
	TrafficControl map[string]interface{} `mapstructure:"traffic_control"`
	Bot            map[string]interface{} `mapstructure:"bot_protection"`
	APISecurity    map[string]interface{} `mapstructure:"api_security"`
	AccessControl  map[string]interface{} `mapstructure:"access_control"`
}

// SectionBaseConfig is the common config for all sections
type SectionBaseConfig struct {
	Enabled         bool `json:"enabled" mapstructure:"enabled"`
	ProtectionLevel int  `json:"protection_level" mapstructure:"protection_level"`
}

// SectionWAFCoreConfig for the WAF Core section
type SectionWAFCoreConfig struct {
	SectionBaseConfig `json:",inline" mapstructure:",squash"`
	Mode              string `json:"mode" mapstructure:"mode"` // blocking, detection, learning
	Engine            struct {
		ParanoiaLevel    int    `json:"paranoia_level" mapstructure:"paranoia_level"`
		AnomalyThreshold int    `json:"anomaly_threshold" mapstructure:"anomaly_threshold"`
		EnableCRS        bool   `json:"enable_crs" mapstructure:"enable_crs"`
		CRSVersion       string `json:"crs_version" mapstructure:"crs_version"`
	} `json:"engine" mapstructure:"engine"`
	Validation struct {
		MaxBodySize    int64    `json:"max_body_size" mapstructure:"max_body_size"`
		MaxURLLength   int      `json:"max_url_length" mapstructure:"max_url_length"`
		MaxHeaders     int      `json:"max_headers" mapstructure:"max_headers"`
		AllowedMethods []string `json:"allowed_methods" mapstructure:"allowed_methods"`
	} `json:"validation" mapstructure:"validation"`
	GraphQL struct {
		Enabled              bool `json:"enabled" mapstructure:"enabled"`
		MaxDepth             int  `json:"max_depth" mapstructure:"max_depth"`
		MaxComplexity        int  `json:"max_complexity" mapstructure:"max_complexity"`
		DisableIntrospection bool `json:"disable_introspection" mapstructure:"disable_introspection"`
	} `json:"graphql" mapstructure:"graphql"`
	Upload struct {
		Enabled           bool     `json:"enabled" mapstructure:"enabled"`
		MaxSize           int64    `json:"max_size" mapstructure:"max_size"`
		BlockedExtensions []string `json:"blocked_extensions" mapstructure:"blocked_extensions"`
	} `json:"upload" mapstructure:"upload"`
}

// GlobalConfig is the shared pointer to the active configuration
var (
	GlobalConfig *Config
	configMu     sync.RWMutex
	updateMu     sync.Mutex
)

// ErrConfigValidation identifies a rejected configuration mutation. Callers
// may safely show its message to a privileged configuration operator.
var ErrConfigValidation = errors.New("config validation failed")

// WithConfigMutation serializes full-document config-file changes with live
// settings writes. Callers that only stage a replacement must not reload the
// active configuration inside this critical section.
func WithConfigMutation(apply func() error) error {
	if apply == nil {
		return errors.New("config mutation callback is required")
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	return apply()
}

// LoadConfig reads the complete runtime configuration from file and
// environment. The runtime must have an administrator password because it may
// create the initial administrator account.
func LoadConfig(path string) (*Config, error) {
	return loadConfig(path, true, true)
}

// LoadControlPlaneConfig reads the configuration needed by local operator
// recovery tools. It deliberately does not require AEGIS_ADMIN_PASSWORD: a
// password-recovery command must still be usable when that credential is the
// one being recovered. It never starts a listener or creates an account.
func LoadControlPlaneConfig(path string) (*Config, error) {
	return loadConfig(path, false, false)
}

func loadConfig(path string, requireAdminPassword, persistMigrations bool) (*Config, error) {
	AutoLoadEnv()
	if err := validateConfigurationOwnershipRegistry(); err != nil {
		return nil, fmt.Errorf("validate configuration ownership registry: %w", err)
	}
	configureConfigViper(viper.GetViper(), path)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}
	if viper.IsSet("database") {
		return nil, errors.New("database is no longer supported; configure ClickHouse under storage.analytics")
	}
	trafficMigrated, err := importLegacyTrafficControlConfig(path)
	if err != nil {
		return nil, err
	}
	applyLegacyUpstreamKeys()

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	if err := resolveStickySecretReference(&cfg); err != nil {
		return nil, err
	}
	applyLegacyTLSKeys(&cfg.Server.TLS)

	// Admin password is required for bootstrap when setup has not yet been completed.
	// Once setup is completed, identities are managed in PostgreSQL.
	password := os.Getenv("AEGIS_ADMIN_PASSWORD")
	if requireAdminPassword && !cfg.Server.Admin.SetupCompleted && password == "" {
		return nil, errors.New("AEGIS_ADMIN_PASSWORD environment variable is required")
	}
	if requireAdminPassword && !cfg.Server.Admin.SetupCompleted && len(password) < 1 {
		return nil, errors.New("AEGIS_ADMIN_PASSWORD must not be empty")
	}
	if password != "" {
		cfg.Server.Admin.Password = password
	}
	applyAnalyticsDatabaseEnvOverrides(&cfg.Storage.Analytics)
	applyControlDatabaseEnvOverrides(&cfg.Storage.Control)
	// Once a control-plane document owns Error Pages, an old YAML copy must not
	// reclaim the runtime during a SIGHUP reload. Bootstrap remains available
	// only until the first successful PostgreSQL import/load.
	preserveManagedErrorPages(&cfg)
	preserveManagedSecurityTXT(&cfg)
	preserveManagedCaptcha(&cfg)
	preserveManagedInfrastructure(&cfg)
	preserveManagedUpstreamRuntimeSettings(&cfg)
	preserveManagedUpstreamGroups(&cfg)
	preserveManagedRouteRules(&cfg)
	preserveManagedCircuitBreaker(&cfg)
	preserveManagedLegacyRoutes(&cfg)
	preserveManagedStickySecret(&cfg)

	// CRITICAL-003 FIX: Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	if persistMigrations && trafficMigrated {
		if err := writeCurrentConfigAtomically(); err != nil {
			return nil, fmt.Errorf("persist configuration migration: %w", err)
		}
	}

	// CRITICAL-002 FIX: Atomic config update with mutex
	configMu.Lock()
	GlobalConfig = &cfg
	configMu.Unlock()

	return &cfg, nil
}

func configureConfigViper(settings *viper.Viper, path string) {
	if path != "" {
		settings.SetConfigFile(path)
	}
	settings.SetConfigType("yaml")

	settings.SetDefault("server.port", 8080)
	settings.SetDefault("server.read_timeout", "10s")
	settings.SetDefault("server.write_timeout", "10s")
	settings.SetDefault("server.read_header_timeout", "2s")
	settings.SetDefault("server.idle_timeout", "120s")
	settings.SetDefault("server.max_header_bytes", 1048576)
	settings.SetDefault("server.enable_http3", true)
	settings.SetDefault("server.admin.host", "127.0.0.1")
	settings.SetDefault("server.admin.port", 8081)
	settings.SetDefault("server.admin.username", "admin")
	settings.SetDefault("server.admin.secure_cookies", false)
	settings.SetDefault("server.admin.audit_retention_days", 0)
	settings.SetDefault("server.admin.setup_completed", false)
	settings.SetDefault("server.tls.cert_dir", "data/tls/certs")
	settings.SetDefault("server.tls.cache_dir", "data/tls/acme")
	settings.SetDefault("server.smtp.host", "localhost")
	settings.SetDefault("server.smtp.port", 1025)
	settings.SetDefault("server.smtp.username", "")
	settings.SetDefault("server.smtp.password", "")
	settings.SetDefault("server.smtp.from", "no-reply@aegis.local")
	settings.SetDefault("license.state_dir", "./data/license")
	settings.SetDefault("license.api_url", "")
	settings.SetDefault("updater.socket_path", "/run/aegis/updater.sock")
	settings.SetDefault("log.level", "info")
	settings.SetDefault("storage.control.enabled", false)
	settings.SetDefault("storage.control.driver", string(storage.ControlDriverPostgreSQL))
	settings.SetDefault("storage.control.host", "")
	settings.SetDefault("storage.control.port", 5432)
	settings.SetDefault("storage.control.database", "aegis")
	settings.SetDefault("storage.control.username", "aegis")
	settings.SetDefault("storage.control.password_secret_ref", "")
	settings.SetDefault("storage.control.ssl_mode", "disable")
	settings.SetDefault("storage.analytics.mode", string(storage.AnalyticsModeDisabled))
	settings.SetDefault("storage.analytics.driver", string(storage.DriverClickHouse))
	settings.SetDefault("storage.analytics.host", "localhost")
	settings.SetDefault("storage.analytics.port", 9000)
	settings.SetDefault("storage.analytics.database", "aegis")
	settings.SetDefault("storage.analytics.username", "default")
	settings.SetDefault("storage.analytics.password_secret_ref", "")
	settings.SetDefault("storage.analytics.secure", false)
	settings.SetDefault("storage.analytics.max_open_conns", 20)
	settings.SetDefault("storage.analytics.max_idle_conns", 10)
	settings.SetDefault("storage.analytics.conn_max_lifetime", time.Hour)
	settings.SetDefault("access_log.enabled", true)
	settings.SetDefault("access_log.path", "./logs/access.log")
	settings.SetDefault("access_log.rotate_size_mb", 100)
	settings.SetDefault("access_log.keep_files", 14)
	settings.SetDefault("telemetry.prometheus_enabled", false)
	settings.SetDefault("telemetry.prometheus_path", "/metrics")
	settings.SetDefault("telemetry.prometheus_token", "")
	settings.SetDefault("telemetry.retention_days", 30)
	settings.SetDefault("telemetry.snapshot_interval", 60)
	settings.SetDefault("telemetry.request_logging", true)
	settings.SetDefault("modules.errorpages.enabled", false)
	settings.SetDefault("modules.errorpages.theme", "auto")
	settings.SetDefault("modules.errorpages.page_403", "")
	settings.SetDefault("modules.errorpages.page_404", "")
	settings.SetDefault("modules.errorpages.page_503", "")
	settings.SetDefault("modules.errorpages.templates", []ErrorPageTemplate{})
	settings.SetDefault("modules.errorpages.active_template_id", "aegis")
	settings.SetDefault("infrastructure.mode", "standalone")
	settings.SetDefault("infrastructure.proxy_provider", "nginx")
	settings.SetDefault("infrastructure.public_base_url", "")
	settings.SetDefault("infrastructure.aegis_address", "")
	settings.SetDefault("infrastructure.trusted_proxies.enabled", false)
	settings.SetDefault("infrastructure.trusted_proxies.cidrs", []string{"127.0.0.1/32", "::1/128"})
	settings.SetDefault("infrastructure.trusted_proxies.real_ip_headers", []string{"X-Forwarded-For", "X-Real-IP"})
	settings.SetDefault("infrastructure.trusted_proxies.proto_header", "X-Forwarded-Proto")
	settings.SetDefault("infrastructure.trusted_proxies.host_header", "X-Forwarded-Host")
	settings.SetDefault("infrastructure.trusted_proxies.forwarded_header", false)
	settings.SetDefault("infrastructure.trusted_proxies.recursive", true)
	settings.SetDefault("infrastructure.trusted_proxies.source_urls", []string{})
	settings.SetDefault("infrastructure.trusted_proxies.source_files", []string{})
	settings.SetDefault("infrastructure.trusted_proxies.source_root", "./data/trusted-proxies/sources")
	settings.SetDefault("infrastructure.trusted_proxies.combined_list", "./data/trusted-proxies/combined.list")
	settings.AutomaticEnv()
	settings.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
}

// ValidateConfigDocument validates a restart-pending configuration without
// changing the active process configuration.
func ValidateConfigDocument(data []byte) error {
	return validateConfigDocument(data, true)
}

// ValidateControlPlaneConfigDocument validates a candidate configuration for
// an operator workflow. It does not require the current administrator password
// because the password is never part of a persisted configuration document.
func ValidateControlPlaneConfigDocument(data []byte) error {
	return validateConfigDocument(data, false)
}

func validateConfigDocument(data []byte, requireAdminPassword bool) error {
	candidate := viper.New()
	configureConfigViper(candidate, "")
	if err := candidate.ReadConfig(bytes.NewReader(data)); err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	if candidate.IsSet("database") {
		return errors.New("database is no longer supported; configure ClickHouse under storage.analytics")
	}

	var cfg Config
	if err := candidate.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("decode configuration: %w", err)
	}
	if err := resolveStickySecretReference(&cfg); err != nil {
		return err
	}
	password := os.Getenv("AEGIS_ADMIN_PASSWORD")
	if requireAdminPassword && !cfg.Server.Admin.SetupCompleted && password == "" {
		return errors.New("AEGIS_ADMIN_PASSWORD environment variable is required")
	}
	if password != "" {
		cfg.Server.Admin.Password = password
	}
	applyAnalyticsDatabaseEnvOverrides(&cfg.Storage.Analytics)
	applyControlDatabaseEnvOverrides(&cfg.Storage.Control)
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	return nil
}

// importLegacyTrafficControlConfig performs a one-time import of the former
// standalone config/traffic.yaml document. A canonical sections.traffic_control
// document always wins, so startup never merges two mutable authorities.
func importLegacyTrafficControlConfig(configPath string) (bool, error) {
	if viper.IsSet("sections.traffic_control") {
		return false, nil
	}

	baseDir := filepath.Dir(configPath)
	candidates := []string{
		filepath.Join(baseDir, "config", "traffic.yaml"),
		filepath.Join(baseDir, "traffic.yaml"),
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}

		data, err := os.ReadFile(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("read legacy traffic config %q: %w", candidate, err)
		}
		var settings map[string]interface{}
		if err := yaml.Unmarshal(data, &settings); err != nil {
			return false, fmt.Errorf("decode legacy traffic config %q: %w", candidate, err)
		}
		settings = canonicalTrafficControlSettings(settings)
		viper.Set("sections.traffic_control", settings)
		return true, nil
	}
	return false, nil
}

func canonicalTrafficControlSettings(value map[string]interface{}) map[string]interface{} {
	if value == nil {
		return map[string]interface{}{}
	}
	keyAliases := map[string]string{
		"protectionlevel":  "protection_level",
		"autoexpire":       "auto_expire",
		"dbpath":           "db_path",
		"autoupdate":       "auto_update",
		"updateinterval":   "update_interval",
		"updateurl":        "update_url",
		"allowcountries":   "allow_countries",
		"blockcountries":   "block_countries",
		"cachettl":         "cache_ttl",
		"dnsblservers":     "dnsbl_servers",
		"blocktor":         "block_tor",
		"blockdatacenter":  "block_datacenter",
		"blockedips":       "blocked_ips",
		"allowedips":       "allowed_ips",
		"apikey":           "api_key",
		"confidencescore":  "confidence_score",
		"droplisturl":      "drop_list_url",
		"maxrps":           "max_rps",
		"maxconnections":   "max_connections",
		"burstmultiplier":  "burst_multiplier",
		"panicthreshold":   "panic_threshold",
		"panicenabled":     "panic_enabled",
		"autoban":          "auto_ban",
		"banduration":      "ban_duration",
		"defaultrate":      "default_rate",
		"defaultburst":     "default_burst",
		"keyby":            "key_by",
		"bypassstatic":     "bypass_static",
		"bypassknownbots":  "bypass_known_bots",
		"cookiename":       "cookie_name",
		"headername":       "header_name",
		"staticextensions": "static_extensions",
		"pathoverrides":    "path_overrides",
		"connstats":        "conn_stats",
		"vipips":           "vip_ips",
	}
	result := make(map[string]interface{}, len(value))
	for key, item := range value {
		canonicalKey := keyAliases[strings.ToLower(strings.TrimSpace(key))]
		if canonicalKey == "" {
			canonicalKey = key
		}
		switch typed := item.(type) {
		case map[string]interface{}:
			result[canonicalKey] = canonicalTrafficControlSettings(typed)
		case []interface{}:
			result[canonicalKey] = canonicalTrafficControlSlice(typed)
		default:
			result[canonicalKey] = item
		}
	}
	return result
}

func canonicalTrafficControlSlice(values []interface{}) []interface{} {
	result := make([]interface{}, len(values))
	for index, value := range values {
		if nested, ok := value.(map[string]interface{}); ok {
			result[index] = canonicalTrafficControlSettings(nested)
		} else {
			result[index] = value
		}
	}
	return result
}

func applyLegacyTLSKeys(tlsCfg *TLSConfig) {
	if tlsCfg == nil {
		return
	}
	// Older versions serialized Go field names as certfile/keyfile. Read them
	// once for compatibility; all new writes use canonical snake_case keys.
	if strings.TrimSpace(tlsCfg.CertFile) == "" {
		tlsCfg.CertFile = strings.TrimSpace(viper.GetString("server.tls.certfile"))
	}
	if strings.TrimSpace(tlsCfg.KeyFile) == "" {
		tlsCfg.KeyFile = strings.TrimSpace(viper.GetString("server.tls.keyfile"))
	}
}

// applyLegacyUpstreamKeys migrates the compact keys emitted by older YAML
// writes (for example healthcheck and preservehost) into the canonical schema
// before mapstructure decodes the configuration. The next successful write
// persists only canonical snake_case keys.
func applyLegacyUpstreamKeys() {
	if raw := viper.Get("upstream.groups"); raw != nil {
		if groups, ok := configValueAsSlice(raw); ok {
			changed := false
			for _, item := range groups {
				group, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				changed = renameLegacyKey(group, "healthcheck", "health_check") || changed
			}
			if changed {
				viper.Set("upstream.groups", groups)
			}
		}
	}

	if raw := viper.Get("upstream.rules"); raw != nil {
		if rules, ok := configValueAsSlice(raw); ok {
			changed := false
			for _, item := range rules {
				route, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				changed = renameLegacyKey(route, "loadbalance", "load_balance") || changed
				changed = renameLegacyKey(route, "stripprefix", "strip_prefix") || changed
				if match, ok := route["match"].(map[string]interface{}); ok {
					changed = renameLegacyKey(match, "sourcecidrs", "source_cidrs") || changed
				}
				if action, ok := route["action"].(map[string]interface{}); ok {
					for legacy, canonical := range map[string]string{
						"preservehost": "preserve_host",
						"rewritepath":  "rewrite_path",
						"stripprefix":  "strip_prefix",
					} {
						changed = renameLegacyKey(action, legacy, canonical) || changed
					}
				}
				if security, ok := route["security"].(map[string]interface{}); ok {
					for legacy, canonical := range map[string]string{
						"wafcore":        "waf_core",
						"trafficcontrol": "traffic_control",
						"httpsecurity":   "http_security",
						"botprotection":  "bot_protection",
						"apisecurity":    "api_security",
						"accesscontrol":  "access_control",
					} {
						changed = renameLegacyKey(security, legacy, canonical) || changed
					}
					if country, ok := security["country"].(map[string]interface{}); ok {
						changed = renameLegacyKey(country, "allowcountries", "allow_countries") || changed
						changed = renameLegacyKey(country, "blockcountries", "block_countries") || changed
					}
				}
			}
			if changed {
				viper.Set("upstream.rules", rules)
			}
		}
	}
}

func configValueAsSlice(value interface{}) ([]interface{}, bool) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	var decoded []interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, false
	}
	return decoded, true
}

func renameLegacyKey(values map[string]interface{}, legacy, canonical string) bool {
	value, exists := values[legacy]
	if !exists {
		return false
	}
	if _, canonicalExists := values[canonical]; !canonicalExists {
		values[canonical] = value
	}
	delete(values, legacy)
	return true
}

func resolveStickySecretReference(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	cfg.Upstream.StickySecretRef = strings.TrimSpace(cfg.Upstream.StickySecretRef)
	if cfg.Upstream.StickySecretRef == "" {
		return nil
	}
	secret, err := ResolveStickySecretReference(cfg.Upstream.StickySecretRef)
	if err != nil {
		return err
	}
	cfg.Upstream.StickySecret = secret
	return nil
}

func applyAnalyticsDatabaseEnvOverrides(analytics *storage.AnalyticsConfig) {
	if analytics == nil {
		return
	}
	if v := os.Getenv("AEGIS_ANALYTICS_MODE"); v != "" {
		analytics.Mode = storage.AnalyticsMode(v)
	}
	if v := os.Getenv("AEGIS_ANALYTICS_HOST"); v != "" {
		analytics.Host = v
	}
	if v := os.Getenv("AEGIS_ANALYTICS_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			analytics.Port = port
		}
	}
	if v := os.Getenv("AEGIS_ANALYTICS_DATABASE"); v != "" {
		analytics.Database = v
	}
	if v := os.Getenv("AEGIS_ANALYTICS_USERNAME"); v != "" {
		analytics.Username = v
	}
	if v := os.Getenv("AEGIS_ANALYTICS_PASSWORD_SECRET_REF"); v != "" {
		analytics.PasswordSecretRef = v
	}
	if v := os.Getenv("AEGIS_ANALYTICS_SECURE"); v != "" {
		analytics.Secure = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
	if v := os.Getenv("AEGIS_ANALYTICS_DRIVER"); v != "" {
		analytics.Driver = storage.DBDriver(v)
	} else if analytics.Driver == "" {
		analytics.Driver = storage.DriverClickHouse
	}
	if analytics.MaxOpenConns <= 0 {
		analytics.MaxOpenConns = 20
	}
	if analytics.MaxIdleConns <= 0 {
		analytics.MaxIdleConns = 10
	}
	if analytics.ConnMaxLifetime <= 0 {
		analytics.ConnMaxLifetime = time.Hour
	}
}

func applyControlDatabaseEnvOverrides(control *storage.ControlConfig) {
	if control == nil {
		return
	}
	if v := os.Getenv("AEGIS_CONTROL_DB_ENABLED"); v != "" {
		control.Enabled = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
	if v := os.Getenv("AEGIS_CONTROL_DB_HOST"); v != "" {
		control.Host = v
	}
	if v := os.Getenv("AEGIS_CONTROL_DB_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			control.Port = port
		}
	}
	if v := os.Getenv("AEGIS_CONTROL_DB_NAME"); v != "" {
		control.Database = v
	}
	if v := os.Getenv("AEGIS_CONTROL_DB_USER"); v != "" {
		control.Username = v
	}
	if v := os.Getenv("AEGIS_CONTROL_DB_USER"); v != "" {
		control.Username = v
	}
	if v := os.Getenv("AEGIS_CONTROL_DB_SSL_MODE"); v != "" {
		control.SSLMode = v
	}
}

// GetCurrentConfig returns the internal viper settings map
func GetCurrentConfig() map[string]interface{} {
	return viper.AllSettings()
}

// UpdateConfig updates a specific key, saves to disk, and refreshes the GlobalConfig struct
func UpdateConfig(key string, value interface{}) error {
	if ContainsInfrastructureUpdate(map[string]interface{}{key: value}) {
		return fmt.Errorf("%w: infrastructure proxy settings must use the dedicated control-plane endpoint", ErrConfigValidation)
	}
	if ContainsUpstreamRuntimeUpdate(map[string]interface{}{key: value}) {
		return fmt.Errorf("%w: upstream settings must use the dedicated control-plane endpoint", ErrConfigValidation)
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	return updateConfigBatchLocked(map[string]interface{}{key: value})
}

// UpdateConfigBatch validates and persists a related group of config updates as
// one revision. Admin forms use this to avoid partial saves and repeated disk
// writes when a single Save action changes several fields.
func UpdateConfigBatch(updates map[string]interface{}) error {
	if len(updates) == 0 {
		return errors.New("at least one configuration update is required")
	}
	if ContainsInfrastructureUpdate(updates) {
		return fmt.Errorf("%w: infrastructure proxy settings must use the dedicated control-plane endpoint", ErrConfigValidation)
	}
	if ContainsUpstreamRuntimeUpdate(updates) {
		return fmt.Errorf("%w: upstream settings must use the dedicated control-plane endpoint", ErrConfigValidation)
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	return updateConfigBatchLocked(updates)
}

// UpdateCaptchaConfig replaces the complete CAPTCHA document instead of using
// Viper's parent-key merge semantics. This guarantees a legacy secret_key is
// removed when the new secret_key_ref configuration is persisted.
func UpdateCaptchaConfig(next CaptchaConfig) error {
	updateMu.Lock()
	defer updateMu.Unlock()

	allSettings := viper.AllSettings()
	modules, ok := allSettings["modules"].(map[string]interface{})
	if !ok {
		modules = make(map[string]interface{})
	} else {
		copied := make(map[string]interface{}, len(modules))
		for key, value := range modules {
			copied[key] = value
		}
		modules = copied
	}
	modules["captcha"] = map[string]interface{}{
		"enabled":         next.Enabled,
		"provider_name":   next.ProviderName,
		"site_key":        next.SiteKey,
		"secret_key_ref":  next.SecretKeyRef,
		"score_threshold": next.ScoreThreshold,
	}
	allSettings["modules"] = modules

	candidateViper := viper.New()
	if err := candidateViper.MergeConfigMap(allSettings); err != nil {
		return fmt.Errorf("merge captcha configuration: %w", err)
	}
	var newCfg Config
	if err := candidateViper.Unmarshal(&newCfg); err != nil {
		return err
	}
	if err := resolveStickySecretReference(&newCfg); err != nil {
		return err
	}
	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	stripManagedControlPlaneFromSettings(allSettings)
	data, err := yaml.Marshal(allSettings)
	if err != nil {
		return fmt.Errorf("marshal captcha configuration: %w", err)
	}
	configPath := viper.ConfigFileUsed()
	if strings.TrimSpace(configPath) == "" {
		return errors.New("configuration file path is not available")
	}
	if err := writeConfigFileAtomically(configPath, data); err != nil {
		return fmt.Errorf("write captcha configuration: %w", err)
	}
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("reload captcha configuration: %w", err)
	}

	configMu.Lock()
	GlobalConfig = &newCfg
	configMu.Unlock()
	return nil
}

// UpdateInfrastructureConfig persists the complete ingress trust contract in
// one validated write. Callers must not split this object into independent
// flattened updates because mode and trusted-proxy enablement are coupled.
func UpdateInfrastructureConfig(next InfrastructureConfig) error {
	if infrastructureControlPlaneIsManaged() {
		return fmt.Errorf("%w: infrastructure proxy settings are managed by PostgreSQL", ErrConfigValidation)
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	return updateConfigLocked("infrastructure", next)
}

// UpdateStorageControlConfig persists the complete PostgreSQL control-plane
// configuration as a pending startup change. Credentials remain an opaque
// environment reference; this function never accepts a password value.
func UpdateStorageControlConfig(next storage.ControlConfig) error {
	if err := validateStorageControlConfig(next); err != nil {
		return fmt.Errorf("invalid PostgreSQL control configuration: %w", err)
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	return updateConfigLocked("storage.control", map[string]interface{}{
		"enabled":             next.Enabled,
		"driver":              string(next.Driver),
		"host":                next.Host,
		"port":                next.Port,
		"database":            next.Database,
		"username":            next.Username,
		"password_secret_ref": next.PasswordSecretRef,
		"ssl_mode":            next.SSLMode,
	})
}

// UpdateStorageAnalyticsConfig persists a complete ClickHouse analytics
// revision. It accepts only a secret reference, never a password, and leaves
// the active analytics client unchanged until the next process start.
func UpdateStorageAnalyticsConfig(next storage.AnalyticsConfig) error {
	next.Mode = next.EffectiveMode()
	if err := next.Validate(); err != nil {
		return fmt.Errorf("invalid ClickHouse analytics configuration: %w", err)
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	return updateConfigLocked("storage.analytics", map[string]interface{}{
		"mode":                string(next.Mode),
		"driver":              string(next.Driver),
		"host":                next.Host,
		"port":                next.Port,
		"database":            next.Database,
		"username":            next.Username,
		"password_secret_ref": next.PasswordSecretRef,
		"secure":              next.Secure,
		"max_open_conns":      next.MaxOpenConns,
		"max_idle_conns":      next.MaxIdleConns,
		"conn_max_lifetime":   next.ConnMaxLifetime,
	})
}

// ControlDatabaseConfigurationEnvironmentLocked reports whether deployment
// environment variables own any non-secret PostgreSQL control setting. Such
// settings cannot truthfully be changed from the Settings page.
func ControlDatabaseConfigurationEnvironmentLocked() bool {
	for _, key := range []string{
		"AEGIS_CONTROL_DB_ENABLED",
		"AEGIS_CONTROL_DB_HOST",
		"AEGIS_CONTROL_DB_PORT",
		"AEGIS_CONTROL_DB_NAME",
		"AEGIS_CONTROL_DB_USER",
		"AEGIS_CONTROL_DB_SSL_MODE",
	} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

// AnalyticsDatabaseConfigurationEnvironmentLocked reports whether deployment
// environment variables own any ClickHouse analytics setting. Operators must
// then update the deployment rather than save a misleading pending revision.
func AnalyticsDatabaseConfigurationEnvironmentLocked() bool {
	for _, key := range []string{
		"AEGIS_ANALYTICS_MODE",
		"AEGIS_ANALYTICS_HOST",
		"AEGIS_ANALYTICS_PORT",
		"AEGIS_ANALYTICS_DATABASE",
		"AEGIS_ANALYTICS_USERNAME",
		"AEGIS_ANALYTICS_PASSWORD_SECRET_REF",
		"AEGIS_ANALYTICS_SECURE",
		"AEGIS_ANALYTICS_DRIVER",
	} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

func updateConfigLocked(key string, value interface{}) error {
	return updateConfigBatchLocked(map[string]interface{}{key: value})
}

func updateConfigBatchLocked(updates map[string]interface{}) error {
	previous := make(map[string]interface{}, len(updates))
	for key := range updates {
		previous[key] = viper.Get(key)
	}
	for key, value := range updates {
		viper.Set(key, value)
	}
	var previousLegacyCertFile, previousLegacyKeyFile interface{}
	_, updatesTLS := updates["server.tls"]
	if updatesTLS {
		previousLegacyCertFile = viper.Get("server.tls.certfile")
		previousLegacyKeyFile = viper.Get("server.tls.keyfile")
		viper.Set("server.tls.certfile", nil)
		viper.Set("server.tls.keyfile", nil)
	}
	restore := func() {
		for key, value := range previous {
			viper.Set(key, value)
		}
		if updatesTLS {
			viper.Set("server.tls.certfile", previousLegacyCertFile)
			viper.Set("server.tls.keyfile", previousLegacyKeyFile)
		}
	}

	var newCfg Config
	if err := viper.Unmarshal(&newCfg); err != nil {
		restore()
		return err
	}
	if err := resolveStickySecretReference(&newCfg); err != nil {
		restore()
		return err
	}
	// Generic YAML settings mutations must not overwrite a document that has
	// already migrated to the PostgreSQL control plane.
	preserveManagedErrorPages(&newCfg)
	preserveManagedSecurityTXT(&newCfg)
	preserveManagedCaptcha(&newCfg)
	preserveManagedInfrastructure(&newCfg)
	preserveManagedUpstreamRuntimeSettings(&newCfg)
	preserveManagedUpstreamGroups(&newCfg)
	preserveManagedRouteRules(&newCfg)
	preserveManagedCircuitBreaker(&newCfg)
	preserveManagedLegacyRoutes(&newCfg)
	preserveManagedStickySecret(&newCfg)

	if err := newCfg.Validate(); err != nil {
		restore()
		return fmt.Errorf("%w: %v", ErrConfigValidation, err)
	}
	var writeErr error
	if updatesTLS {
		writeErr = writeCanonicalTLSConfig(newCfg.Server.TLS)
	} else {
		writeErr = writeCurrentConfigAtomically()
	}
	if writeErr != nil {
		restore()
		return writeErr
	}

	configMu.Lock()
	GlobalConfig = &newCfg
	configMu.Unlock()

	return nil
}

// MutateRouteRules serializes route read-modify-write operations across every
// control-plane caller. The mutator receives a deep copy and the normalized,
// validated result is persisted atomically before becoming globally visible.
func MutateRouteRules(mutator func([]RouteConfig) ([]RouteConfig, error)) ([]RouteConfig, error) {
	if mutator == nil {
		return nil, errors.New("route mutator is required")
	}
	if controlPlaneMutator := routeRulesMutator(); controlPlaneMutator != nil {
		return controlPlaneMutator(mutator)
	}
	if routeRulesControlPlaneIsManaged() {
		return nil, fmt.Errorf("%w: route rules are managed by PostgreSQL", ErrRoutePersistence)
	}
	updateMu.Lock()
	defer updateMu.Unlock()

	configMu.RLock()
	if GlobalConfig == nil {
		configMu.RUnlock()
		return nil, errors.New("configuration is not loaded")
	}
	current := CloneRouteConfigs(GlobalConfig.Upstream.Rules)
	groups := CloneUpstreamGroups(GlobalConfig.Upstream.Groups)
	configMu.RUnlock()

	updated, err := mutator(current)
	if err != nil {
		return nil, err
	}
	normalized, err := NormalizeAndValidateRouteRules(updated, groups)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRouteValidation, err)
	}
	if err := updateConfigLocked("upstream.rules", normalized); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRoutePersistence, err)
	}
	return CloneRouteConfigs(normalized), nil
}

// MutateUpstreamGroups serializes Origin group mutations, rejects dangling
// route references, and persists the complete collection atomically.
func MutateUpstreamGroups(mutator func([]UpstreamGroup) ([]UpstreamGroup, error)) ([]UpstreamGroup, error) {
	if mutator == nil {
		return nil, errors.New("upstream group mutator is required")
	}
	if upstreamGroupsControlPlaneIsManaged() {
		return nil, fmt.Errorf("%w: upstream Origin pools are managed by PostgreSQL", ErrUpstreamPersistence)
	}
	updateMu.Lock()
	defer updateMu.Unlock()

	configMu.RLock()
	if GlobalConfig == nil {
		configMu.RUnlock()
		return nil, errors.New("configuration is not loaded")
	}
	current := CloneUpstreamGroups(GlobalConfig.Upstream.Groups)
	routes := CloneRouteConfigs(GlobalConfig.Upstream.Rules)
	legacyRoutes := make(map[string]string, len(GlobalConfig.Upstream.Routes))
	for host, target := range GlobalConfig.Upstream.Routes {
		legacyRoutes[host] = target
	}
	configMu.RUnlock()

	updated, err := mutator(current)
	if err != nil {
		return nil, err
	}
	normalized, err := NormalizeAndValidateUpstreamGroups(updated)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstreamValidation, err)
	}
	if err := ValidateRouteUpstreamReferences(routes, normalized); err != nil {
		return nil, err
	}
	remaining := make(map[string]struct{}, len(normalized))
	for _, group := range normalized {
		remaining[group.Name] = struct{}{}
	}
	removed := make(map[string]struct{})
	for _, group := range current {
		if _, exists := remaining[group.Name]; !exists {
			removed[group.Name] = struct{}{}
		}
	}
	for host, target := range legacyRoutes {
		if _, wasRemoved := removed[strings.TrimSpace(target)]; wasRemoved {
			return nil, fmt.Errorf("%w: legacy host route %q references upstream group %q", ErrUpstreamDependency, host, target)
		}
	}
	if err := updateConfigLocked("upstream.groups", normalized); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstreamPersistence, err)
	}
	return CloneUpstreamGroups(normalized), nil
}

// UpstreamRuntimeSettings is the non-secret, runtime-backed subset exposed by
// the admin Settings page. Origin pools, routes, and the sticky signing secret
// are intentionally managed by their dedicated APIs.
type UpstreamRuntimeSettings struct {
	Target                 string `json:"target"`
	InsecureSkipVerify     bool   `json:"insecure_skip_verify"`
	MaxIdleConns           int    `json:"max_idle_conns"`
	MaxIdleConnsPerHost    int    `json:"max_idle_conns_per_host"`
	MaxConnsPerHost        int    `json:"max_conns_per_host"`
	IdleTimeout            string `json:"idle_timeout"`
	TLSHandshakeTimeout    string `json:"tls_timeout"`
	HealthCheckConcurrency int    `json:"health_check_concurrency"`
}

func CurrentUpstreamRuntimeSettings() UpstreamRuntimeSettings {
	configMu.RLock()
	defer configMu.RUnlock()
	if GlobalConfig == nil {
		return UpstreamRuntimeSettings{}
	}
	return upstreamRuntimeSettingsFromConfig(GlobalConfig.Upstream)
}

// UpdateUpstreamRuntimeSettings persists the whole runtime-tuning snapshot in
// one validation and one atomic file replacement.
func UpdateUpstreamRuntimeSettings(settings UpstreamRuntimeSettings) (UpstreamRuntimeSettings, error) {
	if upstreamRuntimeControlPlaneIsManaged() {
		return UpstreamRuntimeSettings{}, fmt.Errorf("%w: upstream runtime settings are managed by PostgreSQL", ErrConfigValidation)
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	configMu.RLock()
	if GlobalConfig == nil {
		configMu.RUnlock()
		return UpstreamRuntimeSettings{}, errors.New("configuration is not loaded")
	}
	upstream := GlobalConfig.Upstream
	configMu.RUnlock()

	upstream.Target = strings.TrimSpace(settings.Target)
	upstream.InsecureSkipVerify = settings.InsecureSkipVerify
	upstream.MaxIdleConns = settings.MaxIdleConns
	upstream.MaxIdlePerHost = settings.MaxIdleConnsPerHost
	upstream.MaxConnsPerHost = settings.MaxConnsPerHost
	upstream.IdleTimeout = strings.TrimSpace(settings.IdleTimeout)
	upstream.TLSHandshake = strings.TrimSpace(settings.TLSHandshakeTimeout)
	upstream.HealthConcurrency = settings.HealthCheckConcurrency
	if err := updateConfigLocked("upstream", upstream); err != nil {
		return UpstreamRuntimeSettings{}, err
	}
	return CurrentUpstreamRuntimeSettings(), nil
}

func upstreamRuntimeSettingsFromConfig(upstream UpstreamConfig) UpstreamRuntimeSettings {
	return UpstreamRuntimeSettings{
		Target:                 upstream.Target,
		InsecureSkipVerify:     upstream.InsecureSkipVerify,
		MaxIdleConns:           upstream.MaxIdleConns,
		MaxIdleConnsPerHost:    upstream.MaxIdlePerHost,
		MaxConnsPerHost:        upstream.MaxConnsPerHost,
		IdleTimeout:            upstream.IdleTimeout,
		TLSHandshakeTimeout:    upstream.TLSHandshake,
		HealthCheckConcurrency: upstream.HealthConcurrency,
	}
}

func stripManagedControlPlaneFromSettings(settings map[string]interface{}) {
	if settings == nil {
		return
	}
	stripManagedStickySecretFromSettings(settings)
	delete(settings, "sections")
	delete(settings, "infrastructure")
	delete(settings, "modules")
	delete(settings, "upstream")
	delete(settings, "threat")
	delete(settings, "access")
	delete(settings, "security_txt")
}

func writeCurrentConfigAtomically() error {
	settings := viper.AllSettings()
	stripManagedControlPlaneFromSettings(settings)
	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal configuration: %w", err)
	}
	configPath := viper.ConfigFileUsed()
	if strings.TrimSpace(configPath) == "" {
		return errors.New("configuration file path is not available")
	}
	if err := writeConfigFileAtomically(configPath, data); err != nil {
		return fmt.Errorf("write configuration atomically: %w", err)
	}
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("reload configuration: %w", err)
	}
	return nil
}

func writeCanonicalTLSConfig(tlsCfg TLSConfig) error {
	settings := viper.AllSettings()
	server, ok := settings["server"].(map[string]interface{})
	if !ok {
		return errors.New("server configuration is not a map")
	}
	server["tls"] = structToMap(tlsCfg)
	settings["server"] = server
	stripManagedControlPlaneFromSettings(settings)

	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal canonical TLS configuration: %w", err)
	}
	configPath := viper.ConfigFileUsed()
	if strings.TrimSpace(configPath) == "" {
		return errors.New("configuration file path is not available")
	}
	if err := writeConfigFileAtomically(configPath, data); err != nil {
		return fmt.Errorf("write canonical TLS configuration: %w", err)
	}
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("reload canonical TLS configuration: %w", err)
	}
	return nil
}

func writeConfigFileAtomically(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".aegis-config-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return replaceFileAtomic(tempPath, path)
}

// ReplaceConfigFileAtomically persists a previously validated configuration
// document without changing GlobalConfig. It is used for restart-pending
// imports and resets, where the running process must remain internally
// consistent until the operator restarts it.
func ReplaceConfigFileAtomically(path string, data []byte) error {
	return writeConfigFileAtomically(path, data)
}

// UpdateSectionConfig writes one complete section document with its base
// enabled and protection fields. Callers validate the section-specific values
// before invoking this function.
func UpdateSectionConfig(sectionID string, sectionConfig sections.SectionConfig) error {
	sectionID = strings.TrimSpace(sectionID)
	if sectionID == "" || strings.ContainsAny(sectionID, ".\r\n\x00") {
		return errors.New("invalid section id")
	}
	settings := make(map[string]interface{}, len(sectionConfig.Settings)+2)
	for key, value := range sectionConfig.Settings {
		settings[key] = value
	}
	settings["enabled"] = sectionConfig.Enabled
	settings["protection_level"] = sectionConfig.ProtectionLevel

	// A section document is a replacement boundary. viper.Set on the parent key
	// still recursively merges keys from the file-backed map, so removed nested
	// values can reappear in durable revision documents and invalidate their
	// digest after restart. Build and validate a complete settings tree instead.
	updateMu.Lock()
	defer updateMu.Unlock()

	allSettings := viper.AllSettings()
	sectionSettings, ok := allSettings["sections"].(map[string]interface{})
	if !ok {
		sectionSettings = make(map[string]interface{})
	}
	sectionSettings[sectionID] = settings
	allSettings["sections"] = sectionSettings

	candidateViper := viper.New()
	if err := candidateViper.MergeConfigMap(allSettings); err != nil {
		return fmt.Errorf("merge replacement section configuration: %w", err)
	}
	var newCfg Config
	if err := candidateViper.Unmarshal(&newCfg); err != nil {
		return err
	}
	if err := resolveStickySecretReference(&newCfg); err != nil {
		return err
	}
	preserveManagedErrorPages(&newCfg)
	preserveManagedSecurityTXT(&newCfg)
	preserveManagedCaptcha(&newCfg)
	preserveManagedInfrastructure(&newCfg)
	preserveManagedUpstreamRuntimeSettings(&newCfg)
	preserveManagedUpstreamGroups(&newCfg)
	preserveManagedRouteRules(&newCfg)
	preserveManagedCircuitBreaker(&newCfg)
	preserveManagedLegacyRoutes(&newCfg)
	preserveManagedStickySecret(&newCfg)
	preserveManagedTrafficControl(&newCfg)
	preserveManagedWAF(&newCfg)
	preserveManagedBot(&newCfg)
	preserveManagedHTTPSecurity(&newCfg)
	preserveManagedAPISecurity(&newCfg)
	preserveManagedAccessControl(&newCfg)
	preserveManagedReputation(&newCfg)
	preserveManagedChallenge(&newCfg)
	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	stripManagedControlPlaneFromSettings(allSettings)
	data, err := yaml.Marshal(allSettings)
	if err != nil {
		return fmt.Errorf("marshal replacement section configuration: %w", err)
	}
	configPath := viper.ConfigFileUsed()
	if strings.TrimSpace(configPath) == "" {
		return errors.New("configuration file path is not available")
	}
	if err := writeConfigFileAtomically(configPath, data); err != nil {
		return fmt.Errorf("write replacement section configuration atomically: %w", err)
	}
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("reload replacement section configuration: %w", err)
	}

	configMu.Lock()
	GlobalConfig = &newCfg
	configMu.Unlock()
	return nil
}

// Reload reloads configuration from file
func (c *Config) Reload() error {
	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	return viper.Unmarshal(c)
}

// GetSectionsConfigMap returns section configs in a format usable by SectionManager
func (c *Config) GetSectionsConfigMap() map[string]sections.SectionConfig {
	m := make(map[string]sections.SectionConfig)

	// WAF Core
	wafSettings := structToMap(c.Sections.WAFCore)
	httpSettings := c.Sections.HTTPSecurity
	if httpSettings == nil {
		httpSettings = map[string]interface{}{}
	}
	for _, key := range []string{"upload_protection", "request_body_guard"} {
		if legacy, ok := wafSettings[key]; ok {
			if _, exists := httpSettings[key]; !exists {
				httpSettings[key] = legacy
			}
			delete(wafSettings, key)
		}
	}

	m["waf_core"] = sections.SectionConfig{
		Enabled:         c.Sections.WAFCore.Enabled,
		ProtectionLevel: c.Sections.WAFCore.ProtectionLevel,
		Settings:        wafSettings,
	}

	httpEnabled := true
	if e, ok := httpSettings["enabled"].(bool); ok {
		httpEnabled = e
	}
	httpProtection := 3
	if p, ok := httpSettings["protection_level"].(int); ok {
		httpProtection = p
	} else if p, ok := httpSettings["protection_level"].(float64); ok {
		httpProtection = int(p)
	}
	m["http_security"] = sections.SectionConfig{
		Enabled:         httpEnabled,
		ProtectionLevel: httpProtection,
		Settings:        httpSettings,
	}

	// Traffic Control
	// Manually construct since it's already a map
	tc := canonicalTrafficControlSettings(c.Sections.TrafficControl)
	enabled := true
	protection := 3

	if e, ok := tc["enabled"].(bool); ok {
		enabled = e
	}
	if p, ok := tc["protection_level"].(int); ok {
		protection = p
	} else if p, ok := tc["protection_level"].(float64); ok { // JSON/YAML unmarshal float64 often
		protection = int(p)
	}

	m["traffic_control"] = sections.SectionConfig{
		Enabled:         enabled,
		ProtectionLevel: protection,
		Settings:        tc,
	}

	// Bot Protection
	bc := c.Sections.Bot
	bEnabled := true
	if e, ok := bc["enabled"].(bool); ok {
		bEnabled = e
	}
	m["bot_protection"] = sections.SectionConfig{
		Enabled:  bEnabled,
		Settings: bc,
	}

	// API Security is Enterprise-only at registration time, but its stored
	// configuration must survive Community/Professional operation.
	apiSecurity := c.Sections.APISecurity
	apiEnabled := true
	if e, ok := apiSecurity["enabled"].(bool); ok {
		apiEnabled = e
	}
	m["api_security"] = sections.SectionConfig{
		Enabled:  apiEnabled,
		Settings: apiSecurity,
	}

	// Access Control
	ac := c.Sections.AccessControl
	aEnabled := true
	if e, ok := ac["enabled"].(bool); ok {
		aEnabled = e
	}
	m["access_control"] = sections.SectionConfig{
		Enabled:  aEnabled,
		Settings: ac,
	}

	return m
}

func structToMap(v interface{}) map[string]interface{} {
	data, _ := json.Marshal(v)
	var m map[string]interface{}
	json.Unmarshal(data, &m)
	return m
}

// Validate performs comprehensive validation on configuration values
func (c *Config) Validate() error {
	if _, err := NormalizeSecurityTXTContact(c.SecurityTXT.Contact); err != nil {
		return fmt.Errorf("invalid security_txt.contact: %w", err)
	}
	// Port validation
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server.port: %d (must be 1-65535)", c.Server.Port)
	}
	if c.Server.Admin.Port < 1 || c.Server.Admin.Port > 65535 {
		return fmt.Errorf("invalid server.admin.port: %d (must be 1-65535)", c.Server.Admin.Port)
	}
	if strings.TrimSpace(c.Server.Admin.Host) == "" {
		return fmt.Errorf("server.admin.host is required")
	}
	if strings.ContainsAny(c.Server.Admin.Host, "/\\\x00\r\n\t ") {
		return fmt.Errorf("invalid server.admin.host %q", c.Server.Admin.Host)
	}
	// Relaxed to allow local appliance HTTP admin management over LAN
	// if !IsLoopbackHost(c.Server.Admin.Host) && !c.Server.Admin.SecureCookies {
	// 	return errors.New("server.admin.secure_cookies must be enabled when server.admin.host is not loopback")
	// }
	if c.Server.Admin.AuditRetentionDays < 0 || c.Server.Admin.AuditRetentionDays > 3650 {
		return fmt.Errorf("server.admin.audit_retention_days invalid: %d (must be 0-3650)", c.Server.Admin.AuditRetentionDays)
	}
	if err := c.Modules.ErrorPages.Validate(); err != nil {
		return err
	}
	c.Storage.Analytics.Mode = c.Storage.Analytics.EffectiveMode()
	if err := c.Storage.Analytics.Validate(); err != nil {
		return err
	}
	if err := validateStorageControlConfig(c.Storage.Control); err != nil {
		return err
	}
	if c.AccessLog.Enabled {
		if strings.TrimSpace(c.AccessLog.Path) == "" {
			return fmt.Errorf("access_log.path is required when access logging is enabled")
		}
		if strings.Contains(c.AccessLog.Path, "\x00") {
			return fmt.Errorf("access_log.path contains invalid null byte")
		}
		if c.AccessLog.RotateSizeMB < 1 || c.AccessLog.RotateSizeMB > 10240 {
			return fmt.Errorf("access_log.rotate_size_mb invalid: %d (must be 1-10240)", c.AccessLog.RotateSizeMB)
		}
		if c.AccessLog.KeepFiles < 1 || c.AccessLog.KeepFiles > 365 {
			return fmt.Errorf("access_log.keep_files invalid: %d (must be 1-365)", c.AccessLog.KeepFiles)
		}
	}
	if c.Telemetry.PrometheusPath == "" {
		c.Telemetry.PrometheusPath = "/metrics"
	}
	if err := ValidatePrometheusPath(c.Telemetry.PrometheusPath); err != nil {
		return err
	}
	if c.Telemetry.PrometheusEnabled && !IsLoopbackHost(c.Server.Admin.Host) && strings.TrimSpace(c.Telemetry.PrometheusToken) == "" {
		return errors.New("telemetry.prometheus_token is required when the admin listener is not loopback")
	}
	if c.Telemetry.RetentionDays < 1 || c.Telemetry.RetentionDays > 365 {
		return fmt.Errorf("telemetry.retention_days invalid: %d (must be 1-365)", c.Telemetry.RetentionDays)
	}
	if c.Telemetry.SnapshotInterval < 10 || c.Telemetry.SnapshotInterval > 86400 {
		return fmt.Errorf("telemetry.snapshot_interval invalid: %d (must be 10-86400)", c.Telemetry.SnapshotInterval)
	}

	if err := ValidateInfrastructureConfig(c.Infrastructure); err != nil {
		return err
	}
	if _, err := c.GeoConfig(); err != nil {
		return fmt.Errorf("traffic_control.geo: %w", err)
	}

	// Timeout validation
	if _, err := time.ParseDuration(c.Server.ReadTimeout); err != nil {
		return fmt.Errorf("invalid server.read_timeout: %v", err)
	}
	if _, err := time.ParseDuration(c.Server.WriteTimeout); err != nil {
		return fmt.Errorf("invalid server.write_timeout: %v", err)
	}

	// Size limits validation (prevent DoS)
	const maxBodySize = 100 * 1024 * 1024 // 100MB max
	if c.Sections.WAFCore.Validation.MaxBodySize > maxBodySize {
		return fmt.Errorf("sections.waf_core.validation.max_body_size too large: %d (max %d)",
			c.Sections.WAFCore.Validation.MaxBodySize, maxBodySize)
	}
	if c.Sections.WAFCore.Validation.MaxBodySize < 0 {
		return fmt.Errorf("sections.waf_core.validation.max_body_size cannot be negative")
	}

	// Header count validation
	if c.Sections.WAFCore.Validation.MaxHeaders < 0 || c.Sections.WAFCore.Validation.MaxHeaders > 1000 {
		return fmt.Errorf("sections.waf_core.validation.max_headers invalid: %d (must be 0-1000)",
			c.Sections.WAFCore.Validation.MaxHeaders)
	}

	// URL length validation
	if c.Sections.WAFCore.Validation.MaxURLLength < 0 || c.Sections.WAFCore.Validation.MaxURLLength > 65536 {
		return fmt.Errorf("sections.waf_core.validation.max_url_length invalid: %d (must be 0-65536)",
			c.Sections.WAFCore.Validation.MaxURLLength)
	}

	// TLS configuration validation. Runtime loading performs certificate,
	// hostname, key-strength, and chain checks before activation.
	if c.Server.TLS.Enabled {
		if c.Server.TLS.Auto {
			if len(c.Server.TLS.Domains) == 0 {
				return fmt.Errorf("server.tls.domains requires at least one public hostname when Auto-TLS is enabled")
			}
			for _, domain := range c.Server.TLS.Domains {
				domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
				if domain == "" || strings.ContainsAny(domain, "*/\\:") || net.ParseIP(domain) != nil ||
					domain == "localhost" || strings.HasSuffix(domain, ".localhost") || !strings.Contains(domain, ".") {
					return fmt.Errorf("invalid Auto-TLS domain %q; use a public hostname or upload a manual certificate", domain)
				}
			}
		} else if strings.TrimSpace(c.Server.TLS.CertFile) == "" || strings.TrimSpace(c.Server.TLS.KeyFile) == "" {
			return fmt.Errorf("manual TLS requires server.tls.cert_file and server.tls.key_file")
		}
	}
	for name, value := range map[string]string{
		"server.tls.cert_file": c.Server.TLS.CertFile,
		"server.tls.key_file":  c.Server.TLS.KeyFile,
		"server.tls.cert_dir":  c.Server.TLS.CertDir,
		"server.tls.cache_dir": c.Server.TLS.CacheDir,
	} {
		if strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("%s contains an invalid null byte", name)
		}
	}

	groups, err := NormalizeAndValidateUpstreamGroups(c.Upstream.Groups)
	if err != nil {
		return fmt.Errorf("invalid upstream.groups: %w", err)
	}
	if err := ValidateLegacyRouteUpstreamReferences(c.Upstream.Routes, groups); err != nil {
		return fmt.Errorf("invalid upstream.routes: %w", err)
	}
	if c.Upstream.StickySecretRef != "" && !validStickySecretEnvironmentReference(c.Upstream.StickySecretRef) {
		return fmt.Errorf("upstream.sticky_secret_ref must use env:NAME")
	}
	for _, group := range groups {
		if group.Sticky.Enabled && strings.TrimSpace(c.Upstream.StickySecret) != "" && len(c.Upstream.StickySecret) < 32 {
			return fmt.Errorf("upstream.sticky_session secret must be at least 32 characters when sticky sessions are enabled")
		}
	}
	rules, err := NormalizeAndValidateRouteRules(c.Upstream.Rules, groups)
	if err != nil {
		return fmt.Errorf("invalid upstream.rules: %w", err)
	}
	c.Upstream.Groups = groups
	c.Upstream.Rules = rules
	if c.Upstream.HealthConcurrency <= 0 {
		c.Upstream.HealthConcurrency = 32
	}
	if c.Upstream.HealthConcurrency > 256 {
		return fmt.Errorf("upstream.health_check_concurrency must be between 1 and 256")
	}
	if c.Upstream.MaxIdleConns <= 0 {
		c.Upstream.MaxIdleConns = 1000
	}
	if c.Upstream.MaxIdlePerHost <= 0 {
		c.Upstream.MaxIdlePerHost = 20
	}
	if c.Upstream.MaxConnsPerHost <= 0 {
		c.Upstream.MaxConnsPerHost = 100
	}
	if c.Upstream.MaxIdleConns > 10000 || c.Upstream.MaxIdlePerHost > 2000 || c.Upstream.MaxConnsPerHost > 10000 {
		return fmt.Errorf("upstream connection-pool limits exceed safe maximums")
	}
	if c.Upstream.IdleTimeout == "" {
		c.Upstream.IdleTimeout = "90s"
	}
	if duration, err := time.ParseDuration(c.Upstream.IdleTimeout); err != nil || duration < time.Second || duration > 10*time.Minute {
		return fmt.Errorf("upstream.idle_timeout must be between 1s and 10m")
	}
	if c.Upstream.TLSHandshake == "" {
		c.Upstream.TLSHandshake = "10s"
	}
	if duration, err := time.ParseDuration(c.Upstream.TLSHandshake); err != nil || duration < time.Second || duration > 2*time.Minute {
		return fmt.Errorf("upstream.tls_timeout must be between 1s and 2m")
	}
	if c.Upstream.CircuitBreaker.Threshold <= 0 {
		c.Upstream.CircuitBreaker.Threshold = 5
	}
	if c.Upstream.CircuitBreaker.Threshold > 1000 {
		return fmt.Errorf("upstream.circuit_breaker.threshold must be between 1 and 1000")
	}
	if c.Upstream.CircuitBreaker.Timeout == "" {
		c.Upstream.CircuitBreaker.Timeout = "30s"
	}
	if duration, err := time.ParseDuration(c.Upstream.CircuitBreaker.Timeout); err != nil || duration < time.Second || duration > time.Hour {
		return fmt.Errorf("upstream.circuit_breaker.timeout must be between 1s and 1h")
	}
	if target := strings.TrimSpace(c.Upstream.Target); target != "" {
		if err := validateRouteBackend(UpstreamTarget{URL: target, Weight: 1}); err != nil {
			return fmt.Errorf("invalid upstream.target: %w", err)
		}
		c.Upstream.Target = target
	}

	return nil
}

// IsLoopbackHost reports whether an admin listener remains local to the host.
// Brackets are accepted so callers can safely pass an IPv6 host value.
func IsLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ValidatePrometheusPath keeps the unauthenticated exporter namespace away
// from admin routes and makes the value safe to render in the settings UI.
func ValidatePrometheusPath(raw string) error {
	path := strings.TrimSpace(raw)
	if path == "" || !strings.HasPrefix(path, "/") || path == "/" {
		return errors.New("telemetry.prometheus_path must be a non-root absolute path")
	}
	if path == "/api" || strings.HasPrefix(path, "/api/") {
		return errors.New("telemetry.prometheus_path must not overlap /api routes")
	}
	for _, character := range path {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("/-._~", character) {
			continue
		}
		return errors.New("telemetry.prometheus_path may contain only letters, numbers, '/', '-', '.', '_', and '~'")
	}
	return nil
}

func validateStorageControlConfig(control storage.ControlConfig) error {
	if !control.Enabled {
		return nil
	}
	if control.Driver != storage.ControlDriverPostgreSQL {
		return fmt.Errorf("storage.control.driver must be %q", storage.ControlDriverPostgreSQL)
	}
	if !validStorageControlHost(control.Host) {
		return fmt.Errorf("storage.control.host is invalid")
	}
	if control.Port < 1 || control.Port > 65535 {
		return fmt.Errorf("storage.control.port must be 1-65535")
	}
	if !validStorageControlIdentifier(control.Database) {
		return fmt.Errorf("storage.control.database is invalid")
	}
	if !validStorageControlIdentifier(control.Username) {
		return fmt.Errorf("storage.control.username is invalid")
	}
	if !validStorageControlSecretRef(control.PasswordSecretRef) {
		return fmt.Errorf("storage.control.password_secret_ref must be an environment secret reference")
	}
	switch strings.ToLower(strings.TrimSpace(control.SSLMode)) {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("storage.control.ssl_mode is invalid")
	}
	return nil
}

func validStorageControlHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n\x00/@?#\\") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func validStorageControlIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 63 && !strings.ContainsAny(value, " \t\x00\r\n")
}

func validStorageControlSecretRef(reference string) bool {
	reference = strings.TrimSpace(reference)
	if !strings.HasPrefix(reference, "env:") || len(reference) > 260 {
		return false
	}
	name := strings.TrimPrefix(reference, "env:")
	if name == "" || !(name[0] == '_' || name[0] >= 'A' && name[0] <= 'Z') {
		return false
	}
	for _, char := range name {
		if !(char == '_' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func ValidateRouteCountryPolicy(policy *RouteCountryPolicy) error {
	if policy == nil {
		return nil
	}
	groups := map[string]struct{}{"EU": {}, "EEA": {}, "SCHENGEN": {}, "BENELUX": {}, "DACH": {}, "NORDICS": {}, "USMCA": {}, "FIVE_EYES": {}, "ASEAN": {}, "GCC": {}, "G7": {}, "LATAM": {}, "APAC": {}, "MENA": {}, "AFRICA": {}, "CIS": {}}
	for _, value := range append(append([]string{}, policy.AllowCountries...), policy.BlockCountries...) {
		value = strings.ToUpper(strings.TrimSpace(value))
		if strings.HasPrefix(value, "@") {
			if _, ok := groups[strings.TrimPrefix(value, "@")]; !ok {
				return fmt.Errorf("unknown country group %q", value)
			}
			continue
		}
		if len(value) != 2 || value[0] < 'A' || value[0] > 'Z' || value[1] < 'A' || value[1] > 'Z' {
			return fmt.Errorf("invalid country code %q", value)
		}
	}
	for _, group := range policy.Groups {
		if _, ok := groups[strings.ToUpper(strings.TrimPrefix(strings.TrimSpace(group), "@"))]; !ok {
			return fmt.Errorf("unknown country group %q", group)
		}
	}
	for _, value := range policy.Exceptions {
		if net.ParseIP(value) == nil {
			if _, _, err := net.ParseCIDR(value); err != nil {
				return fmt.Errorf("invalid exception %q", value)
			}
		}
	}
	return nil
}

// GetGlobalConfig returns a thread-safe copy of the global configuration
func GetGlobalConfig() *Config {
	configMu.RLock()
	defer configMu.RUnlock()
	if GlobalConfig == nil {
		return nil
	}
	snapshot := *GlobalConfig
	snapshot.Modules.ErrorPages = cloneErrorPagesConfig(GlobalConfig.Modules.ErrorPages)
	snapshot.Upstream.Rules = CloneRouteConfigs(GlobalConfig.Upstream.Rules)
	snapshot.Upstream.Groups = CloneUpstreamGroups(GlobalConfig.Upstream.Groups)
	if GlobalConfig.Upstream.Routes != nil {
		snapshot.Upstream.Routes = make(map[string]string, len(GlobalConfig.Upstream.Routes))
		for host, target := range GlobalConfig.Upstream.Routes {
			snapshot.Upstream.Routes[host] = target
		}
	}
	return &snapshot
}
