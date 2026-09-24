package rules

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/requestctx"
)

type RuleType string

const (
	RuleTypeWAF       RuleType = "waf"
	RuleTypeBot       RuleType = "bot"
	RuleTypeRateLimit RuleType = "rate_limit"
	RuleTypeGeo       RuleType = "geo"
	RuleTypeIPAccess  RuleType = "ip_access"
	RuleTypeCustom    RuleType = "custom"
	RuleTypeAPI       RuleType = "api"
	RuleTypeHTTPSec   RuleType = "http_security"
	RuleTypeAccess    RuleType = "access"
)

type Action string

const (
	ActionAllow     Action = "allow"
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
	ActionLog       Action = "log"
	ActionRateLimit Action = "rate_limit"
	ActionRedirect  Action = "redirect"
)

type SecurityRule struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Enabled       bool              `json:"enabled"`
	Priority      int               `json:"priority"`
	Type          RuleType          `json:"type"`
	Section       string            `json:"section,omitempty"`
	Source        string            `json:"source,omitempty"`
	Phase         string            `json:"phase,omitempty"`
	Mode          string            `json:"mode,omitempty"`
	Expression    string            `json:"expression"`
	Action        Action            `json:"action"`
	ActionParams  map[string]string `json:"action_params,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	ManagedBy     string            `json:"managed_by,omitempty"`
	SyncStatus    string            `json:"sync_status,omitempty"`
	Version       int               `json:"version,omitempty"`
	LastMatchedAt *time.Time        `json:"last_matched_at,omitempty"`
	MatchCount    int64             `json:"match_count,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type RequestContext struct {
	ClientIP     string            `json:"client_ip"`
	Host         string            `json:"host"`
	Path         string            `json:"path"`
	Method       string            `json:"method"`
	UserAgent    string            `json:"user_agent"`
	Country      string            `json:"country"`
	ASN          string            `json:"asn"`
	ASNOrg       string            `json:"asn_org"`
	BotScore     int               `json:"bot_score"`
	BotCategory  string            `json:"bot_category"`
	BotVerified  bool              `json:"bot_verified"`
	BotHeadless  bool              `json:"bot_headless"`
	IPReputation int               `json:"ip_reputation"`
	WAFScore     int               `json:"waf_score"`
	APIPath      string            `json:"api_path"`
	APIAuthValid bool              `json:"api_auth_valid"`
	TLSVersion   string            `json:"tls_version"`
	TLSJA3       string            `json:"tls_ja3"`
	TLSJA4       string            `json:"tls_ja4"`
	AccessRole   string            `json:"access_role"`
	Headers      map[string]string `json:"headers"`
	Cookies      map[string]string `json:"cookies"`
	Query        map[string]string `json:"query"`
}

type Verdict struct {
	Matched      bool              `json:"matched"`
	RuleID       string            `json:"rule_id,omitempty"`
	RuleName     string            `json:"rule_name,omitempty"`
	RuleType     RuleType          `json:"rule_type,omitempty"`
	RuleVersion  int               `json:"rule_version,omitempty"`
	Action       Action            `json:"action"`
	ActionParams map[string]string `json:"action_params,omitempty"`
	Reason       string            `json:"reason,omitempty"`
}

func NewRequestContext(r *http.Request) RequestContext {
	headers := make(map[string]string, len(r.Header))
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[strings.ToLower(key)] = values[0]
		}
	}
	cookies := make(map[string]string)
	for _, cookie := range r.Cookies() {
		cookies[strings.ToLower(cookie.Name)] = cookie.Value
	}
	query := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			query[strings.ToLower(key)] = values[0]
		}
	}

	identity, _ := requestctx.FromRequest(r)
	ip := identity.ClientIP

	tlsEvidence := identity.TLS
	tlsVersion := tlsEvidence.Version
	if tlsVersion == "" {
		tlsVersion = r.Header.Get("X-Aegis-TLS-Version")
	}
	if tlsVersion == "" && r.TLS != nil {
		tlsVersion = tlsVersionString(r.TLS.Version)
	}

	return RequestContext{
		ClientIP:   ip,
		Host:       r.Host,
		Path:       r.URL.Path,
		Method:     r.Method,
		UserAgent:  r.UserAgent(),
		Country:    identity.Geo.Country,
		ASN:        r.Header.Get("X-Aegis-ASN"),
		ASNOrg:     r.Header.Get("X-Aegis-ASN-Org"),
		APIPath:    r.URL.Path,
		TLSVersion: tlsVersion,
		TLSJA3:     firstNonEmpty(tlsEvidence.JA3, r.Header.Get("X-Aegis-TLS-JA3")),
		TLSJA4:     firstNonEmpty(tlsEvidence.JA4, r.Header.Get("X-Aegis-TLS-JA4")),
		Headers:    headers,
		Cookies:    cookies,
		Query:      query,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return ""
	}
}
