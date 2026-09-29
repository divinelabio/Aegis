package geoip

import (
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/divinelab-io/aegis/internal/infra/requestctx"
)

var RegionCountries = map[string][]string{
	"EU":       {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"},
	"EEA":      {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO"},
	"SCHENGEN": {"AT", "BE", "BG", "HR", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IS", "IT", "LV", "LI", "LT", "LU", "MT", "NL", "NO", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "CH"},
	"BENELUX":  {"BE", "NL", "LU"}, "DACH": {"DE", "AT", "CH"}, "NORDICS": {"DK", "FI", "IS", "NO", "SE"},
	"USMCA": {"US", "CA", "MX"}, "FIVE_EYES": {"AU", "CA", "NZ", "GB", "US"},
	"ASEAN": {"BN", "KH", "ID", "LA", "MY", "MM", "PH", "SG", "TH", "VN"}, "GCC": {"BH", "KW", "OM", "QA", "SA", "AE"},
	"G7": {"CA", "FR", "DE", "IT", "JP", "GB", "US"}, "LATAM": {"AR", "BO", "BR", "CL", "CO", "CR", "CU", "DO", "EC", "SV", "GT", "HN", "MX", "NI", "PA", "PY", "PE", "PR", "UY", "VE"},
	"APAC":   {"AU", "BD", "BN", "KH", "CN", "HK", "IN", "ID", "JP", "KP", "KR", "LA", "MY", "MV", "MN", "MM", "NP", "NZ", "PK", "PH", "SG", "LK", "TW", "TH", "TL", "VN"},
	"MENA":   {"DZ", "BH", "EG", "IQ", "IL", "JO", "KW", "LB", "LY", "MA", "OM", "PS", "QA", "SA", "SY", "TN", "AE", "YE"},
	"AFRICA": {"AO", "BJ", "BW", "BF", "BI", "CM", "CV", "CF", "TD", "KM", "CG", "CD", "CI", "DJ", "GQ", "ER", "ET", "GA", "GM", "GH", "GN", "GW", "KE", "LS", "LR", "MG", "MW", "ML", "MR", "MU", "MZ", "NA", "NE", "NG", "RW", "ST", "SN", "SC", "SL", "SO", "ZA", "SS", "SD", "SZ", "TZ", "TG", "UG", "ZM", "ZW"},
	"CIS":    {"RU", "BY", "KZ", "KG", "TJ", "TM", "UZ", "AM", "AZ", "GE", "MD", "UA"},
}

type PolicyConfig struct {
	Enabled                                                                bool
	AllowCountries, BlockCountries, Groups, Exceptions, Countries, Regions []string
	Mode                                                                   string
}
type Policy struct {
	Enabled                                    bool
	AllowCountries, BlockCountries, Exceptions map[string]struct{}
	ExceptionCIDRs                             []*net.IPNet
	Groups                                     []string
}
type PolicyStatus struct {
	Enabled        bool     `json:"enabled"`
	AllowCountries []string `json:"allow_countries"`
	BlockCountries []string `json:"block_countries"`
	Groups         []string `json:"groups"`
	Exceptions     int      `json:"exceptions"`
	FailOpen       bool     `json:"fail_open"`
}
type Blocker struct {
	mu     sync.RWMutex
	policy *Policy
}

func NewBlocker(cfg PolicyConfig) *Blocker { return &Blocker{policy: CompilePolicy(cfg)} }
func CompilePolicy(cfg PolicyConfig) *Policy {
	allow, block := append([]string(nil), cfg.AllowCountries...), append([]string(nil), cfg.BlockCountries...)
	if len(allow) == 0 && len(block) == 0 && len(cfg.Countries) > 0 {
		if strings.EqualFold(cfg.Mode, "allowlist") {
			allow = append(allow, cfg.Countries...)
		} else {
			block = append(block, cfg.Countries...)
		}
	}
	p := &Policy{Enabled: cfg.Enabled, AllowCountries: map[string]struct{}{}, BlockCountries: map[string]struct{}{}, Exceptions: map[string]struct{}{}, Groups: normalizeGroups(append(append([]string{}, cfg.Groups...), cfg.Regions...))}
	addCountries(p.AllowCountries, allow)
	addCountries(p.BlockCountries, block)
	groupsAllowed := len(p.AllowCountries) > 0 || strings.EqualFold(cfg.Mode, "allowlist")
	for _, group := range p.Groups {
		if groupsAllowed {
			addCountries(p.AllowCountries, RegionCountries[group])
		} else {
			addCountries(p.BlockCountries, RegionCountries[group])
		}
	}
	for _, raw := range cfg.Exceptions {
		value := strings.TrimSpace(raw)
		if ip := net.ParseIP(value); ip != nil {
			p.Exceptions[ip.String()] = struct{}{}
		} else if _, network, err := net.ParseCIDR(value); err == nil {
			p.ExceptionCIDRs = append(p.ExceptionCIDRs, network)
		}
	}
	return p
}
func addCountries(target map[string]struct{}, values []string) {
	for _, raw := range values {
		value := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(raw, "@")))
		if codes, ok := RegionCountries[value]; ok && strings.HasPrefix(strings.TrimSpace(raw), "@") {
			addCountries(target, codes)
			continue
		}
		if len(value) == 2 {
			target[value] = struct{}{}
		}
	}
}
func normalizeGroups(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(value, "@")))
		if _, ok := RegionCountries[value]; !ok {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
func (b *Blocker) UpdateConfig(cfg PolicyConfig) {
	b.mu.Lock()
	b.policy = CompilePolicy(cfg)
	b.mu.Unlock()
}
func (b *Blocker) IsBlocked(ip string, result requestctx.GeoResult, override *Policy) (bool, string, string) {
	b.mu.RLock()
	policy := b.policy
	b.mu.RUnlock()
	if override != nil {
		policy = override
	}
	if policy == nil || !policy.Enabled {
		return false, result.Country, ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, result.Country, ""
	}
	if _, ok := policy.Exceptions[parsed.String()]; ok {
		return false, result.Country, ""
	}
	for _, network := range policy.ExceptionCIDRs {
		if network.Contains(parsed) {
			return false, result.Country, ""
		}
	}
	if result.State != requestctx.GeoKnown || result.Country == "" {
		return false, "", "geo_lookup_unavailable"
	}
	country := strings.ToUpper(result.Country)
	if len(policy.AllowCountries) > 0 {
		if _, ok := policy.AllowCountries[country]; !ok {
			return true, country, "country_not_allowed"
		}
		return false, country, ""
	}
	if _, ok := policy.BlockCountries[country]; ok {
		return true, country, "country_blocked"
	}
	return false, country, ""
}
func (b *Blocker) Status() PolicyStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.policy == nil {
		return PolicyStatus{FailOpen: true}
	}
	return PolicyStatus{Enabled: b.policy.Enabled, AllowCountries: mapKeys(b.policy.AllowCountries), BlockCountries: mapKeys(b.policy.BlockCountries), Groups: append([]string(nil), b.policy.Groups...), Exceptions: len(b.policy.Exceptions) + len(b.policy.ExceptionCIDRs), FailOpen: true}
}
func mapKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
