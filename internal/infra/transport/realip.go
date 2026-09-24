package transport

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/config"
)

type ClientInfo struct {
	IP                 string   `json:"ip"`
	Source             string   `json:"source"`
	TrustedProxy       bool     `json:"trusted_proxy"`
	ImmediatePeer      string   `json:"immediate_peer"`
	OriginalHost       string   `json:"original_host"`
	OriginalProto      string   `json:"original_proto"`
	ForwardedHost      string   `json:"forwarded_host,omitempty"`
	ForwardedProto     string   `json:"forwarded_proto,omitempty"`
	ForwardedHeader    string   `json:"forwarded_header,omitempty"`
	RejectedHeaderHint string   `json:"rejected_header_hint,omitempty"`
	ProxyChain         []string `json:"proxy_chain,omitempty"`
}

type RealIPResolver struct {
	mu              sync.RWMutex
	cfg             config.TrustedProxyConfig
	trusted         *trustedPrefixSet
	combinedModTime time.Time
	combinedSize    int64
}

const (
	maxForwardedHeaderBytes = 8 << 10
	maxProxyChainHops       = 32
	maxTrustedProxyPrefixes = 100000
)

type trustedPrefixSet struct {
	prefixes  map[netip.Prefix]struct{}
	v4Lengths []int
	v6Lengths []int
}

func NewRealIPResolver(cfg config.TrustedProxyConfig) (*RealIPResolver, error) {
	resolver := &RealIPResolver{}
	if err := resolver.Reload(cfg); err != nil {
		return nil, err
	}
	return resolver, nil
}

// Reload atomically replaces the trusted-proxy contract. Parsing and file I/O
// happen before the lock is taken, so requests continue using the last-good
// immutable prefix set until the new snapshot is ready.
func (r *RealIPResolver) Reload(cfg config.TrustedProxyConfig) error {
	cfg = cloneTrustedProxyConfig(cfg)
	trusted, info, err := buildTrustedPrefixSet(cfg)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cfg = cfg
	r.trusted = trusted
	if info != nil {
		r.combinedModTime = info.ModTime()
		r.combinedSize = info.Size()
	} else {
		r.combinedModTime = time.Time{}
		r.combinedSize = 0
	}
	r.mu.Unlock()
	return nil
}

func (r *RealIPResolver) Start(ctx context.Context) {
	if r == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = r.reloadCombinedListIfChanged()
			}
		}
	}()
}

func (r *RealIPResolver) reloadCombinedListIfChanged() error {
	r.mu.RLock()
	cfg := cloneTrustedProxyConfig(r.cfg)
	previousModTime := r.combinedModTime
	previousSize := r.combinedSize
	r.mu.RUnlock()
	if !cfg.Enabled {
		return nil
	}
	path := strings.TrimSpace(cfg.CombinedList)
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.ModTime().Equal(previousModTime) && info.Size() == previousSize {
		return nil
	}
	return r.Reload(cfg)
}

func buildTrustedPrefixSet(cfg config.TrustedProxyConfig) (*trustedPrefixSet, os.FileInfo, error) {
	set := &trustedPrefixSet{prefixes: make(map[netip.Prefix]struct{})}
	for _, raw := range cfg.CIDRs {
		if err := set.add(raw); err != nil {
			return nil, nil, err
		}
	}
	path := strings.TrimSpace(cfg.CombinedList)
	if !cfg.Enabled || path == "" {
		set.finish()
		return set, nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			set.finish()
			return set, nil, nil
		}
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" || strings.HasPrefix(value, "#") || strings.HasPrefix(value, ";") {
			continue
		}
		if err := set.add(value); err != nil {
			return nil, nil, err
		}
		if len(set.prefixes) > maxTrustedProxyPrefixes {
			return nil, nil, fmt.Errorf("combined trusted proxy list exceeds %d entries", maxTrustedProxyPrefixes)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	set.finish()
	return set, info, nil
}

func (s *trustedPrefixSet) add(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var prefix netip.Prefix
	if address, err := netip.ParseAddr(raw); err == nil {
		address = address.Unmap()
		prefix = netip.PrefixFrom(address, address.BitLen())
	} else {
		parsed, parseErr := netip.ParsePrefix(raw)
		if parseErr != nil {
			return parseErr
		}
		prefix = parsed.Masked()
	}
	s.prefixes[prefix] = struct{}{}
	return nil
}

func (s *trustedPrefixSet) finish() {
	if s == nil {
		return
	}
	v4 := make(map[int]struct{})
	v6 := make(map[int]struct{})
	for prefix := range s.prefixes {
		if prefix.Addr().Is4() {
			v4[prefix.Bits()] = struct{}{}
		} else {
			v6[prefix.Bits()] = struct{}{}
		}
	}
	for bits := range v4 {
		s.v4Lengths = append(s.v4Lengths, bits)
	}
	for bits := range v6 {
		s.v6Lengths = append(s.v6Lengths, bits)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.v4Lengths)))
	sort.Sort(sort.Reverse(sort.IntSlice(s.v6Lengths)))
}

func (s *trustedPrefixSet) contains(raw string) bool {
	if s == nil {
		return false
	}
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	address = address.Unmap()
	lengths := s.v6Lengths
	if address.Is4() {
		lengths = s.v4Lengths
	}
	for _, bits := range lengths {
		if _, ok := s.prefixes[netip.PrefixFrom(address, bits).Masked()]; ok {
			return true
		}
	}
	return false
}

func cloneTrustedProxyConfig(cfg config.TrustedProxyConfig) config.TrustedProxyConfig {
	cfg.CIDRs = append([]string(nil), cfg.CIDRs...)
	cfg.RealIPHeaders = append([]string(nil), cfg.RealIPHeaders...)
	cfg.SourceURLs = append([]string(nil), cfg.SourceURLs...)
	cfg.SourceFiles = append([]string(nil), cfg.SourceFiles...)
	return cfg
}

func (r *RealIPResolver) snapshot() (config.TrustedProxyConfig, *trustedPrefixSet) {
	if r == nil {
		return config.TrustedProxyConfig{}, nil
	}
	r.mu.RLock()
	cfg := r.cfg
	trusted := r.trusted
	r.mu.RUnlock()
	return cfg, trusted
}

func (r *RealIPResolver) Resolve(req *http.Request) ClientInfo {
	peer := hostWithoutPort(req.RemoteAddr)
	if peer == "" {
		peer = req.RemoteAddr
	}

	info := ClientInfo{
		IP:            peer,
		Source:        "remote_addr",
		ImmediatePeer: peer,
		OriginalHost:  req.Host,
		OriginalProto: requestProto(req),
	}

	cfg, trusted := r.snapshot()
	if r == nil || !cfg.Enabled {
		if hasForwardedIdentityHeaders(req) {
			info.RejectedHeaderHint = "trusted proxies disabled"
		}
		return info
	}

	info.TrustedProxy = trusted.contains(peer)
	if !info.TrustedProxy {
		if hasForwardedIdentityHeaders(req) {
			info.RejectedHeaderHint = "immediate peer not trusted"
		}
		return info
	}

	if cfg.ForwardedHeader {
		if forwarded := req.Header.Get("Forwarded"); forwarded != "" {
			if len(forwarded) > maxForwardedHeaderBytes {
				info.RejectedHeaderHint = "Forwarded header exceeds safety limit"
				return info
			}
			info.ForwardedHeader = forwarded
			chain, proto, host := parseForwardedChain(forwarded)
			if len(chain) > maxProxyChainHops {
				info.RejectedHeaderHint = "Forwarded chain exceeds hop limit"
				return info
			}
			if validForwardedProto(proto) {
				info.ForwardedProto = proto
			}
			if validForwardedHost(host) {
				info.ForwardedHost = host
			}
			if selected := selectTrustedClient(chain, peer, cfg.Recursive, trusted); selected != "" {
				info.IP = selected
				info.Source = "Forwarded"
				info.ProxyChain = append(chain, peer)
				return info
			}
		}
	}

	for _, header := range realIPHeaders(cfg) {
		value := req.Header.Get(header)
		if value == "" {
			continue
		}
		if len(value) > maxForwardedHeaderBytes {
			info.RejectedHeaderHint = header + " exceeds safety limit"
			return info
		}
		chain := validHeaderIPs(value)
		if len(chain) > maxProxyChainHops {
			info.RejectedHeaderHint = header + " exceeds hop limit"
			return info
		}
		if len(chain) > 0 {
			info.IP = selectTrustedClient(chain, peer, cfg.Recursive, trusted)
			info.Source = header
			info.ProxyChain = append(chain, peer)
			break
		}
	}

	if protoHeader := strings.TrimSpace(cfg.ProtoHeader); protoHeader != "" {
		if value := req.Header.Get(protoHeader); len(value) <= maxForwardedHeaderBytes {
			if proto := firstHeaderToken(value); validForwardedProto(proto) {
				info.ForwardedProto = strings.ToLower(proto)
			}
		}
	}
	if hostHeader := strings.TrimSpace(cfg.HostHeader); hostHeader != "" {
		if value := req.Header.Get(hostHeader); len(value) <= maxForwardedHeaderBytes {
			if host := firstHeaderToken(value); validForwardedHost(host) {
				info.ForwardedHost = host
			}
		}
	}

	return info
}

func realIPHeaders(cfg config.TrustedProxyConfig) []string {
	if len(cfg.RealIPHeaders) > 0 {
		return cfg.RealIPHeaders
	}
	return []string{"X-Forwarded-For", "X-Real-IP"}
}

func selectTrustedClient(chain []string, peer string, recursive bool, trusted *trustedPrefixSet) string {
	if len(chain) == 0 {
		return ""
	}
	if !recursive {
		return chain[len(chain)-1]
	}
	current := peer
	selected := peer
	for i := len(chain) - 1; i >= 0; i-- {
		if !trusted.contains(current) {
			break
		}
		selected = chain[i]
		current = chain[i]
	}
	return selected
}

func hasForwardedIdentityHeaders(req *http.Request) bool {
	return req.Header.Get("Forwarded") != "" ||
		req.Header.Get("X-Forwarded-For") != "" ||
		req.Header.Get("X-Real-IP") != "" ||
		req.Header.Get("CF-Connecting-IP") != ""
}

func hostWithoutPort(value string) string {
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return host
	}
	return strings.Trim(value, "[]")
}

func requestProto(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

func firstHeaderToken(value string) string {
	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func validForwardedProto(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "http" || value == "https"
}

func validForwardedHost(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 255 || strings.ContainsAny(value, "\r\n\t /\\@?#") {
		return false
	}
	host := hostWithoutPort(value)
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validHeaderIPs(value string) []string {
	result := make([]string, 0)
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "\"")
		part = hostWithoutPort(part)
		if net.ParseIP(part) != nil {
			result = append(result, part)
		}
	}
	return result
}

func parseForwardedChain(value string) (chain []string, proto string, host string) {
	for elementIndex, element := range strings.Split(value, ",") {
		for _, rawPart := range strings.Split(element, ";") {
			key, val, ok := strings.Cut(strings.TrimSpace(rawPart), "=")
			if !ok {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			val = strings.Trim(strings.TrimSpace(val), "\"")
			switch key {
			case "for":
				candidate := hostWithoutPort(val)
				if net.ParseIP(candidate) != nil {
					chain = append(chain, candidate)
				}
			case "proto":
				if elementIndex == 0 {
					proto = val
				}
			case "host":
				if elementIndex == 0 {
					host = val
				}
			}
		}
	}
	return chain, proto, host
}
