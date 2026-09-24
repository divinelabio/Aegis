package transport

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/requestctx"
)

const (
	defaultTLSFingerprintTTL      = 5 * time.Minute
	defaultTLSFingerprintCapacity = 100000
)

// TLSFingerprintStore keeps ClientHello-derived evidence only for the lifetime
// of a recently active TLS connection. It never accepts client-provided HTTP
// headers as a fingerprint source.
type TLSFingerprintStore struct {
	mu       sync.Mutex
	entries  map[string]tlsFingerprintEntry
	ttl      time.Duration
	capacity int
}

type tlsFingerprintEntry struct {
	fingerprint requestctx.TLSFingerprint
	expiresAt   time.Time
}

func NewTLSFingerprintStore(ttl time.Duration, capacity int) *TLSFingerprintStore {
	if ttl <= 0 {
		ttl = defaultTLSFingerprintTTL
	}
	if capacity <= 0 {
		capacity = defaultTLSFingerprintCapacity
	}
	return &TLSFingerprintStore{
		entries:  make(map[string]tlsFingerprintEntry),
		ttl:      ttl,
		capacity: capacity,
	}
}

// CaptureClientHello records trusted evidence from the TLS stack before an
// HTTP request exists. ClientHelloInfo is supplied by crypto/tls, not HTTP.
func (s *TLSFingerprintStore) CaptureClientHello(hello *tls.ClientHelloInfo) {
	if s == nil || hello == nil || hello.Conn == nil {
		return
	}
	fingerprint, ok := FingerprintClientHello(hello)
	if !ok {
		return
	}
	key := tlsFingerprintKey(hello.Conn.LocalAddr(), hello.Conn.RemoteAddr())
	if key == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	s.pruneLocked(now)
	if len(s.entries) >= s.capacity {
		s.evictOldestLocked()
	}
	s.entries[key] = tlsFingerprintEntry{fingerprint: fingerprint, expiresAt: now.Add(s.ttl)}
	s.mu.Unlock()
}

// LookupRequest returns evidence only when the request is associated with the
// same local and remote socket pair as a captured ClientHello.
func (s *TLSFingerprintStore) LookupRequest(r *http.Request) (requestctx.TLSFingerprint, bool) {
	if s == nil || r == nil {
		return requestctx.TLSFingerprint{}, false
	}
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	remote, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		return requestctx.TLSFingerprint{}, false
	}
	key := tlsFingerprintKey(local, remote)
	if key == "" {
		return requestctx.TLSFingerprint{}, false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok || !now.Before(entry.expiresAt) {
		delete(s.entries, key)
		return requestctx.TLSFingerprint{}, false
	}
	return entry.fingerprint, true
}

// ForgetConn releases evidence when the HTTP server closes the TCP connection,
// preventing a later source-port reuse from inheriting stale fingerprints.
func (s *TLSFingerprintStore) ForgetConn(conn net.Conn) {
	if s == nil || conn == nil {
		return
	}
	key := tlsFingerprintKey(conn.LocalAddr(), conn.RemoteAddr())
	if key == "" {
		return
	}
	s.mu.Lock()
	delete(s.entries, key)
	s.mu.Unlock()
}

func (s *TLSFingerprintStore) pruneLocked(now time.Time) {
	for key, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			delete(s.entries, key)
		}
	}
}

func (s *TLSFingerprintStore) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range s.entries {
		if oldestKey == "" || entry.expiresAt.Before(oldest) {
			oldestKey, oldest = key, entry.expiresAt
		}
	}
	if oldestKey != "" {
		delete(s.entries, oldestKey)
	}
}

func tlsFingerprintKey(local, remote net.Addr) string {
	if local == nil || remote == nil {
		return ""
	}
	return local.Network() + ":" + local.String() + "|" + remote.Network() + ":" + remote.String()
}

// FingerprintClientHello creates standards-compatible JA3 and JA4 values from
// the ClientHello fields exposed by crypto/tls. Both formats omit GREASE.
func FingerprintClientHello(hello *tls.ClientHelloInfo) (requestctx.TLSFingerprint, bool) {
	if hello == nil || len(hello.CipherSuites) == 0 {
		return requestctx.TLSFingerprint{}, false
	}
	version := maxTLSVersion(hello.SupportedVersions)
	if version == 0 {
		version = tls.VersionTLS12
	}
	return requestctx.TLSFingerprint{
		Version: tlsVersionName(version),
		JA3:     ja3Fingerprint(version, hello),
		JA4:     ja4Fingerprint(version, hello),
	}, true
}

func ja3Fingerprint(version uint16, hello *tls.ClientHelloInfo) string {
	legacyVersion := version
	if version >= tls.VersionTLS13 {
		// TLS 1.3 ClientHello always uses TLS 1.2 as its legacy_version.
		legacyVersion = tls.VersionTLS12
	}
	curves := make([]uint16, 0, len(hello.SupportedCurves))
	for _, curve := range hello.SupportedCurves {
		curves = append(curves, uint16(curve))
	}
	points := make([]uint16, 0, len(hello.SupportedPoints))
	for _, point := range hello.SupportedPoints {
		points = append(points, uint16(point))
	}
	raw := strings.Join([]string{
		fmt.Sprintf("%d", legacyVersion),
		decimalTLSValues(hello.CipherSuites),
		decimalTLSValues(hello.Extensions),
		decimalTLSValues(curves),
		decimalTLSValues(points),
	}, ",")
	sum := md5.Sum([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

func ja4Fingerprint(version uint16, hello *tls.ClientHelloInfo) string {
	ciphers := sortedTLSHexValues(hello.CipherSuites, nil)
	extensions := sortedTLSHexValues(hello.Extensions, map[uint16]struct{}{0: {}, 16: {}})
	signatures := orderedTLSHexValues(signatureSchemeValues(hello.SignatureSchemes), nil)
	alpn := ja4ALPN(hello.SupportedProtos)
	sni := "i"
	if strings.TrimSpace(hello.ServerName) != "" {
		sni = "d"
	}
	prefix := fmt.Sprintf("t%s%s%02d%02d%s", ja4Version(version), sni, minFingerprintCount(len(ciphers)), minFingerprintCount(nonGREASECount(hello.Extensions)), alpn)
	return prefix + "_" + fingerprintHash12(strings.Join(ciphers, ",")) + "_" + fingerprintHash12(strings.Join(extensions, ",")+"_"+strings.Join(signatures, ","))
}

func maxTLSVersion(versions []uint16) uint16 {
	var max uint16
	for _, version := range versions {
		if !isGREASETLSValue(version) && version > max {
			max = version
		}
	}
	return max
}

func tlsVersionName(version uint16) string {
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

func ja4Version(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "10"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS13:
		return "13"
	default:
		return "00"
	}
}

func decimalTLSValues(values []uint16) string {
	formatted := make([]string, 0, len(values))
	for _, value := range values {
		if !isGREASETLSValue(value) {
			formatted = append(formatted, fmt.Sprintf("%d", value))
		}
	}
	return strings.Join(formatted, "-")
}

func sortedTLSHexValues(values []uint16, excluded map[uint16]struct{}) []string {
	formatted := orderedTLSHexValues(values, excluded)
	sort.Strings(formatted)
	return formatted
}

func orderedTLSHexValues(values []uint16, excluded map[uint16]struct{}) []string {
	formatted := make([]string, 0, len(values))
	for _, value := range values {
		if isGREASETLSValue(value) {
			continue
		}
		if _, skip := excluded[value]; skip {
			continue
		}
		formatted = append(formatted, fmt.Sprintf("%04x", value))
	}
	return formatted
}

func signatureSchemeValues(values []tls.SignatureScheme) []uint16 {
	result := make([]uint16, 0, len(values))
	for _, value := range values {
		result = append(result, uint16(value))
	}
	return result
}

func nonGREASECount(values []uint16) int {
	count := 0
	for _, value := range values {
		if !isGREASETLSValue(value) {
			count++
		}
	}
	return count
}

func minFingerprintCount(value int) int {
	if value > 99 {
		return 99
	}
	return value
}

func ja4ALPN(protocols []string) string {
	if len(protocols) == 0 || len(protocols[0]) == 0 {
		return "00"
	}
	value := strings.ToLower(protocols[0])
	if len(value) == 1 {
		return value + value
	}
	return value[:1] + value[len(value)-1:]
}

func fingerprintHash12(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum)[:12]
}

func isGREASETLSValue(value uint16) bool {
	upper, lower := byte(value>>8), byte(value)
	return upper == lower && lower&0x0f == 0x0a
}
