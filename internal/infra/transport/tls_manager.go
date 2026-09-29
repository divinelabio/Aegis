package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
)

const (
	DefaultCertificateDir = "data/tls/certs"
	DefaultACMECacheDir   = "data/tls/acme"
	acmeTLSALPNProtocol   = "acme-tls/1"
)

var ErrTLSRestartRequired = errors.New("TLS restart required")

type tlsRuntimeState struct {
	config       config.TLSConfig
	manualCert   *tls.Certificate
	acmeManager  *autocert.Manager
	allowedHosts map[string]struct{}
}

// AutoCertificateStatus exposes operational ACME state without placing network
// work in the client handshake path.
type AutoCertificateStatus struct {
	Ready        bool      `json:"ready"`
	Provisioning bool      `json:"provisioning"`
	LastAttempt  time.Time `json:"last_attempt,omitempty"`
	LastSuccess  time.Time `json:"last_success,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty"`
}

// TLSManager atomically swaps immutable runtime state. Normal handshakes only
// read an in-memory certificate; ACME issuance and cache reads happen in the
// background.
type TLSManager struct {
	reloadMu sync.Mutex
	state    atomic.Pointer[tlsRuntimeState]
	logger   *zap.Logger

	acmeManager  *autocert.Manager
	acmeCacheDir string
	acmeEmail    string

	readyCertificates sync.Map // map[string]*tls.Certificate
	provisioning      sync.Map // map[string]struct{}
	statusMu          sync.RWMutex
	autoStatus        map[string]AutoCertificateStatus

	certificateLookups atomic.Uint64
	lookupFailures     atomic.Uint64
	coldCacheMisses    atomic.Uint64
	acmeChallenges     atomic.Uint64
	fingerprints       *TLSFingerprintStore
}

// NewTLSManager creates a new TLS manager with the initial config.
func NewTLSManager(cfg config.TLSConfig, logger *zap.Logger, fingerprints ...*TLSFingerprintStore) (*TLSManager, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	m := &TLSManager{
		logger:     logger,
		autoStatus: make(map[string]AutoCertificateStatus),
	}
	if len(fingerprints) > 0 {
		m.fingerprints = fingerprints[0]
	}
	if err := m.Reload(cfg); err != nil {
		return nil, err
	}
	return m, nil
}

// Reload validates and prepares a complete candidate before atomically making
// it visible to handshakes. The old certificate remains active on every error.
func (m *TLSManager) Reload(cfg config.TLSConfig) error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	candidate, err := m.prepareState(cfg)
	if err != nil {
		return err
	}

	m.state.Store(candidate)
	m.removeInactiveAutoCertificates(candidate.allowedHosts)

	switch {
	case !candidate.config.Enabled:
		m.logger.Info("TLS is disabled")
	case candidate.config.Auto:
		m.logger.Info("Auto-TLS configuration activated", zap.Strings("domains", candidate.config.Domains))
		for _, domain := range candidate.config.Domains {
			m.scheduleProvisioning(candidate.acmeManager, domain)
		}
	default:
		m.logger.Info("Manual TLS certificate activated", zap.String("cert", candidate.config.CertFile))
	}
	return nil
}

func (m *TLSManager) scheduleProvisioning(manager *autocert.Manager, domain string) {
	// Startup constructs the TLS manager immediately before opening the public
	// listener. A short delay lets TLS-ALPN-01 reach that listener while still
	// warming cached certificates without waiting for the first client.
	time.AfterFunc(time.Second, func() {
		if m.checkHost(domain) == nil {
			m.startProvisioning(manager, domain)
		}
	})
}

func (m *TLSManager) prepareState(cfg config.TLSConfig) (*tlsRuntimeState, error) {
	cfg.CertDir = tlsDirectory(cfg.CertDir, DefaultCertificateDir)
	cfg.CacheDir = tlsDirectory(cfg.CacheDir, DefaultACMECacheDir)

	state := &tlsRuntimeState{
		config:       cfg,
		allowedHosts: make(map[string]struct{}),
	}
	if !cfg.Enabled {
		return state, nil
	}

	if !cfg.Auto {
		if strings.TrimSpace(cfg.CertFile) == "" || strings.TrimSpace(cfg.KeyFile) == "" {
			return nil, errors.New("manual TLS requires both certificate and private key files")
		}
		certPEM, err := os.ReadFile(cfg.CertFile)
		if err != nil {
			return nil, fmt.Errorf("read certificate: %w", err)
		}
		keyPEM, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read private key: %w", err)
		}
		cert, _, _, err := ValidateCertificatePair(certPEM, keyPEM, "", time.Now())
		if err != nil {
			return nil, fmt.Errorf("validate manual certificate: %w", err)
		}
		state.manualCert = cert
		return state, nil
	}

	domains, err := NormalizeACMEDomains(cfg.Domains)
	if err != nil {
		return nil, err
	}
	cfg.Domains = domains
	state.config = cfg
	for _, domain := range domains {
		state.allowedHosts[domain] = struct{}{}
	}

	if err := os.MkdirAll(cfg.CacheDir, 0700); err != nil {
		return nil, fmt.Errorf("create ACME cache directory: %w", err)
	}

	if m.acmeManager != nil &&
		(m.acmeCacheDir != cfg.CacheDir || m.acmeEmail != strings.TrimSpace(cfg.Email)) {
		return nil, fmt.Errorf("%w: ACME email or cache directory changed", ErrTLSRestartRequired)
	}
	if m.acmeManager == nil {
		m.acmeCacheDir = cfg.CacheDir
		m.acmeEmail = strings.TrimSpace(cfg.Email)
		m.acmeManager = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(cfg.CacheDir),
			Email:  m.acmeEmail,
			HostPolicy: func(_ context.Context, host string) error {
				return m.checkHost(host)
			},
		}
	}
	state.acmeManager = m.acmeManager
	return state, nil
}

func tlsDirectory(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return filepath.Clean(fallback)
	}
	return filepath.Clean(value)
}

// NormalizeACMEDomains validates the host allow-list used by autocert.
// Wildcards, IP literals, localhost, and single-label/internal names require a
// manually supplied certificate because this installation only supports
// TLS-ALPN-01.
func NormalizeACMEDomains(domains []string) ([]string, error) {
	if len(domains) == 0 {
		return nil, errors.New("Auto-TLS requires at least one public domain")
	}

	normalized := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, value := range domains {
		host, err := normalizeACMEDomain(value)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		normalized = append(normalized, host)
	}
	return normalized, nil
}

func normalizeACMEDomain(value string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if host == "" {
		return "", errors.New("Auto-TLS domain cannot be empty")
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/\\:*") {
		return "", fmt.Errorf("Auto-TLS domain %q must be a hostname without scheme, port, path, or wildcard", value)
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("invalid Auto-TLS domain %q: %w", value, err)
	}
	if ascii == "localhost" || strings.HasSuffix(ascii, ".localhost") || !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("Auto-TLS domain %q is not a public hostname; upload a manual certificate instead", value)
	}
	if net.ParseIP(ascii) != nil {
		return "", fmt.Errorf("Auto-TLS domain %q is an IP address; upload a manual certificate instead", value)
	}
	if len(ascii) > 253 {
		return "", fmt.Errorf("Auto-TLS domain %q is too long", value)
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid Auto-TLS domain %q", value)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("invalid Auto-TLS domain %q", value)
			}
		}
	}
	return ascii, nil
}

func (m *TLSManager) checkHost(host string) error {
	state := m.state.Load()
	if state == nil || !state.config.Enabled || !state.config.Auto {
		return errors.New("Auto-TLS is disabled")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if _, allowed := state.allowedHosts[host]; !allowed {
		return fmt.Errorf("host %q is not allowed", host)
	}
	return nil
}

// GetCertificate never starts certificate issuance for an ordinary client
// handshake. A cold domain fails quickly while a single background provisioner
// obtains or loads its certificate. ACME validation handshakes are delegated to
// autocert so TLS-ALPN-01 can complete.
func (m *TLSManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.fingerprints != nil {
		m.fingerprints.CaptureClientHello(hello)
	}
	m.certificateLookups.Add(1)
	state := m.state.Load()
	if state == nil || !state.config.Enabled {
		m.lookupFailures.Add(1)
		return nil, errors.New("TLS is disabled")
	}
	if !state.config.Auto {
		if state.manualCert == nil {
			m.lookupFailures.Add(1)
			return nil, errors.New("no manual certificate is loaded")
		}
		return state.manualCert, nil
	}

	host := strings.TrimSuffix(strings.ToLower(hello.ServerName), ".")
	if _, allowed := state.allowedHosts[host]; !allowed {
		m.lookupFailures.Add(1)
		return nil, fmt.Errorf("host %q is not allowed", host)
	}
	if supportsACMETLSALPN(hello) {
		m.acmeChallenges.Add(1)
		cert, err := state.acmeManager.GetCertificate(hello)
		if err != nil {
			m.lookupFailures.Add(1)
		}
		return cert, err
	}
	if value, ok := m.readyCertificates.Load(host); ok {
		cert := value.(*tls.Certificate)
		if certificateNeedsRefresh(cert, time.Now()) {
			m.startProvisioning(state.acmeManager, host)
		}
		return cert, nil
	}

	m.startProvisioning(state.acmeManager, host)
	m.coldCacheMisses.Add(1)
	m.lookupFailures.Add(1)
	return nil, fmt.Errorf("certificate for %q is provisioning; retry shortly", host)
}

func supportsACMETLSALPN(hello *tls.ClientHelloInfo) bool {
	for _, proto := range hello.SupportedProtos {
		if proto == acmeTLSALPNProtocol {
			return true
		}
	}
	return false
}

func certificateNeedsRefresh(cert *tls.Certificate, now time.Time) bool {
	if cert == nil || cert.Leaf == nil {
		return true
	}
	return now.Add(30 * 24 * time.Hour).After(cert.Leaf.NotAfter)
}

func (m *TLSManager) startProvisioning(manager *autocert.Manager, domain string) {
	if manager == nil || domain == "" {
		return
	}
	if _, loaded := m.provisioning.LoadOrStore(domain, struct{}{}); loaded {
		return
	}
	m.updateAutoStatus(domain, func(status AutoCertificateStatus) AutoCertificateStatus {
		status.Provisioning = true
		status.LastAttempt = time.Now()
		status.LastError = ""
		return status
	})

	go func() {
		defer m.provisioning.Delete(domain)
		cert, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
		if m.discardInactiveAutoDomain(domain) {
			return
		}
		if err != nil {
			m.updateAutoStatus(domain, func(status AutoCertificateStatus) AutoCertificateStatus {
				status.Ready = false
				status.Provisioning = false
				status.LastError = err.Error()
				return status
			})
			m.logger.Warn("Auto-TLS certificate provisioning failed", zap.String("domain", domain), zap.Error(err))
			return
		}
		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			leaf, parseErr := parseLeafDER(cert.Certificate[0])
			if parseErr == nil {
				cert.Leaf = leaf
			}
		}
		m.readyCertificates.Store(domain, cert)
		if m.discardInactiveAutoDomain(domain) {
			return
		}
		m.updateAutoStatus(domain, func(status AutoCertificateStatus) AutoCertificateStatus {
			status.Ready = true
			status.Provisioning = false
			status.LastSuccess = time.Now()
			status.LastError = ""
			if cert.Leaf != nil {
				status.NotAfter = cert.Leaf.NotAfter
			}
			return status
		})
	}()
}

func (m *TLSManager) updateAutoStatus(domain string, update func(AutoCertificateStatus) AutoCertificateStatus) {
	m.statusMu.Lock()
	m.autoStatus[domain] = update(m.autoStatus[domain])
	m.statusMu.Unlock()
}

func (m *TLSManager) removeInactiveAutoCertificates(allowed map[string]struct{}) {
	m.readyCertificates.Range(func(key, _ any) bool {
		domain, _ := key.(string)
		if _, keep := allowed[domain]; !keep {
			m.readyCertificates.Delete(key)
		}
		return true
	})
	m.statusMu.Lock()
	for domain := range m.autoStatus {
		if _, keep := allowed[domain]; !keep {
			delete(m.autoStatus, domain)
		}
	}
	m.statusMu.Unlock()
}

func (m *TLSManager) discardInactiveAutoDomain(domain string) bool {
	if m.checkHost(domain) == nil {
		return false
	}
	m.readyCertificates.Delete(domain)
	m.statusMu.Lock()
	delete(m.autoStatus, domain)
	m.statusMu.Unlock()
	return true
}

// AutoStatus returns a copy suitable for the admin API.
func (m *TLSManager) AutoStatus() map[string]AutoCertificateStatus {
	m.statusMu.RLock()
	defer m.statusMu.RUnlock()
	result := make(map[string]AutoCertificateStatus, len(m.autoStatus))
	for domain, status := range m.autoStatus {
		result[domain] = status
	}
	return result
}

// Metrics returns monotonic, process-local certificate selection counters.
func (m *TLSManager) Metrics() map[string]uint64 {
	return map[string]uint64{
		"certificate_lookups_total": m.certificateLookups.Load(),
		"lookup_failures_total":     m.lookupFailures.Load(),
		"cold_cache_misses_total":   m.coldCacheMisses.Load(),
		"acme_challenges_total":     m.acmeChallenges.Load(),
	}
}

// GetTLSConfig returns a hardened TLS configuration suitable for HTTP/2,
// HTTP/1.1, HTTP/3, and TLS-ALPN-01 validation.
func (m *TLSManager) GetTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acmeTLSALPNProtocol},
	}
}
