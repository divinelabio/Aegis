package handlers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/transport"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	maxCertificateUploadRequest = 2 << 20 // 2 MiB including multipart overhead
	maxCertificateFileSize      = 1 << 20 // 1 MiB per PEM file
)

func (h *Handler) listTLSCertificates(w http.ResponseWriter) {
	h.tlsInventoryMu.Lock()
	defer h.tlsInventoryMu.Unlock()
	if time.Since(h.tlsInventoryAt) < 5*time.Second && h.tlsInventory != nil {
		_ = json.NewEncoder(w).Encode(h.tlsInventory)
		return
	}

	cfg := config.GetGlobalConfig()
	if cfg == nil {
		h.JSONError(w, "Configuration is not available", http.StatusServiceUnavailable)
		return
	}
	tlsCfg := cfg.Server.TLS
	certDir := effectiveTLSDirectory(tlsCfg.CertDir, transport.DefaultCertificateDir)
	cacheDir := effectiveTLSDirectory(tlsCfg.CacheDir, transport.DefaultACMECacheDir)
	activeID := certificateIDFromPath(tlsCfg.CertFile)

	certificates := append(
		listTLSCertificateFiles(certDir, "manual", false, activeID),
		listTLSCertificateFiles(cacheDir, "acme_cache", true, "")...,
	)
	sort.Slice(certificates, func(i, j int) bool {
		if certificates[i]["domain"] == certificates[j]["domain"] {
			return fmt.Sprint(certificates[i]["id"]) < fmt.Sprint(certificates[j]["id"])
		}
		return fmt.Sprint(certificates[i]["domain"]) < fmt.Sprint(certificates[j]["domain"])
	})
	h.tlsInventory = certificates
	h.tlsInventoryAt = time.Now()
	_ = json.NewEncoder(w).Encode(certificates)
}

func (h *Handler) uploadAndActivateTLSCertificate(w http.ResponseWriter, r *http.Request) {
	h.tlsMutationMu.Lock()
	defer h.tlsMutationMu.Unlock()

	r.Body = http.MaxBytesReader(w, r.Body, maxCertificateUploadRequest)
	if err := r.ParseMultipartForm(512 << 10); err != nil {
		h.JSONError(w, "Certificate upload exceeds 2 MiB or is not valid multipart data", http.StatusRequestEntityTooLarge)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	requestedHostname, err := normalizeManualCertificateHostname(r.FormValue("domain"))
	if err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	certPEM, err := readMultipartFile(r, "certificate", maxCertificateFileSize)
	if err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	keyPEM, err := readMultipartFile(r, "key", maxCertificateFileSize)
	if err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, leaf, warnings, err := transport.ValidateCertificatePair(certPEM, keyPEM, requestedHostname, time.Now())
	if err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	displayDomain := requestedHostname
	if displayDomain == "" {
		displayDomain = certificateDomain(leaf, "server")
	}
	id := sanitizeCertificateID(displayDomain)
	if id == "" {
		id = "server"
	}

	cfg := config.GetGlobalConfig()
	if cfg == nil {
		h.JSONError(w, "Configuration is not available", http.StatusServiceUnavailable)
		return
	}
	oldTLS := cfg.Server.TLS
	certDir := effectiveTLSDirectory(oldTLS.CertDir, transport.DefaultCertificateDir)
	fingerprint := transport.CertificateFingerprintSHA256(leaf)
	certPath, keyPath, err := writeVersionedCertificatePair(certDir, id, fingerprint, certPEM, keyPEM)
	if err != nil {
		h.Logger.Error("Failed to store certificate pair", zap.Error(err))
		h.JSONError(w, "Failed to store certificate pair", http.StatusInternalServerError)
		return
	}

	newTLS := oldTLS
	newTLS.Enabled = true
	newTLS.Auto = false
	newTLS.CertDir = certDir
	newTLS.CertFile = certPath
	newTLS.KeyFile = keyPath

	restartRequired, err := h.applyAndPersistTLSConfig(oldTLS, newTLS)
	if err != nil {
		_ = os.Remove(certPath)
		_ = os.Remove(keyPath)
		h.Logger.Error("Failed to activate certificate", zap.Error(err))
		h.JSONError(w, "Certificate was not activated: "+err.Error(), http.StatusInternalServerError)
		return
	}

	status := "activated"
	if restartRequired {
		status = "staged"
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":           status,
		"id":               certificateIDFromPath(certPath),
		"domain":           displayDomain,
		"fingerprint":      fingerprint,
		"not_after":        leaf.NotAfter.Format(time.RFC3339),
		"warnings":         warnings,
		"restart_required": restartRequired,
	})
}

func (h *Handler) deleteTLSCertificate(w http.ResponseWriter, r *http.Request) {
	h.tlsMutationMu.Lock()
	defer h.tlsMutationMu.Unlock()

	var request struct {
		ID string `json:"id"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		h.JSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	id := sanitizeCertificateID(request.ID)
	if id == "" || id != request.ID {
		h.JSONError(w, "Invalid certificate ID", http.StatusBadRequest)
		return
	}

	cfg := config.GetGlobalConfig()
	if cfg == nil {
		h.JSONError(w, "Configuration is not available", http.StatusServiceUnavailable)
		return
	}
	tlsCfg := cfg.Server.TLS
	if certificateIDFromPath(tlsCfg.CertFile) == id {
		h.JSONError(w, "The active certificate cannot be deleted; activate a replacement first", http.StatusConflict)
		return
	}

	certDir := effectiveTLSDirectory(tlsCfg.CertDir, transport.DefaultCertificateDir)
	certPath := findManualCertificatePath(certDir, id)
	keyPath := filepath.Join(certDir, id+".key")
	if certPath == "" || !regularFileExists(keyPath) {
		h.JSONError(w, "Certificate pair was not found", http.StatusNotFound)
		return
	}

	recoveryRetained, err := moveCertificatePairToTrash(certDir, id, certPath, keyPath)
	if err != nil {
		h.Logger.Error("Failed to delete certificate pair", zap.Error(err))
		h.JSONError(w, "Failed to delete certificate pair", http.StatusInternalServerError)
		return
	}
	h.invalidateTLSInventory()
	response := map[string]interface{}{"status": "deleted", "id": id}
	if recoveryRetained {
		response["warnings"] = []string{"The certificate was removed from inventory but protected recovery files remain in the TLS .trash directory."}
	}
	_ = json.NewEncoder(w).Encode(response)
}

func (h *Handler) applyAndPersistTLSConfig(oldTLS, newTLS config.TLSConfig) (bool, error) {
	restartRequired := oldTLS.Enabled != newTLS.Enabled || h.TLSManager == nil
	runtimeApplied := false

	if !restartRequired {
		if err := h.TLSManager.Reload(newTLS); err != nil {
			if errors.Is(err, transport.ErrTLSRestartRequired) {
				restartRequired = true
			} else {
				return false, err
			}
		} else {
			runtimeApplied = true
		}
	}

	if err := config.UpdateConfig("server.tls", tlsConfigPersistenceValue(newTLS)); err != nil {
		if runtimeApplied {
			if rollbackErr := h.TLSManager.Reload(oldTLS); rollbackErr != nil {
				h.Logger.Error("Failed to roll back TLS runtime after persistence error", zap.Error(rollbackErr))
			}
		}
		return false, fmt.Errorf("persist TLS configuration: %w", err)
	}
	h.Config.TLS = newTLS
	h.tlsRestartRequired.Store(restartRequired)
	h.invalidateTLSInventory()
	return restartRequired, nil
}

func (h *Handler) invalidateTLSInventory() {
	h.tlsInventoryMu.Lock()
	h.tlsInventory = nil
	h.tlsInventoryAt = time.Time{}
	h.tlsInventoryMu.Unlock()
}

func tlsConfigPersistenceValue(cfg config.TLSConfig) map[string]interface{} {
	return map[string]interface{}{
		"enabled":   cfg.Enabled,
		"cert_file": cfg.CertFile,
		"key_file":  cfg.KeyFile,
		"cert_dir":  effectiveTLSDirectory(cfg.CertDir, transport.DefaultCertificateDir),
		"cache_dir": effectiveTLSDirectory(cfg.CacheDir, transport.DefaultACMECacheDir),
		"auto":      cfg.Auto,
		"domains":   cfg.Domains,
		"email":     strings.TrimSpace(cfg.Email),
	}
}

func readMultipartFile(r *http.Request, field string, limit int64) ([]byte, error) {
	file, _, err := r.FormFile(field)
	if err != nil {
		return nil, fmt.Errorf("%s file is required", field)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", field, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s file is empty", field)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s file exceeds 1 MiB", field)
	}
	return data, nil
}

func normalizeManualCertificateHostname(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" {
		return "", nil
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, "/\\:*") {
		return "", errors.New("domain must be a hostname or IP address without scheme, port, path, or wildcard")
	}
	if net.ParseIP(value) != nil {
		return value, nil
	}
	if len(value) > 253 {
		return "", errors.New("domain is too long")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("domain is not a valid hostname")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", errors.New("domain is not a valid hostname")
			}
		}
	}
	return value, nil
}

func writeVersionedCertificatePair(dir, id, fingerprint string, certPEM, keyPEM []byte) (string, string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", err
	}
	if err := restrictTLSPath(dir, true); err != nil {
		return "", "", err
	}
	suffix := strings.ToLower(fingerprint)
	if len(suffix) > 12 {
		suffix = suffix[:12]
	}
	base := id + "-" + suffix + "-" + uuid.NewString()[:8]
	certPath := filepath.Join(dir, base+".crt")
	keyPath := filepath.Join(dir, base+".key")

	if err := writeFileAtomically(certPath, certPEM); err != nil {
		return "", "", err
	}
	if err := writeFileAtomically(keyPath, keyPEM); err != nil {
		_ = os.Remove(certPath)
		return "", "", err
	}
	return certPath, keyPath, nil
}

func writeFileAtomically(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".aegis-tls-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}
	defer cleanup()

	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := restrictTLSPath(tempPath, false); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func moveCertificatePairToTrash(dir, id, certPath, keyPath string) (bool, error) {
	trashDir := filepath.Join(dir, ".trash")
	if err := os.MkdirAll(trashDir, 0700); err != nil {
		return false, err
	}
	if err := restrictTLSPath(trashDir, true); err != nil {
		return false, err
	}
	token := uuid.NewString()
	trashCert := filepath.Join(trashDir, id+"-"+token+".crt")
	trashKey := filepath.Join(trashDir, id+"-"+token+".key")
	if err := os.Rename(certPath, trashCert); err != nil {
		return false, err
	}
	if err := os.Rename(keyPath, trashKey); err != nil {
		_ = os.Rename(trashCert, certPath)
		return false, err
	}
	certCleanupErr := os.Remove(trashCert)
	keyCleanupErr := os.Remove(trashKey)
	return certCleanupErr != nil || keyCleanupErr != nil, nil
}

func listTLSCertificateFiles(dir, source string, managed bool, activeID string) []map[string]interface{} {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []map[string]interface{}{}
	}
	certificates := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isCertificateInventoryFile(entry.Name(), managed) {
			continue
		}
		cert, err := readLeafCertificate(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		id := certificateIDFromPath(entry.Name())
		active := !managed && id == activeID
		deletable := !managed && !active && regularFileExists(filepath.Join(dir, id+".key"))
		certificates = append(certificates, certificateResponse(id, certificateDomain(cert, id), cert, source, managed, active, deletable))
	}
	return certificates
}

func findManualCertificatePath(dir, id string) string {
	for _, extension := range []string{".crt", ".pem", ".cer"} {
		path := filepath.Join(dir, id+extension)
		if regularFileExists(path) {
			return path
		}
	}
	return ""
}

func isCertificateInventoryFile(name string, managed bool) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, ".") || strings.HasSuffix(lower, ".key") {
		return false
	}
	if managed {
		return !strings.Contains(lower, "+key") && !strings.Contains(lower, "+token")
	}
	switch filepath.Ext(lower) {
	case ".crt", ".pem", ".cer":
		return true
	default:
		return false
	}
}

func readLeafCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for remaining := data; len(remaining) > 0; {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
	return x509.ParseCertificate(data)
}

func certificateResponse(id, domain string, cert *x509.Certificate, source string, managed, active, deletable bool) map[string]interface{} {
	now := time.Now()
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	status := "valid"
	switch {
	case now.Before(cert.NotBefore):
		status = "not_yet_valid"
	case !now.Before(cert.NotAfter):
		status = "expired"
	case daysRemaining <= 30:
		status = "expiring"
	}

	sans := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	return map[string]interface{}{
		"id":             id,
		"domain":         domain,
		"cn":             cert.Subject.CommonName,
		"issuer":         cert.Issuer.CommonName,
		"fingerprint":    transport.CertificateFingerprintSHA256(cert),
		"sans":           sans,
		"valid":          status == "valid" || status == "expiring",
		"status":         status,
		"source":         source,
		"managed":        managed,
		"active":         active,
		"deletable":      deletable,
		"auto_renew":     managed,
		"days_remaining": daysRemaining,
		"type":           cert.PublicKeyAlgorithm.String(),
		"key_size":       certificateKeySize(cert),
		"not_before":     cert.NotBefore.Format(time.RFC3339),
		"not_after":      cert.NotAfter.Format(time.RFC3339),
	}
}

func certificateKeySize(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	default:
		return 0
	}
}

func certificateDomain(cert *x509.Certificate, fallback string) string {
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	if len(cert.IPAddresses) > 0 {
		return cert.IPAddresses[0].String()
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return fallback
}

func sanitizeCertificateID(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	value = strings.Map(func(char rune) rune {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '.' || char == '_' {
			return char
		}
		return '-'
	}, value)
	value = strings.Trim(value, ".-_")
	return filepath.Base(value)
}

func certificateIDFromPath(path string) string {
	base := filepath.Base(strings.TrimSpace(path))
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func effectiveTLSDirectory(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return filepath.Clean(fallback)
	}
	return filepath.Clean(value)
}

func regularFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
