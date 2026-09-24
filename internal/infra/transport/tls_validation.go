package transport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ValidateCertificatePair performs the checks required before a certificate
// can become active. Trust failures are returned as warnings so private PKI and
// self-signed certificates remain usable by self-hosted installations.
func ValidateCertificatePair(certPEM, keyPEM []byte, hostname string, now time.Time) (*tls.Certificate, *x509.Certificate, []string, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certificate and private key do not form a valid pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, nil, nil, errors.New("certificate chain is empty")
	}

	leaf, err := parseLeafDER(pair.Certificate[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	pair.Leaf = leaf

	if now.Before(leaf.NotBefore) {
		return nil, nil, nil, fmt.Errorf("certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return nil, nil, nil, fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return nil, nil, nil, errors.New("certificate must contain at least one DNS or IP subject alternative name")
	}
	if leaf.IsCA {
		return nil, nil, nil, errors.New("certificate leaf must not be a certificate authority")
	}
	if hostname = strings.TrimSpace(hostname); hostname != "" {
		if err := leaf.VerifyHostname(hostname); err != nil {
			return nil, nil, nil, fmt.Errorf("certificate does not cover %q: %w", hostname, err)
		}
	}
	if !supportsServerAuthentication(leaf.ExtKeyUsage) {
		return nil, nil, nil, errors.New("certificate extended key usage does not allow TLS server authentication")
	}
	if err := validatePublicKeyStrength(leaf.PublicKey); err != nil {
		return nil, nil, nil, err
	}
	if isWeakSignatureAlgorithm(leaf.SignatureAlgorithm) {
		return nil, nil, nil, fmt.Errorf("certificate uses weak signature algorithm %s", leaf.SignatureAlgorithm)
	}

	chain, err := parseCertificateChain(pair.Certificate)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := validateCertificateChain(chain, now); err != nil {
		return nil, nil, nil, err
	}

	warnings := make([]string, 0, 2)
	if now.Add(30 * 24 * time.Hour).After(leaf.NotAfter) {
		warnings = append(warnings, "Certificate expires in less than 30 days.")
	}
	if err := verifySystemTrust(chain, hostname, now); err != nil {
		warnings = append(warnings, "Certificate is not trusted by the host trust store; clients must trust its issuing CA.")
	}

	return &pair, leaf, warnings, nil
}

func parseLeafDER(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

func parseCertificateChain(raw [][]byte) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(raw))
	for _, der := range raw {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse certificate chain: %w", err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

func validateCertificateChain(chain []*x509.Certificate, now time.Time) error {
	for index := 0; index+1 < len(chain); index++ {
		if err := chain[index].CheckSignatureFrom(chain[index+1]); err != nil {
			return fmt.Errorf("certificate chain signature check failed: %w", err)
		}
	}
	for index, cert := range chain[1:] {
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return fmt.Errorf("certificate chain issuer %d is outside its validity period", index+1)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return fmt.Errorf("certificate chain issuer %d is not a valid CA certificate", index+1)
		}
		if err := validatePublicKeyStrength(cert.PublicKey); err != nil {
			return fmt.Errorf("certificate chain issuer %d: %w", index+1, err)
		}
		if isWeakSignatureAlgorithm(cert.SignatureAlgorithm) {
			return fmt.Errorf("certificate chain issuer %d uses weak signature algorithm %s", index+1, cert.SignatureAlgorithm)
		}
	}
	return nil
}

func verifySystemTrust(chain []*x509.Certificate, hostname string, now time.Time) error {
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       hostname,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func supportsServerAuthentication(usages []x509.ExtKeyUsage) bool {
	if len(usages) == 0 {
		return true
	}
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageAny || usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

func validatePublicKeyStrength(publicKey any) error {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key is too weak: %d bits; minimum is 2048", key.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.Curve.Params().BitSize < 256 {
			return errors.New("ECDSA key is too weak; minimum curve size is 256 bits")
		}
	case ed25519.PublicKey:
		// Ed25519 has a fixed, acceptable security level.
	default:
		return fmt.Errorf("unsupported certificate public key type %T", publicKey)
	}
	return nil
}

func isWeakSignatureAlgorithm(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

// CertificateFingerprintSHA256 returns a stable identifier without exposing
// private key material.
func CertificateFingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
