package transport

import (
	"context"
	"net/http"
	"strings"

	"github.com/divinelab-io/aegis/internal/infra/requestctx"
)

type GeoResolver interface {
	Lookup(string) requestctx.GeoResult
}

type TLSFingerprintLookup interface {
	LookupRequest(*http.Request) (requestctx.TLSFingerprint, bool)
}

func NewIdentityMiddleware(ctx context.Context, resolver *RealIPResolver, geo GeoResolver, fingerprints ...TLSFingerprintLookup) func(http.Handler) http.Handler {
	if resolver != nil {
		resolver.Start(ctx)
	}
	var fingerprintLookup TLSFingerprintLookup
	if len(fingerprints) > 0 {
		fingerprintLookup = fingerprints[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stripUntrustedAegisHeaders(r.Header)
			stripUntrustedAuthorizationHeaders(r.Header)
			client := resolver.Resolve(r)
			stripInboundForwardingHeaders(r.Header)
			identity := requestctx.Identity{
				ClientIP: client.IP, Source: client.Source, ImmediatePeer: client.ImmediatePeer,
				TrustedProxy: client.TrustedProxy, ProxyChain: client.ProxyChain,
				OriginalHost: client.OriginalHost, OriginalProto: client.OriginalProto,
				ForwardedHost: client.ForwardedHost, ForwardedProto: client.ForwardedProto,
				RejectedHeaderHint: client.RejectedHeaderHint,
			}
			if geo != nil {
				identity.Geo = geo.Lookup(client.IP)
			} else {
				identity.Geo = requestctx.GeoResult{State: requestctx.GeoError, Error: "geo service unavailable"}
			}
			if fingerprintLookup != nil {
				if fingerprint, ok := fingerprintLookup.LookupRequest(r); ok {
					identity.TLS = fingerprint
					setTrustedTLSHeaders(r.Header, fingerprint)
				}
			}
			r = r.WithContext(requestctx.WithIdentity(r.Context(), identity))
			next.ServeHTTP(w, r)
		})
	}
}

func setTrustedTLSHeaders(headers http.Header, fingerprint requestctx.TLSFingerprint) {
	if headers == nil {
		return
	}
	if fingerprint.Version != "" {
		headers.Set("X-Aegis-TLS-Version", fingerprint.Version)
	}
	if fingerprint.JA3 != "" {
		headers.Set("X-Aegis-TLS-JA3", fingerprint.JA3)
	}
	if fingerprint.JA4 != "" {
		headers.Set("X-Aegis-TLS-JA4", fingerprint.JA4)
	}
}

// stripInboundForwardingHeaders prevents downstream sections and Origins from
// accidentally reinterpreting raw client-controlled proxy metadata. The
// canonical values remain available through requestctx.Identity.
func stripInboundForwardingHeaders(headers http.Header) {
	for _, key := range []string{
		"Forwarded",
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Forwarded-Proto",
		"X-Forwarded-Host",
		"CF-Connecting-IP",
	} {
		headers.Del(key)
	}
}

// stripUntrustedAuthorizationHeaders removes the historical identity headers
// that API Security no longer accepts as evidence of authentication. A trusted
// identity must be attached to request context by a local verifier instead.
func stripUntrustedAuthorizationHeaders(headers http.Header) {
	for _, key := range []string{"X-User-ID", "X-User-Roles", "X-Tenant-ID"} {
		headers.Del(key)
	}
}

func stripUntrustedAegisHeaders(headers http.Header) {
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "x-aegis-") {
			headers.Del(key)
		}
	}
}
