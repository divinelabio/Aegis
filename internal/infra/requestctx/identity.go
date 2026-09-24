package requestctx

import (
	"context"
	"net/http"
)

type GeoState string

const (
	GeoKnown    GeoState = "known"
	GeoPrivate  GeoState = "private"
	GeoNotFound GeoState = "not_found"
	GeoError    GeoState = "error"
)

type GeoResult struct {
	Country    string   `json:"country,omitempty"`
	State      GeoState `json:"state"`
	Generation string   `json:"generation,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// TLSFingerprint contains evidence captured by the local TLS terminator. It
// is set only by trusted server middleware after the ClientHello handshake.
type TLSFingerprint struct {
	Version string `json:"version,omitempty"`
	JA3     string `json:"ja3,omitempty"`
	JA4     string `json:"ja4,omitempty"`
}

type Identity struct {
	ClientIP           string         `json:"client_ip"`
	Source             string         `json:"source"`
	ImmediatePeer      string         `json:"immediate_peer"`
	TrustedProxy       bool           `json:"trusted_proxy"`
	ProxyChain         []string       `json:"proxy_chain,omitempty"`
	OriginalHost       string         `json:"original_host"`
	OriginalProto      string         `json:"original_proto"`
	ForwardedHost      string         `json:"forwarded_host,omitempty"`
	ForwardedProto     string         `json:"forwarded_proto,omitempty"`
	RejectedHeaderHint string         `json:"rejected_header_hint,omitempty"`
	Geo                GeoResult      `json:"geo"`
	TLS                TLSFingerprint `json:"tls,omitempty"`
}

type contextKey struct{}

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, identity)
}

func FromContext(ctx context.Context) (Identity, bool) {
	if ctx == nil {
		return Identity{}, false
	}
	identity, ok := ctx.Value(contextKey{}).(Identity)
	return identity, ok
}

func FromRequest(r *http.Request) (Identity, bool) {
	if r == nil {
		return Identity{}, false
	}
	return FromContext(r.Context())
}

func ClientIP(r *http.Request) string {
	if identity, ok := FromRequest(r); ok {
		return identity.ClientIP
	}
	return ""
}

func Country(r *http.Request) string {
	if identity, ok := FromRequest(r); ok {
		return identity.Geo.Country
	}
	return ""
}
