package requestctx

import (
	"context"
	"net/http"
	"strings"
)

// AuthorizationIdentity is the sole request-scoped source for API Security
// authorization data. It is written only after a local verifier has completed
// all configured token checks; inbound headers are never copied here.
type AuthorizationIdentity struct {
	Authenticated  bool                   `json:"authenticated"`
	ClientIP       string                 `json:"client_ip,omitempty"`
	ClientIPSource string                 `json:"client_ip_source,omitempty"`
	Subject        string                 `json:"subject,omitempty"`
	Roles          []string               `json:"roles,omitempty"`
	Tenant         string                 `json:"tenant,omitempty"`
	Claims         map[string]interface{} `json:"claims,omitempty"`
	Source         string                 `json:"source,omitempty"`
	Issuer         string                 `json:"issuer,omitempty"`
	Audiences      []string               `json:"audiences,omitempty"`
}

type authorizationIdentityKey struct{}

// WithAuthorizationIdentity returns a context with a defensive copy of the
// verified identity. Callers must not mutate request authorization state after
// publishing it.
func WithAuthorizationIdentity(ctx context.Context, identity AuthorizationIdentity) context.Context {
	identity.Subject = strings.TrimSpace(identity.Subject)
	identity.Tenant = strings.TrimSpace(identity.Tenant)
	identity.ClientIP = strings.TrimSpace(identity.ClientIP)
	identity.ClientIPSource = strings.TrimSpace(identity.ClientIPSource)
	identity.Source = strings.TrimSpace(identity.Source)
	identity.Issuer = strings.TrimSpace(identity.Issuer)
	identity.Roles = append([]string(nil), identity.Roles...)
	identity.Audiences = append([]string(nil), identity.Audiences...)
	if identity.Claims != nil {
		claims := identity.Claims
		identity.Claims = make(map[string]interface{}, len(identity.Claims))
		for key, value := range claims {
			identity.Claims[key] = value
		}
	}
	return context.WithValue(ctx, authorizationIdentityKey{}, identity)
}

func AuthorizationIdentityFromContext(ctx context.Context) (AuthorizationIdentity, bool) {
	if ctx == nil {
		return AuthorizationIdentity{}, false
	}
	identity, ok := ctx.Value(authorizationIdentityKey{}).(AuthorizationIdentity)
	return identity, ok && identity.Authenticated
}

func AuthorizationIdentityFromRequest(r *http.Request) (AuthorizationIdentity, bool) {
	if r == nil {
		return AuthorizationIdentity{}, false
	}
	return AuthorizationIdentityFromContext(r.Context())
}
