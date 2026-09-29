package sections

import (
	"context"
	"strings"
)

// authenticatedOperatorContextKey is private so a request identity can only be
// installed by the authenticated admin boundary, not from a client header.
type authenticatedOperatorContextKey struct{}

// WithAuthenticatedOperator attaches an already-authenticated operator identity
// to a request context. Section lifecycle handlers use this identity for their
// durable revision records; they never accept an operator name from a request
// body or header.
func WithAuthenticatedOperator(ctx context.Context, operator string) context.Context {
	operator = strings.TrimSpace(operator)
	if operator == "" {
		return ctx
	}
	return context.WithValue(ctx, authenticatedOperatorContextKey{}, operator)
}

// AuthenticatedOperator returns the operator identity installed by the admin
// authentication boundary.
func AuthenticatedOperator(ctx context.Context) (string, bool) {
	operator, ok := ctx.Value(authenticatedOperatorContextKey{}).(string)
	operator = strings.TrimSpace(operator)
	return operator, ok && operator != ""
}
