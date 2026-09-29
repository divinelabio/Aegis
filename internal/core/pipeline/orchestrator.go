package pipeline

import (
	"net/http"
)

// Middleware defines the standard interface for Aegis security modules.
type Middleware func(next http.Handler) http.Handler

// Pipeline manages the middleware chain.
type Pipeline struct {
	middlewares []Middleware
}

// New creates a new empty Pipeline.
func New() *Pipeline {
	return &Pipeline{
		middlewares: []Middleware{},
	}
}

// Use adds a middleware to the chain.
func (p *Pipeline) Use(m Middleware) {
	p.middlewares = append(p.middlewares, m)
}

// Build compiles the pipeline into a single http.Handler.
// The final handler is the upstream proxy (or application).
func (p *Pipeline) Build(final http.Handler) http.Handler {
	if final == nil {
		final = http.DefaultServeMux
	}

	// Iterate backwards to wrap the handler
	for i := len(p.middlewares) - 1; i >= 0; i-- {
		final = p.middlewares[i](final)
	}

	return final
}
