package admin

import (
	"encoding/json"
	"net/http"

	"github.com/divinelab-io/aegis/internal/edition"
	"github.com/divinelab-io/aegis/internal/licensing"
)

// requireEntitledFeatures is deliberately independent from RBAC: a user can
// hold a permission only within the active product plan that exposes it.
func requireEntitledFeatures(manager licensing.Manager, features ...edition.FeatureID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if manager == nil {
				communityFeatures := edition.FeaturesForTier(edition.CommunityTier)
				for _, feature := range features {
					if !communityFeatures.Has(feature) {
						writeFeatureNotEntitled(w)
						return
					}
				}
				next.ServeHTTP(w, r)
				return
			}
			for _, feature := range features {
				if !manager.Has(feature) {
					writeFeatureNotEntitled(w)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *AdminServer) requireEditionFeatures(features ...edition.FeatureID) func(http.Handler) http.Handler {
	var manager licensing.Manager
	if s != nil && s.handlers != nil {
		manager = s.handlers.License
	}
	return requireEntitledFeatures(manager, features...)
}

func writeFeatureNotEntitled(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "feature_not_entitled"})
}
