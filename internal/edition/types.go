// Package edition defines Aegis build tiers and feature entitlements.
package edition

import (
	"fmt"
	"sort"
)

// BuildTier identifies the maximum edition compiled into a binary.
type BuildTier string

const (
	CommunityTier    BuildTier = "community"
	ProfessionalTier BuildTier = "professional"
	EnterpriseTier   BuildTier = "enterprise"
)

func (t BuildTier) Valid() bool {
	switch t {
	case CommunityTier, ProfessionalTier, EnterpriseTier:
		return true
	default:
		return false
	}
}

func (t BuildTier) Rank() int {
	switch t {
	case CommunityTier:
		return 0
	case ProfessionalTier:
		return 1
	case EnterpriseTier:
		return 2
	default:
		return -1
	}
}

func ParseBuildTier(value string) (BuildTier, error) {
	tier := BuildTier(value)
	if !tier.Valid() {
		return "", fmt.Errorf("unknown Aegis edition %q", value)
	}
	return tier, nil
}

// FeatureID is a stable capability identifier used by backend and UI gates.
type FeatureID string

const (
	FeatureProxyCore         FeatureID = "proxy.core"
	FeatureTLS               FeatureID = "proxy.tls"
	FeatureRouting           FeatureID = "proxy.routing"
	FeatureLoadBalancing     FeatureID = "proxy.load_balancing"
	FeatureWAFCore           FeatureID = "waf.core"
	FeatureWAFCustomRules    FeatureID = "waf.custom_rules"
	FeatureWAFLeakProtection FeatureID = "waf.leak_protection"
	FeatureWAFUpload         FeatureID = "waf.upload_protection"
	FeatureWAFBodyGuard      FeatureID = "waf.body_guard"
	FeatureWAFAdvancedPolicy FeatureID = "waf.advanced_policy"
	FeatureHTTPSecurity      FeatureID = "http_security.basic"
	FeatureHTTPAdvanced      FeatureID = "http_security.advanced"
	FeatureTrafficBlacklist  FeatureID = "traffic.blacklist"
	FeatureTrafficRateLimit  FeatureID = "traffic.rate_limit"
	FeatureTrafficConnStats  FeatureID = "traffic.connection_stats"
	FeatureTrafficGeo        FeatureID = "traffic.geo"
	FeatureTrafficReputation FeatureID = "traffic.reputation"
	FeatureTrafficDDoS       FeatureID = "traffic.ddos"
	FeatureTrafficPriority   FeatureID = "traffic.priority"
	FeatureBotProtection     FeatureID = "bot.all"
	FeatureAPISecurity       FeatureID = "api_security.all"
	FeatureAccessControl     FeatureID = "access_control.all"
	FeatureAdminSingleUser   FeatureID = "admin.single_user"
	FeatureAdminMFA          FeatureID = "admin.mfa"
	FeatureAdminMultiUser    FeatureID = "admin.multi_user"
	FeatureAdminRBAC         FeatureID = "admin.rbac"
	FeatureAdminAudit        FeatureID = "admin.audit"
	FeatureAnalyticsBasic    FeatureID = "analytics.basic"
	FeatureAnalyticsAdvanced FeatureID = "analytics.advanced"
)

// FeatureSet is an immutable-by-convention set. Clone before changing it.
type FeatureSet map[FeatureID]struct{}

func NewFeatureSet(features ...FeatureID) FeatureSet {
	set := make(FeatureSet, len(features))
	for _, feature := range features {
		set[feature] = struct{}{}
	}
	return set
}

func (s FeatureSet) Has(feature FeatureID) bool {
	_, ok := s[feature]
	return ok
}

func (s FeatureSet) Clone() FeatureSet {
	clone := make(FeatureSet, len(s))
	for feature := range s {
		clone[feature] = struct{}{}
	}
	return clone
}

func (s FeatureSet) Sorted() []FeatureID {
	features := make([]FeatureID, 0, len(s))
	for feature := range s {
		features = append(features, feature)
	}
	sort.Slice(features, func(i, j int) bool { return features[i] < features[j] })
	return features
}

func Intersect(compiled, entitled FeatureSet) FeatureSet {
	result := make(FeatureSet)
	for feature := range compiled {
		if entitled.Has(feature) {
			result[feature] = struct{}{}
		}
	}
	return result
}

var communityFeatures = NewFeatureSet(
	FeatureProxyCore,
	FeatureTLS,
	FeatureRouting,
	FeatureLoadBalancing,
	FeatureWAFCore,
	FeatureWAFCustomRules,
	FeatureWAFUpload,
	FeatureHTTPSecurity,
	FeatureHTTPAdvanced,
	FeatureTrafficBlacklist,
	FeatureTrafficRateLimit,
	FeatureTrafficConnStats,
	FeatureTrafficGeo,
	FeatureAdminSingleUser,
	FeatureAdminMFA,
	FeatureAnalyticsBasic,
)

var professionalFeatures = mergeFeatureSets(communityFeatures, NewFeatureSet(
	FeatureWAFLeakProtection,
	FeatureWAFUpload,
	FeatureWAFBodyGuard,
	FeatureWAFAdvancedPolicy,
	FeatureHTTPAdvanced,
	FeatureTrafficDDoS,
	FeatureTrafficPriority,
	FeatureTrafficReputation,
	FeatureBotProtection,
))

var enterpriseFeatures = mergeFeatureSets(professionalFeatures, NewFeatureSet(
	FeatureAPISecurity,
	FeatureAccessControl,
	FeatureAdminMultiUser,
	FeatureAdminRBAC,
	FeatureAdminAudit,
	FeatureAnalyticsAdvanced,
))

func FeaturesForTier(tier BuildTier) FeatureSet {
	switch tier {
	case EnterpriseTier:
		return enterpriseFeatures.Clone()
	case ProfessionalTier:
		return professionalFeatures.Clone()
	default:
		return communityFeatures.Clone()
	}
}

func mergeFeatureSets(sets ...FeatureSet) FeatureSet {
	result := make(FeatureSet)
	for _, set := range sets {
		for feature := range set {
			result[feature] = struct{}{}
		}
	}
	return result
}
