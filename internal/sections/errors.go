package sections

import "errors"

// Error definitions for sections
var (
	// Section errors
	ErrSectionNotFound    = errors.New("section not found")
	ErrSectionDisabled    = errors.New("section is disabled")
	ErrSectionInitFailed  = errors.New("section initialization failed")
	ErrSectionStartFailed = errors.New("section start failed")

	// Function errors
	ErrFunctionNotFound   = errors.New("function not found")
	ErrFunctionDisabled   = errors.New("function is disabled")
	ErrFunctionInitFailed = errors.New("function initialization failed")

	// Rule errors
	ErrRuleMissingID       = errors.New("rule missing ID")
	ErrRuleNoConditions    = errors.New("rule has no conditions")
	ErrRuleInvalidField    = errors.New("invalid rule field")
	ErrRuleInvalidOperator = errors.New("invalid rule operator")
	ErrRuleInvalidValue    = errors.New("invalid rule value")

	// Policy errors
	ErrPolicyMissingID = errors.New("policy missing ID")
	ErrPolicyNotFound  = errors.New("policy not found")

	// Config errors
	ErrConfigInvalid         = errors.New("invalid configuration")
	ErrConfigMissingField    = errors.New("missing required config field")
	ErrFeatureNotEntitled    = errors.New("feature_not_entitled")
	ErrFeatureNotImplemented = errors.New("feature_not_implemented")
	ErrUnsupportedConfigKey  = errors.New("unsupported_config_key")
)
