package rules

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type ASTNode struct {
	Type        string     `json:"type"`
	Value       string     `json:"value,omitempty"`
	Field       string     `json:"field,omitempty"`
	Operator    string     `json:"operator,omitempty"`
	Values      []string   `json:"values,omitempty"`
	Children    []*ASTNode `json:"children,omitempty"`
	matcher     *regexp.Regexp
	fieldSource fieldSource
	fieldKey    string
}

type fieldSource uint8

const (
	fieldSourceUncompiled fieldSource = iota
	fieldSourceClientIP
	fieldSourceHost
	fieldSourcePath
	fieldSourceMethod
	fieldSourceUserAgent
	fieldSourceCountry
	fieldSourceASN
	fieldSourceIPReputation
	fieldSourceBotScore
	fieldSourceBotCategory
	fieldSourceBotVerified
	fieldSourceBotHeadless
	fieldSourceWAFScore
	fieldSourceAPIPath
	fieldSourceAPIAuthValid
	fieldSourceTLSVersion
	fieldSourceTLSJA3
	fieldSourceTLSJA4
	fieldSourceAccessRole
	fieldSourceHeader
	fieldSourceCookie
	fieldSourceQuery
)

type ExpressionError struct {
	Message    string `json:"message"`
	Position   int    `json:"position"`
	Expected   string `json:"expected,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

func (e ExpressionError) Error() string {
	if e.Position > 0 {
		return fmt.Sprintf("%s at token %d", e.Message, e.Position)
	}
	return e.Message
}

type ValidationResult struct {
	Valid                bool              `json:"valid"`
	AST                  *ASTNode          `json:"ast,omitempty"`
	NormalizedExpression string            `json:"normalized_expression"`
	Errors               []ExpressionError `json:"errors,omitempty"`
	Warnings             []string          `json:"warnings,omitempty"`
	FieldsUsed           []string          `json:"fields_used,omitempty"`
	SectionTarget        string            `json:"section_target,omitempty"`
}

type FieldSpec struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Section     string   `json:"section"`
	Operators   []string `json:"operators"`
	Description string   `json:"description"`
	InputType   string   `json:"input_type,omitempty"`
	Options     []string `json:"options,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
	Multi       bool     `json:"multi,omitempty"`
}

type token struct {
	value string
	pos   int
}

type expressionParser struct {
	tokens []token
	pos    int
}

func EvaluateExpression(expression string, ctx RequestContext) (bool, error) {
	ast, err := ParseExpression(expression)
	if err != nil {
		return false, err
	}
	return EvaluateAST(ast, ctx)
}

// EvaluateAST evaluates a previously parsed expression. Callers that keep a
// validated expression in an immutable runtime snapshot can use this to avoid
// reparsing it on every request.
func EvaluateAST(ast *ASTNode, ctx RequestContext) (bool, error) {
	return evalAST(ast, ctx)
}

func ParseExpression(expression string) (*ASTNode, error) {
	expression = strings.TrimSpace(expression)
	if expression == "" || strings.EqualFold(expression, "true") {
		return &ASTNode{Type: "literal", Value: "true"}, nil
	}
	p := &expressionParser{tokens: tokenize(expression)}
	ast, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.tokens) {
		t := p.tokens[p.pos]
		return nil, ExpressionError{Message: "unexpected token " + strconv.Quote(t.value), Position: t.pos, Suggestion: "Remove it or join another condition with and/or"}
	}
	return ast, nil
}

func ValidateExpression(expression string) ValidationResult {
	ast, err := ParseExpression(expression)
	if err != nil {
		if exprErr, ok := err.(ExpressionError); ok {
			return ValidationResult{Valid: false, Errors: []ExpressionError{exprErr}}
		}
		return ValidationResult{Valid: false, Errors: []ExpressionError{{Message: err.Error()}}}
	}
	fields := collectFields(ast, nil)
	errors := typedValueErrors(ast)
	warnings := unknownFieldWarnings(fields)
	return ValidationResult{
		Valid:                len(errors) == 0 && len(warnings) == 0,
		AST:                  ast,
		NormalizedExpression: NormalizeExpression(ast),
		Errors:               errors,
		Warnings:             warnings,
		FieldsUsed:           fields,
		SectionTarget:        SectionForFields(fields),
	}
}

func RuleFields() []FieldSpec {
	stringOps := []string{"eq", "ne", "contains", "starts_with", "ends_with", "matches", "in", "not in"}
	numberOps := []string{"eq", "ne", "gt", "lt", "ge", "le", "in", "not in"}
	boolOps := []string{"eq", "ne"}
	return []FieldSpec{
		{Name: "ip.src", Label: "Client IP", Type: "ip", Section: "geo_ip", Operators: stringOps, Description: "Client source IP or CIDR target", InputType: "ip", Placeholder: "203.0.113.10 or 203.0.113.0/24", Multi: true},
		{Name: "ip.geoip.country", Label: "Country", Type: "string", Section: "geo_ip", Operators: stringOps, Description: "Two-letter country code", InputType: "country", Placeholder: "US", Multi: true},
		{Name: "ip.asn", Label: "ASN", Type: "string", Section: "geo_ip", Operators: stringOps, Description: "Autonomous system number", InputType: "text", Placeholder: "AS13335"},
		{Name: "ip.reputation.score", Label: "IP Reputation", Type: "number", Section: "bot", Operators: numberOps, Description: "IP reputation score from 0-100", InputType: "number", Placeholder: "50"},
		{Name: "http.host", Label: "Host", Type: "string", Section: "waf", Operators: stringOps, Description: "Request host", InputType: "text", Placeholder: "example.com"},
		{Name: "http.request.uri.path", Label: "Path", Type: "string", Section: "waf", Operators: stringOps, Description: "Request path", InputType: "text", Placeholder: "/admin"},
		{Name: "http.request.method", Label: "Method", Type: "string", Section: "waf", Operators: stringOps, Description: "HTTP method", InputType: "select", Options: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}, Placeholder: "GET", Multi: true},
		{Name: "http.user_agent", Label: "User Agent", Type: "string", Section: "bot", Operators: stringOps, Description: "User-Agent header", InputType: "text", Placeholder: "HeadlessChrome"},
		{Name: `http.request.headers["content-type"]`, Label: "Header", Type: "string", Section: "http_security", Operators: stringOps, Description: "HTTP request header value", InputType: "text", Placeholder: "application/json"},
		{Name: `http.cookie["session"]`, Label: "Cookie", Type: "string", Section: "bot", Operators: stringOps, Description: "HTTP cookie value", InputType: "text", Placeholder: "session-value"},
		{Name: `http.request.query["q"]`, Label: "Query", Type: "string", Section: "bot", Operators: stringOps, Description: "HTTP query parameter value", InputType: "text", Placeholder: "needle"},
		{Name: "aegis.bot.score", Label: "Bot Score", Type: "number", Section: "bot", Operators: numberOps, Description: "Lower values are more bot-like", InputType: "number", Placeholder: "30"},
		{Name: "aegis.bot.category", Label: "Bot Category", Type: "string", Section: "bot", Operators: stringOps, Description: "Bot classification category", InputType: "text", Placeholder: "suspicious"},
		{Name: "aegis.bot.verified", Label: "Verified Bot", Type: "boolean", Section: "bot", Operators: boolOps, Description: "Whether the bot identity was verified", InputType: "boolean", Options: []string{"true", "false"}, Placeholder: "false"},
		{Name: "aegis.bot.headless", Label: "Headless", Type: "boolean", Section: "bot", Operators: boolOps, Description: "Whether headless browser signals were detected", InputType: "boolean", Options: []string{"true", "false"}, Placeholder: "true"},
		{Name: "aegis.waf.score", Label: "WAF Score", Type: "number", Section: "waf", Operators: numberOps, Description: "WAF risk score", InputType: "number", Placeholder: "50"},
		{Name: "api.path", Label: "API Path", Type: "string", Section: "api", Operators: stringOps, Description: "Discovered or protected API path", InputType: "text", Placeholder: "/api/"},
		{Name: "api.auth.valid", Label: "API Auth Valid", Type: "boolean", Section: "api", Operators: boolOps, Description: "API authentication validity", InputType: "boolean", Options: []string{"true", "false"}, Placeholder: "false"},
		{Name: "tls.version", Label: "TLS Version", Type: "string", Section: "http_security", Operators: stringOps, Description: "Negotiated TLS version", InputType: "select", Options: []string{"TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"}, Placeholder: "TLS1.2", Multi: true},
		{Name: "tls.ja3", Label: "JA3", Type: "string", Section: "bot", Operators: stringOps, Description: "JA3 TLS fingerprint", InputType: "text", Placeholder: "e7d705a3286e19ea42f587b344ee6865"},
		{Name: "tls.ja4", Label: "JA4", Type: "string", Section: "bot", Operators: stringOps, Description: "JA4 TLS fingerprint", InputType: "text", Placeholder: "t13d1516h2_8daaf6152771_b0da82dd1658"},
		{Name: "access.identity.role", Label: "Access Role", Type: "string", Section: "access", Operators: stringOps, Description: "Authenticated role or group", InputType: "text", Placeholder: "guest"},
	}
}

// BotRuleFields is the subset whose values are populated before Bot Protection
// evaluates a request. Keeping this explicit prevents the Bot editor from
// offering cross-section fields that would otherwise fail open as empty.
func BotRuleFields() []FieldSpec {
	allowed := map[string]struct{}{
		"ip.src":                               {},
		"ip.geoip.country":                     {},
		"ip.reputation.score":                  {},
		"http.host":                            {},
		"http.request.uri.path":                {},
		"http.request.method":                  {},
		"http.user_agent":                      {},
		`http.request.headers["content-type"]`: {},
		`http.cookie["session"]`:               {},
		`http.request.query["q"]`:              {},
		"aegis.bot.score":                      {},
		"aegis.bot.category":                   {},
		"aegis.bot.verified":                   {},
		"aegis.bot.headless":                   {},
		"tls.version":                          {},
		"tls.ja3":                              {},
		"tls.ja4":                              {},
	}
	all := RuleFields()
	fields := make([]FieldSpec, 0, len(allowed))
	for _, field := range all {
		if _, ok := allowed[field.Name]; ok {
			fields = append(fields, field)
		}
	}
	return fields
}

// IsBotRuleField reports whether a parsed expression field is populated by
// Bot Protection before a unified Bot rule is evaluated.
func IsBotRuleField(field string) bool {
	field = strings.ToLower(strings.TrimSpace(normalizeFieldAlias(field)))
	if strings.HasPrefix(field, "http.request.headers[") ||
		strings.HasPrefix(field, "http.cookie[") ||
		strings.HasPrefix(field, "http.request.query[") {
		return true
	}
	switch field {
	case "ip.src", "ip.geoip.country", "ip.reputation.score",
		"http.host", "http.request.uri.path", "http.request.method", "http.user_agent",
		"aegis.bot.score", "aegis.bot.category", "aegis.bot.verified", "aegis.bot.headless",
		"tls.version", "tls.ja3", "tls.ja4":
		return true
	default:
		return false
	}
}

func SectionForFields(fields []string) string {
	counts := map[string]int{}
	for _, field := range fields {
		for _, spec := range RuleFields() {
			if strings.EqualFold(field, spec.Name) || strings.EqualFold(normalizeFieldAlias(field), spec.Name) {
				counts[spec.Section]++
			}
		}
	}
	bestSection, bestCount := "custom", 0
	for section, count := range counts {
		if count > bestCount {
			bestSection, bestCount = section, count
		}
	}
	return bestSection
}

func tokenize(input string) []token {
	var tokens []token
	for i := 0; i < len(input); {
		if unicode.IsSpace(rune(input[i])) {
			i++
			continue
		}
		switch input[i] {
		case '(', ')', '{', '}':
			tokens = append(tokens, token{value: input[i : i+1], pos: len(tokens) + 1})
			i++
		case '"', '\'':
			quote := input[i]
			j := i + 1
			for j < len(input) && input[j] != quote {
				if input[j] == '\\' && j+1 < len(input) {
					j += 2
					continue
				}
				j++
			}
			if j < len(input) {
				tokens = append(tokens, token{value: input[i+1 : j], pos: len(tokens) + 1})
				i = j + 1
			} else {
				tokens = append(tokens, token{value: input[i+1:], pos: len(tokens) + 1})
				i = len(input)
			}
		default:
			j := i
			for j < len(input) && !unicode.IsSpace(rune(input[j])) && !strings.ContainsRune("(){}", rune(input[j])) {
				j++
			}
			tokens = append(tokens, token{value: input[i:j], pos: len(tokens) + 1})
			i = j
		}
	}
	return tokens
}

func (p *expressionParser) parseOr() (*ASTNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.match("or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &ASTNode{Type: "or", Children: []*ASTNode{left, right}}
	}
	return left, nil
}

func (p *expressionParser) parseAnd() (*ASTNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.match("and") {
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &ASTNode{Type: "and", Children: []*ASTNode{left, right}}
	}
	return left, nil
}

func (p *expressionParser) parseNot() (*ASTNode, error) {
	if p.match("not") {
		value, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &ASTNode{Type: "not", Children: []*ASTNode{value}}, nil
	}
	return p.parsePrimary()
}

func (p *expressionParser) parsePrimary() (*ASTNode, error) {
	if p.match("(") {
		value, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.match(")") {
			return nil, ExpressionError{Message: "missing closing parenthesis", Position: p.position(), Expected: ")", Suggestion: "Close the grouped expression"}
		}
		return value, nil
	}
	return p.parseCondition()
}

func (p *expressionParser) parseCondition() (*ASTNode, error) {
	field, ok := p.next()
	if !ok {
		return nil, ExpressionError{Message: "expected field", Position: p.position(), Expected: "field", Suggestion: "Choose a field such as http.request.uri.path"}
	}
	op, ok := p.next()
	if !ok {
		return nil, ExpressionError{Message: "expected operator after " + field.value, Position: p.position(), Expected: "operator", Suggestion: "Use eq, contains, in, matches, gt, lt, ge, or le"}
	}
	operator := strings.ToLower(op.value)
	if operator == "not" {
		next, ok := p.next()
		if !ok || !strings.EqualFold(next.value, "in") {
			return nil, ExpressionError{Message: "expected 'not in'", Position: op.pos, Expected: "not in"}
		}
		operator = "not in"
	}
	if operator == "in" || operator == "not in" {
		values, err := p.parseSet()
		if err != nil {
			return nil, err
		}
		return &ASTNode{Type: "condition", Field: normalizeFieldAlias(field.value), Operator: operator, Values: values}, nil
	}
	value, ok := p.next()
	if !ok {
		return nil, ExpressionError{Message: "expected value after " + field.value + " " + op.value, Position: p.position(), Expected: "value"}
	}
	if !supportedOperator(operator) {
		return nil, ExpressionError{Message: "unsupported operator " + strconv.Quote(op.value), Position: op.pos, Expected: "supported operator", Suggestion: "Use eq, ne, contains, starts_with, ends_with, matches, in, not in, gt, lt, ge, or le"}
	}
	return &ASTNode{Type: "condition", Field: normalizeFieldAlias(field.value), Operator: operator, Values: []string{value.value}}, nil
}

func (p *expressionParser) parseSet() ([]string, error) {
	if !p.match("{") {
		value, ok := p.next()
		if !ok {
			return nil, ExpressionError{Message: "expected set value", Position: p.position(), Expected: "value"}
		}
		return []string{strings.Trim(value.value, ",")}, nil
	}
	var values []string
	for {
		value, ok := p.next()
		if !ok {
			return nil, ExpressionError{Message: "unterminated set", Position: p.position(), Expected: "}", Suggestion: "Close the set with }"}
		}
		if value.value == "}" {
			break
		}
		values = append(values, strings.Trim(value.value, ","))
	}
	return values, nil
}

func (p *expressionParser) match(value string) bool {
	if p.pos >= len(p.tokens) || !strings.EqualFold(p.tokens[p.pos].value, value) {
		return false
	}
	p.pos++
	return true
}

func (p *expressionParser) next() (token, bool) {
	if p.pos >= len(p.tokens) {
		return token{}, false
	}
	t := p.tokens[p.pos]
	p.pos++
	return t, true
}

func (p *expressionParser) position() int {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos].pos
	}
	return len(p.tokens) + 1
}

func evalAST(node *ASTNode, ctx RequestContext) (bool, error) {
	if node == nil {
		return false, nil
	}
	switch node.Type {
	case "literal":
		return strings.EqualFold(node.Value, "true"), nil
	case "and":
		left, err := evalAST(node.Children[0], ctx)
		if err != nil || !left {
			return left, err
		}
		return evalAST(node.Children[1], ctx)
	case "or":
		left, err := evalAST(node.Children[0], ctx)
		if err != nil || left {
			return left, err
		}
		return evalAST(node.Children[1], ctx)
	case "not":
		value, err := evalAST(node.Children[0], ctx)
		return !value, err
	case "condition":
		actual := nodeFieldValue(node, ctx)
		if node.Operator == "in" {
			return contains(node.Values, actual), nil
		}
		if node.Operator == "not in" {
			return !contains(node.Values, actual), nil
		}
		if node.Operator == "matches" && node.matcher != nil {
			return node.matcher.MatchString(actual), nil
		}
		value := ""
		if len(node.Values) > 0 {
			value = node.Values[0]
		}
		return compare(actual, node.Operator, value)
	default:
		return false, fmt.Errorf("unknown AST node type %q", node.Type)
	}
}

func compileASTMatchers(node *ASTNode) {
	if node == nil {
		return
	}
	if node.Type == "condition" && strings.EqualFold(node.Operator, "matches") && len(node.Values) > 0 {
		if matcher, err := regexp.Compile(node.Values[0]); err == nil {
			node.matcher = matcher
		}
	}
	for _, child := range node.Children {
		compileASTMatchers(child)
	}
}

func compileASTFieldSources(node *ASTNode) {
	if node == nil {
		return
	}
	if node.Type == "condition" {
		node.fieldSource, node.fieldKey = compileFieldSource(node.Field)
	}
	for _, child := range node.Children {
		compileASTFieldSources(child)
	}
}

func compileFieldSource(field string) (fieldSource, string) {
	switch strings.ToLower(normalizeFieldAlias(field)) {
	case "ip.src":
		return fieldSourceClientIP, ""
	case "http.host":
		return fieldSourceHost, ""
	case "http.request.uri.path":
		return fieldSourcePath, ""
	case "http.request.method":
		return fieldSourceMethod, ""
	case "http.user_agent":
		return fieldSourceUserAgent, ""
	case "ip.geoip.country":
		return fieldSourceCountry, ""
	case "ip.asn":
		return fieldSourceASN, ""
	case "ip.reputation.score":
		return fieldSourceIPReputation, ""
	case "aegis.bot.score":
		return fieldSourceBotScore, ""
	case "aegis.bot.category":
		return fieldSourceBotCategory, ""
	case "aegis.bot.verified":
		return fieldSourceBotVerified, ""
	case "aegis.bot.headless":
		return fieldSourceBotHeadless, ""
	case "aegis.waf.score":
		return fieldSourceWAFScore, ""
	case "api.path":
		return fieldSourceAPIPath, ""
	case "api.auth.valid":
		return fieldSourceAPIAuthValid, ""
	case "tls.version":
		return fieldSourceTLSVersion, ""
	case "tls.ja3":
		return fieldSourceTLSJA3, ""
	case "tls.ja4":
		return fieldSourceTLSJA4, ""
	case "access.identity.role":
		return fieldSourceAccessRole, ""
	}

	lower := strings.ToLower(field)
	if strings.HasPrefix(lower, "http.request.headers[") {
		return fieldSourceHeader, dynamicFieldKey(field, "http.request.headers[")
	}
	if strings.HasPrefix(lower, "http.cookie[") {
		return fieldSourceCookie, dynamicFieldKey(field, "http.cookie[")
	}
	if strings.HasPrefix(lower, "http.request.query[") {
		return fieldSourceQuery, dynamicFieldKey(field, "http.request.query[")
	}
	return fieldSourceUncompiled, ""
}

func dynamicFieldKey(field, prefix string) string {
	name := strings.TrimPrefix(field, prefix)
	name = strings.TrimSuffix(name, "]")
	name = strings.Trim(name, `"'`)
	return strings.ToLower(name)
}

func nodeFieldValue(node *ASTNode, ctx RequestContext) string {
	switch node.fieldSource {
	case fieldSourceClientIP:
		return ctx.ClientIP
	case fieldSourceHost:
		return ctx.Host
	case fieldSourcePath:
		return ctx.Path
	case fieldSourceMethod:
		return ctx.Method
	case fieldSourceUserAgent:
		return ctx.UserAgent
	case fieldSourceCountry:
		return ctx.Country
	case fieldSourceASN:
		return ctx.ASN
	case fieldSourceIPReputation:
		return strconv.Itoa(ctx.IPReputation)
	case fieldSourceBotScore:
		return strconv.Itoa(ctx.BotScore)
	case fieldSourceBotCategory:
		return ctx.BotCategory
	case fieldSourceBotVerified:
		return strconv.FormatBool(ctx.BotVerified)
	case fieldSourceBotHeadless:
		return strconv.FormatBool(ctx.BotHeadless)
	case fieldSourceWAFScore:
		return strconv.Itoa(ctx.WAFScore)
	case fieldSourceAPIPath:
		if ctx.APIPath != "" {
			return ctx.APIPath
		}
		return ctx.Path
	case fieldSourceAPIAuthValid:
		return strconv.FormatBool(ctx.APIAuthValid)
	case fieldSourceTLSVersion:
		return ctx.TLSVersion
	case fieldSourceTLSJA3:
		return ctx.TLSJA3
	case fieldSourceTLSJA4:
		return ctx.TLSJA4
	case fieldSourceAccessRole:
		return ctx.AccessRole
	case fieldSourceHeader:
		return ctx.Headers[node.fieldKey]
	case fieldSourceCookie:
		return ctx.Cookies[node.fieldKey]
	case fieldSourceQuery:
		return ctx.Query[node.fieldKey]
	default:
		return fieldValue(node.Field, ctx)
	}
}

func fieldValue(field string, ctx RequestContext) string {
	switch strings.ToLower(normalizeFieldAlias(field)) {
	case "ip.src":
		return ctx.ClientIP
	case "http.host":
		return ctx.Host
	case "http.request.uri.path":
		return ctx.Path
	case "http.request.method":
		return ctx.Method
	case "http.user_agent":
		return ctx.UserAgent
	case "ip.geoip.country":
		return ctx.Country
	case "ip.asn":
		return ctx.ASN
	case "ip.reputation.score":
		return strconv.Itoa(ctx.IPReputation)
	case "aegis.bot.score":
		return strconv.Itoa(ctx.BotScore)
	case "aegis.bot.category":
		return ctx.BotCategory
	case "aegis.bot.verified":
		return strconv.FormatBool(ctx.BotVerified)
	case "aegis.bot.headless":
		return strconv.FormatBool(ctx.BotHeadless)
	case "aegis.waf.score":
		return strconv.Itoa(ctx.WAFScore)
	case "api.path":
		if ctx.APIPath != "" {
			return ctx.APIPath
		}
		return ctx.Path
	case "api.auth.valid":
		return strconv.FormatBool(ctx.APIAuthValid)
	case "tls.version":
		return ctx.TLSVersion
	case "tls.ja3":
		return ctx.TLSJA3
	case "tls.ja4":
		return ctx.TLSJA4
	case "access.identity.role":
		return ctx.AccessRole
	default:
		lower := strings.ToLower(field)
		if strings.HasPrefix(lower, "http.request.headers[") {
			name := strings.TrimPrefix(field, "http.request.headers[")
			name = strings.TrimSuffix(name, "]")
			name = strings.Trim(name, `"'`)
			return ctx.Headers[strings.ToLower(name)]
		}
		if strings.HasPrefix(lower, "http.cookie[") {
			name := strings.TrimPrefix(field, "http.cookie[")
			name = strings.TrimSuffix(name, "]")
			name = strings.Trim(name, `"'`)
			return ctx.Cookies[strings.ToLower(name)]
		}
		if strings.HasPrefix(lower, "http.request.query[") {
			name := strings.TrimPrefix(field, "http.request.query[")
			name = strings.TrimSuffix(name, "]")
			name = strings.Trim(name, `"'`)
			return ctx.Query[strings.ToLower(name)]
		}
		return ""
	}
}

func compare(left, op, right string) (bool, error) {
	switch strings.ToLower(op) {
	case "eq", "==":
		if cidrMatches(left, right) {
			return true, nil
		}
		return strings.EqualFold(left, right), nil
	case "ne", "!=":
		return !strings.EqualFold(left, right), nil
	case "contains":
		return strings.Contains(strings.ToLower(left), strings.ToLower(right)), nil
	case "starts_with":
		return strings.HasPrefix(strings.ToLower(left), strings.ToLower(right)), nil
	case "ends_with":
		return strings.HasSuffix(strings.ToLower(left), strings.ToLower(right)), nil
	case "matches":
		return regexp.MatchString(right, left)
	case "gt", "lt", "ge", "le":
		l, lerr := strconv.ParseFloat(left, 64)
		r, rerr := strconv.ParseFloat(right, 64)
		if lerr != nil || rerr != nil {
			return false, fmt.Errorf("numeric comparison requires numbers")
		}
		switch strings.ToLower(op) {
		case "gt":
			return l > r, nil
		case "lt":
			return l < r, nil
		case "ge":
			return l >= r, nil
		default:
			return l <= r, nil
		}
	default:
		return false, fmt.Errorf("unsupported operator %q", op)
	}
}

func cidrMatches(ipValue, candidate string) bool {
	if !strings.Contains(candidate, "/") {
		return false
	}
	ip := net.ParseIP(ipValue)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(candidate)
	return err == nil && network.Contains(ip)
}

func NormalizeExpression(node *ASTNode) string {
	if node == nil {
		return ""
	}
	switch node.Type {
	case "literal":
		return node.Value
	case "not":
		return "not (" + NormalizeExpression(node.Children[0]) + ")"
	case "and", "or":
		return "(" + NormalizeExpression(node.Children[0]) + " " + node.Type + " " + NormalizeExpression(node.Children[1]) + ")"
	case "condition":
		if node.Operator == "in" || node.Operator == "not in" {
			return node.Field + " " + node.Operator + " {" + quoteValues(node.Values) + "}"
		}
		value := ""
		if len(node.Values) > 0 {
			value = quoteValue(node.Values[0])
		}
		return node.Field + " " + node.Operator + " " + value
	default:
		return ""
	}
}

func collectFields(node *ASTNode, fields []string) []string {
	if node == nil {
		return fields
	}
	if node.Type == "condition" {
		if !contains(fields, node.Field) {
			fields = append(fields, node.Field)
		}
	}
	for _, child := range node.Children {
		fields = collectFields(child, fields)
	}
	return fields
}

func unknownFieldWarnings(fields []string) []string {
	var warnings []string
	for _, field := range fields {
		known := false
		for _, spec := range RuleFields() {
			lower := strings.ToLower(field)
			if strings.EqualFold(field, spec.Name) ||
				strings.HasPrefix(lower, "http.request.headers[") ||
				strings.HasPrefix(lower, "http.cookie[") ||
				strings.HasPrefix(lower, "http.request.query[") {
				known = true
				break
			}
		}
		if !known {
			warnings = append(warnings, "Unknown field: "+field)
		}
	}
	return warnings
}

func typedValueErrors(node *ASTNode) []ExpressionError {
	var errors []ExpressionError
	collectTypedValueErrors(node, &errors)
	return errors
}

func collectTypedValueErrors(node *ASTNode, errors *[]ExpressionError) {
	if node == nil {
		return
	}
	if node.Type == "condition" {
		field := strings.ToLower(normalizeFieldAlias(node.Field))
		switch field {
		case "ip.src":
			for _, value := range node.Values {
				trimmed := strings.Trim(value, `"'`)
				if trimmed == "" {
					continue
				}
				if strings.Contains(trimmed, "/") {
					if _, _, err := net.ParseCIDR(trimmed); err != nil {
						*errors = append(*errors, ExpressionError{Message: "Invalid IP/CIDR value: " + trimmed, Suggestion: "Use an IP address such as 203.0.113.10 or CIDR such as 203.0.113.0/24"})
					}
					continue
				}
				if net.ParseIP(trimmed) == nil {
					*errors = append(*errors, ExpressionError{Message: "Invalid IP value: " + trimmed, Suggestion: "Use an IP address such as 203.0.113.10"})
				}
			}
		case "ip.geoip.country":
			for _, value := range node.Values {
				trimmed := strings.Trim(value, `"'`)
				if len(trimmed) != 2 || !isAlpha(trimmed) {
					*errors = append(*errors, ExpressionError{Message: "Invalid country code: " + trimmed, Suggestion: "Use a two-letter ISO country code such as US or TN"})
				}
			}
		}
	}
	for _, child := range node.Children {
		collectTypedValueErrors(child, errors)
	}
}

func isAlpha(value string) bool {
	for _, char := range value {
		if !unicode.IsLetter(char) {
			return false
		}
	}
	return value != ""
}

func normalizeFieldAlias(field string) string {
	switch strings.ToLower(field) {
	case "client.ip":
		return "ip.src"
	case "asn":
		return "ip.asn"
	case "ip_reputation", "reputation_score":
		return "ip.reputation.score"
	case "path":
		return "http.request.uri.path"
	case "method":
		return "http.request.method"
	case "user_agent":
		return "http.user_agent"
	case "country":
		return "ip.geoip.country"
	case "aegis.bot_score", "cf.bot_score", "bot_score":
		return "aegis.bot.score"
	case "bot_category":
		return "aegis.bot.category"
	case "verified_bot":
		return "aegis.bot.verified"
	case "is_headless", "headless":
		return "aegis.bot.headless"
	case "aegis.waf_score", "waf_score":
		return "aegis.waf.score"
	case "ja3":
		return "tls.ja3"
	case "ja4":
		return "tls.ja4"
	default:
		return field
	}
}

func supportedOperator(op string) bool {
	switch strings.ToLower(op) {
	case "eq", "==", "ne", "!=", "contains", "starts_with", "ends_with", "matches", "gt", "lt", "ge", "le":
		return true
	default:
		return false
	}
}

func quoteValues(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, quoteValue(value))
	}
	return strings.Join(quoted, " ")
}

func quoteValue(value string) string {
	if value == "true" || value == "false" {
		return value
	}
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		return value
	}
	return strconv.Quote(value)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		trimmed := strings.Trim(value, `"'`)
		if strings.EqualFold(trimmed, wanted) || cidrMatches(wanted, trimmed) {
			return true
		}
	}
	return false
}
