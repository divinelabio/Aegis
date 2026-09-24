package rules

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type EventSink interface {
	RecordRuleEvent(ctx context.Context, event RuleEvent)
}

type RuleEvent struct {
	Timestamp time.Time
	Rule      SecurityRule
	Verdict   Verdict
	Request   RequestContext
	Status    int
}

// RuleSource supplies the ordered unified rule set used by the request engine.
// The production implementation is Store; keeping this boundary narrow makes
// snapshot behavior independently testable without a PostgreSQL dependency.
type RuleSource interface {
	List(context.Context) ([]SecurityRule, error)
}

// RuleChangeSubscriber is implemented by a source that can announce a
// committed change to its rule set.
type RuleChangeSubscriber interface {
	SubscribeRuleChanges(func(context.Context))
}

type compiledRule struct {
	rule       SecurityRule
	expression *ASTNode
}

type ruleSnapshot struct {
	rules                    []compiledRule
	hasGlobalMiddlewareRules bool
}

type Engine struct {
	source    RuleSource
	sink      EventSink
	snapshot  atomic.Pointer[ruleSnapshot]
	refreshMu sync.Mutex
}

func NewEngine(source RuleSource, sink EventSink) *Engine {
	engine := &Engine{source: source, sink: sink}
	if subscriber, ok := source.(RuleChangeSubscriber); ok {
		subscriber.SubscribeRuleChanges(func(ctx context.Context) {
			// A refresh failure invalidates the previous snapshot so traffic never
			// evaluates a rule set known to be stale. The next request retries the
			// load and retains the existing fail-open behavior on a store error.
			_ = engine.Refresh(ctx)
		})
	}
	return engine
}

func (e *Engine) Evaluate(ctx context.Context, req RequestContext) (Verdict, error) {
	return e.EvaluateWithFilter(ctx, req, nil)
}

// Refresh atomically publishes the latest ordered rule set. It is called at
// startup and after successful rule-store mutations, never for steady-state
// request evaluation.
func (e *Engine) Refresh(ctx context.Context) error {
	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()
	return e.refreshLocked(ctx)
}

func (e *Engine) EvaluateWithFilter(ctx context.Context, req RequestContext, include func(SecurityRule) bool) (Verdict, error) {
	snapshot, err := e.currentSnapshot(ctx)
	if err != nil {
		return Verdict{Action: ActionAllow}, err
	}
	return evaluateSnapshot(snapshot, req, include)
}

func evaluateSnapshot(snapshot *ruleSnapshot, req RequestContext, include func(SecurityRule) bool) (Verdict, error) {
	for _, compiled := range snapshot.rules {
		rule := compiled.rule
		if !rule.Enabled {
			continue
		}
		if include != nil && !include(rule) {
			continue
		}
		if compiled.expression == nil {
			continue
		}
		matched, err := EvaluateAST(compiled.expression, req)
		if err != nil || !matched {
			continue
		}
		return Verdict{
			Matched:      true,
			RuleID:       rule.ID,
			RuleName:     rule.Name,
			RuleType:     rule.Type,
			RuleVersion:  rule.Version,
			Action:       rule.Action,
			ActionParams: cloneRuleActionParams(rule.ActionParams),
			Reason:       "matched unified security rule",
		}, nil
	}
	return Verdict{Action: ActionAllow}, nil
}

func (e *Engine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snapshot, err := e.currentSnapshot(r.Context())
		if err != nil || !snapshot.hasGlobalMiddlewareRules {
			next.ServeHTTP(w, r)
			return
		}
		reqCtx := NewRequestContext(r)
		verdict, err := evaluateSnapshot(snapshot, reqCtx, isGlobalMiddlewareRule)
		if err != nil || !verdict.Matched {
			next.ServeHTTP(w, r)
			return
		}

		status := http.StatusOK
		switch verdict.Action {
		case ActionBlock:
			status = http.StatusForbidden
			if e.sink != nil {
				e.sink.RecordRuleEvent(r.Context(), RuleEvent{Timestamp: time.Now().UTC(), Verdict: verdict, Request: reqCtx, Status: status})
			}
			http.Error(w, "blocked by Aegis security rule", http.StatusForbidden)
			return
		case ActionRedirect:
			target := verdict.ActionParams["location"]
			if target == "" {
				target = "/"
			}
			status = http.StatusFound
			if e.sink != nil {
				e.sink.RecordRuleEvent(r.Context(), RuleEvent{Timestamp: time.Now().UTC(), Verdict: verdict, Request: reqCtx, Status: status})
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		default:
			if e.sink != nil {
				e.sink.RecordRuleEvent(r.Context(), RuleEvent{Timestamp: time.Now().UTC(), Verdict: verdict, Request: reqCtx, Status: status})
			}
			next.ServeHTTP(w, r)
		}
	})
}

func (e *Engine) currentSnapshot(ctx context.Context) (*ruleSnapshot, error) {
	if snapshot := e.snapshot.Load(); snapshot != nil {
		return snapshot, nil
	}

	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()
	if snapshot := e.snapshot.Load(); snapshot != nil {
		return snapshot, nil
	}
	if err := e.refreshLocked(ctx); err != nil {
		return nil, err
	}
	return e.snapshot.Load(), nil
}

func (e *Engine) refreshLocked(ctx context.Context) error {
	if e.source == nil {
		return errors.New("security rule source is required")
	}
	rules, err := e.source.List(ctx)
	if err != nil {
		e.snapshot.Store(nil)
		return err
	}
	compiled, hasGlobalMiddlewareRules := compileSecurityRules(cloneSecurityRules(rules))
	e.snapshot.Store(&ruleSnapshot{rules: compiled, hasGlobalMiddlewareRules: hasGlobalMiddlewareRules})
	return nil
}

func compileSecurityRules(rules []SecurityRule) ([]compiledRule, bool) {
	compiled := make([]compiledRule, len(rules))
	hasGlobalMiddlewareRules := false
	for index, rule := range rules {
		compiled[index].rule = rule
		expression, err := ParseExpression(rule.Expression)
		if err == nil {
			compileASTMatchers(expression)
			compileASTFieldSources(expression)
			compiled[index].expression = expression
			if rule.Enabled && isGlobalMiddlewareRule(rule) {
				hasGlobalMiddlewareRules = true
			}
		}
	}
	return compiled, hasGlobalMiddlewareRules
}

func isGlobalMiddlewareRule(rule SecurityRule) bool {
	return rule.Type != RuleTypeBot && !strings.EqualFold(rule.Section, "bot") && !strings.EqualFold(rule.Section, "bot_protection")
}

func cloneSecurityRules(rules []SecurityRule) []SecurityRule {
	cloned := make([]SecurityRule, len(rules))
	for index, rule := range rules {
		cloned[index] = rule
		cloned[index].ActionParams = cloneRuleActionParams(rule.ActionParams)
		cloned[index].Tags = append([]string(nil), rule.Tags...)
		if rule.LastMatchedAt != nil {
			matchedAt := *rule.LastMatchedAt
			cloned[index].LastMatchedAt = &matchedAt
		}
	}
	return cloned
}

func cloneRuleActionParams(params map[string]string) map[string]string {
	if params == nil {
		return nil
	}
	cloned := make(map[string]string, len(params))
	for key, value := range params {
		cloned[key] = value
	}
	return cloned
}

func Templates() []SecurityRule {
	return []SecurityRule{
		{Name: "Block high-risk countries", Description: "Block requests from selected countries", Enabled: false, Priority: 100, Type: RuleTypeGeo, Section: "geo_ip", Phase: "access", Expression: `ip.geoip.country in {"CN" "RU"}`, Action: ActionBlock, Tags: []string{"template", "geo"}},
		{Name: "Protect API from suspicious bots", Description: "Challenge low bot-score API traffic", Enabled: false, Priority: 200, Type: RuleTypeBot, Section: "bot", Phase: "bot", Expression: `http.request.uri.path starts_with "/api/" and aegis.bot.score lt 30`, Action: ActionChallenge, Tags: []string{"template", "bot", "api"}},
		{Name: "Rate limit login", Description: "Limit repeated login traffic", Enabled: false, Priority: 250, Type: RuleTypeRateLimit, Section: "rate_limit", Phase: "rate_limit", Expression: `http.request.uri.path starts_with "/login"`, Action: ActionRateLimit, ActionParams: map[string]string{"rate": "20", "burst": "5", "window": "60s"}, Tags: []string{"template", "rate_limit"}},
		{Name: "Require valid API auth", Description: "Block API calls without valid auth", Enabled: false, Priority: 275, Type: RuleTypeAPI, Section: "api", Phase: "api", Expression: `api.path starts_with "/api/" and api.auth.valid eq false`, Action: ActionBlock, Tags: []string{"template", "api"}},
		{Name: "Log old TLS", Description: "Log requests using old TLS versions", Enabled: false, Priority: 290, Type: RuleTypeHTTPSec, Section: "http_security", Phase: "http_security", Expression: `tls.version in {"TLS1.0" "TLS1.1"}`, Action: ActionLog, Tags: []string{"template", "http_security"}},
		{Name: "Log admin access", Description: "Log all requests to admin paths", Enabled: false, Priority: 300, Type: RuleTypeCustom, Section: "custom", Phase: "http_request_firewall_custom", Expression: `http.request.uri.path starts_with "/admin"`, Action: ActionLog, Tags: []string{"template", "audit"}},
	}
}
