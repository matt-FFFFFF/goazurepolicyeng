package goazurepolicyeng

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/matt-FFFFFF/goarmfunctions"
	"github.com/matt-FFFFFF/goarmfunctions/armparser"
	"github.com/matt-FFFFFF/goazurepolicyeng/condition"
	"github.com/matt-FFFFFF/goazurepolicyeng/effect"
	"github.com/matt-FFFFFF/goazurepolicyeng/result"
	"github.com/matt-FFFFFF/goazurepolicyeng/scope"
)

// DefaultParseCacheSize is the default number of parsed ARM expression ASTs
// cached by the underlying goarmfunctions evaluator. Repeated evaluations of
// the same expression string (e.g. "[parameters('effect')]") reuse the cached
// parse tree instead of re-parsing, which is substantially faster in bulk
// evaluation scenarios.
const DefaultParseCacheSize = goarmfunctions.DefaultParseCacheSize

// SetParseCacheSize configures the maximum number of parsed expression ASTs
// held in the global LRU cache. Setting size to 0 disables caching (every
// expression is parsed fresh). The cache is shared across all Engine instances.
func SetParseCacheSize(size int) { goarmfunctions.SetParseCacheSize(size) }

// ResetParseCache clears all cached parse results. This is useful in tests or
// after a bulk evaluation pass where the working set of expressions changes
// completely.
func ResetParseCache() { goarmfunctions.ResetParseCache() }

// ParseCacheLen returns the current number of entries in the expression parse
// cache. This is useful for observability and tuning the cache size.
func ParseCacheLen() int { return goarmfunctions.ParseCacheLen() }

// RelatedResourceFinder looks up related resources for AINE/DINE existence checks.
type RelatedResourceFinder interface {
	Find(ctx context.Context, query RelatedResourceQuery) ([]Resource, error)
}

// RelatedResourceQuery describes what related resources to find.
type RelatedResourceQuery struct {
	ResourceType string // e.g. "Microsoft.Compute/virtualMachines/extensions"
	Scope        string // resource group or subscription scope
	Name         string // optional specific resource name
}

// AliasResolver maps Azure policy aliases to values from resource JSON.
// Implementations can be in-memory, file-backed, or DB-backed.
type AliasResolver interface {
	// GetPath returns the gjson path for an alias.
	// Returns empty string and false if alias is unknown.
	GetPath(alias string) (jsonPath string, ok bool)
}

// FieldResolverFunc resolves a field from resource JSON (e.g. via alias lookup).
type FieldResolverFunc func(resourceJSON string, field string) (any, error)

// FieldArrayResolverFunc resolves a [*] array field from resource JSON.
type FieldArrayResolverFunc func(resourceJSON string, field string) ([]any, error)

// Engine evaluates Azure Policy rules against resources.
type Engine struct {
	aliases           AliasResolver
	related           RelatedResourceFinder
	resolveField      FieldResolverFunc
	resolveFieldArray FieldArrayResolverFunc
	tracing           bool

	// parsedRuleCache caches parsed policy rules by definition ID to avoid
	// re-parsing the same policy rule for every resource in bulk evaluation.
	parsedRuleCache sync.Map // map[string]*ParsedRule

	// baseRegistry is a cached base ARM function registry. buildPolicyRegistry
	// clones from this instead of creating a new DefaultRegistry() each time.
	baseRegistryOnce sync.Once
	baseRegistry     *armparser.FuncRegistry

	// evalCtxPool reduces allocation pressure in bulk evaluation by reusing
	// EvalContext structs. Callers must call releaseEvalContext when done.
	evalCtxPool sync.Pool
}

// Option configures the Engine.
type Option func(*Engine)

// WithTracing enables or disables evaluation tracing.
func WithTracing(enabled bool) Option {
	return func(e *Engine) { e.tracing = enabled }
}

// WithRelatedResourceFinder sets the related resource finder for AINE/DINE checks.
func WithRelatedResourceFinder(f RelatedResourceFinder) Option {
	return func(e *Engine) { e.related = f }
}

// WithFieldResolvers sets the field resolution functions.
func WithFieldResolvers(resolve FieldResolverFunc, resolveArray FieldArrayResolverFunc) Option {
	return func(e *Engine) {
		e.resolveField = resolve
		e.resolveFieldArray = resolveArray
	}
}

// WithParseCacheSize sets the maximum number of parsed ARM expression ASTs
// held in the global LRU cache used by goarmfunctions. This is applied once
// at Engine construction time and affects all Engine instances (the cache is
// global). A size of 0 disables caching entirely.
//
// The default is [DefaultParseCacheSize] (1000 entries), which is appropriate
// for most workloads. Increase the size when evaluating policies that contain
// a large number of distinct ARM template expressions (e.g. thousands of
// unique parameter/concat combinations).
func WithParseCacheSize(size int) Option {
	return func(e *Engine) {
		goarmfunctions.SetParseCacheSize(size)
	}
}

// New creates a new Engine with the given alias resolver and options.
func New(aliases AliasResolver, opts ...Option) *Engine {
	e := &Engine{aliases: aliases}
	for _, o := range opts {
		o(e)
	}
	return e
}

// getParsedRule returns a cached ParsedRule for the definition, parsing on first access.
func (e *Engine) getParsedRule(def *PolicyDefinition) (*ParsedRule, error) {
	if def.ID != "" {
		if cached, ok := e.parsedRuleCache.Load(def.ID); ok {
			return cached.(*ParsedRule), nil
		}
	}
	parsed, err := ParsePolicyRule(def.PolicyRule)
	if err != nil {
		return nil, err
	}
	if def.ID != "" {
		e.parsedRuleCache.Store(def.ID, parsed)
	}
	return parsed, nil
}

// EvaluateInput bundles everything needed to evaluate one policy against one resource.
type EvaluateInput struct {
	Definition *PolicyDefinition
	Assignment *Assignment
	Resource   *Resource
	// Initiative context (set when evaluating as part of a policy set)
	SetDefinitionID       string
	DefinitionReferenceID string
}

// EvaluationResult captures the outcome of evaluating one policy against one resource.
type EvaluationResult struct {
	State        ComplianceState
	Effect       string // resolved effect (audit, deny, etc.)
	PolicyID     string // definition ID
	AssignmentID string // assignment ID
	Reasons      []result.Reason
	Trace        *result.Trace // nil unless tracing enabled
	Errors       []error
}

// Evaluate evaluates a single policy against a single resource.
func (e *Engine) Evaluate(ctx context.Context, input EvaluateInput) EvaluationResult {
	def := input.Definition
	assignment := input.Assignment
	resource := input.Resource

	// 1. Parse the policy rule (cached by definition ID)
	parsed, err := e.getParsedRule(def)
	if err != nil {
		return EvaluationResult{State: Error, Errors: []error{err}}
	}

	// 2. Resolve effect (may be overridden by initiative, or be a parameter expression)
	effectStr := parsed.Effect
	if assignment.EffectOverride != "" {
		effectStr = assignment.EffectOverride
	}
	if isExpression(effectStr) {
		params := mergeParameters(assignment.Parameters, def.Parameters)
		armCtx := e.buildScopeChain(resource, assignment, def, params, input.SetDefinitionID, input.DefinitionReferenceID)
		registry := e.buildPolicyRegistry(resource, armCtx)
		resolved, err := e.evalExpression(ctx, effectStr, armCtx, registry, nil)
		if err != nil {
			return EvaluationResult{State: Error, Errors: []error{err}}
		}
		effectStr = fmt.Sprintf("%v", resolved)
	}

	eff, err := effect.ParseEffect(effectStr)
	if err != nil {
		return EvaluationResult{State: Error, Errors: []error{err}}
	}

	// 3. Skip if disabled
	if eff == effect.Disabled {
		return EvaluationResult{State: NotApplicable, Effect: string(eff)}
	}

	// 4. Build EvalContext (with initiative context if present)
	evalCtx := e.buildEvalContextWithInitiative(ctx, resource, assignment, def, input.SetDefinitionID, input.DefinitionReferenceID)
	defer e.releaseEvalContext(evalCtx)

	// 5. Evaluate the if-condition
	matched, err := parsed.Condition.Evaluate(evalCtx)
	if err != nil {
		return EvaluationResult{State: Error, Effect: string(eff), Errors: []error{err}}
	}

	// 6. Determine compliance
	if !matched {
		res := EvaluationResult{State: Compliant, Effect: string(eff)}
		if e.tracing && evalCtx.Trace != nil {
			res.Trace = evalCtx.Trace
		}
		return res
	}

	// 7. For AINE/DINE, check existence
	if eff == effect.AuditIfNotExists || eff == effect.DeployIfNotExists {
		if e.related != nil {
			exists, err := e.checkExistence(ctx, parsed, resource, assignment, def)
			if err != nil {
				return EvaluationResult{State: Error, Effect: string(eff), Errors: []error{err}}
			}
			if exists {
				return EvaluationResult{State: Compliant, Effect: string(eff)}
			}
		}
		// No related resource finder or resource doesn't exist → NonCompliant
	}

	// 8. If-matched + non-existence effects → NonCompliant
	res := EvaluationResult{
		State:   NonCompliant,
		Effect:  string(eff),
		Reasons: evalCtx.Reasons,
	}
	if e.tracing && evalCtx.Trace != nil {
		res.Trace = evalCtx.Trace
	}
	return res
}

// buildEvalContext creates a condition.EvalContext wired to the engine's resolvers.
func (e *Engine) buildEvalContext(ctx context.Context, resource *Resource, assignment *Assignment, def *PolicyDefinition) *condition.EvalContext {
	return e.buildEvalContextWithInitiative(ctx, resource, assignment, def, "", "")
}

// acquireEvalContext gets an EvalContext from the pool or creates a new one.
func (e *Engine) acquireEvalContext() *condition.EvalContext {
	if v := e.evalCtxPool.Get(); v != nil {
		return v.(*condition.EvalContext)
	}
	return &condition.EvalContext{}
}

// releaseEvalContext returns an EvalContext to the pool after resetting it.
func (e *Engine) releaseEvalContext(ctx *condition.EvalContext) {
	ctx.Reset()
	e.evalCtxPool.Put(ctx)
}

// buildEvalContextWithInitiative creates a condition.EvalContext with optional initiative context.
func (e *Engine) buildEvalContextWithInitiative(ctx context.Context, resource *Resource, assignment *Assignment, def *PolicyDefinition, setDefinitionID, definitionReferenceID string) *condition.EvalContext {
	params := mergeParameters(assignment.Parameters, def.Parameters)

	// Build tiered scope chain: parameters → subscription → resourceGroup → policy
	armCtx := e.buildScopeChain(resource, assignment, def, params, setDefinitionID, definitionReferenceID)
	registry := e.buildPolicyRegistry(resource, armCtx)

	evalCtx := e.acquireEvalContext()
	evalCtx.ResourceJSON = string(resource.Raw)
	evalCtx.ResolveField = func(json string, field string) (any, error) {
		if e.resolveField != nil {
			return e.resolveField(json, field)
		}
		return nil, fmt.Errorf("no field resolver configured")
	}
	evalCtx.ResolveFieldArray = func(json string, field string) ([]any, error) {
		if e.resolveFieldArray != nil {
			return e.resolveFieldArray(json, field)
		}
		return nil, fmt.Errorf("no field array resolver configured")
	}
	evalCtx.Operators = condition.DefaultOperatorRegistry()
	evalCtx.CountScopes = nil
	evalCtx.Tracing = e.tracing

	// Assign EvalExpression after creation so the closure can capture evalCtx pointer.
	evalCtx.EvalExpression = func(expr string) (any, error) {
		return e.evalExpression(ctx, expr, armCtx, registry, nil)
	}

	// EvalExpressionWithCurrent is used by childContext to rebind current() in count where clauses.
	evalCtx.EvalExpressionWithCurrent = func(expr string, resolveCurrent func(string) (any, bool)) (any, error) {
		return e.evalExpressionWithCurrent(ctx, expr, armCtx, registry, resolveCurrent)
	}

	if e.tracing {
		evalCtx.Trace = result.NewTrace()
	}
	return evalCtx
}

// buildScopeChain builds a tiered ARM scope chain for expression evaluation.
func (e *Engine) buildScopeChain(resource *Resource, assignment *Assignment, def *PolicyDefinition, params map[string]ParameterValue, setDefinitionID, definitionReferenceID string) armparser.EvalContext {
	// Parameters scope (base)
	paramValues := make(map[string]any)
	for k, v := range params {
		paramValues[k] = v.Value
	}
	paramScope := armparser.NewScope("parameters", paramValues, nil)

	// Subscription scope
	subScope := armparser.NewScope("subscription", map[string]any{
		"subscriptionId": resource.SubscriptionID,
		"id":             "/subscriptions/" + resource.SubscriptionID,
		"tenantId":       resource.TenantID,
	}, paramScope)

	// Resource group scope
	rgScope := armparser.NewScope("resourceGroup", map[string]any{
		"name":     resource.ResourceGroup,
		"location": resource.Location,
		"id":       fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", resource.SubscriptionID, resource.ResourceGroup),
	}, subScope)

	// Policy scope
	policyScope := armparser.NewScope("policy", map[string]any{
		"definitionId":          def.ID,
		"setDefinitionId":       setDefinitionID,
		"definitionReferenceId": definitionReferenceID,
		"assignmentId":          assignment.ID,
	}, rgScope)

	return policyScope
}

// getBaseRegistry returns a cached base ARM function registry.
func (e *Engine) getBaseRegistry() *armparser.FuncRegistry {
	e.baseRegistryOnce.Do(func() {
		e.baseRegistry = armparser.DefaultRegistry()
	})
	return e.baseRegistry
}

// buildPolicyRegistry creates a function registry with policy-specific functions.
func (e *Engine) buildPolicyRegistry(resource *Resource, armCtx armparser.EvalContext) *armparser.FuncRegistry {
	registry := e.getBaseRegistry().Clone()

	// field(aliasName) — resolve a field from the resource
	registry.Register("field", func(ctx context.Context, call *armparser.FunctionCall, evalCtx armparser.EvalContext) (any, error) {
		if len(call.Args) != 1 || call.Args[0].String == nil {
			return nil, fmt.Errorf("field() requires exactly 1 string argument")
		}
		fieldName := *call.Args[0].String
		if e.resolveField == nil {
			return nil, fmt.Errorf("no field resolver configured")
		}
		return e.resolveField(string(resource.Raw), fieldName)
	})

	// subscription() — returns subscription context as a map
	registry.Register("subscription", func(ctx context.Context, call *armparser.FunctionCall, evalCtx armparser.EvalContext) (any, error) {
		s := armparser.FindScope(armCtx, "subscription")
		if s == nil {
			return map[string]any{}, nil
		}
		subID, _ := s.GetLocal("subscriptionId")
		id, _ := s.GetLocal("id")
		tenantID, _ := s.GetLocal("tenantId")
		return map[string]any{
			"subscriptionId": subID,
			"id":             id,
			"tenantId":       tenantID,
		}, nil
	})

	// resourceGroup() — returns RG context as a map
	registry.Register("resourceGroup", func(ctx context.Context, call *armparser.FunctionCall, evalCtx armparser.EvalContext) (any, error) {
		s := armparser.FindScope(armCtx, "resourceGroup")
		if s == nil {
			return map[string]any{}, nil
		}
		name, _ := s.GetLocal("name")
		location, _ := s.GetLocal("location")
		id, _ := s.GetLocal("id")
		return map[string]any{
			"name":     name,
			"location": location,
			"id":       id,
		}, nil
	})

	// policy() — returns policy assignment context
	registry.Register("policy", func(ctx context.Context, call *armparser.FunctionCall, evalCtx armparser.EvalContext) (any, error) {
		s := armparser.FindScope(armCtx, "policy")
		if s == nil {
			return map[string]any{}, nil
		}
		defID, _ := s.GetLocal("definitionId")
		setDefID, _ := s.GetLocal("setDefinitionId")
		defRefID, _ := s.GetLocal("definitionReferenceId")
		assignID, _ := s.GetLocal("assignmentId")
		return map[string]any{
			"definitionId":          defID,
			"setDefinitionId":       setDefID,
			"definitionReferenceId": defRefID,
			"assignmentId":          assignID,
		}, nil
	})

	// requestContext() — stub
	registry.Register("requestContext", func(ctx context.Context, call *armparser.FunctionCall, evalCtx armparser.EvalContext) (any, error) {
		return map[string]any{"apiVersion": ""}, nil
	})

	// ipRangeContains(range, ip) — CIDR containment check
	registry.Register("ipRangeContains", func(ctx context.Context, call *armparser.FunctionCall, evalCtx armparser.EvalContext) (any, error) {
		if len(call.Args) != 2 {
			return nil, fmt.Errorf("ipRangeContains() requires 2 arguments")
		}
		reg := armparser.RegistryFromContext(ctx)
		if reg == nil {
			reg = registry
		}
		arg0, err := call.Args[0].Evaluate(ctx, evalCtx, reg)
		if err != nil {
			return nil, fmt.Errorf("ipRangeContains() first arg: %w", err)
		}
		arg1, err := call.Args[1].Evaluate(ctx, evalCtx, reg)
		if err != nil {
			return nil, fmt.Errorf("ipRangeContains() second arg: %w", err)
		}
		cidr, ok1 := arg0.(string)
		ip, ok2 := arg1.(string)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("ipRangeContains() arguments must be strings")
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return nil, fmt.Errorf("invalid IP %q", ip)
		}
		return network.Contains(parsed), nil
	})

	// addDays(dateTime, days) — date arithmetic
	registry.Register("addDays", func(ctx context.Context, call *armparser.FunctionCall, evalCtx armparser.EvalContext) (any, error) {
		if len(call.Args) != 2 {
			return nil, fmt.Errorf("addDays() requires 2 arguments")
		}
		reg := armparser.RegistryFromContext(ctx)
		if reg == nil {
			reg = registry
		}
		arg0, err := call.Args[0].Evaluate(ctx, evalCtx, reg)
		if err != nil {
			return nil, fmt.Errorf("addDays() first arg: %w", err)
		}
		arg1, err := call.Args[1].Evaluate(ctx, evalCtx, reg)
		if err != nil {
			return nil, fmt.Errorf("addDays() second arg: %w", err)
		}
		dateStr, ok := arg0.(string)
		if !ok {
			return nil, fmt.Errorf("addDays() first argument must be a date string")
		}
		days, ok := toInt(arg1)
		if !ok {
			return nil, fmt.Errorf("addDays() second argument must be an integer")
		}
		t, err := time.Parse(time.RFC3339, dateStr)
		if err != nil {
			return nil, fmt.Errorf("addDays() invalid date %q: %w", dateStr, err)
		}
		return t.AddDate(0, 0, days).Format(time.RFC3339), nil
	})

	return registry
}

// evalExpression evaluates an ARM template expression using goarmfunctions.
func (e *Engine) evalExpression(ctx context.Context, expr string, armCtx armparser.EvalContext, registry *armparser.FuncRegistry, resolveCurrent func(string) (any, bool)) (any, error) {
	return e.evalExpressionWithCurrent(ctx, expr, armCtx, registry, resolveCurrent)
}

// evalExpressionWithCurrent evaluates an ARM expression with optional current() support.
func (e *Engine) evalExpressionWithCurrent(ctx context.Context, expr string, armCtx armparser.EvalContext, registry *armparser.FuncRegistry, resolveCurrent func(string) (any, bool)) (any, error) {
	// Clone registry if we need to register current() to avoid mutating shared state
	reg := registry
	if resolveCurrent != nil {
		reg = registry.Clone()
		reg.Register("current", func(fCtx context.Context, call *armparser.FunctionCall, evalCtx armparser.EvalContext) (any, error) {
			name := ""
			if len(call.Args) > 0 && call.Args[0].String != nil {
				name = *call.Args[0].String
			}
			v, ok := resolveCurrent(name)
			if !ok {
				if name == "" {
					name = "default"
				}
				return nil, fmt.Errorf("current('%s') not found in count scope", name)
			}
			return v, nil
		})
	}

	result, err := goarmfunctions.Evaluate(ctx, expr, armCtx, reg, nil)
	if err != nil {
		return nil, fmt.Errorf("evaluating expression %q: %w", expr, err)
	}

	return result, nil
}

// toInt converts a value to int.
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

// checkExistence runs the AINE/DINE existence check.
func (e *Engine) checkExistence(ctx context.Context, parsed *ParsedRule, resource *Resource, assignment *Assignment, def *PolicyDefinition) (bool, error) {
	// Parse the "then.details" block from the policy rule
	var rule map[string]json.RawMessage
	if err := json.Unmarshal(def.PolicyRule, &rule); err != nil {
		return false, fmt.Errorf("unmarshal policy rule for existence details: %w", err)
	}

	thenRaw, ok := rule["then"]
	if !ok {
		return false, fmt.Errorf("policy rule missing 'then' block")
	}

	var then map[string]json.RawMessage
	if err := json.Unmarshal(thenRaw, &then); err != nil {
		return false, fmt.Errorf("unmarshal 'then': %w", err)
	}

	detailsRaw, ok := then["details"]
	if !ok {
		return false, fmt.Errorf("AINE/DINE policy missing 'details' in 'then'")
	}

	var details effect.ExistenceDetails
	if err := json.Unmarshal(detailsRaw, &details); err != nil {
		return false, fmt.Errorf("unmarshal existence details: %w", err)
	}

	// Build scope from resource ID
	resourceScope := resource.ID
	if idx := strings.LastIndex(resourceScope, "/providers/"); idx >= 0 {
		resourceScope = resourceScope[:idx]
	}

	// Convert RelatedResourceFinder to effect.ResourceFinder
	finder := &relatedFinderAdapter{e.related}

	// Parse the existence condition once and reuse.
	var compiledCond condition.Node
	if len(details.ExistenceCondition) != 0 {
		cond, err := parseCondition(details.ExistenceCondition)
		if err != nil {
			return false, err
		}
		compiledCond = cond
	}

	condEvaluator := func(resourceJSON string) (bool, error) {
		if compiledCond == nil {
			return true, nil
		}
		tempResource := &Resource{Raw: json.RawMessage(resourceJSON)}
		evalCtx := e.buildEvalContext(ctx, tempResource, assignment, def)
		defer e.releaseEvalContext(evalCtx)
		return compiledCond.Evaluate(evalCtx)
	}

	return effect.CheckExistence(ctx, details, resourceScope, finder, condEvaluator)
}

// relatedFinderAdapter adapts RelatedResourceFinder to effect.ResourceFinder.
type relatedFinderAdapter struct {
	inner RelatedResourceFinder
}

func (a *relatedFinderAdapter) Find(ctx context.Context, query effect.ResourceQuery) ([]effect.Resource, error) {
	results, err := a.inner.Find(ctx, RelatedResourceQuery{
		ResourceType: query.ResourceType,
		Scope:        query.Scope,
		Name:         query.Name,
	})
	if err != nil {
		return nil, err
	}
	out := make([]effect.Resource, len(results))
	for i, r := range results {
		out[i] = effect.Resource{JSON: string(r.Raw)}
	}
	return out, nil
}

// isExpression returns true if the string is an ARM template expression (wrapped in brackets).
func isExpression(s string) bool {
	return len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']'
}

// mergeParameters merges assignment parameters with definition defaults.
func mergeParameters(assigned map[string]ParameterValue, defined map[string]ParameterDefinition) map[string]ParameterValue {
	merged := make(map[string]ParameterValue)
	for k, v := range assigned {
		merged[k] = v
	}
	for k, def := range defined {
		if _, ok := merged[k]; !ok && def.DefaultValue != nil {
			merged[k] = ParameterValue{Value: def.DefaultValue}
		}
	}
	return merged
}

// Catalog holds the set of policy definitions and policy set (initiative)
// definitions available for evaluation.
type Catalog struct {
	Definitions    map[string]*PolicyDefinition
	SetDefinitions map[string]*PolicySetDefinition
}

// isAssignmentApplicable checks whether an assignment applies to a resource,
// based on its scope, notScopes, and any resource selectors.
func isAssignmentApplicable(a *Assignment, resource *Resource) bool {
	scopeSelectors := make([]scope.ResourceSelector, len(a.ResourceSelectors))
	for j, rs := range a.ResourceSelectors {
		sels := make([]scope.SelectorExpression, len(rs.Selectors))
		for k, s := range rs.Selectors {
			sels[k] = scope.SelectorExpression{Kind: s.Kind, In: s.In, NotIn: s.NotIn}
		}
		scopeSelectors[j] = scope.ResourceSelector{Name: rs.Name, Selectors: sels}
	}
	return scope.IsApplicable(a.Scope, a.NotScopes, scopeSelectors, resource.ID, resource.Location, resource.Type)
}

// EvaluateAll evaluates all applicable policies against a single resource.
// It handles both direct policy assignments and initiative (policy set) assignments.
func (e *Engine) EvaluateAll(ctx context.Context, resource *Resource, assignments []Assignment, catalog Catalog) []EvaluationResult {
	var results []EvaluationResult
	for i := range assignments {
		a := &assignments[i]

		// Applicability check: includes scope, notScopes, and any resource selectors.
		if !isAssignmentApplicable(a, resource) {
			continue
		}

		// Try direct policy definition first.
		if def, ok := catalog.Definitions[a.PolicyDefinitionID]; ok {
			result := e.Evaluate(ctx, EvaluateInput{
				Definition: def,
				Assignment: a,
				Resource:   resource,
			})
			result.PolicyID = def.ID
			result.AssignmentID = a.ID
			results = append(results, result)
			continue
		}

		// Try policy set (initiative) definition.
		if catalog.SetDefinitions != nil {
			if setDef, ok := catalog.SetDefinitions[a.PolicyDefinitionID]; ok {
				initResults := e.EvaluateInitiative(ctx, resource, a, setDef, catalog.Definitions)
				results = append(results, initResults...)
			}
		}
	}
	return results
}

// EvaluateBulk evaluates all policies against multiple resources using a worker pool.
// It handles both direct policy assignments and initiative (policy set) assignments.
func (e *Engine) EvaluateBulk(ctx context.Context, resources []Resource, assignments []Assignment, catalog Catalog, workers int) map[string][]EvaluationResult {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	results := make(map[string][]EvaluationResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	jobs := make(chan *Resource)

	// Start worker goroutines.
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case r, ok := <-jobs:
					if !ok {
						return
					}
					res := e.EvaluateAll(ctx, r, assignments, catalog)

					mu.Lock()
					results[r.ID] = res
					mu.Unlock()
				}
			}
		}()
	}

	// Feed jobs to the workers.
feedLoop:
	for i := range resources {
		select {
		case <-ctx.Done():
			break feedLoop
		case jobs <- &resources[i]:
		}
	}
	close(jobs)

	wg.Wait()
	return results
}

// EvaluateInitiative evaluates all member policies of an initiative against a resource.
func (e *Engine) EvaluateInitiative(ctx context.Context, resource *Resource, assignment *Assignment, setDef *PolicySetDefinition, definitions map[string]*PolicyDefinition) []EvaluationResult {
	var results []EvaluationResult

	for _, ref := range setDef.PolicyDefinitions {
		def, ok := definitions[ref.PolicyDefinitionID]
		if !ok {
			continue
		}

		// Resolve parameters: initiative params → member params
		memberParams := resolveInitiativeParams(ctx, ref.Parameters, assignment.Parameters, setDef.Parameters)

		memberAssignment := &Assignment{
			ID:                 assignment.ID,
			Scope:              assignment.Scope,
			NotScopes:          assignment.NotScopes,
			PolicyDefinitionID: ref.PolicyDefinitionID,
			Parameters:         memberParams,
			ResourceSelectors:  assignment.ResourceSelectors,
		}

		// Apply overrides if present
		for _, ov := range assignment.Overrides {
			if strings.EqualFold(ov.Kind, "policyEffect") {
				if matchesOverrideSelectors(ov.Selectors, ref.DefinitionReferenceID) {
					// Override the effect by injecting it as a parameter
					// The engine will resolve the effect from the policy rule,
					// but we can override via a synthetic wrapper
					memberAssignment.EffectOverride = ov.Value
				}
			}
		}

		result := e.Evaluate(ctx, EvaluateInput{
			Definition:            def,
			Assignment:            memberAssignment,
			Resource:              resource,
			SetDefinitionID:       setDef.ID,
			DefinitionReferenceID: ref.DefinitionReferenceID,
		})
		result.PolicyID = def.ID
		result.AssignmentID = assignment.ID
		results = append(results, result)
	}

	return results
}

// resolveInitiativeParams resolves parameter expressions from initiative ref params
// against assignment params and set definition defaults.
func resolveInitiativeParams(ctx context.Context, refParams map[string]ParameterValue, assignmentParams map[string]ParameterValue, setParams map[string]ParameterDefinition) map[string]ParameterValue {
	resolved := make(map[string]ParameterValue)
	for k, v := range refParams {
		if s, ok := v.Value.(string); ok && isExpression(s) {
			paramName := extractParameterName(s)
			if paramName != "" {
				if av, ok := assignmentParams[paramName]; ok {
					resolved[k] = av
					continue
				}
				if sd, ok := setParams[paramName]; ok && sd.DefaultValue != nil {
					resolved[k] = ParameterValue{Value: sd.DefaultValue}
					continue
				}
			}
		}
		resolved[k] = v
	}
	return resolved
}

// extractParameterName extracts the parameter name from "[parameters('name')]".
var parameterExprRegex = regexp.MustCompile(`^\[parameters\('([^']+)'\)\]$`)

func extractParameterName(expr string) string {
	matches := parameterExprRegex.FindStringSubmatch(expr)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

// hasScopePrefix checks if id starts with scope at a path-segment boundary.
func hasScopePrefix(id, scope string) bool {
	if !strings.HasPrefix(id, scope) {
		return false
	}
	if len(id) == len(scope) {
		return true
	}
	return id[len(scope)] == '/'
}

// isInScope checks if a resource ID falls under the assignment scope and is not excluded.
func isInScope(resourceID, assignmentScope string, notScopes []string) bool {
	lowerID := strings.ToLower(resourceID)
	lowerScope := strings.ToLower(assignmentScope)

	if !hasScopePrefix(lowerID, lowerScope) {
		return false
	}

	for _, ns := range notScopes {
		if hasScopePrefix(lowerID, strings.ToLower(ns)) {
			return false
		}
	}

	return true
}

// matchesOverrideSelectors checks if an override applies to a given definition reference.
func matchesOverrideSelectors(selectors []SelectorExpression, defRefID string) bool {
	if len(selectors) == 0 {
		return true // no selectors means applies to all
	}
	for _, sel := range selectors {
		if strings.EqualFold(sel.Kind, "policyDefinitionReferenceId") {
			// Check NotIn first so exclusions take precedence
			for _, id := range sel.NotIn {
				if strings.EqualFold(id, defRefID) {
					return false
				}
			}
			for _, id := range sel.In {
				if strings.EqualFold(id, defRefID) {
					return true
				}
			}
		}
	}
	return false
}
