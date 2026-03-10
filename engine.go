package goazurepolicyeng

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/matt-FFFFFF/goarmfunctions"
	"github.com/matt-FFFFFF/goarmfunctions/armparser"
	"github.com/matt-FFFFFF/goazurepolicyeng/condition"
	"github.com/matt-FFFFFF/goazurepolicyeng/effect"
	"github.com/matt-FFFFFF/goazurepolicyeng/result"
	"github.com/matt-FFFFFF/goazurepolicyeng/scope"
)

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

// New creates a new Engine with the given alias resolver and options.
func New(aliases AliasResolver, opts ...Option) *Engine {
	e := &Engine{aliases: aliases}
	for _, o := range opts {
		o(e)
	}
	return e
}

// EvaluateInput bundles everything needed to evaluate one policy against one resource.
type EvaluateInput struct {
	Definition *PolicyDefinition
	Assignment *Assignment
	Resource   *Resource
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

	// 1. Parse the policy rule
	parsed, err := ParsePolicyRule(def.PolicyRule)
	if err != nil {
		return EvaluationResult{State: Error, Errors: []error{err}}
	}

	// 2. Resolve effect (may be overridden by initiative, or be a parameter expression)
	effectStr := parsed.Effect
	if assignment.EffectOverride != "" {
		effectStr = assignment.EffectOverride
	}
	if isExpression(effectStr) {
		resolved, err := e.evalExpression(ctx, effectStr, assignment.Parameters, def.Parameters)
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

	// 4. Build EvalContext
	evalCtx := e.buildEvalContext(ctx, resource, assignment, def)

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
	params := mergeParameters(assignment.Parameters, def.Parameters)

	evalCtx := &condition.EvalContext{
		ResourceJSON: string(resource.Raw),
		ResolveField: func(json string, field string) (any, error) {
			if e.resolveField != nil {
				return e.resolveField(json, field)
			}
			return nil, fmt.Errorf("no field resolver configured")
		},
		ResolveFieldArray: func(json string, field string) ([]any, error) {
			if e.resolveFieldArray != nil {
				return e.resolveFieldArray(json, field)
			}
			return nil, fmt.Errorf("no field array resolver configured")
		},
		Operators: condition.DefaultOperatorRegistry(),
		EvalExpression: func(expr string) (any, error) {
			return e.evalExpression(ctx, expr, params, nil)
		},
		CountScopes: nil,
		Tracing:     e.tracing,
	}
	if e.tracing {
		evalCtx.Trace = result.NewTrace()
	}
	return evalCtx
}

// evalExpression evaluates an ARM template expression using goarmfunctions.
func (e *Engine) evalExpression(ctx context.Context, expr string, assignmentParams map[string]ParameterValue, defParams map[string]ParameterDefinition) (any, error) {
	// Build parameter scope
	paramScope := make(map[string]any)
	for k, v := range assignmentParams {
		paramScope[k] = v.Value
	}
	if defParams != nil {
		for k, def := range defParams {
			if _, ok := paramScope[k]; !ok && def.DefaultValue != nil {
				paramScope[k] = def.DefaultValue
			}
		}
	}

	// goarmfunctions: build scope chain and evaluate with registry
	evalCtx := armparser.FromMap(paramScope)
	registry := armparser.DefaultRegistry()

	result, err := goarmfunctions.Evaluate(ctx, expr, evalCtx, registry, nil)
	if err != nil {
		return nil, fmt.Errorf("evaluating expression %q: %w", expr, err)
	}

	return result, nil
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
	if defined != nil {
		for k, def := range defined {
			if _, ok := merged[k]; !ok && def.DefaultValue != nil {
				merged[k] = ParameterValue{Value: def.DefaultValue}
			}
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
	for i := range resources {
		select {
		case <-ctx.Done():
			break
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
			Definition: def,
			Assignment: memberAssignment,
			Resource:   resource,
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
