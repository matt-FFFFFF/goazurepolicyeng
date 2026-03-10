package goazurepolicyeng

import (
	"context"

	"github.com/matt-FFFFFF/goazurepolicyeng/result"
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

// Engine evaluates Azure Policy rules against resources.
type Engine struct {
	aliases AliasResolver
	related RelatedResourceFinder
	tracing bool
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
	Errors       []error
}

// Evaluate evaluates a single policy against a single resource.
func (e *Engine) Evaluate(ctx context.Context, input EvaluateInput) EvaluationResult {
	// Stub — will be implemented in later phases
	return EvaluationResult{State: NotApplicable}
}
