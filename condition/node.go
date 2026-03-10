package condition

import (
	"fmt"
	"strings"
)

// Node is the interface for all condition tree nodes.
type Node interface {
	Evaluate(ctx *EvalContext) (bool, error)
}

// FieldResolver resolves a field reference from resource JSON.
type FieldResolver func(resourceJSON string, field string) (any, error)

// FieldArrayResolver resolves a [*] array field reference.
type FieldArrayResolver func(resourceJSON string, field string) ([]any, error)

// Trace records evaluation steps for diagnostics.
type Trace struct {
	Steps []TraceStep
}

// TraceStep is a single evaluation step.
type TraceStep struct {
	Depth   int
	Type    string // "allOf", "anyOf", "not", "field", "value", "count"
	Result  bool
	Field   string
	Value   any
	Details string
}

// Record adds a step to the trace.
func (t *Trace) Record(step TraceStep) {
	t.Steps = append(t.Steps, step)
}

// EvalContext carries evaluation state through the condition tree.
type EvalContext struct {
	ResourceJSON      string
	ResolveField      FieldResolver
	ResolveFieldArray FieldArrayResolver
	Operators         *OperatorRegistry
	EvalExpression    func(expr string) (any, error)
	CountScopes       map[string]any
	// ResolveCurrent returns the current count iteration value for the given name.
	// Empty string means the default/unnamed scope.
	ResolveCurrent func(name string) (any, bool)
	Tracing        bool
	Trace          *Trace
}

// AllOf requires all children to be true (logical AND).
type AllOf struct {
	Conditions []Node
}

func (a *AllOf) Evaluate(ctx *EvalContext) (bool, error) {
	for _, c := range a.Conditions {
		result, err := c.Evaluate(ctx)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil
		}
	}
	return true, nil
}

// AnyOf requires at least one child to be true (logical OR).
type AnyOf struct {
	Conditions []Node
}

func (a *AnyOf) Evaluate(ctx *EvalContext) (bool, error) {
	for _, c := range a.Conditions {
		result, err := c.Evaluate(ctx)
		if err != nil {
			return false, err
		}
		if result {
			return true, nil
		}
	}
	return false, nil
}

// Not negates its child.
type Not struct {
	Condition Node
}

func (n *Not) Evaluate(ctx *EvalContext) (bool, error) {
	result, err := n.Condition.Evaluate(ctx)
	if err != nil {
		return false, err
	}
	return !result, nil
}

// FieldCondition is a leaf: resolve a field alias and compare with an operator.
type FieldCondition struct {
	Field    string // alias or built-in field name
	Operator string // "equals", "notEquals", "contains", "in", "like", "match", etc.
	Value    any    // the operand to compare against
}

func (f *FieldCondition) Evaluate(ctx *EvalContext) (bool, error) {
	op, ok := ctx.Operators.Get(f.Operator)
	if !ok {
		return false, fmt.Errorf("unknown operator: %s", f.Operator)
	}

	// Check if this is an array alias with [*]
	if strings.Contains(f.Field, "[*]") {
		values, err := ctx.ResolveFieldArray(ctx.ResourceJSON, f.Field)
		if err != nil {
			return false, err
		}
		if len(values) == 0 {
			return true, nil // vacuous truth — empty array
		}
		for _, v := range values {
			result, err := op.Evaluate(v, f.Value)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil
			}
		}
		return true, nil
	}

	// Scalar field
	value, err := ctx.ResolveField(ctx.ResourceJSON, f.Field)
	if err != nil {
		return false, err
	}
	return op.Evaluate(value, f.Value)
}

// ValueCondition evaluates an ARM expression and compares the result.
type ValueCondition struct {
	Value    string // ARM expression, e.g. "[concat(field('name'), '-suffix')]"
	Operator string
	Operand  any // the value to compare against
}

func (v *ValueCondition) Evaluate(ctx *EvalContext) (bool, error) {
	if ctx.EvalExpression == nil {
		return false, fmt.Errorf("ARM expression evaluation not configured")
	}
	op, ok := ctx.Operators.Get(v.Operator)
	if !ok {
		return false, fmt.Errorf("unknown operator: %s", v.Operator)
	}

	resolved, err := ctx.EvalExpression(v.Value)
	if err != nil {
		return false, fmt.Errorf("evaluating expression %q: %w", v.Value, err)
	}

	return op.Evaluate(resolved, v.Operand)
}

// CountCondition evaluates a count expression.
type CountCondition struct {
	// FieldCount
	Field string // e.g. "Microsoft.Network/nsg/securityRules[*]" — must contain [*]
	// ValueCount
	ValueExpr string // ARM expression that returns an array
	// Common
	Name  string // iteration variable name
	Where Node   // optional condition evaluated per element
	// The outer operator + operand
	Operator string
	Operand  any
}

func (c *CountCondition) Evaluate(ctx *EvalContext) (bool, error) {
	op, ok := ctx.Operators.Get(c.Operator)
	if !ok {
		return false, fmt.Errorf("unknown operator: %s", c.Operator)
	}

	var count int

	if c.Field != "" {
		values, err := ctx.ResolveFieldArray(ctx.ResourceJSON, c.Field)
		if err != nil {
			return false, err
		}

		if c.Where == nil {
			count = len(values)
		} else {
			for _, v := range values {
				childCtx := c.childContext(ctx, v)
				// Per-element scoping: wrap resolvers so [*] aliases matching
				// the count field resolve to just the current element.
				parentResolveField := childCtx.ResolveField
				parentResolveFieldArray := childCtx.ResolveFieldArray
				fieldPrefix := c.Field // e.g. "properties.networkAcls.ipRules[*]"

				childCtx.ResolveFieldArray = func(resourceJSON string, field string) ([]any, error) {
					// If the field starts with our count field prefix, resolve from current element
					if field == fieldPrefix {
						return []any{v}, nil
					}
					if strings.HasPrefix(field, fieldPrefix) && len(field) > len(fieldPrefix) && field[len(fieldPrefix)] == '.' {
						// e.g. "ipRules[*].action" → extract ".action" from current element
						suffix := field[len(fieldPrefix)+1:] // after the "."
						if elem, ok := v.(map[string]any); ok {
							val := resolveNestedProperty(elem, suffix)
							return []any{val}, nil
						}
						return []any{nil}, nil
					}
					return parentResolveFieldArray(resourceJSON, field)
				}

				childCtx.ResolveField = func(resourceJSON string, field string) (any, error) {
					// Check count scopes for [*] alias resolution
					if field == fieldPrefix {
						return v, nil
					}
					if strings.HasPrefix(field, fieldPrefix) && len(field) > len(fieldPrefix) && field[len(fieldPrefix)] == '.' {
						suffix := field[len(fieldPrefix)+1:]
						if elem, ok := v.(map[string]any); ok {
							return resolveNestedProperty(elem, suffix), nil
						}
						return nil, nil
					}
					return parentResolveField(resourceJSON, field)
				}

				result, err := c.Where.Evaluate(childCtx)
				if err != nil {
					return false, err
				}
				if result {
					count++
				}
			}
		}
	} else if c.ValueExpr != "" {
		if ctx.EvalExpression == nil {
			return false, fmt.Errorf("ARM expression evaluation not configured for value count")
		}
		resolved, err := ctx.EvalExpression(c.ValueExpr)
		if err != nil {
			return false, err
		}
		arr, ok := resolved.([]any)
		if !ok {
			return false, fmt.Errorf("count value expression did not return array")
		}

		if c.Where == nil {
			count = len(arr)
		} else {
			for _, v := range arr {
				childCtx := c.childContext(ctx, v)
				result, err := c.Where.Evaluate(childCtx)
				if err != nil {
					return false, err
				}
				if result {
					count++
				}
			}
		}
	}

	return op.Evaluate(count, c.Operand)
}

func (c *CountCondition) childContext(ctx *EvalContext, currentElement any) *EvalContext {
	childCtx := *ctx
	if childCtx.CountScopes == nil {
		childCtx.CountScopes = make(map[string]any)
	} else {
		newScopes := make(map[string]any, len(ctx.CountScopes)+1)
		for k, v := range ctx.CountScopes {
			newScopes[k] = v
		}
		childCtx.CountScopes = newScopes
	}
	name := c.Name
	if name == "" {
		if c.Field != "" {
			name = c.Field
		} else {
			name = "default"
		}
	}
	childCtx.CountScopes[name] = currentElement
	// Also store as "default" for unnamed access
	if c.Name == "" {
		childCtx.CountScopes["default"] = currentElement
	}

	// Set up ResolveCurrent to read from count scopes
	scopes := childCtx.CountScopes
	childCtx.ResolveCurrent = func(scopeName string) (any, bool) {
		if scopeName == "" {
			scopeName = "default"
		}
		v, ok := scopes[scopeName]
		return v, ok
	}

	return &childCtx
}

// resolveNestedProperty resolves a dot-separated property path on a map.
func resolveNestedProperty(obj map[string]any, path string) any {
	parts := strings.Split(path, ".")
	var current any = obj
	for _, p := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = m[p]
		if !ok {
			return nil
		}
	}
	return current
}
