package condition

import (
	"fmt"
	"strings"
	"time"

	"github.com/matt-FFFFFF/goazurepolicyeng/result"
)

// Node is the interface for all condition tree nodes.
type Node interface {
	Evaluate(ctx *EvalContext) (bool, error)
}

// FieldResolver resolves a field reference from resource JSON.
type FieldResolver func(resourceJSON string, field string) (any, error)

// FieldArrayResolver resolves a [*] array field reference.
type FieldArrayResolver func(resourceJSON string, field string) ([]any, error)

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
	Trace          *result.Trace
	Reasons        []result.Reason // collected during evaluation
	depth          int             // current evaluation depth for trace indentation
}

// child returns a shallow copy of EvalContext with incremented depth.
func (ctx *EvalContext) child() *EvalContext {
	c := *ctx
	c.depth = ctx.depth + 1
	return &c
}

// AllOf requires all children to be true (logical AND).
type AllOf struct {
	Conditions []Node
}

func (a *AllOf) Evaluate(ctx *EvalContext) (bool, error) {
	var start time.Time
	if ctx.Tracing {
		start = time.Now()
	}
	res := true
	for _, c := range a.Conditions {
		r, err := c.Evaluate(ctx.child())
		if err != nil {
			return false, err
		}
		if !r {
			res = false
			break
		}
	}
	if ctx.Tracing && ctx.Trace != nil {
		ctx.Trace.Record(result.TraceStep{
			Depth:    ctx.depth,
			Type:     "allOf",
			Result:   res,
			Duration: time.Since(start),
			Detail:   fmt.Sprintf("allOf: %d conditions, result=%v", len(a.Conditions), res),
		})
	}
	return res, nil
}

// AnyOf requires at least one child to be true (logical OR).
type AnyOf struct {
	Conditions []Node
}

func (a *AnyOf) Evaluate(ctx *EvalContext) (bool, error) {
	var start time.Time
	if ctx.Tracing {
		start = time.Now()
	}
	var res bool
	for _, c := range a.Conditions {
		r, err := c.Evaluate(ctx.child())
		if err != nil {
			return false, err
		}
		if r {
			res = true
			break
		}
	}
	if ctx.Tracing && ctx.Trace != nil {
		ctx.Trace.Record(result.TraceStep{
			Depth:    ctx.depth,
			Type:     "anyOf",
			Result:   res,
			Duration: time.Since(start),
			Detail:   fmt.Sprintf("anyOf: %d conditions, result=%v", len(a.Conditions), res),
		})
	}
	return res, nil
}

// Not negates its child.
type Not struct {
	Condition Node
}

func (n *Not) Evaluate(ctx *EvalContext) (bool, error) {
	var start time.Time
	if ctx.Tracing {
		start = time.Now()
	}
	r, err := n.Condition.Evaluate(ctx.child())
	if err != nil {
		return false, err
	}
	res := !r
	if ctx.Tracing && ctx.Trace != nil {
		ctx.Trace.Record(result.TraceStep{
			Depth:    ctx.depth,
			Type:     "not",
			Result:   res,
			Duration: time.Since(start),
			Detail:   fmt.Sprintf("not: child=%v, result=%v", r, res),
		})
	}
	return res, nil
}

// FieldCondition is a leaf: resolve a field alias and compare with an operator.
type FieldCondition struct {
	Field    string // alias or built-in field name
	Operator string // "equals", "notEquals", "contains", "in", "like", "match", etc.
	Value    any    // the operand to compare against
}

func (f *FieldCondition) Evaluate(ctx *EvalContext) (bool, error) {
	var start time.Time
	if ctx.Tracing {
		start = time.Now()
	}

	op, ok := ctx.Operators.Get(f.Operator)
	if !ok {
		return false, fmt.Errorf("unknown operator: %s", f.Operator)
	}

	var res bool
	var resolvedValue any

	// Check if this is an array alias with [*]
	if strings.Contains(f.Field, "[*]") {
		values, err := ctx.ResolveFieldArray(ctx.ResourceJSON, f.Field)
		if err != nil {
			return false, err
		}
		if len(values) == 0 {
			res = true // vacuous truth — empty array
		} else {
			res = true
			for _, v := range values {
				r, err := op.Evaluate(v, f.Value)
				if err != nil {
					return false, err
				}
				if !r {
					res = false
					break
				}
			}
			if len(values) > 0 {
				resolvedValue = values
			}
		}
	} else {
		// Scalar field
		value, err := ctx.ResolveField(ctx.ResourceJSON, f.Field)
		if err != nil {
			return false, err
		}
		resolvedValue = value
		res, err = op.Evaluate(value, f.Value)
		if err != nil {
			return false, err
		}
	}

	if res {
		ctx.Reasons = append(ctx.Reasons, result.Reason{
			Field:    f.Field,
			Operator: f.Operator,
			Expected: f.Value,
			Actual:   resolvedValue,
			Message:  fmt.Sprintf("Field '%s' %s '%v' (actual: '%v')", f.Field, f.Operator, f.Value, resolvedValue),
		})
	}

	if ctx.Tracing && ctx.Trace != nil {
		ctx.Trace.Record(result.TraceStep{
			Depth:    ctx.depth,
			Type:     "field",
			Result:   res,
			Duration: time.Since(start),
			Field:    f.Field,
			Operator: f.Operator,
			Expected: f.Value,
			Actual:   resolvedValue,
			Detail:   fmt.Sprintf("field '%s' %s '%v': actual='%v' → %v", f.Field, f.Operator, f.Value, resolvedValue, res),
		})
	}
	return res, nil
}

// ValueCondition evaluates an ARM expression and compares the result.
type ValueCondition struct {
	Value    string // ARM expression, e.g. "[concat(field('name'), '-suffix')]"
	Operator string
	Operand  any // the value to compare against
}

func (v *ValueCondition) Evaluate(ctx *EvalContext) (bool, error) {
	var start time.Time
	if ctx.Tracing {
		start = time.Now()
	}

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

	res, err := op.Evaluate(resolved, v.Operand)
	if err != nil {
		return false, err
	}

	if ctx.Tracing && ctx.Trace != nil {
		ctx.Trace.Record(result.TraceStep{
			Depth:    ctx.depth,
			Type:     "value",
			Result:   res,
			Duration: time.Since(start),
			Operator: v.Operator,
			Expected: v.Operand,
			Actual:   resolved,
			Detail:   fmt.Sprintf("value '%s' %s '%v': resolved='%v' → %v", v.Value, v.Operator, v.Operand, resolved, res),
		})
	}
	return res, nil
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
	var start time.Time
	if ctx.Tracing {
		start = time.Now()
	}

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
				fieldPrefix := c.Field

				childCtx.ResolveFieldArray = func(resourceJSON string, field string) ([]any, error) {
					if field == fieldPrefix {
						return []any{v}, nil
					}
					if strings.HasPrefix(field, fieldPrefix) && len(field) > len(fieldPrefix) && field[len(fieldPrefix)] == '.' {
						suffix := field[len(fieldPrefix)+1:]
						if elem, ok := v.(map[string]any); ok {
							val := resolveNestedProperty(elem, suffix)
							return []any{val}, nil
						}
						return []any{nil}, nil
					}
					return parentResolveFieldArray(resourceJSON, field)
				}

				childCtx.ResolveField = func(resourceJSON string, field string) (any, error) {
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

	res, err := op.Evaluate(count, c.Operand)
	if err != nil {
		return false, err
	}

	if ctx.Tracing && ctx.Trace != nil {
		countVal := count
		ctx.Trace.Record(result.TraceStep{
			Depth:    ctx.depth,
			Type:     "count",
			Result:   res,
			Duration: time.Since(start),
			Operator: c.Operator,
			Expected: c.Operand,
			Count:    &countVal,
			Detail:   fmt.Sprintf("count: %d %s %v → %v", count, c.Operator, c.Operand, res),
		})
	}
	return res, nil
}

func (c *CountCondition) childContext(ctx *EvalContext, currentElement any) *EvalContext {
	childCtx := *ctx
	childCtx.depth = ctx.depth + 1
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
	if c.Name == "" {
		childCtx.CountScopes["default"] = currentElement
	}

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
