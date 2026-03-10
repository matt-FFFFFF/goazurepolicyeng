package condition

// Node is the interface for all condition tree nodes.
type Node interface {
	Evaluate(ctx *EvalContext) (bool, error)
}

// EvalContext carries evaluation state through the tree.
type EvalContext struct {
	// Will be filled in Phase 5
}

// AllOf requires all children to be true (logical AND).
type AllOf struct {
	Conditions []Node
}

func (a *AllOf) Evaluate(_ *EvalContext) (bool, error) { return false, nil }

// AnyOf requires at least one child to be true (logical OR).
type AnyOf struct {
	Conditions []Node
}

func (a *AnyOf) Evaluate(_ *EvalContext) (bool, error) { return false, nil }

// Not negates its child.
type Not struct {
	Condition Node
}

func (n *Not) Evaluate(_ *EvalContext) (bool, error) { return false, nil }

// FieldCondition is a leaf: resolve a field alias and compare with an operator.
type FieldCondition struct {
	Field    string // alias or built-in field name
	Operator string // "equals", "notEquals", "contains", "in", "like", "match", etc.
	Value    any    // the operand to compare against
}

func (f *FieldCondition) Evaluate(_ *EvalContext) (bool, error) { return false, nil }

// ValueCondition evaluates an ARM expression and compares the result.
type ValueCondition struct {
	Value    string // ARM expression, e.g. "[concat(field('name'), '-suffix')]"
	Operator string
	Operand  any // the value to compare against
}

func (v *ValueCondition) Evaluate(_ *EvalContext) (bool, error) { return false, nil }

// CountCondition evaluates a count expression.
type CountCondition struct {
	// FieldCount
	Field string // e.g. "Microsoft.Network/nsg/securityRules[*]" — must contain [*]
	// ValueCount
	ValueExpr string // ARM expression that returns an array
	// Common
	Name  string // iteration variable name (required for value count, optional for field count)
	Where Node   // optional condition evaluated per element
	// The outer operator + operand
	Operator string
	Operand  any
}

func (c *CountCondition) Evaluate(_ *EvalContext) (bool, error) { return false, nil }
