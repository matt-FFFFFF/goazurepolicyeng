package condition

import (
	"strings"
	"sync"
)

// Operator evaluates a comparison between a field/value and a condition operand.
type Operator interface {
	Evaluate(fieldValue any, conditionValue any) (bool, error)
}

// OperatorFunc adapts a function to the Operator interface.
type OperatorFunc func(fieldValue any, conditionValue any) (bool, error)

func (f OperatorFunc) Evaluate(fv any, cv any) (bool, error) { return f(fv, cv) }

// OperatorRegistry stores operators by name.
type OperatorRegistry struct {
	ops map[string]Operator
}

// NewOperatorRegistry creates an empty registry.
func NewOperatorRegistry() *OperatorRegistry {
	return &OperatorRegistry{ops: make(map[string]Operator)}
}

// Register adds an operator. Name is stored lowercase.
func (r *OperatorRegistry) Register(name string, op Operator) {
	r.ops[strings.ToLower(name)] = op
}

// Get retrieves an operator by name (case-insensitive).
func (r *OperatorRegistry) Get(name string) (Operator, bool) {
	op, ok := r.ops[strings.ToLower(name)]
	return op, ok
}

var (
	defaultOperatorRegistryOnce sync.Once
	defaultOperatorRegistry     *OperatorRegistry
)

// DefaultOperatorRegistry returns a shared, read-only registry with all Azure Policy operators.
// The registry is created once and reused across all callers.
func DefaultOperatorRegistry() *OperatorRegistry {
	defaultOperatorRegistryOnce.Do(func() {
		defaultOperatorRegistry = newDefaultOperatorRegistry()
	})
	return defaultOperatorRegistry
}

func newDefaultOperatorRegistry() *OperatorRegistry {
	r := NewOperatorRegistry()
	r.Register("equals", OperatorFunc(opEquals))
	r.Register("notEquals", OperatorFunc(opNotEquals))
	r.Register("like", OperatorFunc(opLike))
	r.Register("notLike", OperatorFunc(opNotLike))
	r.Register("match", OperatorFunc(opMatch))
	r.Register("notMatch", OperatorFunc(opNotMatch))
	r.Register("matchInsensitively", OperatorFunc(opMatchInsensitively))
	r.Register("notMatchInsensitively", OperatorFunc(opNotMatchInsensitively))
	r.Register("contains", OperatorFunc(opContains))
	r.Register("notContains", OperatorFunc(opNotContains))
	r.Register("in", OperatorFunc(opIn))
	r.Register("notIn", OperatorFunc(opNotIn))
	r.Register("containsKey", OperatorFunc(opContainsKey))
	r.Register("notContainsKey", OperatorFunc(opNotContainsKey))
	r.Register("exists", OperatorFunc(opExists))
	r.Register("greater", OperatorFunc(opGreater))
	r.Register("greaterOrEquals", OperatorFunc(opGreaterOrEquals))
	r.Register("less", OperatorFunc(opLess))
	r.Register("lessOrEquals", OperatorFunc(opLessOrEquals))
	return r
}
