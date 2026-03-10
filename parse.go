package goazurepolicyeng

import (
	"encoding/json"
	"fmt"

	"github.com/matt-FFFFFF/goazurepolicyeng/condition"
)

// ParsedRule contains the parsed condition tree and effect.
type ParsedRule struct {
	Condition condition.Node
	Effect    string // raw effect string — may be "[parameters('effect')]"
}

// validOperators is the set of recognized policy condition operators.
var validOperators = map[string]bool{
	"equals":                  true,
	"notEquals":               true,
	"like":                    true,
	"notLike":                 true,
	"match":                   true,
	"notMatch":                true,
	"matchInsensitively":      true,
	"notMatchInsensitively":   true,
	"contains":                true,
	"notContains":             true,
	"in":                      true,
	"notIn":                   true,
	"containsKey":             true,
	"notContainsKey":          true,
	"exists":                  true,
	"greater":                 true,
	"greaterOrEquals":         true,
	"less":                    true,
	"lessOrEquals":            true,
}

// nonOperatorKeys are keys that are not operators in a condition object.
var nonOperatorKeys = map[string]bool{
	"field": true,
	"value": true,
	"count": true,
	"name":  true,
	"where": true,
}

// ParsePolicyRule parses a policyRule JSON into a condition tree and effect.
func ParsePolicyRule(raw json.RawMessage) (*ParsedRule, error) {
	var rule map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rule); err != nil {
		return nil, fmt.Errorf("unmarshal policy rule: %w", err)
	}

	ifBlock, ok := rule["if"]
	if !ok {
		return nil, fmt.Errorf("policy rule missing 'if' block")
	}

	thenBlock, ok := rule["then"]
	if !ok {
		return nil, fmt.Errorf("policy rule missing 'then' block")
	}

	cond, err := parseCondition(ifBlock)
	if err != nil {
		return nil, fmt.Errorf("parse 'if': %w", err)
	}

	var then map[string]json.RawMessage
	if err := json.Unmarshal(thenBlock, &then); err != nil {
		return nil, fmt.Errorf("unmarshal 'then': %w", err)
	}

	effectRaw, ok := then["effect"]
	if !ok {
		return nil, fmt.Errorf("'then' block missing 'effect'")
	}

	var effect string
	if err := json.Unmarshal(effectRaw, &effect); err != nil {
		return nil, fmt.Errorf("unmarshal effect: %w", err)
	}

	return &ParsedRule{Condition: cond, Effect: effect}, nil
}

func parseCondition(raw json.RawMessage) (condition.Node, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("unmarshal condition: %w", err)
	}

	// Logical operators
	if allOf, ok := obj["allOf"]; ok {
		var items []json.RawMessage
		if err := json.Unmarshal(allOf, &items); err != nil {
			return nil, fmt.Errorf("unmarshal allOf: %w", err)
		}
		nodes := make([]condition.Node, 0, len(items))
		for i, item := range items {
			n, err := parseCondition(item)
			if err != nil {
				return nil, fmt.Errorf("allOf[%d]: %w", i, err)
			}
			nodes = append(nodes, n)
		}
		return &condition.AllOf{Conditions: nodes}, nil
	}

	if anyOf, ok := obj["anyOf"]; ok {
		var items []json.RawMessage
		if err := json.Unmarshal(anyOf, &items); err != nil {
			return nil, fmt.Errorf("unmarshal anyOf: %w", err)
		}
		nodes := make([]condition.Node, 0, len(items))
		for i, item := range items {
			n, err := parseCondition(item)
			if err != nil {
				return nil, fmt.Errorf("anyOf[%d]: %w", i, err)
			}
			nodes = append(nodes, n)
		}
		return &condition.AnyOf{Conditions: nodes}, nil
	}

	if notRaw, ok := obj["not"]; ok {
		child, err := parseCondition(notRaw)
		if err != nil {
			return nil, fmt.Errorf("not: %w", err)
		}
		return &condition.Not{Condition: child}, nil
	}

	// Find operator key
	op, opVal, err := findOperator(obj)
	if err != nil {
		return nil, err
	}

	var operand any
	if err := json.Unmarshal(opVal, &operand); err != nil {
		return nil, fmt.Errorf("unmarshal operator value: %w", err)
	}

	// Count condition
	if countRaw, ok := obj["count"]; ok {
		return parseCountCondition(countRaw, op, operand)
	}

	// Field condition
	if fieldRaw, ok := obj["field"]; ok {
		var field string
		if err := json.Unmarshal(fieldRaw, &field); err != nil {
			return nil, fmt.Errorf("unmarshal field: %w", err)
		}
		return &condition.FieldCondition{Field: field, Operator: op, Value: operand}, nil
	}

	// Value condition
	if valueRaw, ok := obj["value"]; ok {
		var value string
		if err := json.Unmarshal(valueRaw, &value); err != nil {
			return nil, fmt.Errorf("unmarshal value: %w", err)
		}
		return &condition.ValueCondition{Value: value, Operator: op, Operand: operand}, nil
	}

	return nil, fmt.Errorf("unrecognized condition object with keys: %v", keysOf(obj))
}

func parseCountCondition(countRaw json.RawMessage, op string, operand any) (condition.Node, error) {
	var countObj map[string]json.RawMessage
	if err := json.Unmarshal(countRaw, &countObj); err != nil {
		return nil, fmt.Errorf("unmarshal count: %w", err)
	}

	c := &condition.CountCondition{
		Operator: op,
		Operand:  operand,
	}

	if fieldRaw, ok := countObj["field"]; ok {
		var field string
		if err := json.Unmarshal(fieldRaw, &field); err != nil {
			return nil, fmt.Errorf("unmarshal count field: %w", err)
		}
		c.Field = field
	}

	if valueRaw, ok := countObj["value"]; ok {
		var value string
		if err := json.Unmarshal(valueRaw, &value); err != nil {
			return nil, fmt.Errorf("unmarshal count value: %w", err)
		}
		c.ValueExpr = value
	}

	if nameRaw, ok := countObj["name"]; ok {
		var name string
		if err := json.Unmarshal(nameRaw, &name); err != nil {
			return nil, fmt.Errorf("unmarshal count name: %w", err)
		}
		c.Name = name
	}

	if whereRaw, ok := countObj["where"]; ok {
		where, err := parseCondition(whereRaw)
		if err != nil {
			return nil, fmt.Errorf("count where: %w", err)
		}
		c.Where = where
	}

	return c, nil
}

func findOperator(obj map[string]json.RawMessage) (string, json.RawMessage, error) {
	for key, val := range obj {
		if nonOperatorKeys[key] {
			continue
		}
		if validOperators[key] {
			return key, val, nil
		}
	}
	return "", nil, fmt.Errorf("no valid operator found in condition with keys: %v", keysOf(obj))
}

func keysOf(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
