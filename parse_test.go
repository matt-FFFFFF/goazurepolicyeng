package goazurepolicyeng

import (
	"encoding/json"
	"testing"

	"github.com/matt-FFFFFF/goazurepolicyeng/condition"
)

func TestParsePolicyRule_SimpleFieldCondition(t *testing.T) {
	rule := json.RawMessage(`{
		"if": {
			"field": "type",
			"equals": "Microsoft.Storage/storageAccounts"
		},
		"then": {
			"effect": "audit"
		}
	}`)
	parsed, err := ParsePolicyRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Effect != "audit" {
		t.Errorf("effect = %q, want %q", parsed.Effect, "audit")
	}
	fc, ok := parsed.Condition.(*condition.FieldCondition)
	if !ok {
		t.Fatalf("condition type = %T, want *FieldCondition", parsed.Condition)
	}
	if fc.Field != "type" || fc.Operator != "equals" || fc.Value != "Microsoft.Storage/storageAccounts" {
		t.Errorf("field condition = %+v", fc)
	}
}

func TestParsePolicyRule_AllOfWithNot(t *testing.T) {
	rule := json.RawMessage(`{
		"if": {
			"allOf": [
				{"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
				{"not": {"field": "location", "in": ["eastus", "westus"]}}
			]
		},
		"then": {"effect": "deny"}
	}`)
	parsed, err := ParsePolicyRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Effect != "deny" {
		t.Errorf("effect = %q, want %q", parsed.Effect, "deny")
	}
	allOf, ok := parsed.Condition.(*condition.AllOf)
	if !ok {
		t.Fatalf("condition type = %T, want *AllOf", parsed.Condition)
	}
	if len(allOf.Conditions) != 2 {
		t.Fatalf("allOf has %d conditions, want 2", len(allOf.Conditions))
	}
	if _, ok := allOf.Conditions[0].(*condition.FieldCondition); !ok {
		t.Errorf("allOf[0] type = %T, want *FieldCondition", allOf.Conditions[0])
	}
	notNode, ok := allOf.Conditions[1].(*condition.Not)
	if !ok {
		t.Fatalf("allOf[1] type = %T, want *Not", allOf.Conditions[1])
	}
	if _, ok := notNode.Condition.(*condition.FieldCondition); !ok {
		t.Errorf("not child type = %T, want *FieldCondition", notNode.Condition)
	}
}

func TestParsePolicyRule_AnyOf(t *testing.T) {
	rule := json.RawMessage(`{
		"if": {
			"anyOf": [
				{"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
				{"field": "type", "equals": "Microsoft.Sql/servers"}
			]
		},
		"then": {"effect": "audit"}
	}`)
	parsed, err := ParsePolicyRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	anyOf, ok := parsed.Condition.(*condition.AnyOf)
	if !ok {
		t.Fatalf("condition type = %T, want *AnyOf", parsed.Condition)
	}
	if len(anyOf.Conditions) != 2 {
		t.Errorf("anyOf has %d conditions, want 2", len(anyOf.Conditions))
	}
}

func TestParsePolicyRule_ValueCondition(t *testing.T) {
	rule := json.RawMessage(`{
		"if": {
			"value": "[concat(field('name'), '-suffix')]",
			"equals": "myresource-suffix"
		},
		"then": {"effect": "audit"}
	}`)
	parsed, err := ParsePolicyRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vc, ok := parsed.Condition.(*condition.ValueCondition)
	if !ok {
		t.Fatalf("condition type = %T, want *ValueCondition", parsed.Condition)
	}
	if vc.Value != "[concat(field('name'), '-suffix')]" {
		t.Errorf("value = %q", vc.Value)
	}
	if vc.Operator != "equals" || vc.Operand != "myresource-suffix" {
		t.Errorf("operator=%q operand=%v", vc.Operator, vc.Operand)
	}
}

func TestParsePolicyRule_CountField(t *testing.T) {
	rule := json.RawMessage(`{
		"if": {
			"count": {
				"field": "Microsoft.Network/networkSecurityGroups/securityRules[*]",
				"where": {
					"field": "Microsoft.Network/networkSecurityGroups/securityRules[*].direction",
					"equals": "Inbound"
				}
			},
			"greater": 0
		},
		"then": {"effect": "audit"}
	}`)
	parsed, err := ParsePolicyRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cc, ok := parsed.Condition.(*condition.CountCondition)
	if !ok {
		t.Fatalf("condition type = %T, want *CountCondition", parsed.Condition)
	}
	if cc.Field != "Microsoft.Network/networkSecurityGroups/securityRules[*]" {
		t.Errorf("field = %q", cc.Field)
	}
	if cc.Operator != "greater" || cc.Operand != float64(0) {
		t.Errorf("operator=%q operand=%v", cc.Operator, cc.Operand)
	}
	if cc.Where == nil {
		t.Fatal("where is nil")
	}
}

func TestParsePolicyRule_CountValue(t *testing.T) {
	rule := json.RawMessage(`{
		"if": {
			"count": {
				"value": "[parameters('allowedPrefixes')]",
				"name": "prefix",
				"where": {
					"value": "[startsWith(field('name'), current('prefix'))]",
					"equals": true
				}
			},
			"equals": 0
		},
		"then": {"effect": "deny"}
	}`)
	parsed, err := ParsePolicyRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cc, ok := parsed.Condition.(*condition.CountCondition)
	if !ok {
		t.Fatalf("condition type = %T, want *CountCondition", parsed.Condition)
	}
	if cc.ValueExpr != "[parameters('allowedPrefixes')]" {
		t.Errorf("valueExpr = %q", cc.ValueExpr)
	}
	if cc.Name != "prefix" {
		t.Errorf("name = %q", cc.Name)
	}
	if cc.Where == nil {
		t.Fatal("where is nil")
	}
}

func TestParsePolicyRule_NestedLogical(t *testing.T) {
	rule := json.RawMessage(`{
		"if": {
			"allOf": [
				{"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
				{"anyOf": [
					{"field": "location", "equals": "eastus"},
					{"field": "location", "equals": "westus"}
				]}
			]
		},
		"then": {"effect": "deny"}
	}`)
	parsed, err := ParsePolicyRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	allOf, ok := parsed.Condition.(*condition.AllOf)
	if !ok {
		t.Fatalf("condition type = %T, want *AllOf", parsed.Condition)
	}
	if len(allOf.Conditions) != 2 {
		t.Fatalf("allOf has %d conditions, want 2", len(allOf.Conditions))
	}
	anyOf, ok := allOf.Conditions[1].(*condition.AnyOf)
	if !ok {
		t.Fatalf("allOf[1] type = %T, want *AnyOf", allOf.Conditions[1])
	}
	if len(anyOf.Conditions) != 2 {
		t.Errorf("anyOf has %d conditions, want 2", len(anyOf.Conditions))
	}
}

func TestParsePolicyRule_ParameterEffect(t *testing.T) {
	rule := json.RawMessage(`{
		"if": {
			"field": "type",
			"equals": "Microsoft.Storage/storageAccounts"
		},
		"then": {
			"effect": "[parameters('effect')]"
		}
	}`)
	parsed, err := ParsePolicyRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Effect != "[parameters('effect')]" {
		t.Errorf("effect = %q, want %q", parsed.Effect, "[parameters('effect')]")
	}
}
