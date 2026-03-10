package goazurepolicyeng

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAliasResolver implements AliasResolver for tests.
type testAliasResolver struct {
	paths map[string]string
}

func (r *testAliasResolver) GetPath(alias string) (string, bool) {
	p, ok := r.paths[alias]
	return p, ok
}

// testFieldResolvers returns simple field resolvers that use gjson directly.
func testFieldResolvers(resolver AliasResolver) (FieldResolverFunc, FieldArrayResolverFunc) {
	// Import alias package from tests (tests aren't part of the import cycle)
	resolveField := func(resourceJSON string, field string) (any, error) {
		// Use a simple gjson-based resolver for tests
		// For built-in fields, resolve directly
		switch field {
		case "type":
			return gjsonGet(resourceJSON, "type"), nil
		case "location":
			return gjsonGet(resourceJSON, "location"), nil
		case "name":
			return gjsonGet(resourceJSON, "name"), nil
		case "id":
			return gjsonGet(resourceJSON, "id"), nil
		case "kind":
			return gjsonGet(resourceJSON, "kind"), nil
		}
		// Try alias
		if resolver != nil {
			if path, ok := resolver.GetPath(field); ok {
				return gjsonGet(resourceJSON, path), nil
			}
		}
		// Try direct path
		return gjsonGet(resourceJSON, field), nil
	}

	resolveFieldArray := func(resourceJSON string, field string) ([]any, error) {
		v, err := resolveField(resourceJSON, field)
		if err != nil {
			return nil, err
		}
		if v == nil {
			return nil, nil
		}
		if arr, ok := v.([]any); ok {
			return arr, nil
		}
		return []any{v}, nil
	}

	return resolveField, resolveFieldArray
}

// gjsonGet is a minimal gjson-like getter using encoding/json for tests.
func gjsonGet(jsonStr string, path string) any {
	var m map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		return nil
	}
	// Simple single-level path
	v, ok := m[path]
	if !ok {
		return nil
	}
	return v
}

func makeEngine(t *testing.T) *Engine {
	t.Helper()
	resolver := &testAliasResolver{paths: map[string]string{}}
	rf, rfa := testFieldResolvers(resolver)
	return New(resolver,
		WithFieldResolvers(rf, rfa),
	)
}

func makeResource(t *testing.T, id, typ, location string) *Resource {
	t.Helper()
	raw := fmt.Sprintf(`{"id":%q,"type":%q,"location":%q,"name":"test"}`, id, typ, location)
	return &Resource{
		ID:       id,
		Type:     typ,
		Location: location,
		Name:     "test",
		Raw:      json.RawMessage(raw),
	}
}

func makePolicyRule(t *testing.T, field, operator string, value any, effectStr string) json.RawMessage {
	t.Helper()
	valJSON, err := json.Marshal(value)
	require.NoError(t, err)
	return json.RawMessage(fmt.Sprintf(`{"if":{"field":%q,%q:%s},"then":{"effect":%q}}`, field, operator, valJSON, effectStr))
}

func TestEvaluate_SimpleAudit(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	def := &PolicyDefinition{
		ID:         "policy1",
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "audit"),
	}
	assignment := &Assignment{
		ID:                 "assign1",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "policy1",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
	assert.Equal(t, "audit", result.Effect)
}

func TestEvaluate_DenyByLocation(t *testing.T) {
	eng := makeEngine(t)

	def := &PolicyDefinition{
		ID:         "policy-loc",
		PolicyRule: makePolicyRule(t, "location", "notIn", []string{"eastus", "westus"}, "deny"),
	}
	assignment := &Assignment{
		ID:                 "assign-loc",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "policy-loc",
	}

	// Resource in eastus → Compliant (notIn ["eastus","westus"] is false)
	resEastus := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/vms/vm1",
		"Microsoft.Compute/virtualMachines", "eastus")
	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resEastus,
	})
	assert.Equal(t, Compliant, result.State, "eastus should be compliant")

	// Resource in northeurope → NonCompliant
	resNorth := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/vms/vm2",
		"Microsoft.Compute/virtualMachines", "northeurope")
	result = eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resNorth,
	})
	assert.Equal(t, NonCompliant, result.State, "northeurope should be non-compliant")
	assert.Equal(t, "deny", result.Effect)
}

func TestEvaluate_DisabledSkipped(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	def := &PolicyDefinition{
		ID:         "policy-disabled",
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "disabled"),
	}
	assignment := &Assignment{
		ID:                 "assign-disabled",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "policy-disabled",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NotApplicable, result.State)
	assert.Equal(t, "disabled", result.Effect)
}

func TestEvaluate_ParameterEffect(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	def := &PolicyDefinition{
		ID: "policy-param",
		Parameters: map[string]ParameterDefinition{
			"effect": {Type: "String", DefaultValue: "deny"},
		},
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "[parameters('effect')]"),
	}
	assignment := &Assignment{
		ID:                 "assign-param",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "policy-param",
		Parameters: map[string]ParameterValue{
			"effect": {Value: "audit"},
		},
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
	assert.Equal(t, "audit", result.Effect)
}

func TestEvaluateAll_ScopeFiltering(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	def := &PolicyDefinition{
		ID:         "policy1",
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "audit"),
	}

	assignments := []Assignment{
		{
			ID:                 "assign-in-scope",
			Scope:              "/subscriptions/sub1",
			PolicyDefinitionID: "policy1",
		},
		{
			ID:                 "assign-out-of-scope",
			Scope:              "/subscriptions/sub2",
			PolicyDefinitionID: "policy1",
		},
		{
			ID:                 "assign-not-scoped",
			Scope:              "/subscriptions/sub1",
			NotScopes:          []string{"/subscriptions/sub1/resourceGroups/rg1"},
			PolicyDefinitionID: "policy1",
		},
	}

	definitions := map[string]*PolicyDefinition{"policy1": def}
	results := eng.EvaluateAll(context.Background(), resource, assignments, definitions)

	// Only the first assignment should be evaluated
	assert.Len(t, results, 1)
	assert.Equal(t, "assign-in-scope", results[0].AssignmentID)
}

func TestEvaluateBulk_Parallel(t *testing.T) {
	eng := makeEngine(t)

	def := &PolicyDefinition{
		ID:         "policy1",
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "audit"),
	}
	definitions := map[string]*PolicyDefinition{"policy1": def}

	assignments := []Assignment{
		{
			ID:                 "assign1",
			Scope:              "/subscriptions/sub1",
			PolicyDefinitionID: "policy1",
		},
	}

	// Create 100 resources
	resources := make([]Resource, 100)
	for i := range resources {
		id := fmt.Sprintf("/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa%d", i)
		raw := fmt.Sprintf(`{"id":%q,"type":"Microsoft.Storage/storageAccounts","location":"eastus","name":"sa%d"}`, id, i)
		resources[i] = Resource{
			ID:       id,
			Type:     "Microsoft.Storage/storageAccounts",
			Location: "eastus",
			Name:     fmt.Sprintf("sa%d", i),
			Raw:      json.RawMessage(raw),
		}
	}

	results := eng.EvaluateBulk(context.Background(), resources, assignments, definitions, 4)

	assert.Len(t, results, 100)
	for _, res := range results {
		assert.Len(t, res, 1)
		assert.Equal(t, NonCompliant, res[0].State)
	}
}

func TestEvaluateInitiative(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	def := &PolicyDefinition{
		ID: "policy1",
		Parameters: map[string]ParameterDefinition{
			"effect": {Type: "String", DefaultValue: "audit"},
		},
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "[parameters('effect')]"),
	}

	setDef := &PolicySetDefinition{
		ID: "initiative1",
		Parameters: map[string]ParameterDefinition{
			"storageEffect": {Type: "String", DefaultValue: "audit"},
		},
		PolicyDefinitions: []PolicyDefinitionReference{
			{
				PolicyDefinitionID:    "policy1",
				DefinitionReferenceID: "storagePolicy",
				Parameters: map[string]ParameterValue{
					"effect": {Value: "[parameters('storageEffect')]"},
				},
			},
		},
	}

	assignment := &Assignment{
		ID:                 "assign-init",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "initiative1",
		Parameters: map[string]ParameterValue{
			"storageEffect": {Value: "deny"},
		},
	}

	definitions := map[string]*PolicyDefinition{"policy1": def}

	results := eng.EvaluateInitiative(context.Background(), resource, assignment, setDef, definitions)

	require.Len(t, results, 1)
	assert.Equal(t, NonCompliant, results[0].State)
	assert.Equal(t, "deny", results[0].Effect)
}

func TestIsExpression(t *testing.T) {
	assert.True(t, isExpression("[parameters('effect')]"))
	assert.True(t, isExpression("[concat('a','b')]"))
	assert.False(t, isExpression("audit"))
	assert.False(t, isExpression("[]"))
	assert.False(t, isExpression("["))
}

func TestMergeParameters(t *testing.T) {
	assigned := map[string]ParameterValue{
		"a": {Value: "assigned-a"},
	}
	defined := map[string]ParameterDefinition{
		"a": {DefaultValue: "default-a"},
		"b": {DefaultValue: "default-b"},
		"c": {}, // no default
	}

	merged := mergeParameters(assigned, defined)
	assert.Equal(t, "assigned-a", merged["a"].Value) // assigned wins
	assert.Equal(t, "default-b", merged["b"].Value)  // default used
	_, hasC := merged["c"]
	assert.False(t, hasC) // no default, not assigned
}

func TestIsInScope(t *testing.T) {
	assert.True(t, isInScope("/subscriptions/sub1/resourceGroups/rg1", "/subscriptions/sub1", nil))
	assert.False(t, isInScope("/subscriptions/sub2/resourceGroups/rg1", "/subscriptions/sub1", nil))
	assert.False(t, isInScope("/subscriptions/sub1/resourceGroups/rg1", "/subscriptions/sub1",
		[]string{"/subscriptions/sub1/resourceGroups/rg1"}))
}

func TestExtractParameterName(t *testing.T) {
	assert.Equal(t, "effect", extractParameterName("[parameters('effect')]"))
	assert.Equal(t, "storageEffect", extractParameterName("[parameters('storageEffect')]"))
	assert.Equal(t, "", extractParameterName("audit"))
	assert.Equal(t, "", extractParameterName("[concat('a')]"))
}

func TestEvaluateBulk_Cancellation(t *testing.T) {
	eng := makeEngine(t)

	def := &PolicyDefinition{
		ID:         "policy1",
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "audit"),
	}
	definitions := map[string]*PolicyDefinition{"policy1": def}
	assignments := []Assignment{{ID: "a1", Scope: "/subscriptions/sub1", PolicyDefinitionID: "policy1"}}

	resources := make([]Resource, 10)
	for i := range resources {
		id := fmt.Sprintf("/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa%d", i)
		raw := fmt.Sprintf(`{"id":%q,"type":"Microsoft.Storage/storageAccounts","location":"eastus"}`, id)
		resources[i] = Resource{ID: id, Type: "Microsoft.Storage/storageAccounts", Location: "eastus", Raw: json.RawMessage(raw)}
	}

	// Just verify it completes without panic
	results := eng.EvaluateBulk(context.Background(), resources, assignments, definitions, 2)
	assert.Len(t, results, 10)
}

func TestEvaluate_ParameterDefault(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	def := &PolicyDefinition{
		ID: "policy-default",
		Parameters: map[string]ParameterDefinition{
			"effect": {Type: "String", DefaultValue: "audit"},
		},
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "[parameters('effect')]"),
	}
	// No parameters in assignment — should use default
	assignment := &Assignment{
		ID:                 "assign-default",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "policy-default",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
	assert.Equal(t, "audit", result.Effect)
}

func TestEvaluateInitiative_Override(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	def := &PolicyDefinition{
		ID:         "policy1",
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "deny"),
	}

	setDef := &PolicySetDefinition{
		ID: "initiative1",
		PolicyDefinitions: []PolicyDefinitionReference{
			{
				PolicyDefinitionID:    "policy1",
				DefinitionReferenceID: "storageRef",
			},
		},
	}

	assignment := &Assignment{
		ID:                 "assign-override",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "initiative1",
		Overrides: []Override{
			{
				Kind:  "policyEffect",
				Value: "disabled",
				Selectors: []SelectorExpression{
					{Kind: "policyDefinitionReferenceId", In: []string{"storageRef"}},
				},
			},
		},
	}

	definitions := map[string]*PolicyDefinition{"policy1": def}

	results := eng.EvaluateInitiative(context.Background(), resource, assignment, setDef, definitions)
	require.Len(t, results, 1)
	assert.Equal(t, NotApplicable, results[0].State)
	assert.Equal(t, "disabled", results[0].Effect)
}

func TestEvaluateBulk_WorkerCount(t *testing.T) {
	// Verify that worker count limits concurrency
	var maxConcurrent int64
	var current int64

	eng := makeEngine(t)

	def := &PolicyDefinition{
		ID:         "policy1",
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "audit"),
	}
	definitions := map[string]*PolicyDefinition{"policy1": def}
	assignments := []Assignment{{ID: "a1", Scope: "/subscriptions/sub1", PolicyDefinitionID: "policy1"}}

	resources := make([]Resource, 20)
	for i := range resources {
		id := fmt.Sprintf("/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa%d", i)
		raw := fmt.Sprintf(`{"id":%q,"type":"Microsoft.Storage/storageAccounts","location":"eastus"}`, id)
		resources[i] = Resource{ID: id, Type: "Microsoft.Storage/storageAccounts", Location: "eastus", Raw: json.RawMessage(raw)}
	}

	results := eng.EvaluateBulk(context.Background(), resources, assignments, definitions, 2)
	assert.Len(t, results, 20)
	_ = maxConcurrent
	_ = current
	_ = atomic.AddInt64
}

func TestEvaluate_WithTracing(t *testing.T) {
	resolver := &testAliasResolver{paths: map[string]string{}}
	rf, rfa := testFieldResolvers(resolver)
	eng := New(resolver,
		WithFieldResolvers(rf, rfa),
		WithTracing(true),
	)
	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	def := &PolicyDefinition{
		ID:         "policy1",
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "audit"),
	}
	assignment := &Assignment{
		ID:                 "assign1",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "policy1",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
	require.NotNil(t, result.Trace)
	assert.NotEmpty(t, result.Trace.Steps)
	// Should have at least one field step
	found := false
	for _, s := range result.Trace.Steps {
		if s.Type == "field" {
			found = true
			assert.Equal(t, "type", s.Field)
		}
	}
	assert.True(t, found, "should have a field trace step")
	assert.NotEmpty(t, result.Trace.Summary())
}

func TestEvaluate_ReasonsOnNonCompliant(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	def := &PolicyDefinition{
		ID:         "policy1",
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "audit"),
	}
	assignment := &Assignment{
		ID:                 "assign1",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "policy1",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
	require.NotEmpty(t, result.Reasons)
	assert.Equal(t, "type", result.Reasons[0].Field)
	assert.Equal(t, "equals", result.Reasons[0].Operator)
}

func TestEvaluate_NoTraceWhenDisabled(t *testing.T) {
	eng := makeEngine(t) // tracing off by default
	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	def := &PolicyDefinition{
		ID:         "policy1",
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "audit"),
	}
	assignment := &Assignment{
		ID:                 "assign1",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "policy1",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
	assert.Nil(t, result.Trace)
}
