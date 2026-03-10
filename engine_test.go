package goazurepolicyeng

import (
	"context"
	"encoding/json"
	"fmt"
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
	results := eng.EvaluateAll(context.Background(), resource, assignments, Catalog{Definitions: definitions})

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

	results := eng.EvaluateBulk(context.Background(), resources, assignments, Catalog{Definitions: definitions}, 4)

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
	results := eng.EvaluateBulk(context.Background(), resources, assignments, Catalog{Definitions: definitions}, 2)
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

	results := eng.EvaluateBulk(context.Background(), resources, assignments, Catalog{Definitions: definitions}, 2)
	assert.Len(t, results, 20)
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

func TestEvaluateAll_MixedDirectAndInitiative(t *testing.T) {
	eng := makeEngine(t)

	// Direct policy definition
	directDef := &PolicyDefinition{
		ID:         "direct-policy",
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "audit"),
	}

	// Initiative member policy definition
	memberDef := &PolicyDefinition{
		ID:         "member-policy",
		PolicyRule: makePolicyRule(t, "location", "equals", "eastus", "deny"),
	}

	definitions := map[string]*PolicyDefinition{
		"direct-policy": directDef,
		"member-policy": memberDef,
	}

	// Policy set (initiative)
	setDef := &PolicySetDefinition{
		ID:   "initiative-1",
		Name: "test-initiative",
		PolicyDefinitions: []PolicyDefinitionReference{
			{
				PolicyDefinitionID:    "member-policy",
				DefinitionReferenceID: "member-ref-1",
				Parameters:            map[string]ParameterValue{},
			},
		},
	}
	setDefinitions := map[string]*PolicySetDefinition{
		"initiative-1": setDef,
	}

	// Two assignments: one direct, one initiative
	assignments := []Assignment{
		{
			ID:                 "assign-direct",
			Scope:              "/subscriptions/sub1",
			PolicyDefinitionID: "direct-policy",
		},
		{
			ID:                 "assign-initiative",
			Scope:              "/subscriptions/sub1",
			PolicyDefinitionID: "initiative-1",
		},
	}

	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	catalog := Catalog{
		Definitions:    definitions,
		SetDefinitions: setDefinitions,
	}

	results := eng.EvaluateAll(context.Background(), resource, assignments, catalog)

	// Should have 2 results: one from direct policy, one from initiative member
	require.Len(t, results, 2)

	// Direct policy result
	assert.Equal(t, "assign-direct", results[0].AssignmentID)
	assert.Equal(t, "direct-policy", results[0].PolicyID)
	assert.Equal(t, NonCompliant, results[0].State)
	assert.Equal(t, "audit", results[0].Effect)

	// Initiative member result
	assert.Equal(t, "assign-initiative", results[1].AssignmentID)
	assert.Equal(t, "member-policy", results[1].PolicyID)
	assert.Equal(t, NonCompliant, results[1].State)
	assert.Equal(t, "deny", results[1].Effect)
}

func TestEvaluateAll_InitiativeOnlySkippedWithoutSetDefs(t *testing.T) {
	eng := makeEngine(t)

	assignments := []Assignment{
		{
			ID:                 "assign-initiative",
			Scope:              "/subscriptions/sub1",
			PolicyDefinitionID: "initiative-1",
		},
	}

	resource := makeResource(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus")

	// No set definitions in catalog — initiative assignment should be silently skipped
	catalog := Catalog{
		Definitions: map[string]*PolicyDefinition{},
	}

	results := eng.EvaluateAll(context.Background(), resource, assignments, catalog)
	assert.Len(t, results, 0)
}

func makeResourceFull(t *testing.T, id, typ, location, subID, rg, tenantID string) *Resource {
	t.Helper()
	raw := fmt.Sprintf(`{"id":%q,"type":%q,"location":%q,"name":"test"}`, id, typ, location)
	return &Resource{
		ID:             id,
		Type:           typ,
		Location:       location,
		Name:           "test",
		SubscriptionID: subID,
		ResourceGroup:  rg,
		TenantID:       tenantID,
		Raw:            json.RawMessage(raw),
	}
}

func TestEvaluate_SubscriptionExpression(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	// Policy that uses [subscription().subscriptionId] in a value condition
	def := &PolicyDefinition{
		ID: "policy-sub",
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[subscription().subscriptionId]",
				"equals": "sub-123"
			},
			"then": {"effect": "audit"}
		}`),
	}
	assignment := &Assignment{
		ID:                 "assign-sub",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-sub",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
	assert.Equal(t, "audit", result.Effect)
}

func TestEvaluate_ResourceGroupExpression(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	def := &PolicyDefinition{
		ID: "policy-rg",
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[resourceGroup().name]",
				"equals": "rg1"
			},
			"then": {"effect": "audit"}
		}`),
	}
	assignment := &Assignment{
		ID:                 "assign-rg",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-rg",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
}

func TestEvaluate_FieldExpression(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	// Use field() in a value condition (not a field condition)
	def := &PolicyDefinition{
		ID: "policy-field-expr",
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[field('location')]",
				"equals": "eastus"
			},
			"then": {"effect": "audit"}
		}`),
	}
	assignment := &Assignment{
		ID:                 "assign-field-expr",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-field-expr",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
}

func TestEvaluate_PolicyExpression(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	def := &PolicyDefinition{
		ID: "policy-meta",
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[policy().assignmentId]",
				"equals": "assign-meta"
			},
			"then": {"effect": "audit"}
		}`),
	}
	assignment := &Assignment{
		ID:                 "assign-meta",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-meta",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
}

func TestEvaluate_InitiativePolicyScope(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	// Policy checks that setDefinitionId is populated
	def := &PolicyDefinition{
		ID: "policy-set-check",
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[policy().setDefinitionId]",
				"equals": "initiative-1"
			},
			"then": {"effect": "audit"}
		}`),
	}

	setDef := &PolicySetDefinition{
		ID: "initiative-1",
		PolicyDefinitions: []PolicyDefinitionReference{
			{
				PolicyDefinitionID:    "policy-set-check",
				DefinitionReferenceID: "member-ref",
			},
		},
	}

	assignment := &Assignment{
		ID:                 "assign-init",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "initiative-1",
	}

	definitions := map[string]*PolicyDefinition{"policy-set-check": def}
	results := eng.EvaluateInitiative(context.Background(), resource, assignment, setDef, definitions)

	require.Len(t, results, 1)
	assert.Equal(t, NonCompliant, results[0].State)
}

func TestEvaluate_IpRangeContains(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Network/nsg/nsg1",
		"Microsoft.Network/networkSecurityGroups", "eastus", "sub-123", "rg1", "tenant-456")

	def := &PolicyDefinition{
		ID: "policy-ip",
		Parameters: map[string]ParameterDefinition{
			"testIP": {Type: "String", DefaultValue: "10.1.2.3"},
		},
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[ipRangeContains('10.0.0.0/8', parameters('testIP'))]",
				"equals": true
			},
			"then": {"effect": "audit"}
		}`),
	}
	assignment := &Assignment{
		ID:                 "assign-ip",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-ip",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
}

func TestEvaluate_AddDays(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	def := &PolicyDefinition{
		ID: "policy-adddays",
		Parameters: map[string]ParameterDefinition{
			"baseDate": {Type: "String", DefaultValue: "2025-01-01T00:00:00Z"},
		},
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[addDays(parameters('baseDate'), 30)]",
				"equals": "2025-01-31T00:00:00Z"
			},
			"then": {"effect": "audit"}
		}`),
	}
	assignment := &Assignment{
		ID:                 "assign-adddays",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-adddays",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State)
}

func TestEvaluate_ParametersInValueCondition(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	def := &PolicyDefinition{
		ID: "policy-param-value",
		Parameters: map[string]ParameterDefinition{
			"allowedLocation": {Type: "String", DefaultValue: "westus"},
		},
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[parameters('allowedLocation')]",
				"equals": "eastus"
			},
			"then": {"effect": "audit"}
		}`),
	}
	assignment := &Assignment{
		ID:                 "assign-param-value",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-param-value",
		Parameters: map[string]ParameterValue{
			"allowedLocation": {Value: "eastus"},
		},
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State, "parameters('allowedLocation') should resolve to 'eastus'")
}

func TestEvaluate_CurrentInCountWhere(t *testing.T) {
	eng := makeEngine(t)

	// Resource with tags array-like structure to count over
	raw := `{"id":"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Network/nsg/nsg1","type":"Microsoft.Network/networkSecurityGroups","location":"eastus","properties":{"securityRules":["rule1","rule2","rule3"]}}`
	resource := &Resource{
		ID:             "/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Network/nsg/nsg1",
		Type:           "Microsoft.Network/networkSecurityGroups",
		Location:       "eastus",
		SubscriptionID: "sub-123",
		ResourceGroup:  "rg1",
		TenantID:       "tenant-456",
		Raw:            json.RawMessage(raw),
	}

	// Use a value count with current() in the where clause
	def := &PolicyDefinition{
		ID: "policy-current",
		Parameters: map[string]ParameterDefinition{
			"items": {Type: "Array", DefaultValue: []any{"a", "b", "c"}},
		},
		PolicyRule: json.RawMessage(`{
			"if": {
				"count": {
					"value": "[parameters('items')]",
					"where": {
						"value": "[current()]",
						"equals": "b"
					}
				},
				"greater": 0
			},
			"then": {"effect": "audit"}
		}`),
	}
	assignment := &Assignment{
		ID:                 "assign-current",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-current",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	// Count of items where current() == "b" should be 1, which is > 0
	assert.Equal(t, NonCompliant, result.State, "current() should resolve in count where clause")
}

func TestEvaluateBulk_UsesTieredScopeChain(t *testing.T) {
	eng := makeEngine(t)

	// Policy that uses subscription().subscriptionId — only works with tiered scope chain
	def := &PolicyDefinition{
		ID: "policy-sub-bulk",
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[subscription().subscriptionId]",
				"equals": "sub-123"
			},
			"then": {"effect": "audit"}
		}`),
	}
	definitions := map[string]*PolicyDefinition{"policy-sub-bulk": def}
	assignments := []Assignment{{
		ID:                 "assign-bulk",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-sub-bulk",
	}}

	resources := make([]Resource, 5)
	for i := range resources {
		id := fmt.Sprintf("/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa%d", i)
		raw := fmt.Sprintf(`{"id":%q,"type":"Microsoft.Storage/storageAccounts","location":"eastus"}`, id)
		resources[i] = Resource{
			ID:             id,
			Type:           "Microsoft.Storage/storageAccounts",
			Location:       "eastus",
			SubscriptionID: "sub-123",
			ResourceGroup:  "rg1",
			TenantID:       "tenant-456",
			Raw:            json.RawMessage(raw),
		}
	}

	results := eng.EvaluateBulk(context.Background(), resources, assignments, Catalog{Definitions: definitions}, 2)

	assert.Len(t, results, 5, "should have results for all 5 resources")
	for id, res := range results {
		require.Len(t, res, 1, "resource %s should have 1 result", id)
		assert.Equal(t, NonCompliant, res[0].State, "resource %s should be NonCompliant via subscription() expression", id)
	}
}

func TestEvaluateAll_UsesTieredScopeChain(t *testing.T) {
	eng := makeEngine(t)

	// Policy that uses resourceGroup().name — only works with tiered scope chain
	def := &PolicyDefinition{
		ID: "policy-rg-all",
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[resourceGroup().name]",
				"equals": "rg1"
			},
			"then": {"effect": "audit"}
		}`),
	}
	definitions := map[string]*PolicyDefinition{"policy-rg-all": def}
	assignments := []Assignment{{
		ID:                 "assign-rg-all",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-rg-all",
	}}

	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	results := eng.EvaluateAll(context.Background(), resource, assignments, Catalog{Definitions: definitions})

	require.Len(t, results, 1)
	assert.Equal(t, NonCompliant, results[0].State, "resourceGroup().name should work through EvaluateAll")
}

func TestEvaluate_InitiativeDefinitionReferenceID(t *testing.T) {
	eng := makeEngine(t)
	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	// Policy checks that definitionReferenceId is populated from initiative
	def := &PolicyDefinition{
		ID: "policy-defref",
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[policy().definitionReferenceId]",
				"equals": "storage-ref-1"
			},
			"then": {"effect": "audit"}
		}`),
	}

	setDef := &PolicySetDefinition{
		ID: "initiative-defref",
		PolicyDefinitions: []PolicyDefinitionReference{
			{
				PolicyDefinitionID:    "policy-defref",
				DefinitionReferenceID: "storage-ref-1",
			},
		},
	}

	assignment := &Assignment{
		ID:                 "assign-defref",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "initiative-defref",
	}

	definitions := map[string]*PolicyDefinition{"policy-defref": def}
	results := eng.EvaluateInitiative(context.Background(), resource, assignment, setDef, definitions)

	require.Len(t, results, 1)
	assert.Equal(t, NonCompliant, results[0].State, "definitionReferenceId should be populated from initiative")
}

func TestEvaluate_RequestContext(t *testing.T) {
	resource := &Resource{
		ID:             "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1",
		Type:           "Microsoft.Compute/virtualMachines",
		Location:       "eastus",
		SubscriptionID: "sub-1",
		ResourceGroup:  "rg-1",
		Raw:            json.RawMessage(`{"type":"Microsoft.Compute/virtualMachines","location":"eastus"}`),
	}
	// Policy: value "[requestContext().apiVersion]" equals "" → should match since apiVersion is empty stub
	def := &PolicyDefinition{
		ID: "test-requestcontext",
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[requestContext().apiVersion]",
				"equals": ""
			},
			"then": { "effect": "audit" }
		}`),
	}
	assignment := &Assignment{
		ID:                 "assign-rc",
		Scope:              "/subscriptions/sub-1",
		PolicyDefinitionID: "test-requestcontext",
	}

	eng := New(nil, WithFieldResolvers(
		func(j string, f string) (any, error) { return gjsonGet(j, f), nil },
		func(j string, f string) ([]any, error) { return nil, nil },
	))
	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State, "requestContext().apiVersion should be empty string, matching equals ''")
}

