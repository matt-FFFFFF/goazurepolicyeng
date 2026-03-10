package goazurepolicyeng

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Shared benchmark helpers (from main)
// ---------------------------------------------------------------------------

// makeBenchPolicyRule creates a policy rule without requiring *testing.T.
func makeBenchPolicyRule(field, operator string, value any, effectStr string) json.RawMessage {
	valJSON, _ := json.Marshal(value)
	return json.RawMessage(fmt.Sprintf(`{"if":{"field":%q,%q:%s},"then":{"effect":%q}}`, field, operator, valJSON, effectStr))
}

func makeBenchEngine() *Engine {
	resolver := &testAliasResolver{paths: map[string]string{
		"Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly": "properties.supportsHttpsTrafficOnly",
	}}
	rf, rfa := testFieldResolvers(resolver)
	return New(resolver, WithFieldResolvers(rf, rfa))
}

func makeBenchResource(i int) Resource {
	id := fmt.Sprintf("/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa%d", i)
	raw := fmt.Sprintf(`{"id":%q,"type":"Microsoft.Storage/storageAccounts","location":"eastus","name":"sa%d","properties":{"supportsHttpsTrafficOnly":true}}`, id, i)
	return Resource{
		ID:             id,
		Type:           "Microsoft.Storage/storageAccounts",
		Location:       "eastus",
		Name:           fmt.Sprintf("sa%d", i),
		SubscriptionID: "sub1",
		ResourceGroup:  "rg1",
		Raw:            json.RawMessage(raw),
	}
}

// makeBenchCatalog builds a catalog with multiple policy types for realistic benchmarks.
func makeBenchCatalog() (Catalog, []Assignment) {
	definitions := map[string]*PolicyDefinition{
		"policy-type": {
			ID:         "policy-type",
			PolicyRule: makeBenchPolicyRule("type", "equals", "Microsoft.Storage/storageAccounts", "audit"),
		},
		"policy-location": {
			ID:         "policy-location",
			PolicyRule: makeBenchPolicyRule("location", "notIn", []string{"westeurope", "northeurope"}, "deny"),
		},
		"policy-param": {
			ID:         "policy-param",
			PolicyRule: makeBenchPolicyRule("type", "equals", "Microsoft.Compute/virtualMachines", "[parameters('effect')]"),
			Parameters: map[string]ParameterDefinition{
				"effect": {Type: "String", DefaultValue: "audit"},
			},
		},
		"policy-name": {
			ID:         "policy-name",
			PolicyRule: makeBenchPolicyRule("name", "like", "sa*", "audit"),
		},
		"policy-location2": {
			ID:         "policy-location2",
			PolicyRule: makeBenchPolicyRule("location", "equals", "eastus", "deny"),
		},
	}

	assignments := []Assignment{
		{ID: "assign1", Scope: "/subscriptions/sub1", PolicyDefinitionID: "policy-type"},
		{ID: "assign2", Scope: "/subscriptions/sub1", PolicyDefinitionID: "policy-location"},
		{ID: "assign3", Scope: "/subscriptions/sub1", PolicyDefinitionID: "policy-param",
			Parameters: map[string]ParameterValue{"effect": {Value: "deny"}}},
		{ID: "assign4", Scope: "/subscriptions/sub1", PolicyDefinitionID: "policy-name"},
		{ID: "assign5", Scope: "/subscriptions/sub1", PolicyDefinitionID: "policy-location2"},
	}

	return Catalog{Definitions: definitions}, assignments
}

func makeBenchResources(n int) []Resource {
	resources := make([]Resource, n)
	for i := range resources {
		resources[i] = makeBenchResource(i)
	}
	return resources
}

// ---------------------------------------------------------------------------
// Cache sizing integration tests
// ---------------------------------------------------------------------------

func TestParseCachePopulatesAndResets(t *testing.T) {
	// Start from a known state with the default cache size.
	SetParseCacheSize(DefaultParseCacheSize)
	ResetParseCache()
	defer ResetParseCache()

	eng := makeEngine(t)

	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	def := &PolicyDefinition{
		ID: "policy-cache",
		Parameters: map[string]ParameterDefinition{
			"effect": {Type: "String", DefaultValue: "audit"},
		},
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "[parameters('effect')]"),
	}
	assignment := &Assignment{
		ID:                 "assign-cache",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-cache",
	}

	// Evaluate once to populate the cache.
	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})
	assert.Equal(t, NonCompliant, result.State)
	assert.Greater(t, ParseCacheLen(), 0, "cache should be populated after evaluation")

	// Reset and verify.
	ResetParseCache()
	assert.Equal(t, 0, ParseCacheLen(), "cache should be empty after reset")
}

func TestWithParseCacheSize_Option(t *testing.T) {
	ResetParseCache()
	defer func() {
		// Restore default cache size.
		SetParseCacheSize(DefaultParseCacheSize)
		ResetParseCache()
	}()

	resolver := &testAliasResolver{paths: map[string]string{}}
	rf, rfa := testFieldResolvers(resolver)
	eng := New(resolver,
		WithFieldResolvers(rf, rfa),
		WithParseCacheSize(2), // tiny cache
	)

	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	// Evaluate three different expressions to exceed cache capacity.
	expressions := []struct {
		expr  string
		value string
	}{
		{"[parameters('effect')]", "audit"},
		{"[subscription().subscriptionId]", "sub-123"},
		{"[resourceGroup().name]", "rg1"},
	}
	for _, tc := range expressions {
		def := &PolicyDefinition{
			ID: "policy-" + tc.value,
			Parameters: map[string]ParameterDefinition{
				"effect": {Type: "String", DefaultValue: "audit"},
			},
			PolicyRule: json.RawMessage(fmt.Sprintf(`{
				"if": {"value": %q, "equals": %q},
				"then": {"effect": "audit"}
			}`, tc.expr, tc.value)),
		}
		assignment := &Assignment{
			ID:                 "assign-" + tc.value,
			Scope:              "/subscriptions/sub-123",
			PolicyDefinitionID: "policy-" + tc.value,
		}
		result := eng.Evaluate(context.Background(), EvaluateInput{
			Definition: def,
			Assignment: assignment,
			Resource:   resource,
		})
		require.Equal(t, NonCompliant, result.State)
	}

	// Cache should be capped at 2 (the configured size).
	assert.LessOrEqual(t, ParseCacheLen(), 2, "cache should respect WithParseCacheSize limit")
}

func TestSetParseCacheSize_Zero(t *testing.T) {
	defer func() {
		SetParseCacheSize(DefaultParseCacheSize)
		ResetParseCache()
	}()

	SetParseCacheSize(0)

	eng := makeEngine(t)
	resource := makeResourceFull(t,
		"/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"Microsoft.Storage/storageAccounts", "eastus", "sub-123", "rg1", "tenant-456")

	def := &PolicyDefinition{
		ID: "policy-nocache",
		Parameters: map[string]ParameterDefinition{
			"effect": {Type: "String", DefaultValue: "audit"},
		},
		PolicyRule: makePolicyRule(t, "type", "equals", "Microsoft.Storage/storageAccounts", "[parameters('effect')]"),
	}
	assignment := &Assignment{
		ID:                 "assign-nocache",
		Scope:              "/subscriptions/sub-123",
		PolicyDefinitionID: "policy-nocache",
	}

	result := eng.Evaluate(context.Background(), EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	assert.Equal(t, NonCompliant, result.State, "evaluation should still work with cache disabled")
	assert.Equal(t, 0, ParseCacheLen(), "cache should be empty when disabled")
}

// ---------------------------------------------------------------------------
// Production-scale benchmarks (from main)
// ---------------------------------------------------------------------------

// BenchmarkEvaluateBulk benchmarks bulk evaluation at production scale.
// 1000 resources × 5 policies = 5000 evaluations per iteration.
func BenchmarkEvaluateBulk(b *testing.B) {
	eng := makeBenchEngine()
	catalog, assignments := makeBenchCatalog()
	resources := makeBenchResources(1000)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.EvaluateBulk(ctx, resources, assignments, catalog, 4)
	}
}

// BenchmarkEvaluateBulk_2000 benchmarks at 2000 resources to show scaling.
func BenchmarkEvaluateBulk_2000(b *testing.B) {
	eng := makeBenchEngine()
	catalog, assignments := makeBenchCatalog()
	resources := makeBenchResources(2000)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.EvaluateBulk(ctx, resources, assignments, catalog, 4)
	}
}

// BenchmarkEvaluateBulk_WithTracing benchmarks with tracing enabled at scale.
func BenchmarkEvaluateBulk_WithTracing(b *testing.B) {
	resolver := &testAliasResolver{paths: map[string]string{}}
	rf, rfa := testFieldResolvers(resolver)
	eng := New(resolver, WithFieldResolvers(rf, rfa), WithTracing(true))
	catalog, assignments := makeBenchCatalog()
	resources := makeBenchResources(1000)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.EvaluateBulk(ctx, resources, assignments, catalog, 4)
	}
}

// BenchmarkEvaluate_Single benchmarks a single evaluation for comparison.
func BenchmarkEvaluate_Single(b *testing.B) {
	eng := makeBenchEngine()

	def := &PolicyDefinition{
		ID:         "policy-type",
		PolicyRule: makeBenchPolicyRule("type", "equals", "Microsoft.Storage/storageAccounts", "audit"),
	}
	assignment := &Assignment{
		ID:                 "assign1",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "policy-type",
	}
	resource := makeBenchResource(0)
	input := EvaluateInput{Definition: def, Assignment: assignment, Resource: &resource}

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.Evaluate(ctx, input)
	}
}

// ---------------------------------------------------------------------------
// Parse cache comparison benchmarks (cached vs uncached)
// ---------------------------------------------------------------------------

// BenchmarkEvaluate_SingleExpression benchmarks a single policy evaluation
// that resolves an ARM template expression. With v0.5.0's parse cache, repeated
// evaluations of the same expression reuse the cached AST.
func BenchmarkEvaluate_SingleExpression(b *testing.B) {
	ResetParseCache()
	defer ResetParseCache()

	eng := makeBenchEngine()

	def := &PolicyDefinition{
		ID: "bench-expr-policy",
		Parameters: map[string]ParameterDefinition{
			"effect": {Type: "String", DefaultValue: "audit"},
		},
		PolicyRule: makeBenchPolicyRule("type", "equals", "Microsoft.Storage/storageAccounts", "[parameters('effect')]"),
	}
	assignment := &Assignment{
		ID:                 "bench-expr-assign",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "bench-expr-policy",
	}
	resource := makeBenchResource(0)
	input := EvaluateInput{Definition: def, Assignment: assignment, Resource: &resource}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.Evaluate(ctx, input)
	}
}

// BenchmarkEvaluate_SingleExpression_NoCache benchmarks evaluation with the
// parse cache disabled to measure the raw parse + evaluate cost on every call.
func BenchmarkEvaluate_SingleExpression_NoCache(b *testing.B) {
	ResetParseCache()
	SetParseCacheSize(0)
	defer func() {
		SetParseCacheSize(DefaultParseCacheSize)
		ResetParseCache()
	}()

	eng := makeBenchEngine()

	def := &PolicyDefinition{
		ID: "bench-expr-policy",
		Parameters: map[string]ParameterDefinition{
			"effect": {Type: "String", DefaultValue: "audit"},
		},
		PolicyRule: makeBenchPolicyRule("type", "equals", "Microsoft.Storage/storageAccounts", "[parameters('effect')]"),
	}
	assignment := &Assignment{
		ID:                 "bench-expr-assign",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "bench-expr-policy",
	}
	resource := makeBenchResource(0)
	input := EvaluateInput{Definition: def, Assignment: assignment, Resource: &resource}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.Evaluate(ctx, input)
	}
}

// BenchmarkEvaluateBulk_ExpressionCache benchmarks bulk evaluation of 100
// resources against a policy with an ARM expression parameter.
func BenchmarkEvaluateBulk_ExpressionCache(b *testing.B) {
	ResetParseCache()
	defer ResetParseCache()

	eng := makeBenchEngine()

	def := &PolicyDefinition{
		ID: "bench-bulk-expr-policy",
		Parameters: map[string]ParameterDefinition{
			"effect": {Type: "String", DefaultValue: "audit"},
		},
		PolicyRule: makeBenchPolicyRule("type", "equals", "Microsoft.Storage/storageAccounts", "[parameters('effect')]"),
	}
	definitions := map[string]*PolicyDefinition{"bench-bulk-expr-policy": def}
	assignments := []Assignment{{
		ID:                 "bench-bulk-expr-assign",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "bench-bulk-expr-policy",
	}}

	resources := makeBenchResources(100)
	catalog := Catalog{Definitions: definitions}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.EvaluateBulk(ctx, resources, assignments, catalog, 4)
	}
}

// BenchmarkEvaluateBulk_ExpressionCache_NoCache benchmarks the same bulk
// scenario with the expression parse cache disabled.
func BenchmarkEvaluateBulk_ExpressionCache_NoCache(b *testing.B) {
	ResetParseCache()
	SetParseCacheSize(0)
	defer func() {
		SetParseCacheSize(DefaultParseCacheSize)
		ResetParseCache()
	}()

	eng := makeBenchEngine()

	def := &PolicyDefinition{
		ID: "bench-bulk-expr-policy",
		Parameters: map[string]ParameterDefinition{
			"effect": {Type: "String", DefaultValue: "audit"},
		},
		PolicyRule: makeBenchPolicyRule("type", "equals", "Microsoft.Storage/storageAccounts", "[parameters('effect')]"),
	}
	definitions := map[string]*PolicyDefinition{"bench-bulk-expr-policy": def}
	assignments := []Assignment{{
		ID:                 "bench-bulk-expr-assign",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "bench-bulk-expr-policy",
	}}

	resources := makeBenchResources(100)
	catalog := Catalog{Definitions: definitions}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.EvaluateBulk(ctx, resources, assignments, catalog, 4)
	}
}

// BenchmarkEvaluate_ComplexExpression benchmarks evaluation with a more
// complex ARM expression involving nested function calls.
func BenchmarkEvaluate_ComplexExpression(b *testing.B) {
	ResetParseCache()
	defer ResetParseCache()

	eng := makeBenchEngine()
	resource := makeBenchResource(0)

	def := &PolicyDefinition{
		ID: "bench-complex",
		Parameters: map[string]ParameterDefinition{
			"prefix": {Type: "String", DefaultValue: "prod"},
			"suffix": {Type: "String", DefaultValue: "eastus"},
		},
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[concat(parameters('prefix'), '-', parameters('suffix'))]",
				"equals": "prod-eastus"
			},
			"then": {"effect": "audit"}
		}`),
	}
	assignment := &Assignment{
		ID:                 "bench-complex-assign",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "bench-complex",
	}

	input := EvaluateInput{Definition: def, Assignment: assignment, Resource: &resource}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.Evaluate(ctx, input)
	}
}

// BenchmarkEvaluate_ComplexExpression_NoCache benchmarks the same complex
// expression with caching disabled.
func BenchmarkEvaluate_ComplexExpression_NoCache(b *testing.B) {
	ResetParseCache()
	SetParseCacheSize(0)
	defer func() {
		SetParseCacheSize(DefaultParseCacheSize)
		ResetParseCache()
	}()

	eng := makeBenchEngine()
	resource := makeBenchResource(0)

	def := &PolicyDefinition{
		ID: "bench-complex",
		Parameters: map[string]ParameterDefinition{
			"prefix": {Type: "String", DefaultValue: "prod"},
			"suffix": {Type: "String", DefaultValue: "eastus"},
		},
		PolicyRule: json.RawMessage(`{
			"if": {
				"value": "[concat(parameters('prefix'), '-', parameters('suffix'))]",
				"equals": "prod-eastus"
			},
			"then": {"effect": "audit"}
		}`),
	}
	assignment := &Assignment{
		ID:                 "bench-complex-assign",
		Scope:              "/subscriptions/sub1",
		PolicyDefinitionID: "bench-complex",
	}

	input := EvaluateInput{Definition: def, Assignment: assignment, Resource: &resource}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.Evaluate(ctx, input)
	}
}
