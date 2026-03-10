package goazurepolicyeng

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

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
