# goazurepolicyeng

Go library for offline Azure Policy evaluation.

Evaluates Azure Policy rules offline against cached ARM resource data. Use cases include What-If simulation, bulk compliance scanning, and policy testing — no Azure connection required at evaluation time.

## Installation

```bash
go get github.com/matt-FFFFFF/goazurepolicyeng
```

## Quick Start

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/matt-FFFFFF/goazurepolicyeng"
	"github.com/matt-FFFFFF/goazurepolicyeng/alias"
)

func main() {
	// Create an alias resolver (built-in or custom)
	resolver := alias.NewBuiltinResolver()

	// Create the engine
	engine := goazurepolicyeng.New(
		resolver,
		goazurepolicyeng.WithTracing(true),
	)

	// Define a policy
	def := &goazurepolicyeng.PolicyDefinition{
		ID:   "/providers/Microsoft.Authorization/policyDefinitions/my-policy",
		Name: "my-policy",
		PolicyRule: json.RawMessage(`{
			"if": {
				"field": "type",
				"equals": "Microsoft.Compute/virtualMachines"
			},
			"then": {
				"effect": "audit"
			}
		}`),
	}

	// Define an assignment
	assignment := &goazurepolicyeng.Assignment{
		ID:                 "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/policyAssignments/my-assignment",
		Scope:              "/subscriptions/00000000-0000-0000-0000-000000000000",
		PolicyDefinitionID: def.ID,
	}

	// A resource to evaluate
	resource := &goazurepolicyeng.Resource{
		ID:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
		Type: "Microsoft.Compute/virtualMachines",
		Raw:  json.RawMessage(`{"type": "Microsoft.Compute/virtualMachines", "location": "eastus"}`),
	}

	// Evaluate
	result := engine.Evaluate(context.Background(), goazurepolicyeng.EvaluateInput{
		Definition: def,
		Assignment: assignment,
		Resource:   resource,
	})

	fmt.Printf("State: %s, Effect: %s\n", result.State, result.Effect)
}
```

## Architecture

The library is organized into focused packages:

| Package | Purpose |
|---------|---------|
| `goazurepolicyeng` (root) | Engine, types, bulk evaluation, initiative support |
| `alias` | Azure Policy alias resolution via gjson paths |
| `condition` | Condition tree parsing and evaluation (allOf/anyOf/not/field/value/count) |
| `effect` | Effect parsing, AINE/DINE existence checks |
| `scope` | Assignment scoping (notScopes, resource selectors) |
| `result` | Evaluation results, non-compliance reasons, trace/diagnostics |

## Features

- **19 condition operators** matching Azure semantics: equals, notEquals, contains, notContains, in, notIn, containsKey, notContainsKey, less, lessOrEquals, greater, greaterOrEquals, exists, like, notLike, match, matchInsensitively, notMatch, notMatchInsensitively
- **Condition trees** with allOf, anyOf, and not logical combinators
- **Array alias resolution** with `[*]` support via gjson
- **Count expressions** with `current()` scoping for per-element evaluation
- **ARM template expressions** evaluated via [goarmfunctions](https://github.com/matt-FFFFFF/goarmfunctions) (e.g. `[parameters('effect')]`)
- **Initiative (policy set) evaluation** with parameter passthrough and effect overrides by `policyDefinitionReferenceId`
- **Assignment scoping** with notScopes, resource selectors, and overrides
- **AINE/DINE existence checks** via pluggable `RelatedResourceFinder` interface
- **Bulk parallel evaluation** across multiple resources with configurable worker pool (`EvaluateBulk`)
- **Trace/diagnostics mode** with structured trace output and non-compliance reasons
- **Pluggable resolvers** — bring your own alias resolver, field resolvers, and related resource finder

## Key APIs

### Single evaluation

```go
result := engine.Evaluate(ctx, goazurepolicyeng.EvaluateInput{
	Definition: def,
	Assignment: assignment,
	Resource:   resource,
})
```

### All policies against one resource

```go
results := engine.EvaluateAll(ctx, resource, assignments, definitions)
```

### Bulk evaluation (parallel)

```go
// Returns map[resourceID][]EvaluationResult
results := engine.EvaluateBulk(ctx, resources, assignments, definitions, workers)
```

### Initiative evaluation

```go
results := engine.EvaluateInitiative(ctx, resource, assignment, setDef, definitions)
```

## Dependencies

- [goarmfunctions](https://github.com/matt-FFFFFF/goarmfunctions) — ARM template expression evaluation
- [gjson](https://github.com/tidwall/gjson) — JSON path queries for alias resolution

## License

[MIT](LICENSE)
