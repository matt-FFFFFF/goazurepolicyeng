# goazurepolicyeng

Go library for evaluating Azure Policy rules offline against cached resource data.

## Status

🚧 Work in progress.

## Dependencies

- [goarmfunctions](https://github.com/matt-FFFFFF/goarmfunctions) — ARM template function evaluation
- [gjson](https://github.com/tidwall/gjson) — JSON path queries against resource documents

## Usage

```go
engine := goazurepolicyeng.New(aliasResolver,
    goazurepolicyeng.WithTracing(true),
)

result := engine.Evaluate(ctx, goazurepolicyeng.EvaluateInput{
    Definition: &policyDef,
    Assignment: &assignment,
    Resource:   &resource,
})

fmt.Println(result.State) // Compliant, NonCompliant, NotApplicable, Error
```
