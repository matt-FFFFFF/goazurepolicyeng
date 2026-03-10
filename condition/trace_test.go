package condition

import (
	"encoding/json"
	"testing"

	"github.com/matt-FFFFFF/goazurepolicyeng/result"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tracingCtx(resourceJSON string) *EvalContext {
	return &EvalContext{
		ResourceJSON: resourceJSON,
		ResolveField: func(j string, field string) (any, error) {
			return simpleGet(j, field), nil
		},
		ResolveFieldArray: func(j string, field string) ([]any, error) {
			v := simpleGet(j, field)
			if v == nil {
				return nil, nil
			}
			if arr, ok := v.([]any); ok {
				return arr, nil
			}
			return []any{v}, nil
		},
		Operators: DefaultOperatorRegistry(),
		Tracing:   true,
		Trace:     result.NewTrace(),
	}
}

func simpleGet(jsonStr string, path string) any {
	var m map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		return nil
	}
	return m[path]
}

func TestTrace_FieldCondition(t *testing.T) {
	ctx := tracingCtx(`{"type":"Microsoft.Storage/storageAccounts"}`)
	fc := &FieldCondition{Field: "type", Operator: "equals", Value: "Microsoft.Storage/storageAccounts"}

	res, err := fc.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, res)
	require.Len(t, ctx.Trace.Steps, 1)

	step := ctx.Trace.Steps[0]
	assert.Equal(t, "field", step.Type)
	assert.Equal(t, "type", step.Field)
	assert.Equal(t, "equals", step.Operator)
	assert.True(t, step.Result)
	assert.Equal(t, "Microsoft.Storage/storageAccounts", step.Expected)
	assert.Equal(t, "Microsoft.Storage/storageAccounts", step.Actual)
}

func TestTrace_AllOfWithChildren(t *testing.T) {
	ctx := tracingCtx(`{"type":"Microsoft.Storage/storageAccounts","location":"eastus"}`)
	allOf := &AllOf{Conditions: []Node{
		&FieldCondition{Field: "type", Operator: "equals", Value: "Microsoft.Storage/storageAccounts"},
		&FieldCondition{Field: "location", Operator: "equals", Value: "eastus"},
	}}

	res, err := allOf.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, res)
	// 2 child field steps + 1 allOf = 3
	require.Len(t, ctx.Trace.Steps, 3)
	assert.Equal(t, "field", ctx.Trace.Steps[0].Type)
	assert.Equal(t, "field", ctx.Trace.Steps[1].Type)
	assert.Equal(t, "allOf", ctx.Trace.Steps[2].Type)
	// Children should be depth 1, allOf at depth 0
	assert.Equal(t, 1, ctx.Trace.Steps[0].Depth)
	assert.Equal(t, 1, ctx.Trace.Steps[1].Depth)
	assert.Equal(t, 0, ctx.Trace.Steps[2].Depth)
}

func TestTrace_DisabledNoTrace(t *testing.T) {
	ctx := &EvalContext{
		ResourceJSON: `{"type":"Microsoft.Storage/storageAccounts"}`,
		ResolveField: func(json string, field string) (any, error) {
			return simpleGet(json, field), nil
		},
		ResolveFieldArray: func(json string, field string) ([]any, error) {
			return nil, nil
		},
		Operators: DefaultOperatorRegistry(),
		Tracing:   false,
		Trace:     nil,
	}

	fc := &FieldCondition{Field: "type", Operator: "equals", Value: "Microsoft.Storage/storageAccounts"}
	res, err := fc.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, res)
	assert.Nil(t, ctx.Trace)
}

func TestReasons_Collected(t *testing.T) {
	ctx := tracingCtx(`{"type":"Microsoft.Storage/storageAccounts"}`)
	fc := &FieldCondition{Field: "type", Operator: "equals", Value: "Microsoft.Storage/storageAccounts"}

	res, err := fc.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, res)
	require.Len(t, ctx.Reasons, 1)
	assert.Equal(t, "type", ctx.Reasons[0].Field)
	assert.Equal(t, "equals", ctx.Reasons[0].Operator)
	assert.Equal(t, "Microsoft.Storage/storageAccounts", ctx.Reasons[0].Expected)
	assert.Equal(t, "Microsoft.Storage/storageAccounts", ctx.Reasons[0].Actual)
}

func TestReasons_NotCollectedWhenFalse(t *testing.T) {
	ctx := tracingCtx(`{"type":"Microsoft.Compute/virtualMachines"}`)
	fc := &FieldCondition{Field: "type", Operator: "equals", Value: "Microsoft.Storage/storageAccounts"}

	res, err := fc.Evaluate(ctx)
	require.NoError(t, err)
	assert.False(t, res)
	assert.Empty(t, ctx.Reasons)
}

func TestTrace_Summary(t *testing.T) {
	tr := result.NewTrace()
	tr.Record(result.TraceStep{Depth: 0, Type: "field", Result: true, Detail: "field 'type' equals 'X': actual='X' → true"})
	s := tr.Summary()
	assert.Contains(t, s, "✓")
	assert.Contains(t, s, "field 'type'")
}

func TestTrace_SummaryNil(t *testing.T) {
	var tr *result.Trace
	assert.Equal(t, "<no trace>", tr.Summary())
}
