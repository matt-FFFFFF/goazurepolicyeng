package condition

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

var testStorageAccount = `{
    "id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
    "name": "sa1",
    "type": "Microsoft.Storage/storageAccounts",
    "location": "eastus",
    "kind": "StorageV2",
    "tags": {"env": "prod", "team": "platform"},
    "sku": {"name": "Standard_LRS", "tier": "Standard"},
    "identity": {"type": "SystemAssigned"},
    "properties": {
        "supportsHttpsTrafficOnly": true,
        "networkAcls": {
            "defaultAction": "Allow",
            "ipRules": [
                {"action": "Allow", "value": "1.2.3.0/24"},
                {"action": "Deny", "value": "5.6.7.0/24"}
            ]
        },
        "encryption": {
            "services": {
                "blob": {"enabled": true},
                "file": {"enabled": true}
            }
        }
    }
}`

// simpleResolveField resolves a field from JSON using gjson directly.
func simpleResolveField(resourceJSON string, field string) (any, error) {
	// Handle builtins
	switch field {
	case "name", "fullName":
		return gjsonVal(resourceJSON, "name"), nil
	case "type":
		return gjsonVal(resourceJSON, "type"), nil
	case "location":
		return gjsonVal(resourceJSON, "location"), nil
	case "kind":
		return gjsonVal(resourceJSON, "kind"), nil
	case "id":
		return gjsonVal(resourceJSON, "id"), nil
	}
	// Direct path
	return gjsonVal(resourceJSON, field), nil
}

// simpleResolveFieldArray resolves array fields from JSON.
func simpleResolveFieldArray(resourceJSON string, field string) ([]any, error) {
	if strings.Contains(field, "[*]") {
		// If field ends with [*], resolve the base array
		if strings.HasSuffix(field, "[*]") {
			basePath := field[:len(field)-3]
			r := gjson.Get(resourceJSON, basePath)
			if !r.Exists() || r.Type == gjson.Null {
				return nil, nil
			}
			if r.IsArray() {
				arr := r.Array()
				out := make([]any, len(arr))
				for i, v := range arr {
					out[i] = v.Value()
				}
				return out, nil
			}
			return []any{r.Value()}, nil
		}
		// Has suffix after [*], e.g. ipRules[*].action — use # syntax
		path := strings.ReplaceAll(field, "[*]", ".#")
		path = strings.ReplaceAll(path, "..#", ".#")
		r := gjson.Get(resourceJSON, path)
		if !r.Exists() || r.Type == gjson.Null {
			return nil, nil
		}
		if r.IsArray() {
			arr := r.Array()
			out := make([]any, len(arr))
			for i, v := range arr {
				out[i] = v.Value()
			}
			return out, nil
		}
		return []any{r.Value()}, nil
	}
	v, err := simpleResolveField(resourceJSON, field)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	return []any{v}, nil
}

func gjsonVal(json string, path string) any {
	r := gjson.Get(json, path)
	if !r.Exists() || r.Type == gjson.Null {
		return nil
	}
	return r.Value()
}

func testEvalContext() *EvalContext {
	return &EvalContext{
		ResourceJSON:      testStorageAccount,
		ResolveField:      simpleResolveField,
		ResolveFieldArray: simpleResolveFieldArray,
		Operators:         DefaultOperatorRegistry(),
	}
}

func TestAllOf_BothTrue(t *testing.T) {
	ctx := testEvalContext()
	node := &AllOf{
		Conditions: []Node{
			&FieldCondition{Field: "type", Operator: "equals", Value: "Microsoft.Storage/storageAccounts"},
			&FieldCondition{Field: "location", Operator: "equals", Value: "eastus"},
		},
	}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, result)
}

func TestAllOf_OneFalse(t *testing.T) {
	ctx := testEvalContext()
	node := &AllOf{
		Conditions: []Node{
			&FieldCondition{Field: "type", Operator: "equals", Value: "Microsoft.Storage/storageAccounts"},
			&FieldCondition{Field: "location", Operator: "equals", Value: "westus"},
		},
	}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestAnyOf_OneTrue(t *testing.T) {
	ctx := testEvalContext()
	node := &AnyOf{
		Conditions: []Node{
			&FieldCondition{Field: "location", Operator: "equals", Value: "westus"},
			&FieldCondition{Field: "location", Operator: "equals", Value: "eastus"},
		},
	}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, result)
}

func TestAnyOf_AllFalse(t *testing.T) {
	ctx := testEvalContext()
	node := &AnyOf{
		Conditions: []Node{
			&FieldCondition{Field: "location", Operator: "equals", Value: "westus"},
			&FieldCondition{Field: "location", Operator: "equals", Value: "northeurope"},
		},
	}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestNot_Negation(t *testing.T) {
	ctx := testEvalContext()
	node := &Not{
		Condition: &FieldCondition{Field: "location", Operator: "equals", Value: "westus"},
	}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, result)
}

func TestFieldCondition_Equals(t *testing.T) {
	ctx := testEvalContext()
	node := &FieldCondition{Field: "name", Operator: "equals", Value: "sa1"}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, result)
}

func TestFieldCondition_ArrayAlias_ImplicitAllOf(t *testing.T) {
	ctx := testEvalContext()
	node := &FieldCondition{
		Field:    "properties.networkAcls.ipRules[*].action",
		Operator: "equals",
		Value:    "Allow",
	}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.False(t, result, "not all ipRules have action=Allow")
}

func TestFieldCondition_ArrayAlias_EmptyVacuousTrue(t *testing.T) {
	emptyJSON := `{
		"name": "sa2",
		"type": "Microsoft.Storage/storageAccounts",
		"properties": {
			"networkAcls": {
				"ipRules": []
			}
		}
	}`
	ctx := &EvalContext{
		ResourceJSON:      emptyJSON,
		ResolveField:      simpleResolveField,
		ResolveFieldArray: simpleResolveFieldArray,
		Operators:         DefaultOperatorRegistry(),
	}
	node := &FieldCondition{
		Field:    "properties.networkAcls.ipRules[*].action",
		Operator: "equals",
		Value:    "Allow",
	}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, result, "empty array should be vacuous true")
}

func TestFieldCondition_MissingField(t *testing.T) {
	ctx := testEvalContext()
	node := &FieldCondition{Field: "nonexistent.field", Operator: "exists", Value: false}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, result, "missing field with exists=false should be true")
}

func TestCountCondition_FieldCount(t *testing.T) {
	ctx := testEvalContext()
	node := &CountCondition{
		Field:    "properties.networkAcls.ipRules[*]",
		Operator: "greaterOrEquals",
		Operand:  float64(2),
	}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, result, "should have >= 2 ipRules")
}

func TestCountCondition_FieldCountWithWhere(t *testing.T) {
	// Count ipRules where type != nil (all of them have fields, so count=2)
	ctx := testEvalContext()
	node := &CountCondition{
		Field: "properties.networkAcls.ipRules[*]",
		Where: &FieldCondition{
			Field:    "type",
			Operator: "equals",
			Value:    "Microsoft.Storage/storageAccounts",
		},
		Operator: "equals",
		Operand:  float64(2),
	}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, result, "where always true → count should equal total elements")
}

func TestCountCondition_FieldCountWithWhereFalse(t *testing.T) {
	// Count with where that's always false → count=0
	ctx := testEvalContext()
	node := &CountCondition{
		Field: "properties.networkAcls.ipRules[*]",
		Where: &FieldCondition{
			Field:    "type",
			Operator: "equals",
			Value:    "nonexistent",
		},
		Operator: "equals",
		Operand:  float64(0),
	}
	result, err := node.Evaluate(ctx)
	require.NoError(t, err)
	assert.True(t, result, "where always false → count should be 0")
}
