package alias

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func testResolver() *MapResolver {
	return NewMapResolver(map[string]string{
		"Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly":    "properties.supportsHttpsTrafficOnly",
		"Microsoft.Storage/storageAccounts/networkAcls.defaultAction":   "properties.networkAcls.defaultAction",
		"Microsoft.Storage/storageAccounts/networkAcls.ipRules":         "properties.networkAcls.ipRules",
		"Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].action": "properties.networkAcls.ipRules",
		"Microsoft.Storage/storageAccounts/sku.name":                    "sku.name",
	})
}

func TestResolveField_BuiltinFields(t *testing.T) {
	r := testResolver()

	tests := []struct {
		field string
		want  any
	}{
		{"name", "sa1"},
		{"fullName", "sa1"},
		{"type", "Microsoft.Storage/storageAccounts"},
		{"location", "eastus"},
		{"kind", "StorageV2"},
		{"id", "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1"},
		{"identity.type", "SystemAssigned"},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			got, err := ResolveField(testStorageAccount, tt.field, r)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveField_Tags(t *testing.T) {
	r := testResolver()

	// Whole tags object
	got, err := ResolveField(testStorageAccount, "tags", r)
	require.NoError(t, err)
	tags, ok := got.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "prod", tags["env"])
	assert.Equal(t, "platform", tags["team"])

	// tags['env']
	got, err = ResolveField(testStorageAccount, "tags['env']", r)
	require.NoError(t, err)
	assert.Equal(t, "prod", got)

	// tags.env
	got, err = ResolveField(testStorageAccount, "tags.env", r)
	require.NoError(t, err)
	assert.Equal(t, "prod", got)

	// Missing tag
	got, err = ResolveField(testStorageAccount, "tags['missing']", r)
	require.NoError(t, err)
	assert.Nil(t, got)

	// Missing tag via dot
	got, err = ResolveField(testStorageAccount, "tags.missing", r)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestResolveField_AliasResolution(t *testing.T) {
	r := testResolver()

	// properties field via alias
	got, err := ResolveField(testStorageAccount, "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly", r)
	require.NoError(t, err)
	assert.Equal(t, true, got)

	got, err = ResolveField(testStorageAccount, "Microsoft.Storage/storageAccounts/networkAcls.defaultAction", r)
	require.NoError(t, err)
	assert.Equal(t, "Allow", got)

	// Top-level alias (sku.name, not under properties)
	got, err = ResolveField(testStorageAccount, "Microsoft.Storage/storageAccounts/sku.name", r)
	require.NoError(t, err)
	assert.Equal(t, "Standard_LRS", got)
}

func TestResolveField_DirectPath(t *testing.T) {
	r := testResolver()

	// Direct gjson path (no alias needed)
	got, err := ResolveField(testStorageAccount, "sku.name", r)
	require.NoError(t, err)
	assert.Equal(t, "Standard_LRS", got)

	got, err = ResolveField(testStorageAccount, "properties.supportsHttpsTrafficOnly", r)
	require.NoError(t, err)
	assert.Equal(t, true, got)
}

func TestResolveField_ArrayAlias(t *testing.T) {
	r := testResolver()

	got, err := ResolveFieldArray(testStorageAccount, "properties.networkAcls.ipRules[*].action", r)
	require.NoError(t, err)
	assert.Equal(t, []any{"Allow", "Deny"}, got)
}

func TestResolveField_Missing(t *testing.T) {
	r := testResolver()

	got, err := ResolveField(testStorageAccount, "nonexistent.field", r)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestResolveFieldArray_NonArray(t *testing.T) {
	r := testResolver()

	got, err := ResolveFieldArray(testStorageAccount, "name", r)
	require.NoError(t, err)
	assert.Equal(t, []any{"sa1"}, got)
}

func TestResolveFieldArray_Missing(t *testing.T) {
	r := testResolver()

	got, err := ResolveFieldArray(testStorageAccount, "nonexistent", r)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestIsBuiltinField(t *testing.T) {
	assert.True(t, IsBuiltinField("name"))
	assert.True(t, IsBuiltinField("tags"))
	assert.True(t, IsBuiltinField("tags['env']"))
	assert.True(t, IsBuiltinField("tags.env"))
	assert.True(t, IsBuiltinField("identity.type"))
	assert.False(t, IsBuiltinField("properties.foo"))
	assert.False(t, IsBuiltinField("sku.name"))
}
