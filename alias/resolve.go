package alias

import (
	"strings"

	goazurepolicyeng "github.com/matt-FFFFFF/goazurepolicyeng"
	"github.com/tidwall/gjson"
)

// ResolveField resolves a field reference from a resource JSON document.
func ResolveField(resourceJSON string, field string, resolver goazurepolicyeng.AliasResolver) (any, error) {
	// Handle built-in fields
	if IsBuiltinField(field) {
		return resolveBuiltin(resourceJSON, field), nil
	}

	// Check if it contains [*] — array alias
	if strings.Contains(field, "[*]") {
		return resolveArrayAlias(resourceJSON, field, resolver), nil
	}

	// Regular alias lookup
	if resolver != nil {
		path, ok := resolver.GetPath(field)
		if ok {
			return resolveGjsonPath(resourceJSON, path), nil
		}
	}

	// Try as a direct gjson path (for fields like sku.name)
	return resolveGjsonPath(resourceJSON, field), nil
}

// ResolveFieldArray resolves a [*] array alias and returns individual elements.
// For non-array fields, wraps the single value in a slice.
func ResolveFieldArray(resourceJSON string, field string, resolver goazurepolicyeng.AliasResolver) ([]any, error) {
	if strings.Contains(field, "[*]") {
		result := resolveArrayAliasSlice(resourceJSON, field, resolver)
		return result, nil
	}

	v, err := ResolveField(resourceJSON, field, resolver)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	return []any{v}, nil
}

func resolveBuiltin(resourceJSON string, field string) any {
	switch {
	case field == "name" || field == "fullName":
		return resolveGjsonPath(resourceJSON, "name")
	case field == "type":
		return resolveGjsonPath(resourceJSON, "type")
	case field == "kind":
		return resolveGjsonPath(resourceJSON, "kind")
	case field == "location":
		v := resolveGjsonPath(resourceJSON, "location")
		if s, ok := v.(string); ok {
			return strings.ToLower(strings.ReplaceAll(s, " ", ""))
		}
		return v
	case field == "id":
		return resolveGjsonPath(resourceJSON, "id")
	case field == "identity.type":
		return resolveGjsonPath(resourceJSON, "identity.type")
	case field == "tags":
		r := gjson.Get(resourceJSON, "tags")
		if !r.Exists() || r.Type == gjson.Null {
			return nil
		}
		return r.Value()
	case strings.HasPrefix(field, "tags['") && strings.HasSuffix(field, "']"):
		key := field[6 : len(field)-2]
		return resolveGjsonPath(resourceJSON, "tags."+key)
	case strings.HasPrefix(field, "tags."):
		return resolveGjsonPath(resourceJSON, field)
	}
	return nil
}

func resolveGjsonPath(resourceJSON string, path string) any {
	r := gjson.Get(resourceJSON, path)
	if !r.Exists() || r.Type == gjson.Null {
		return nil
	}
	return r.Value()
}

func resolveArrayAlias(resourceJSON string, field string, resolver goazurepolicyeng.AliasResolver) any {
	gjsonPath := convertArrayPath(field, resolver)
	if gjsonPath == "" {
		return nil
	}
	r := gjson.Get(resourceJSON, gjsonPath)
	if !r.Exists() || r.Type == gjson.Null {
		return nil
	}
	if r.IsArray() {
		arr := r.Array()
		if len(arr) == 0 {
			return []any{}
		}
		out := make([]any, len(arr))
		for i, v := range arr {
			out[i] = v.Value()
		}
		return out
	}
	return r.Value()
}

func resolveArrayAliasSlice(resourceJSON string, field string, resolver goazurepolicyeng.AliasResolver) []any {
	v := resolveArrayAlias(resourceJSON, field, resolver)
	if v == nil {
		return nil
	}
	if arr, ok := v.([]any); ok {
		return arr
	}
	return []any{v}
}

// convertArrayPath converts a field with [*] to a gjson path using # syntax.
// It first strips [*] to look up the base alias, then reapplies # syntax.
func convertArrayPath(field string, resolver goazurepolicyeng.AliasResolver) string {
	// e.g. "properties.networkAcls.ipRules[*].action"
	// Try direct path conversion: replace [*] with #
	gjsonPath := strings.ReplaceAll(field, "[*]", ".#")
	// Clean up double dots
	gjsonPath = strings.ReplaceAll(gjsonPath, "..#", ".#")

	// If we have a resolver, try looking up the base alias
	if resolver != nil {
		// Strip [*] and everything after to get base alias
		base := field
		suffix := ""
		if idx := strings.Index(field, "[*]"); idx >= 0 {
			base = field[:idx]
			suffix = field[idx+3:] // e.g. ".action" or ""
		}
		if path, ok := resolver.GetPath(base); ok {
			gjsonPath = path + ".#" + suffix
			gjsonPath = strings.ReplaceAll(gjsonPath, "..#", ".#")
		} else if path, ok := resolver.GetPath(field); ok {
			// Try full field as alias
			gjsonPath = strings.ReplaceAll(path, "[*]", ".#")
			gjsonPath = strings.ReplaceAll(gjsonPath, "..#", ".#")
		}
	}

	return gjsonPath
}
