package alias

import "strings"

// builtinFields lists fields resolved directly from the resource document
// without alias lookup.
var builtinFields = map[string]bool{
	"name":          true,
	"fullName":      true,
	"type":          true,
	"kind":          true,
	"location":      true,
	"id":            true,
	"identity.type": true,
}

// IsBuiltinField returns true if the field is a built-in policy field
// (not an alias that needs lookup).
func IsBuiltinField(field string) bool {
	if builtinFields[field] {
		return true
	}
	// tags, tags['key'], tags.key
	if field == "tags" || strings.HasPrefix(field, "tags[") || strings.HasPrefix(field, "tags.") {
		return true
	}
	return false
}
