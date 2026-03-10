package alias

// Mapping maps an alias name to its JSON path within the resource document.
type Mapping struct {
	Alias   string // e.g. "Microsoft.Storage/storageAccounts/networkAcls.defaultAction"
	Path    string // e.g. "properties.networkAcls.defaultAction"
	IsArray bool   // true if this is a [*] alias
}

// MapResolver is an in-memory AliasResolver backed by a map.
type MapResolver struct {
	aliases map[string]string // alias → gjson path
}

// NewMapResolver creates a resolver from a set of alias→path mappings.
func NewMapResolver(mappings map[string]string) *MapResolver {
	m := make(map[string]string, len(mappings))
	for k, v := range mappings {
		m[k] = v
	}
	return &MapResolver{aliases: m}
}

// GetPath returns the gjson path for an alias.
func (r *MapResolver) GetPath(alias string) (string, bool) {
	p, ok := r.aliases[alias]
	return p, ok
}
