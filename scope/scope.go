// Package scope implements Azure Policy assignment scoping logic.
package scope

import "strings"

// hasScopePrefix checks if id starts with scope at a path-segment boundary.
func hasScopePrefix(id, scope string) bool {
	if !strings.HasPrefix(id, scope) {
		return false
	}
	if len(id) == len(scope) {
		return true
	}
	return id[len(scope)] == '/'
}

// ResourceSelector mirrors the root package type to avoid circular imports.
type ResourceSelector struct {
	Name      string
	Selectors []SelectorExpression
}

// SelectorExpression is a single selector within a ResourceSelector or Override.
type SelectorExpression struct {
	Kind  string // "resourceLocation", "resourceType", "resourceWithoutLocation", "policyDefinitionReferenceId"
	In    []string
	NotIn []string
}

// Override allows overriding the effect of a policy.
type Override struct {
	Kind      string // "policyEffect"
	Value     string
	Selectors []SelectorExpression
}

// IsApplicable determines whether an assignment applies to a resource.
// Checks scope hierarchy, notScopes, and resource selectors.
// All comparisons are case-insensitive per Azure spec.
func IsApplicable(
	assignmentScope string,
	notScopes []string,
	selectors []ResourceSelector,
	resourceID string,
	resourceLocation string,
	resourceType string,
) bool {
	lowerResID := strings.ToLower(resourceID)

	// 1. Scope check: resource ID must start with assignment scope at a path boundary
	if !hasScopePrefix(lowerResID, strings.ToLower(assignmentScope)) {
		return false
	}

	// 2. NotScopes: resource ID must NOT start with any notScope
	for _, ns := range notScopes {
		if hasScopePrefix(lowerResID, strings.ToLower(ns)) {
			return false
		}
	}

	// 3. Resource selectors
	if !matchesResourceSelectors(selectors, resourceLocation, resourceType) {
		return false
	}

	return true
}

func matchesResourceSelectors(selectors []ResourceSelector, resourceLocation, resourceType string) bool {
	if len(selectors) == 0 {
		return true
	}
	// ALL resource selectors must match (AND)
	for _, rs := range selectors {
		if !matchesSelectorGroup(rs.Selectors, resourceLocation, resourceType) {
			return false
		}
	}
	return true
}

func matchesSelectorGroup(selectors []SelectorExpression, resourceLocation, resourceType string) bool {
	for _, s := range selectors {
		switch s.Kind {
		case "resourceLocation":
			if !matchesInNotIn(resourceLocation, s.In, s.NotIn) {
				return false
			}
		case "resourceType":
			if !matchesInNotIn(resourceType, s.In, s.NotIn) {
				return false
			}
		case "resourceWithoutLocation":
			hasLocation := resourceLocation != ""
			if len(s.In) > 0 {
				wantWithout := containsLower(s.In, "true")
				wantWith := containsLower(s.In, "false")
				if wantWithout && hasLocation {
					return false
				}
				if wantWith && !hasLocation {
					return false
				}
			}
		}
	}
	return true
}

func matchesInNotIn(value string, in []string, notIn []string) bool {
	lower := strings.ToLower(value)
	if len(in) > 0 {
		found := false
		for _, v := range in {
			if strings.ToLower(v) == lower {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(notIn) > 0 {
		for _, v := range notIn {
			if strings.ToLower(v) == lower {
				return false
			}
		}
	}
	return true
}

func containsLower(slice []string, target string) bool {
	for _, v := range slice {
		if strings.ToLower(v) == target {
			return true
		}
	}
	return false
}

// ResolveOverride checks if any override applies for the given definition reference ID.
// Returns the overridden effect and true if found, or empty string and false.
func ResolveOverride(overrides []Override, definitionReferenceID string) (string, bool) {
	for _, o := range overrides {
		if !strings.EqualFold(o.Kind, "policyEffect") {
			continue
		}
		for _, s := range o.Selectors {
			if strings.EqualFold(s.Kind, "policyDefinitionReferenceId") {
				if matchesInNotIn(definitionReferenceID, s.In, s.NotIn) {
					return o.Value, true
				}
			}
		}
	}
	return "", false
}
