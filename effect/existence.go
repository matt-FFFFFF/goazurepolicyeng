package effect

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ExistenceDetails holds the parsed "then.details" for AINE/DINE effects.
type ExistenceDetails struct {
	Type               string          `json:"type"`               // Related resource type
	Name               string          `json:"name"`               // Optional specific name
	ExistenceScope     string          `json:"existenceScope"`     // "ResourceGroup" (default) or "Subscription"
	ResourceGroupName  string          `json:"resourceGroupName"`  // Optional override RG
	ExistenceCondition json.RawMessage `json:"existenceCondition"` // Optional policy condition
}

// ResourceFinder looks up related resources.
type ResourceFinder interface {
	Find(ctx context.Context, query ResourceQuery) ([]Resource, error)
}

// ResourceQuery describes what related resources to find.
type ResourceQuery struct {
	ResourceType string
	Scope        string // subscription or resource group scope
	Name         string // optional filter by name
}

// Resource represents a found related resource.
type Resource struct {
	JSON string // Full ARM JSON for condition evaluation
}

// CheckExistence evaluates the existence check for AINE/DINE.
// Returns true if a qualifying related resource exists (→ Compliant).
// Returns false if no related resource matches (→ NonCompliant).
//
// conditionEvaluator is called for each found resource to check existenceCondition.
// If existenceCondition is nil/empty, any resource of the right type satisfies the check.
func CheckExistence(
	ctx context.Context,
	details ExistenceDetails,
	primaryResourceScope string,
	finder ResourceFinder,
	conditionEvaluator func(resourceJSON string) (bool, error),
) (bool, error) {
	scope, err := resolveScope(details, primaryResourceScope)
	if err != nil {
		return false, err
	}

	query := ResourceQuery{
		ResourceType: details.Type,
		Scope:        scope,
		Name:         details.Name,
	}
	resources, err := finder.Find(ctx, query)
	if err != nil {
		return false, err
	}

	// If no existenceCondition, any resource satisfies.
	if len(details.ExistenceCondition) == 0 {
		return len(resources) > 0, nil
	}

	// Evaluate existenceCondition against each resource.
	for _, r := range resources {
		matched, err := conditionEvaluator(r.JSON)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}

	return false, nil
}

// resolveScope determines the scope for the existence query based on the details
// and the primary resource's scope.
func resolveScope(details ExistenceDetails, primaryResourceScope string) (string, error) {
	scope := primaryResourceScope

	// Extract subscription from scope.
	subID := extractSubscription(primaryResourceScope)
	if subID == "" {
		return "", fmt.Errorf("cannot extract subscription from scope: %q", primaryResourceScope)
	}

	if details.ResourceGroupName != "" {
		// Override to a specific resource group within the same subscription.
		scope = "/subscriptions/" + subID + "/resourceGroups/" + details.ResourceGroupName
	}

	if strings.EqualFold(details.ExistenceScope, "Subscription") {
		// Widen to subscription scope.
		scope = "/subscriptions/" + subID
	}

	return scope, nil
}

// extractSubscription pulls the subscription ID from an ARM scope string.
func extractSubscription(scope string) string {
	lower := strings.ToLower(scope)
	const prefix = "/subscriptions/"
	idx := strings.Index(lower, prefix)
	if idx < 0 {
		return ""
	}
	rest := scope[idx+len(prefix):]
	if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
		return rest[:slashIdx]
	}
	return rest
}
