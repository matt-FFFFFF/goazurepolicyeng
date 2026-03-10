package scope

import "testing"

func TestIsApplicable_InScope(t *testing.T) {
	ok := IsApplicable(
		"/subscriptions/sub1",
		nil, nil,
		"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		"eastus", "Microsoft.Compute/virtualMachines",
	)
	if !ok {
		t.Fatal("expected applicable")
	}
}

func TestIsApplicable_OutOfScope(t *testing.T) {
	ok := IsApplicable(
		"/subscriptions/sub1",
		nil, nil,
		"/subscriptions/sub2/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		"eastus", "Microsoft.Compute/virtualMachines",
	)
	if ok {
		t.Fatal("expected not applicable")
	}
}

func TestIsApplicable_NotScoped(t *testing.T) {
	ok := IsApplicable(
		"/subscriptions/sub1",
		[]string{"/subscriptions/sub1/resourceGroups/excluded"},
		nil,
		"/subscriptions/sub1/resourceGroups/excluded/providers/Microsoft.Compute/virtualMachines/vm1",
		"eastus", "Microsoft.Compute/virtualMachines",
	)
	if ok {
		t.Fatal("expected not applicable due to notScope")
	}
}

func TestIsApplicable_ResourceSelectorLocation(t *testing.T) {
	sel := []ResourceSelector{{
		Name: "locationFilter",
		Selectors: []SelectorExpression{{
			Kind: "resourceLocation",
			In:   []string{"eastus", "westus"},
		}},
	}}
	if !IsApplicable("/subscriptions/sub1", nil, sel,
		"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		"eastus", "Microsoft.Compute/virtualMachines") {
		t.Fatal("expected applicable for eastus")
	}
	if IsApplicable("/subscriptions/sub1", nil, sel,
		"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		"northeurope", "Microsoft.Compute/virtualMachines") {
		t.Fatal("expected not applicable for northeurope")
	}
}

func TestIsApplicable_ResourceSelectorType(t *testing.T) {
	sel := []ResourceSelector{{
		Selectors: []SelectorExpression{{
			Kind: "resourceType",
			In:   []string{"Microsoft.Storage/storageAccounts"},
		}},
	}}
	if IsApplicable("/subscriptions/sub1", nil, sel,
		"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		"eastus", "Microsoft.Compute/virtualMachines") {
		t.Fatal("expected not applicable for VM type")
	}
}

func TestIsApplicable_ResourceSelectorNotIn(t *testing.T) {
	sel := []ResourceSelector{{
		Selectors: []SelectorExpression{{
			Kind:  "resourceLocation",
			NotIn: []string{"eastus"},
		}},
	}}
	if IsApplicable("/subscriptions/sub1", nil, sel,
		"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		"eastus", "Microsoft.Compute/virtualMachines") {
		t.Fatal("expected not applicable for excluded location")
	}
	if !IsApplicable("/subscriptions/sub1", nil, sel,
		"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		"westus", "Microsoft.Compute/virtualMachines") {
		t.Fatal("expected applicable for non-excluded location")
	}
}

func TestIsApplicable_NoSelectors(t *testing.T) {
	ok := IsApplicable(
		"/subscriptions/sub1",
		nil, nil,
		"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		"eastus", "Microsoft.Compute/virtualMachines",
	)
	if !ok {
		t.Fatal("expected applicable with no selectors")
	}
}

func TestResolveOverride_Match(t *testing.T) {
	overrides := []Override{{
		Kind:  "policyEffect",
		Value: "Disabled",
		Selectors: []SelectorExpression{{
			Kind: "policyDefinitionReferenceId",
			In:   []string{"defRef1"},
		}},
	}}
	effect, ok := ResolveOverride(overrides, "defRef1")
	if !ok || effect != "Disabled" {
		t.Fatalf("expected Disabled, got %s (ok=%v)", effect, ok)
	}
}

func TestResolveOverride_NoMatch(t *testing.T) {
	overrides := []Override{{
		Kind:  "policyEffect",
		Value: "Disabled",
		Selectors: []SelectorExpression{{
			Kind: "policyDefinitionReferenceId",
			In:   []string{"defRef1"},
		}},
	}}
	_, ok := ResolveOverride(overrides, "defRef999")
	if ok {
		t.Fatal("expected no match")
	}
}

func TestIsApplicable_CaseInsensitive(t *testing.T) {
	ok := IsApplicable(
		"/Subscriptions/SUB1",
		nil, nil,
		"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		"eastus", "Microsoft.Compute/virtualMachines",
	)
	if !ok {
		t.Fatal("expected case-insensitive scope match")
	}

	// NotScopes case-insensitive
	ok = IsApplicable(
		"/subscriptions/sub1",
		[]string{"/Subscriptions/Sub1/ResourceGroups/Excluded"},
		nil,
		"/subscriptions/sub1/resourcegroups/excluded/providers/Microsoft.Compute/virtualMachines/vm1",
		"eastus", "Microsoft.Compute/virtualMachines",
	)
	if ok {
		t.Fatal("expected case-insensitive notScope match")
	}
}
