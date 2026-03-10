package effect

import (
	"context"
	"encoding/json"
	"testing"
)

func TestParseEffect_CaseInsensitive(t *testing.T) {
	tests := []struct {
		input string
		want  Effect
	}{
		{"deny", Deny},
		{"Deny", Deny},
		{"DENY", Deny},
		{"AuditIfNotExists", AuditIfNotExists},
		{"auditifnotexists", AuditIfNotExists},
		{"DeployIfNotExists", DeployIfNotExists},
		{"denyAction", DenyAction},
		{"DENYACTION", DenyAction},
		{"Mutate", Mutate},
		{"disabled", Disabled},
		{"manual", Manual},
	}
	for _, tt := range tests {
		got, err := ParseEffect(tt.input)
		if err != nil {
			t.Errorf("ParseEffect(%q) returned error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseEffect(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseEffect_Invalid(t *testing.T) {
	_, err := ParseEffect("notAnEffect")
	if err == nil {
		t.Error("ParseEffect(\"notAnEffect\") should return error")
	}
}

func TestComplianceFromEffect_DenyMatched(t *testing.T) {
	got := ComplianceFromEffect(Deny, true)
	if got != NonCompliant {
		t.Errorf("got %v, want NonCompliant", got)
	}
}

func TestComplianceFromEffect_AuditNotMatched(t *testing.T) {
	got := ComplianceFromEffect(Audit, false)
	if got != Compliant {
		t.Errorf("got %v, want Compliant", got)
	}
}

func TestComplianceFromEffect_Disabled(t *testing.T) {
	got := ComplianceFromEffect(Disabled, true)
	if got != NotApplicable {
		t.Errorf("got %v, want NotApplicable", got)
	}
}

func TestComplianceFromEffect_Manual(t *testing.T) {
	got := ComplianceFromEffect(Manual, true)
	if got != Compliant {
		t.Errorf("got %v, want Compliant", got)
	}
}

func TestComplianceFromEffect_AINE(t *testing.T) {
	got := ComplianceFromEffect(AuditIfNotExists, true)
	if got != NeedsExistenceCheck {
		t.Errorf("got %v, want NeedsExistenceCheck", got)
	}
}

// mockFinder is a test helper implementing ResourceFinder.
type mockFinder struct {
	resources []Resource
	err       error
}

func (m *mockFinder) Find(_ context.Context, _ ResourceQuery) ([]Resource, error) {
	return m.resources, m.err
}

func TestCheckExistence_Found(t *testing.T) {
	finder := &mockFinder{resources: []Resource{{JSON: `{"type":"Microsoft.Compute/extensions"}`}}}
	details := ExistenceDetails{Type: "Microsoft.Compute/extensions"}
	got, err := CheckExistence(context.Background(), details, "/subscriptions/sub1/resourceGroups/rg1", finder, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("expected true (resource found)")
	}
}

func TestCheckExistence_NotFound(t *testing.T) {
	finder := &mockFinder{resources: nil}
	details := ExistenceDetails{Type: "Microsoft.Compute/extensions"}
	got, err := CheckExistence(context.Background(), details, "/subscriptions/sub1/resourceGroups/rg1", finder, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Error("expected false (no resource found)")
	}
}

func TestCheckExistence_WithCondition(t *testing.T) {
	finder := &mockFinder{resources: []Resource{
		{JSON: `{"properties":{"enabled":false}}`},
		{JSON: `{"properties":{"enabled":true}}`},
	}}
	details := ExistenceDetails{
		Type:               "Microsoft.Compute/extensions",
		ExistenceCondition: json.RawMessage(`{"field":"properties.enabled","equals":true}`),
	}

	callCount := 0
	evaluator := func(resourceJSON string) (bool, error) {
		callCount++
		// Simulate: only the second resource matches.
		return callCount == 2, nil
	}

	got, err := CheckExistence(context.Background(), details, "/subscriptions/sub1/resourceGroups/rg1", finder, evaluator)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("expected true (second resource matches condition)")
	}
}

func TestCheckExistence_NoCondition(t *testing.T) {
	finder := &mockFinder{resources: []Resource{{JSON: `{}`}}}
	details := ExistenceDetails{Type: "Microsoft.Compute/extensions"}
	got, err := CheckExistence(context.Background(), details, "/subscriptions/sub1/resourceGroups/rg1", finder, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("expected true (no condition, resource exists)")
	}
}

func TestCheckExistence_SubscriptionScope(t *testing.T) {
	var capturedQuery ResourceQuery
	finder := &mockFinder{resources: []Resource{{JSON: `{}`}}}
	origFind := finder.Find
	_ = origFind
	// Use a wrapper to capture the query.
	wrapper := &queryCaptureFinder{inner: finder, captured: &capturedQuery}

	details := ExistenceDetails{
		Type:           "Microsoft.Insights/diagnosticSettings",
		ExistenceScope: "Subscription",
	}
	_, err := CheckExistence(context.Background(), details, "/subscriptions/sub1/resourceGroups/rg1", wrapper, nil)
	if err != nil {
		t.Fatal(err)
	}
	if capturedQuery.Scope != "/subscriptions/sub1" {
		t.Errorf("scope = %q, want /subscriptions/sub1", capturedQuery.Scope)
	}
}

type queryCaptureFinder struct {
	inner    ResourceFinder
	captured *ResourceQuery
}

func (q *queryCaptureFinder) Find(ctx context.Context, query ResourceQuery) ([]Resource, error) {
	*q.captured = query
	return q.inner.Find(ctx, query)
}

func TestCheckExistence_ResourceGroupOverride(t *testing.T) {
	var capturedQuery ResourceQuery
	finder := &mockFinder{resources: []Resource{{JSON: `{}`}}}
	wrapper := &queryCaptureFinder{inner: finder, captured: &capturedQuery}

	details := ExistenceDetails{
		Type:              "Microsoft.Network/networkWatchers",
		ResourceGroupName: "NetworkWatcherRG",
	}
	_, err := CheckExistence(context.Background(), details, "/subscriptions/sub1/resourceGroups/rg1", wrapper, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "/subscriptions/sub1/resourceGroups/NetworkWatcherRG"
	if capturedQuery.Scope != want {
		t.Errorf("scope = %q, want %q", capturedQuery.Scope, want)
	}
}
