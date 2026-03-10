package goazurepolicyeng

import "encoding/json"

// ComplianceState represents the evaluation result.
type ComplianceState int

const (
	Compliant ComplianceState = iota
	NonCompliant
	NotApplicable // disabled effect or not in scope
	Error         // evaluation error
)

func (c ComplianceState) String() string {
	switch c {
	case Compliant:
		return "Compliant"
	case NonCompliant:
		return "NonCompliant"
	case NotApplicable:
		return "NotApplicable"
	case Error:
		return "Error"
	default:
		return "Unknown"
	}
}

// PolicyDefinition represents a parsed Azure Policy definition.
type PolicyDefinition struct {
	ID          string                         `json:"id"`
	Name        string                         `json:"name"`
	DisplayName string                         `json:"displayName"`
	PolicyType  string                         `json:"policyType"` // BuiltIn, Custom, Static
	Mode        string                         `json:"mode"`       // All, Indexed
	Parameters  map[string]ParameterDefinition `json:"parameters"`
	PolicyRule  json.RawMessage                `json:"policyRule"` // Parsed later into condition tree
}

// ParameterDefinition defines a policy parameter.
type ParameterDefinition struct {
	Type          string `json:"type"` // String, Array, Object, Boolean, Integer, Float, DateTime
	DefaultValue  any    `json:"defaultValue"`
	AllowedValues []any  `json:"allowedValues"`
	Metadata      any    `json:"metadata"`
}

// PolicySetDefinition represents an initiative.
type PolicySetDefinition struct {
	ID                     string                      `json:"id"`
	Name                   string                      `json:"name"`
	DisplayName            string                      `json:"displayName"`
	Parameters             map[string]ParameterDefinition `json:"parameters"`
	PolicyDefinitions      []PolicyDefinitionReference `json:"policyDefinitions"`
	PolicyDefinitionGroups []PolicyDefinitionGroup     `json:"policyDefinitionGroups"`
}

// PolicyDefinitionReference is a reference to a policy within an initiative.
type PolicyDefinitionReference struct {
	PolicyDefinitionID    string                    `json:"policyDefinitionId"`
	DefinitionReferenceID string                    `json:"policyDefinitionReferenceId"`
	Parameters            map[string]ParameterValue `json:"parameters"`
	GroupNames            []string                  `json:"groupNames"`
}

// PolicyDefinitionGroup groups policies within an initiative.
type PolicyDefinitionGroup struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Category    string `json:"category"`
}

// ParameterValue holds a parameter value.
type ParameterValue struct {
	Value any `json:"value"`
}

// Assignment represents a policy or initiative assignment.
type Assignment struct {
	ID                 string                    `json:"id"`
	Name               string                    `json:"name"`
	DisplayName        string                    `json:"displayName"`
	Scope              string                    `json:"scope"`              // e.g. /subscriptions/{id}
	NotScopes          []string                  `json:"notScopes"`
	PolicyDefinitionID string                    `json:"policyDefinitionId"` // could be definition or set
	Parameters         map[string]ParameterValue `json:"parameters"`
	EnforcementMode    string                    `json:"enforcementMode"` // Default, DoNotEnforce
	ResourceSelectors  []ResourceSelector        `json:"resourceSelectors"`
	Overrides          []Override                `json:"overrides"`
	EffectOverride     string                    `json:"-"` // Set by initiative evaluation to override effect
}

// ResourceSelector filters which resources an assignment applies to.
type ResourceSelector struct {
	Name      string               `json:"name"`
	Selectors []SelectorExpression `json:"selectors"`
}

// SelectorExpression is a single selector within a ResourceSelector or Override.
type SelectorExpression struct {
	Kind  string   `json:"kind"` // resourceLocation, resourceType
	In    []string `json:"in"`
	NotIn []string `json:"notIn"`
}

// Override allows overriding the effect of a policy.
type Override struct {
	Kind      string               `json:"kind"`  // policyEffect
	Value     string               `json:"value"`
	Selectors []SelectorExpression `json:"selectors"`
}

// Resource represents a cached Azure resource for evaluation.
type Resource struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Location       string            `json:"location"`
	Kind           string            `json:"kind"`
	SubscriptionID string            `json:"subscriptionId"`
	ResourceGroup  string            `json:"resourceGroup"`
	TenantID       string            `json:"tenantId"`
	Tags           map[string]string `json:"tags"`
	Identity       *Identity         `json:"identity"`
	Raw            json.RawMessage   `json:"-"` // Full ARM JSON document for gjson queries
}

// Identity represents the managed identity of a resource.
type Identity struct {
	Type string `json:"type"`
}
